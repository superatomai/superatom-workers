/**
 * Chat-attachment upload routes — a file the user attaches to a chat agent
 * conversation, PUT directly to R2.
 *
 * Flow:
 *   1. POST /upload/chat-attachment/initiate   → reserve key, get one presigned PUT URL
 *   2. Browser PUTs the file directly to R2
 *   3. POST /upload/chat-attachment/complete   → confirm the object landed (and its size)
 *   4. POST /upload/chat-attachment/signed-get → presigned GET URL (backend, or the uploader)
 *   5. POST /upload/chat-attachment/delete     → remove the object (e.g. its chat was deleted)
 *
 * Same direct-to-R2 approach as source-upload.ts, but sized for chat: files are
 * small, so a single presigned PUT replaces the multipart dance. Objects live in
 * the private source-files bucket under their own `chat-attachments/` prefix —
 * never the public `sa-assets` bucket.
 *
 * Key: chat-attachments/{projectId}/{appId}/{userId}/{uuid}/{fileName}
 * The app (chat agent) and uploader are in the key, so every later call can
 * re-check access from the key alone.
 *
 * Every R2 call here — signing, checking, deleting — goes through R2's S3 API
 * with the same credentials, never the R2_SOURCE_FILES binding. Under
 * `wrangler dev` that binding is a local simulation, so it never sees what the
 * browser PUT to the real bucket; the S3 API sees the same bucket everywhere.
 *
 * CORS reminder: the `sa-source-files` bucket must allow PUT from the runtime
 * UI origins (not just the platform UI) for step 2 to work from the browser.
 */

import { Hono } from "hono";
import { and, eq, ne, sql } from "drizzle-orm";
import { files } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, authenticateRequest } from "../middleware/auth";
import { assertProjectAccess, type AppContext } from "../lib/project-access";
import { r2S3Client, objectUrl, deleteObject } from "../lib/r2-objects";

const KEY_PREFIX = "chat-attachments/";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

const UPLOAD_URL_TTL_SECONDS = 15 * 60; // 15 minutes — one small file
const DOWNLOAD_URL_TTL_SECONDS = 60 * 60; // 1 hour

const ALLOWED_EXTENSIONS = [
	"pdf", "docx", "txt", "md", "json",
	"csv", "xlsx", "xls",
	"png", "jpg", "jpeg", "webp", "gif",
];

const chatAttachmentRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/** Marks the file's row deleted. No row (an upload from before files were recorded) is fine. */
async function markFileDeleted(c: AppContext, key: string): Promise<void> {
	await c
		.get("db")
		.update(files)
		.set({ status: "deleted", deletedAt: new Date() })
		.where(and(eq(files.r2Key, key), ne(files.status, "deleted")));
}

function sanitizeFileName(name: string): string {
	return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 200);
}

function buildObjectKey(projectId: string, appId: string, userId: string, fileName: string): string {
	return `${KEY_PREFIX}${projectId}/${appId}/${userId}/${crypto.randomUUID()}/${sanitizeFileName(fileName)}`;
}

/** The ids a key was built from, or null when it isn't a chat-attachment key. */
function parseKey(key: string): { projectId: string; appId: string; userId: string; fileName: string } | null {
	if (!key.startsWith(KEY_PREFIX) || key.includes("..")) return null;
	const parts = key.slice(KEY_PREFIX.length).split("/");
	if (parts.length !== 5 || parts.some((p) => !p)) return null;
	const [projectId, appId, userId, , fileName] = parts;
	return { projectId, appId, userId, fileName };
}

/**
 * A signed-in caller may act on a key only when they uploaded it and its
 * project is still in their org.
 */
async function assertKeyOwner(c: AppContext, key: string) {
	const parsed = parseKey(key);
	if (!parsed) return { ok: false as const, status: 400 as const, error: "Invalid key" };
	if (parsed.userId !== c.get("userId")) {
		return { ok: false as const, status: 403 as const, error: "Not permitted for this file" };
	}
	return assertProjectAccess(c, parsed.projectId);
}

/**
 * Accept the backend's service token, or a signed-in user (who must then own
 * the key). Mirrors source-upload's signed-get/delete dual auth.
 */
async function authorizeKeyAccess(
	c: AppContext,
	key: string,
): Promise<{ ok: true } | { ok: false; status: 400 | 401 | 403 | 404 | 503; error: string }> {
	if (!parseKey(key)) return { ok: false, status: 400, error: "Invalid key" };

	const serviceToken = c.req.header("X-SA-Service-Token");
	if (serviceToken && serviceToken === c.env.SA_INTERNAL_SERVICE_TOKEN) return { ok: true };

	// authMiddleware can't run after the service-token branch above, so run the
	// same check and populate the same context it would.
	const auth = await authenticateRequest(c);
	if (!auth.ok) return auth;
	c.set("userId", auth.userId);
	c.set("orgId", auth.orgId);
	c.set("userRole", auth.role);
	c.set("sessionId", auth.sessionId);
	c.set("tokenSource", auth.tokenSource);

	return assertKeyOwner(c, key);
}

/**
 * POST /upload/chat-attachment/initiate
 * Body: { projectId, appId, fileName, contentType?, fileSize, threadId? }
 * Returns: { key, fileId, uploadUrl, expiresIn }
 *
 * The file is recorded (status "pending") before the upload URL is handed out, so
 * an upload never exists in R2 without a row; /complete confirms it.
 */
chatAttachmentRouter.post("/initiate", authMiddleware, async (c) => {
	const body = await c.req
		.json<{
			projectId: string;
			appId: string;
			fileName: string;
			contentType?: string;
			fileSize: number;
			threadId?: string;
		}>()
		.catch(() => null);
	if (!body) return c.json({ error: "Invalid JSON body" }, 400);

	const { projectId, appId, fileName, fileSize } = body;
	if (!projectId) return c.json({ error: "projectId is required" }, 400);
	// appId becomes a key segment — same uuid shape as every app id.
	if (!appId || !UUID.test(appId)) return c.json({ error: "A valid appId is required" }, 400);
	if (!fileName) return c.json({ error: "fileName is required" }, 400);
	if (typeof fileSize !== "number" || fileSize <= 0) {
		return c.json({ error: "fileSize must be a positive number" }, 400);
	}
	if (fileSize > MAX_FILE_SIZE) {
		return c.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024} MB.` }, 400);
	}

	const ext = fileName.split(".").pop()?.toLowerCase();
	if (!ext || !ALLOWED_EXTENSIONS.includes(ext)) {
		return c.json({ error: `Unsupported file type. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}` }, 400);
	}

	const access = await assertProjectAccess(c, projectId);
	if (!access.ok) return c.json({ error: access.error }, access.status);

	const key = buildObjectKey(projectId, appId, c.get("userId"), fileName);
	const [row] = await c
		.get("db")
		.insert(files)
		.values({
			orgId: access.orgId,
			projectId,
			appId,
			userId: c.get("userId"),
			kind: "chat_attachment",
			...(typeof body.threadId === "string" && body.threadId
				? { ownerType: "thread", ownerId: body.threadId.slice(0, 255) }
				: {}),
			fileName: sanitizeFileName(fileName),
			contentType: body.contentType ?? null,
			sizeBytes: fileSize,
			r2Key: key,
		})
		.returning({ id: files.id });

	const signed = await r2S3Client(c.env).sign(`${objectUrl(c.env, key)}?X-Amz-Expires=${UPLOAD_URL_TTL_SECONDS}`, {
		method: "PUT",
		aws: { signQuery: true },
	});

	return c.json({ key, fileId: row.id, uploadUrl: signed.url, expiresIn: UPLOAD_URL_TTL_SECONDS });
});

/**
 * POST /upload/chat-attachment/complete
 * Body: { key }
 * Returns: { key, fileName, size, contentType }
 *
 * The PUT itself bypasses this worker, so this is where the uploaded object is
 * checked: it must exist and be within the size limit (the size declared at
 * initiate isn't binding on the PUT). An oversized object is deleted.
 */
chatAttachmentRouter.post("/complete", authMiddleware, async (c) => {
	const body = await c.req.json<{ key: string }>().catch(() => null);
	if (!body?.key) return c.json({ error: "key is required" }, 400);

	const owner = await assertKeyOwner(c, body.key);
	if (!owner.ok) return c.json({ error: owner.error }, owner.status);

	// A one-byte ranged GET rather than HEAD: its Content-Range ("bytes 0-0/<total>")
	// always carries the object's size, where a HEAD's Content-Length can come
	// back empty. An empty object can't be ranged at all (416).
	const probe = await r2S3Client(c.env).fetch(objectUrl(c.env, body.key), {
		method: "GET",
		headers: { Range: "bytes=0-0" },
	});
	await probe.body?.cancel();
	if (probe.status === 404) return c.json({ error: "Upload not found" }, 404);
	if (probe.status === 416) {
		await deleteObject(c.env, body.key).catch(() => {});
		await markFileDeleted(c, body.key).catch(() => {});
		return c.json({ error: "The file is empty" }, 400);
	}
	if (!probe.ok) {
		console.error("[chat-attachment] size check failed", probe.status, body.key);
		return c.json({ error: `Could not check the upload (R2 HTTP ${probe.status})` }, 502);
	}

	const size = Number(probe.headers.get("content-range")?.split("/")[1]);
	if (!Number.isFinite(size)) {
		return c.json({ error: "Could not read the uploaded file's size" }, 502);
	}
	if (size > MAX_FILE_SIZE) {
		await deleteObject(c.env, body.key).catch(() => {});
		await markFileDeleted(c, body.key).catch(() => {});
		return c.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024} MB.` }, 400);
	}

	const parsed = parseKey(body.key)!;
	const contentType = probe.headers.get("content-type");
	const etag = probe.headers.get("etag")?.replace(/"/g, "") || null;

	// Confirm the row /initiate wrote. An upload started before files were recorded
	// has none, so it is written here, already confirmed. A file deleted since is left alone.
	const [row] = await c
		.get("db")
		.insert(files)
		.values({
			orgId: owner.orgId,
			projectId: parsed.projectId,
			appId: parsed.appId,
			userId: parsed.userId,
			kind: "chat_attachment",
			fileName: parsed.fileName,
			contentType,
			sizeBytes: size,
			r2Key: body.key,
			etag,
			status: "ready",
		})
		.onConflictDoUpdate({
			target: files.r2Key,
			set: { status: "ready", sizeBytes: size, contentType, etag },
			setWhere: sql`${files.status} in ('pending', 'ready')`,
		})
		.returning({ id: files.id });

	return c.json({
		key: body.key,
		fileId: row?.id ?? null,
		fileName: parsed.fileName,
		size,
		contentType,
	}, 201);
});

/**
 * POST /upload/chat-attachment/signed-get
 * Auth: X-SA-Service-Token (backend → worker), or the uploader's Bearer JWT.
 * Body: { key }
 * Returns: { url, expiresIn }
 */
chatAttachmentRouter.post("/signed-get", async (c) => {
	const body = await c.req.json<{ key: string }>().catch(() => null);
	if (!body?.key) return c.json({ error: "key is required" }, 400);

	const auth = await authorizeKeyAccess(c, body.key);
	if (!auth.ok) return c.json({ error: auth.error }, auth.status);

	const signed = await r2S3Client(c.env).sign(`${objectUrl(c.env, body.key)}?X-Amz-Expires=${DOWNLOAD_URL_TTL_SECONDS}`, {
		method: "GET",
		aws: { signQuery: true },
	});
	return c.json({ url: signed.url, expiresIn: DOWNLOAD_URL_TTL_SECONDS });
});

/**
 * POST /upload/chat-attachment/delete
 * Auth: X-SA-Service-Token (backend → worker), or the uploader's Bearer JWT.
 * Body: { key }
 * Returns: { deleted: true }   (idempotent — succeeds even if the key is gone)
 */
chatAttachmentRouter.post("/delete", async (c) => {
	const body = await c.req.json<{ key: string }>().catch(() => null);
	if (!body?.key) return c.json({ error: "key is required" }, 400);

	const auth = await authorizeKeyAccess(c, body.key);
	if (!auth.ok) return c.json({ error: auth.error }, auth.status);

	try {
		await deleteObject(c.env, body.key);
		await markFileDeleted(c, body.key);
		return c.json({ deleted: true });
	} catch (err: any) {
		console.error("[chat-attachment] delete failed", err?.message || err, body.key);
		return c.json({ error: `Delete failed: ${err?.message || String(err)}` }, 500);
	}
});

export default chatAttachmentRouter;
