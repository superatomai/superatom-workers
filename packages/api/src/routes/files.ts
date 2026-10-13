/**
 * Files kept in R2 and recorded in the `files` table — registering the ones the
 * chat agent writes, and downloading any of them.
 *
 * Agent output (backend → worker, X-SA-Service-Token):
 *   1. POST /files/register          → record the file (pending), get one presigned PUT URL
 *   2. The backend PUTs the file to R2
 *   3. POST /files/:id/complete      → confirm the object landed; the row becomes ready
 *
 * Download (the signed-in user):
 *   POST /files/:id/download         → a short-lived link that downloads the file
 *
 * A file that changes is never overwritten: registering a file whose name the
 * thread already has makes a new object and a new row, one version up, pointing at
 * the one it replaces. Each answer keeps the id of the version it delivered.
 *
 * Key: agent-outputs/{projectId}/{userId}/{uuid}/{fileName}
 */

import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { files, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import type { AppContext } from "../lib/project-access";
import { checkObject, deleteObject, signObjectUrl } from "../lib/r2-objects";

const KEY_PREFIX = "agent-outputs/";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

const UPLOAD_URL_TTL_SECONDS = 15 * 60;
const DOWNLOAD_URL_TTL_SECONDS = 5 * 60;

const filesRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

function sanitizeFileName(name: string): string {
	return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 200);
}

/** The backend's service token, on routes only the backend calls. */
function hasServiceToken(c: AppContext): boolean {
	const token = c.req.header("X-SA-Service-Token");
	return Boolean(token) && token === c.env.SA_INTERNAL_SERVICE_TOKEN;
}

/**
 * POST /files/register
 * Auth: X-SA-Service-Token
 * Body: { projectId, userId, threadId, fileName, contentType?, fileSize }
 * Returns: { fileId, key, version, uploadUrl, expiresIn }
 */
filesRouter.post("/register", async (c) => {
	if (!hasServiceToken(c)) return c.json({ error: "Unauthorized" }, 401);

	const body = await c.req
		.json<{
			projectId: string;
			userId: string;
			threadId: string;
			fileName: string;
			contentType?: string;
			fileSize: number;
		}>()
		.catch(() => null);
	if (!body) return c.json({ error: "Invalid JSON body" }, 400);

	const { projectId, userId, threadId, fileName, fileSize } = body;
	if (!projectId || !UUID.test(projectId)) return c.json({ error: "A valid projectId is required" }, 400);
	if (!userId || !UUID.test(userId)) return c.json({ error: "A valid userId is required" }, 400);
	if (!threadId || typeof threadId !== "string" || threadId.length > 255) {
		return c.json({ error: "threadId is required" }, 400);
	}
	if (!fileName) return c.json({ error: "fileName is required" }, 400);
	if (typeof fileSize !== "number" || fileSize <= 0) {
		return c.json({ error: "fileSize must be a positive number" }, 400);
	}
	if (fileSize > MAX_FILE_SIZE) {
		return c.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024} MB.` }, 400);
	}

	const db = c.get("db");
	const [project] = await db.select({ orgId: projects.orgId }).from(projects).where(eq(projects.id, projectId)).limit(1);
	if (!project) return c.json({ error: "Project not found" }, 404);
	const [user] = await db.select({ id: users.id }).from(users).where(eq(users.id, userId)).limit(1);
	if (!user) return c.json({ error: "User not found" }, 404);

	const safeName = sanitizeFileName(fileName);

	// The newest confirmed copy of a file with this name in this thread is the one this replaces.
	const [previous] = await db
		.select({ id: files.id, version: files.version })
		.from(files)
		.where(
			and(
				eq(files.kind, "agent_output"),
				eq(files.ownerType, "thread"),
				eq(files.ownerId, threadId),
				eq(files.fileName, safeName),
				eq(files.status, "ready"),
			),
		)
		.orderBy(desc(files.version))
		.limit(1);

	const key = `${KEY_PREFIX}${projectId}/${userId}/${crypto.randomUUID()}/${safeName}`;
	const [row] = await db
		.insert(files)
		.values({
			orgId: project.orgId,
			projectId,
			userId,
			kind: "agent_output",
			ownerType: "thread",
			ownerId: threadId,
			fileName: safeName,
			contentType: body.contentType ?? null,
			sizeBytes: fileSize,
			r2Key: key,
			version: previous ? previous.version + 1 : 1,
			previousVersionId: previous?.id ?? null,
		})
		.returning({ id: files.id, version: files.version });

	const uploadUrl = await signObjectUrl(c.env, key, "PUT", UPLOAD_URL_TTL_SECONDS);
	return c.json({ fileId: row.id, key, version: row.version, uploadUrl, expiresIn: UPLOAD_URL_TTL_SECONDS });
});

/**
 * POST /files/:id/complete
 * Auth: X-SA-Service-Token
 * Returns: { fileId, fileName, size, contentType, version }
 *
 * The PUT bypasses this worker, so this is where the object is checked: it must
 * exist, be non-empty and be within the size limit. A file that fails is removed.
 */
filesRouter.post("/:id/complete", async (c) => {
	if (!hasServiceToken(c)) return c.json({ error: "Unauthorized" }, 401);

	const id = c.req.param("id");
	if (!UUID.test(id)) return c.json({ error: "File not found" }, 404);

	const db = c.get("db");
	const [row] = await db.select().from(files).where(and(eq(files.id, id), eq(files.kind, "agent_output"))).limit(1);
	if (!row) return c.json({ error: "File not found" }, 404);
	if (row.status === "deleted" || row.status === "expired") return c.json({ error: "File is no longer available" }, 410);

	const checked = await checkObject(c.env, row.r2Key);
	if (checked.state === "missing") return c.json({ error: "Upload not found" }, 404);
	if (checked.state === "error") {
		console.error("[files] size check failed", checked.status, row.r2Key);
		return c.json({ error: `Could not check the upload (R2 HTTP ${checked.status})` }, 502);
	}
	if (checked.state === "unreadable") return c.json({ error: "Could not read the uploaded file's size" }, 502);

	if (checked.state === "empty" || checked.size > MAX_FILE_SIZE) {
		await deleteObject(c.env, row.r2Key).catch(() => {});
		await db.update(files).set({ status: "deleted", deletedAt: new Date() }).where(eq(files.id, id));
		return checked.state === "empty"
			? c.json({ error: "The file is empty" }, 400)
			: c.json({ error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024} MB.` }, 400);
	}

	await db
		.update(files)
		.set({
			status: "ready",
			sizeBytes: checked.size,
			contentType: checked.contentType ?? row.contentType,
			etag: checked.etag,
		})
		.where(eq(files.id, id));

	return c.json(
		{
			fileId: id,
			fileName: row.fileName,
			size: checked.size,
			contentType: checked.contentType ?? row.contentType,
			version: row.version,
		},
		201,
	);
});

/**
 * POST /files/:id/download
 * Auth: signed-in user (Bearer JWT) — the file's owner, in the file's org
 * Returns: { url, fileName, expiresIn }
 *
 * The permission is decided here, when the link is made: a signed URL can't be
 * revoked, so it is short-lived and forces a download.
 */
filesRouter.post("/:id/download", authMiddleware, async (c) => {
	const id = c.req.param("id");
	if (!UUID.test(id)) return c.json({ error: "File not found" }, 404);

	const [row] = await c.get("db").select().from(files).where(eq(files.id, id)).limit(1);
	if (!row || row.status !== "ready") return c.json({ error: "File not found" }, 404);

	const isSuperAdmin = c.get("userRole") === "super_admin";
	if (!isSuperAdmin && (row.orgId !== c.get("orgId") || row.userId !== c.get("userId"))) {
		return c.json({ error: "Not permitted for this file" }, 403);
	}

	const url = await signObjectUrl(c.env, row.r2Key, "GET", DOWNLOAD_URL_TTL_SECONDS, {
		"response-content-disposition": `attachment; filename="${row.fileName}"`,
	});
	return c.json({ url, fileName: row.fileName, expiresIn: DOWNLOAD_URL_TTL_SECONDS });
});

export default filesRouter;
