/**
 * Source-file upload routes — multipart PUT directly to R2.
 *
 * Flow:
 *   1. POST /upload/source-file/initiate   → reserve key, get presigned PUT URLs for each part
 *   2. Browser PUTs each part directly to R2 (parallel, retries)
 *   3. POST /upload/source-file/complete   → finalize multipart upload
 *   4. POST /upload/source-file/abort      → discard a half-finished upload
 *   5. POST /upload/source-file/signed-get → backend asks for a presigned GET URL to fetch the file
 *
 * Why multipart + presigned URLs (not worker proxy): Cloudflare Workers cap request
 * body at ~100 MB (free) / ~500 MB (paid). Excel files can be 1 GB+, so we bypass
 * the worker for the actual byte transfer.
 *
 * Why aws4fetch (not the R2 binding alone): worker bindings don't expose a
 * `getSignedUrl()` API. To let the browser PUT directly, we sign URLs against
 * R2's S3-compatible endpoint using aws4fetch + an R2 API token.
 *
 * CORS reminder: the `sa-source-files` R2 bucket must allow PUT from the platform
 * UI origin (https://platform.superatom.ai, etc.) and expose the `ETag` header.
 * Configure via Cloudflare dashboard or `wrangler r2 bucket cors put`.
 */

import { Hono } from "hono";
import { AwsClient } from "aws4fetch";
import { eq } from "drizzle-orm";
import { projects } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, authenticateRequest } from "../middleware/auth";

// 5 MB is the S3/R2 minimum part size (except for the last part).
// 10 MB chosen as default — gives 100 parts for a 1 GB file, well under the 10,000 cap.
const DEFAULT_PART_SIZE = 10 * 1024 * 1024;
const MIN_PART_SIZE = 5 * 1024 * 1024;
const MAX_PARTS = 10_000;

// Sanity ceiling on file size to prevent abuse. R2 itself allows up to 5 TB per object.
const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5 GB

// Presigned URL TTL — long enough to upload a 1 GB file on a slow connection.
const UPLOAD_URL_TTL_SECONDS = 60 * 60; // 1 hour
const DOWNLOAD_URL_TTL_SECONDS = 60 * 60; // 1 hour

const ALLOWED_EXTENSIONS = ["xlsx", "xls", "csv"];

const sourceUploadRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * Build an aws4fetch client bound to R2's S3-compatible API.
 * R2 region is always "auto".
 */
function r2S3Client(env: Env): AwsClient {
  return new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto",
  });
}

function r2EndpointBase(env: Env): string {
  return `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
}

function bucketName(env: Env): string {
  return env.R2_SOURCE_FILES_BUCKET_NAME;
}

function sanitizeFileName(name: string): string {
  // Keep alphanumerics, dot, dash, underscore. Replace everything else.
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 200);
}

function buildObjectKey(projectId: string, fileName: string): string {
  const safeProjectId = projectId.replace(/[^a-zA-Z0-9_-]/g, "");
  const safeName = sanitizeFileName(fileName);
  // crypto.randomUUID is available in Workers runtime.
  const uniq = crypto.randomUUID();
  return `sources/${safeProjectId}/${uniq}/${safeName}`;
}

/**
 * Verify the caller is allowed to write to this project: the project must
 * belong to the caller's org. Super admins bypass.
 */
async function assertProjectAccess(
  c: { get: (k: any) => any; var: AppVariables },
  projectId: string,
): Promise<{ ok: true } | { ok: false; status: 403 | 404; error: string }> {
  const role = c.get("userRole") as AppVariables["userRole"];
  if (role === "super_admin") return { ok: true };

  const userOrgId = c.get("orgId") as string | null;
  if (!userOrgId) return { ok: false, status: 403, error: "Missing org context" };

  const db = c.get("db") as AppVariables["db"];
  const rows = await db
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);

  if (rows.length === 0) return { ok: false, status: 404, error: "Project not found" };
  if (rows[0].orgId !== userOrgId) {
    return { ok: false, status: 403, error: "Forbidden: project belongs to another organization" };
  }
  return { ok: true };
}

/**
 * POST /upload/source-file/initiate
 * Body: { projectId, fileName, contentType?, fileSize }
 * Returns: { uploadId, key, partSize, partUrls: [{ partNumber, url }] }
 */
sourceUploadRouter.post("/initiate", authMiddleware, async (c) => {
  const body = await c.req.json<{
    projectId: string;
    fileName: string;
    contentType?: string;
    fileSize: number;
  }>().catch(() => null);

  if (!body) return c.json({ error: "Invalid JSON body" }, 400);

  const { projectId, fileName, contentType, fileSize } = body;

  if (!projectId) return c.json({ error: "projectId is required" }, 400);
  if (!fileName) return c.json({ error: "fileName is required" }, 400);
  if (typeof fileSize !== "number" || fileSize <= 0) {
    return c.json({ error: "fileSize must be a positive number" }, 400);
  }
  if (fileSize > MAX_FILE_SIZE) {
    return c.json(
      { error: `File too large (${(fileSize / 1024 / 1024 / 1024).toFixed(2)} GB). Max ${MAX_FILE_SIZE / 1024 / 1024 / 1024} GB.` },
      400,
    );
  }

  const ext = fileName.split(".").pop()?.toLowerCase();
  if (!ext || !ALLOWED_EXTENSIONS.includes(ext)) {
    return c.json(
      { error: `Unsupported file extension. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}` },
      400,
    );
  }

  const access = await assertProjectAccess(c as any, projectId);
  if (!access.ok) return c.json({ error: access.error }, access.status);

  // Compute part layout. If file is smaller than the part size, we still use
  // multipart (one part) — keeps the flow uniform on the client.
  const partSize = DEFAULT_PART_SIZE < MIN_PART_SIZE ? MIN_PART_SIZE : DEFAULT_PART_SIZE;
  const partCount = Math.max(1, Math.ceil(fileSize / partSize));
  if (partCount > MAX_PARTS) {
    return c.json({ error: `Too many parts (${partCount}). Increase part size.` }, 400);
  }

  const key = buildObjectKey(projectId, fileName);

  // Start the multipart upload via the binding — simpler than signing CreateMultipartUpload.
  const mpu = await c.env.R2_SOURCE_FILES.createMultipartUpload(key, {
    httpMetadata: contentType ? { contentType } : undefined,
  });

  // Presign one PUT URL per part. The URL points at R2's S3-compatible endpoint
  // and includes uploadId + partNumber in the query string.
  const aws = r2S3Client(c.env);
  const base = `${r2EndpointBase(c.env)}/${bucketName(c.env)}/${encodeURI(key)}`;

  const partUrls: Array<{ partNumber: number; url: string }> = [];
  for (let i = 1; i <= partCount; i++) {
    const url = `${base}?partNumber=${i}&uploadId=${encodeURIComponent(mpu.uploadId)}&X-Amz-Expires=${UPLOAD_URL_TTL_SECONDS}`;
    const signed = await aws.sign(url, {
      method: "PUT",
      aws: { signQuery: true },
    });
    partUrls.push({ partNumber: i, url: signed.url });
  }

  return c.json({
    uploadId: mpu.uploadId,
    key,
    partSize,
    partCount,
    partUrls,
  });
});

/**
 * POST /upload/source-file/complete
 * Body: { key, uploadId, parts: [{ partNumber, etag }] }
 * Returns: { key, size }
 */
sourceUploadRouter.post("/complete", authMiddleware, async (c) => {
  const body = await c.req.json<{
    key: string;
    uploadId: string;
    parts: Array<{ partNumber: number; etag: string }>;
  }>().catch(() => null);

  if (!body) return c.json({ error: "Invalid JSON body" }, 400);
  const { key, uploadId, parts } = body;

  if (!key || !uploadId || !Array.isArray(parts) || parts.length === 0) {
    return c.json({ error: "key, uploadId, and non-empty parts are required" }, 400);
  }

  // Pull the projectId out of the key (sources/{projectId}/{uuid}/{filename})
  // and re-verify access — the caller must still be authorized to this project.
  const projectId = key.split("/")[1];
  if (!projectId) return c.json({ error: "Invalid key shape" }, 400);
  const access = await assertProjectAccess(c as any, projectId);
  if (!access.ok) return c.json({ error: access.error }, access.status);

  // R2's S3 API returns ETags wrapped in double quotes ("abc123"), but the
  // Workers binding's complete() expects them unquoted. Strip both surrounding
  // quotes and any leading W/ (weak etag prefix) just in case.
  const ordered = [...parts]
    .sort((a, b) => a.partNumber - b.partNumber)
    .map((p) => ({
      partNumber: p.partNumber,
      etag: (p.etag || "").replace(/^W\//, "").replace(/^"|"$/g, ""),
    }));

  console.log(
    `[source-upload] complete key=${key} uploadId=${uploadId} parts=${ordered.length} firstEtag=${ordered[0]?.etag}`,
  );

  try {
    const mpu = c.env.R2_SOURCE_FILES.resumeMultipartUpload(key, uploadId);
    const obj = await mpu.complete(ordered);
    return c.json({ key, size: obj.size }, 201);
  } catch (err: any) {
    // Surface the part list so we can diagnose mismatches in the logs.
    console.error(
      "[source-upload] complete failed",
      err?.message || err,
      JSON.stringify({ key, uploadId, parts: ordered.slice(0, 3) }),
    );
    return c.json({ error: `Multipart complete failed: ${err?.message || String(err)}` }, 500);
  }
});

/**
 * POST /upload/source-file/abort
 * Body: { key, uploadId }
 */
sourceUploadRouter.post("/abort", authMiddleware, async (c) => {
  const body = await c.req.json<{ key: string; uploadId: string }>().catch(() => null);
  if (!body) return c.json({ error: "Invalid JSON body" }, 400);
  const { key, uploadId } = body;
  if (!key || !uploadId) return c.json({ error: "key and uploadId are required" }, 400);

  const projectId = key.split("/")[1];
  if (projectId) {
    const access = await assertProjectAccess(c as any, projectId);
    if (!access.ok) return c.json({ error: access.error }, access.status);
  }

  try {
    const mpu = c.env.R2_SOURCE_FILES.resumeMultipartUpload(key, uploadId);
    await mpu.abort();
    return c.json({ aborted: true });
  } catch (err: any) {
    // Abort failures are usually safe to ignore (e.g. already-completed uploads).
    console.warn("[source-upload] abort warning", err);
    return c.json({ aborted: false, warning: String(err?.message || err) });
  }
});

/**
 * POST /upload/source-file/signed-get
 * Returns a presigned GET URL the backend uses to download the file.
 *
 * Auth: accepts either
 *   (a) a normal Bearer JWT (user-initiated download), or
 *   (b) an internal service token via X-SA-Service-Token header (backend → worker).
 *
 * Body: { key }
 * Returns: { url, expiresIn }
 */
sourceUploadRouter.post("/signed-get", async (c) => {
  const serviceToken = c.req.header("X-SA-Service-Token");
  const isService = !!serviceToken && serviceToken === c.env.SA_INTERNAL_SERVICE_TOKEN;

  // If not a service call, require a normal JWT.
  if (!isService) {
    // Can't mount authMiddleware per-route after the service-token branch above,
    // so run the same check directly — including the per-org secret and the
    // account status lookup, not just the signature.
    const auth = await authenticateRequest(c);
    if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  }

  const body = await c.req.json<{ key: string }>().catch(() => null);
  if (!body?.key) return c.json({ error: "key is required" }, 400);

  const aws = r2S3Client(c.env);
  const url = `${r2EndpointBase(c.env)}/${bucketName(c.env)}/${encodeURI(body.key)}?X-Amz-Expires=${DOWNLOAD_URL_TTL_SECONDS}`;
  const signed = await aws.sign(url, { method: "GET", aws: { signQuery: true } });

  return c.json({ url: signed.url, expiresIn: DOWNLOAD_URL_TTL_SECONDS });
});

/**
 * POST /upload/source-file/delete
 * Remove a source file object from R2. Called when a data source is deleted or
 * when its file is replaced (the old object would otherwise be orphaned).
 *
 * Uses the R2 binding directly (no presigning needed — the delete runs here on
 * the worker, unlike PUT/GET which the browser/backend perform against R2).
 *
 * Auth: same dual mode as signed-get —
 *   (a) internal service token via X-SA-Service-Token (backend → worker), or
 *   (b) a normal Bearer JWT.
 *
 * Body: { key }
 * Returns: { deleted: true }   (idempotent — succeeds even if the key is gone)
 */
sourceUploadRouter.post("/delete", async (c) => {
  const serviceToken = c.req.header("X-SA-Service-Token");
  const isService = !!serviceToken && serviceToken === c.env.SA_INTERNAL_SERVICE_TOKEN;

  if (!isService) {
    const auth = await authenticateRequest(c);
    if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  }

  const body = await c.req.json<{ key: string }>().catch(() => null);
  if (!body?.key) return c.json({ error: "key is required" }, 400);

  // Confine deletion to source-file objects so a stray key can't target
  // arbitrary objects in the bucket.
  if (!body.key.startsWith("sources/")) {
    return c.json({ error: "Invalid key: must be a source-file object" }, 400);
  }

  try {
    await c.env.R2_SOURCE_FILES.delete(body.key);
    console.log(`[source-upload] deleted key=${body.key}`);
    return c.json({ deleted: true });
  } catch (err: any) {
    console.error("[source-upload] delete failed", err?.message || err, body.key);
    return c.json({ error: `Delete failed: ${err?.message || String(err)}` }, 500);
  }
});

export default sourceUploadRouter;
