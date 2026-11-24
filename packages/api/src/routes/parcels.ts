/**
 * Parcel routes — upload and download of large payloads. See lib/parcels.ts.
 *
 *   PUT /parcels/:projectId/:hash.:ext   body = raw bytes
 *   GET /parcels/:projectId/:hash.:ext
 *
 * The sender computes the sha256 and names the parcel by it; R2 verifies the
 * bytes against that hash on write, so a parcel's name is proof of its content.
 *
 * Auth, either of:
 *   - an engine's project key, `Authorization: Bearer sa_live_…` (or `sa_test_…`),
 *     which must be the active key of that same project — the check the
 *     websocket worker makes when the engine connects;
 *   - a user's access token, for a project in the user's org (super admins any).
 *
 * Nothing here is project-agnostic: every key is under the project's own prefix
 * and every call is checked against that project.
 */
import { Hono } from "hono";
import { and, eq } from "drizzle-orm";
import { apiKeys } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authenticateRequest } from "../middleware/auth";
import { assertProjectAccess, type AppContext } from "../lib/project-access";
// Same hash the websocket worker validates engine keys with — one key format.
import { hashApiKey } from "../../../websocket/src/api-keys/service";
import { MAX_PARCEL_BYTES, isExpired, isExt, isProjectId, isSha256, parcelKey } from "../lib/parcels";

const parcelsRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

type Caller = { ok: true; who: string } | { ok: false; status: 401 | 403 | 404 | 503; error: string };

/** The engine of this project, or a user who may reach it. */
async function authorize(c: AppContext, projectId: string): Promise<Caller> {
  const header = c.req.header("Authorization") ?? "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (bearer.startsWith("sa_live_") || bearer.startsWith("sa_test_")) {
    try {
      const [key] = await c
        .get("db")
        .select({ id: apiKeys.id })
        .from(apiKeys)
        .where(
          and(
            eq(apiKeys.projectId, projectId),
            eq(apiKeys.keyHash, await hashApiKey(bearer)),
            eq(apiKeys.isActive, true),
          ),
        )
        .limit(1);
      if (!key) return { ok: false, status: 403, error: "Not permitted for this project" };
      return { ok: true, who: "engine" };
    } catch (err: any) {
      console.error("[parcels] key lookup failed:", err?.message ?? err);
      return { ok: false, status: 503, error: "Authorization service unavailable" };
    }
  }

  const auth = await authenticateRequest(c);
  if (!auth.ok) return auth;
  // assertProjectAccess reads these, as it does behind authMiddleware.
  c.set("userId", auth.userId);
  c.set("orgId", auth.orgId);
  c.set("userRole", auth.role);
  const access = await assertProjectAccess(c, projectId);
  if (!access.ok) return access;
  return { ok: true, who: `user:${auth.userId}` };
}

/** `<hash>.<ext>` from the last path segment, or null if either part is malformed. */
function parseFile(file: string): { hash: string; ext: string } | null {
  const dot = file.indexOf(".");
  if (dot < 0) return null;
  const hash = file.slice(0, dot).toLowerCase();
  const ext = file.slice(dot + 1).toLowerCase();
  return isSha256(hash) && isExt(ext) ? { hash, ext } : null;
}

parcelsRouter.put("/:projectId/:file", async (c) => {
  const projectId = c.req.param("projectId");
  const file = parseFile(c.req.param("file"));
  if (!isProjectId(projectId) || !file) return c.json({ error: "Invalid parcel address" }, 400);

  const caller = await authorize(c, projectId);
  if (!caller.ok) return c.json({ error: caller.error }, caller.status);

  /* A known length is required: R2 needs it to stream the body, and it is what
   * lets an oversized parcel be refused before a byte is read. */
  const size = Number(c.req.header("Content-Length"));
  if (!Number.isFinite(size) || size <= 0) return c.json({ error: "Content-Length is required" }, 411);
  if (size > MAX_PARCEL_BYTES) {
    return c.json({ error: `Parcel too large (${size} bytes, limit ${MAX_PARCEL_BYTES})` }, 413);
  }
  if (!c.req.raw.body) return c.json({ error: "Empty body" }, 400);

  const key = parcelKey(projectId, file.hash, file.ext);
  try {
    await c.env.R2_PARCELS.put(key, c.req.raw.body, {
      /* R2 rejects the write if the bytes do not hash to the name. */
      sha256: file.hash,
      httpMetadata: { contentType: c.req.header("Content-Type") || "application/octet-stream" },
      customMetadata: { sender: caller.who },
    });
  } catch (err: any) {
    const message = String(err?.message ?? err);
    if (/sha-?256|checksum|digest/i.test(message)) {
      return c.json({ error: "Content does not match its hash" }, 422);
    }
    console.error(`[parcels] put failed key=${key}:`, message);
    return c.json({ error: "Could not store the parcel" }, 500);
  }

  console.log(`[parcels] stored ${key} size=${size} by=${caller.who}`);
  return c.json({ projectId, hash: file.hash, ext: file.ext, size }, 201);
});

parcelsRouter.get("/:projectId/:file", async (c) => {
  const projectId = c.req.param("projectId");
  const file = parseFile(c.req.param("file"));
  if (!isProjectId(projectId) || !file) return c.json({ error: "Invalid parcel address" }, 400);

  const caller = await authorize(c, projectId);
  if (!caller.ok) return c.json({ error: caller.error }, caller.status);

  const key = parcelKey(projectId, file.hash, file.ext);
  let object: R2ObjectBody | null;
  try {
    object = await c.env.R2_PARCELS.get(key);
  } catch (err: any) {
    console.error(`[parcels] get failed key=${key}:`, err?.message ?? err);
    return c.json({ error: "Could not read the parcel" }, 500);
  }
  if (!object) return c.json({ error: "Parcel not found" }, 404);
  if (isExpired(object.uploaded)) {
    await object.body.cancel();
    return c.json({ error: "Parcel has expired" }, 410);
  }

  return new Response(object.body, {
    headers: {
      "Content-Type": object.httpMetadata?.contentType || "application/octet-stream",
      "Content-Length": String(object.size),
      "Cache-Control": "private, no-store",
      "X-SA-Sha256": file.hash,
    },
  });
});

export default parcelsRouter;
