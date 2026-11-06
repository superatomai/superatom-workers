import { Hono } from "hono";
import { eq } from "drizzle-orm";
import { apps, projects } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly } from "../middleware/auth";

/**
 * Icon upload.
 *
 * SVG is deliberately NOT accepted. An SVG is an executable document, not an
 * image: served as image/svg+xml it runs its own <script> and event handlers,
 * which made this endpoint a stored-XSS vector against anyone viewing an
 * org/app/project icon. Sanitizing SVG reliably is a losing game, so icons are
 * raster-only. If SVG is ever needed, serve it from a separate sandboxed origin
 * — never one that shares anything with the app.
 */
const ALLOWED_TYPES: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

const MAX_SIZE = 2 * 1024 * 1024; // 2MB
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const uploadRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

uploadRouter.use("*", authMiddleware, adminOnly);

/**
 * Confirm the bytes really are the declared image type. `file.type` is just a
 * header the client chose, so on its own it proves nothing — an SVG announced as
 * image/png would otherwise be stored and served under a type a browser could
 * sniff its way back out of.
 */
export function matchesMagicBytes(mime: string, bytes: Uint8Array): boolean {
  const startsWith = (...sig: number[]) =>
    sig.length <= bytes.length && sig.every((b, i) => bytes[i] === b);

  switch (mime) {
    case "image/png":
      return startsWith(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
    case "image/jpeg":
      return startsWith(0xff, 0xd8, 0xff);
    case "image/gif":
      return startsWith(0x47, 0x49, 0x46, 0x38); // "GIF8"
    case "image/webp":
      // "RIFF" .... "WEBP"
      return (
        startsWith(0x52, 0x49, 0x46, 0x46) &&
        bytes.length >= 12 &&
        bytes[8] === 0x57 &&
        bytes[9] === 0x45 &&
        bytes[10] === 0x42 &&
        bytes[11] === 0x50
      );
    default:
      return false;
  }
}

/**
 * Verify the caller's organization owns the entity being written to.
 *
 * Without this, `entityId` is an unchecked path component: any admin could
 * overwrite — or delete — the icon of any org, app or project on the platform.
 * Returns an error message when access is denied, or null when allowed.
 *
 * Denial is deliberately indistinguishable from "no such entity", so this
 * cannot be used to enumerate which IDs exist.
 */
async function denyEntityAccess(
  c: any,
  entity: string,
  entityId: string
): Promise<string | null> {
  const DENIED = "Not permitted for this entity";

  const role = c.get("userRole");
  const callerOrgId = c.get("orgId");

  // super_admin may administer any tenant, matching orgScopeGuard elsewhere.
  if (role === "super_admin") return null;
  if (!callerOrgId) return DENIED;

  const db = c.get("db");

  if (entity === "org") {
    return entityId === callerOrgId ? null : DENIED;
  }

  if (entity === "project") {
    const [row] = await db
      .select({ orgId: projects.orgId })
      .from(projects)
      .where(eq(projects.id, entityId))
      .limit(1);
    return row && row.orgId === callerOrgId ? null : DENIED;
  }

  // app → project → org
  const [row] = await db
    .select({ orgId: projects.orgId })
    .from(apps)
    .innerJoin(projects, eq(projects.id, apps.projectId))
    .where(eq(apps.id, entityId))
    .limit(1);
  return row && row.orgId === callerOrgId ? null : DENIED;
}

/**
 * POST /upload/icon
 * Upload an icon image to R2.
 *
 * Expects multipart/form-data with:
 *   - file: the image file (raster only — see ALLOWED_TYPES)
 *   - entity: "org" | "project" | "app"
 *   - entityId: the UUID of the entity, which the caller's org must own
 *
 * Returns: { url: string }
 */
uploadRouter.post("/icon", async (c) => {
  const formData = await c.req.formData();
  const file = formData.get("file");
  const entity = formData.get("entity") as string | null;
  const entityId = formData.get("entityId") as string | null;

  if (!file || !(file instanceof File)) {
    return c.json({ error: "No file provided" }, 400);
  }
  if (!entity || !["org", "project", "app"].includes(entity)) {
    return c.json({ error: 'entity must be "org", "project", or "app"' }, 400);
  }
  if (!entityId || !UUID_RE.test(entityId)) {
    return c.json({ error: "entityId must be a valid UUID" }, 400);
  }

  // Validate file type
  const ext = ALLOWED_TYPES[file.type];
  if (!ext) {
    return c.json(
      {
        error: `Unsupported file type: ${file.type}. Allowed: ${Object.keys(ALLOWED_TYPES).join(", ")}`,
      },
      400
    );
  }

  // Validate file size
  if (file.size > MAX_SIZE) {
    return c.json({ error: `File too large. Max size: ${MAX_SIZE / 1024 / 1024}MB` }, 400);
  }

  const denied = await denyEntityAccess(c, entity, entityId);
  if (denied) {
    return c.json({ error: denied }, 403);
  }

  // Buffered rather than streamed so the content can be inspected before it is
  // stored; bounded by MAX_SIZE above.
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!matchesMagicBytes(file.type, bytes)) {
    return c.json({ error: "File content does not match its declared image type" }, 400);
  }

  // The extension comes from the validated MIME type, never from the uploaded
  // filename, so it cannot contribute an attacker-chosen suffix to the key.
  const key = `${entity}s/${entityId}/icon.${ext}`;

  await c.env.R2_BUCKET.put(key, bytes, {
    httpMetadata: {
      contentType: file.type,
      cacheControl: "public, max-age=31536000, immutable",
    },
  });

  // Return the public URL using the configured R2 public domain
  const baseUrl = c.env.R2_PUBLIC_URL || "https://sa-assets.superatom.ai";
  const url = `${baseUrl}/${key}`;

  return c.json({ url }, 201);
});

/**
 * DELETE /upload/icon
 * Delete an icon from R2.
 *
 * Expects JSON body: { entity, entityId }
 */
uploadRouter.delete("/icon", async (c) => {
  const { entity, entityId } = await c.req.json<{ entity: string; entityId: string }>();

  if (!entity || !["org", "project", "app"].includes(entity)) {
    return c.json({ error: 'entity must be "org", "project", or "app"' }, 400);
  }
  if (!entityId || !UUID_RE.test(entityId)) {
    return c.json({ error: "entityId must be a valid UUID" }, 400);
  }

  // Same ownership rule as upload: otherwise anyone could wipe any tenant's icon.
  const denied = await denyEntityAccess(c, entity, entityId);
  if (denied) {
    return c.json({ error: denied }, 403);
  }

  // List and delete all icon files for this entity (handles extension changes)
  const prefix = `${entity}s/${entityId}/icon.`;
  const listed = await c.env.R2_BUCKET.list({ prefix });

  for (const obj of listed.objects) {
    await c.env.R2_BUCKET.delete(obj.key);
  }

  return c.json({ message: "Icon deleted" });
});

export default uploadRouter;
