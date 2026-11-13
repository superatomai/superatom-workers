/**
 * The program catalogue of one project.
 *
 * Two callers. Engines, with the internal service token, list what to run and
 * fetch signed download links. Admins (and the publish CLI, which also carries
 * the service token) register builds, complete uploads, publish, unpublish and
 * pin. Archive bytes go through the worker's R2 binding (small files; R2
 * verifies the sha256 on upload), so no S3 token scope is involved.
 */
import { Hono } from "hono";
import { and, desc, eq } from "drizzle-orm";
import { projectPrograms, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authenticateRequest } from "../middleware/auth";
import type { AppContext } from "../lib/project-access";
import { builtKey, currentRows, draftsFor, engineView, parseRegistration, pinPlan, pinsOf, publishPlan, sourceKey, unpublishPlan, type FlagChanges } from "../lib/programs/catalogue";
import { notifyPrograms } from "../lib/programs/notify";

const router = new Hono<{ Bindings: Env; Variables: AppVariables }>();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Caller = { kind: "service"; who: string } | { kind: "user"; userId: string; email: string; role: AppVariables["userRole"]; orgId: string | null };

function hasServiceToken(c: AppContext): boolean {
  const token = c.req.header("X-SA-Service-Token");
  return Boolean(token) && token === c.env.SA_INTERNAL_SERVICE_TOKEN;
}

/** Service token, or a signed-in admin of the project's org. */
async function caller(c: AppContext, projectId: string, opts: { adminOnly: boolean }): Promise<{ ok: true; caller: Caller; orgId: string } | { ok: false; status: 401 | 403 | 404; error: string }> {
  if (!UUID.test(projectId)) return { ok: false, status: 404, error: "Project not found" };
  const db = c.get("db");
  const [project] = await db.select({ orgId: projects.orgId }).from(projects).where(eq(projects.id, projectId)).limit(1);
  if (!project) return { ok: false, status: 404, error: "Project not found" };
  if (hasServiceToken(c)) return { ok: true, caller: { kind: "service", who: c.req.header("X-SA-Actor") ?? "service" }, orgId: project.orgId };
  const auth = await authenticateRequest(c as any);
  if (!auth.ok) return { ok: false, status: 401, error: auth.error };
  const isAdmin = auth.role === "org_admin" || auth.role === "super_admin";
  if (auth.role !== "super_admin" && auth.orgId !== project.orgId) return { ok: false, status: 403, error: "Not permitted for this project" };
  if (opts.adminOnly && !isAdmin) return { ok: false, status: 403, error: "Forbidden: admin role required" };
  const [u] = await db.select({ email: users.email }).from(users).where(eq(users.id, auth.userId)).limit(1);
  return { ok: true, caller: { kind: "user", userId: auth.userId, email: u?.email ?? auth.userId, role: auth.role, orgId: auth.orgId }, orgId: project.orgId };
}

function actor(k: Caller): string { return k.kind === "user" ? k.email : k.who; }

function runLater(c: AppContext, p: Promise<unknown>): void {
  try { c.executionCtx.waitUntil(p); } catch { void p; }
}

/** Writes a plan's current/pinned changes, one update per row. */
async function applyFlags(db: AppContext["var"]["db"], changes: FlagChanges): Promise<void> {
  for (const [id, f] of Object.entries(changes)) {
    await db.update(projectPrograms).set({ current: f.current, ...(f.pinned !== undefined ? { pinned: f.pinned } : {}) }).where(eq(projectPrograms.id, id));
  }
}

async function rowsOf(c: AppContext, projectId: string) {
  return c.get("db").select().from(projectPrograms).where(eq(projectPrograms.projectId, projectId)).orderBy(desc(projectPrograms.uploadedAt));
}

/* ------------------------------ list (engine / admin) ------------------------------ */

router.get("/", async (c) => {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: false });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  const db = c.get("db");
  const rows = await rowsOf(c, projectId);
  // The pointer on the row decides what runs; `pins` is derived for callers that still read the old map.
  const pins = pinsOf(rows);
  if (who.caller.kind === "service" || c.req.query("view") === "engine") {
    // The engine view: what to run, plus the creator's drafts when asked for.
    const creatorId = c.req.query("drafts") ?? undefined;
    const live = currentRows(rows);
    const drafts = draftsFor(rows, UUID.test(creatorId ?? "") ? creatorId : undefined);
    return c.json({ pins, programs: [...live.map((r) => engineView(r)), ...drafts.map((r) => engineView(r, true))] });
  }
  const live = new Set(currentRows(rows).map((r) => r.id));
  return c.json({
    pins,
    programs: rows.map((r) => ({
      id: r.id, name: r.name, version: r.version, hash: r.hash, bytes: r.bytes, status: r.status,
      live: live.has(r.id), current: Boolean(r.current), pinned: Boolean(r.pinned),
      commit: r.commit || null, builtBy: r.builtBy, uploadedAt: r.uploadedAt, publishedBy: r.publishedBy, publishedAt: r.publishedAt,
      notes: r.notes, creatorId: r.creatorId, hasSource: Boolean(r.sourceKey),
      title: (r.manifest as any)?.title ?? null, description: (r.manifest as any)?.description ?? null,
      // Manifest v2: `visibility.prompt` replaced `default`, `web` is a boolean (older rows still carry `default` / `web.kind`).
      default: Boolean((r.manifest as any)?.visibility?.prompt ?? (r.manifest as any)?.default), server: Boolean((r.manifest as any)?.server), web: Boolean((r.manifest as any)?.web),
    })),
  });
});

/* ------------------------------ register + complete ------------------------------ */

router.post("/register", async (c) => {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: true });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  const parsed = parseRegistration(await c.req.json().catch(() => null));
  if (!parsed.ok) return c.json({ error: parsed.error }, 400);
  const r = parsed.value;
  const db = c.get("db");

  const [dup] = await db.select({ id: projectPrograms.id, hash: projectPrograms.hash, status: projectPrograms.status })
    .from(projectPrograms).where(and(eq(projectPrograms.projectId, projectId), eq(projectPrograms.name, r.name), eq(projectPrograms.version, r.version))).limit(1);
  // A finished build is immutable under its version; one that never uploaded can be replaced.
  if (dup && dup.status !== "pending" && dup.hash !== r.hash) return c.json({ error: `${r.name}@${r.version} is already registered with a different hash; bump the version` }, 409);
  if (dup && dup.status === "ready") return c.json({ error: `${r.name}@${r.version} is already uploaded`, id: dup.id }, 409);

  const key = builtKey(projectId, r.name, r.version, r.hash);
  const sKey = r.sourceHash ? sourceKey(projectId, r.name, r.version, r.hash) : null;
  const values = {
    projectId, name: r.name, version: r.version, hash: r.hash, bytes: r.bytes, commit: r.commit ?? "", builtBy: r.builtBy ?? actor(who.caller),
    notes: r.notes ?? null, manifest: r.manifest, status: "pending", key, sourceKey: sKey, sourceHash: r.sourceHash ?? null, sourceBytes: r.sourceBytes ?? null,
    creatorId: who.caller.kind === "user" ? who.caller.userId : (r.creatorId ?? null), uploadedAt: new Date(),
  };
  const [row] = dup
    ? await db.update(projectPrograms).set(values).where(eq(projectPrograms.id, dup.id)).returning({ id: projectPrograms.id })
    : await db.insert(projectPrograms).values(values).returning({ id: projectPrograms.id });

  return c.json({ id: row.id, key, sourceKey: sKey, upload: `/projects/${projectId}/programs/${row.id}/archive`, sourceUpload: sKey ? `/projects/${projectId}/programs/${row.id}/source` : null });
});

/**
 * PUT the archive bytes. R2 checks the sha256 against the registration, so a
 * corrupt or swapped upload is refused by R2 itself; the size is checked here.
 * The row becomes ready once the built archive (and the source, if declared) is in.
 */
async function putArchive(c: AppContext, source: boolean) {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: true });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  const id = c.req.param("id") ?? "";
  if (!UUID.test(id)) return c.json({ error: "Program not found" }, 404);
  const db = c.get("db");
  const [row] = await db.select().from(projectPrograms).where(and(eq(projectPrograms.id, id), eq(projectPrograms.projectId, projectId))).limit(1);
  if (!row || !row.key) return c.json({ error: "Program not found" }, 404);
  if (row.status === "ready" && row.publishedAt) return c.json({ error: "A published build cannot be replaced; bump the version" }, 409);
  const key = source ? row.sourceKey : row.key;
  const hash = source ? row.sourceHash : row.hash;
  const bytes = source ? row.sourceBytes : row.bytes;
  if (!key || !hash || !bytes) return c.json({ error: "No source archive was declared for this build" }, 400);
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared && declared !== bytes) return c.json({ error: `upload is ${declared} bytes, registered as ${bytes}` }, 400);
  if (!c.req.raw.body) return c.json({ error: "No body" }, 400);
  let obj: R2Object;
  try {
    obj = await c.env.PROGRAMS.put(key, c.req.raw.body, { sha256: hash, httpMetadata: { contentType: "application/gzip" } });
  } catch (err) {
    return c.json({ error: `R2 refused the upload: ${(err as Error)?.message ?? err}` }, 400);
  }
  if (obj.size !== bytes) {
    await c.env.PROGRAMS.delete(key).catch(() => {});
    return c.json({ error: `upload is ${obj.size} bytes, registered as ${bytes}` }, 400);
  }
  // Ready when everything declared is in.
  const have = async (k: string | null) => !k || Boolean(await c.env.PROGRAMS.head(k));
  const ready = (await have(row.key)) && (await have(row.sourceKey));
  if (ready && row.status !== "ready") {
    await db.update(projectPrograms).set({ status: "ready" }).where(eq(projectPrograms.id, id));
    runLater(c, notifyPrograms(c.env, projectId)); // a draft: the creator's dev engine picks it up
  }
  return c.json({ id, name: row.name, version: row.version, hash: row.hash, uploaded: source ? "source" : "archive", status: ready ? "ready" : "pending" }, 201);
}
router.put("/:id/archive", (c) => putArchive(c, false));
router.put("/:id/source", (c) => putArchive(c, true));

/* ------------------------------ publish / unpublish / pin ------------------------------ */

async function setPublished(c: AppContext, projish: boolean) {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: true });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  const id = c.req.param("id") ?? "";
  if (!UUID.test(id)) return c.json({ error: "Program not found" }, 404);
  const db = c.get("db");
  const [row] = await db.select().from(projectPrograms).where(and(eq(projectPrograms.id, id), eq(projectPrograms.projectId, projectId))).limit(1);
  if (!row) return c.json({ error: "Program not found" }, 404);
  const siblings = await db.select().from(projectPrograms).where(and(eq(projectPrograms.projectId, projectId), eq(projectPrograms.name, row.name)));
  let current = false;
  if (projish) {
    if (row.status !== "ready") return c.json({ error: "The archive has not been uploaded yet" }, 409);
    const body = await c.req.json<{ notes?: unknown }>().catch(() => ({} as { notes?: unknown }));
    const notes = typeof body?.notes === "string" ? body.notes.slice(0, 4000) : row.notes;
    const publishedAt = new Date();
    const plan = publishPlan(siblings.map((s) => (s.id === id ? { ...s, status: "ready", publishedAt } : s)), id);
    await db.update(projectPrograms).set({ publishedAt, publishedBy: actor(who.caller), notes }).where(eq(projectPrograms.id, id));
    await applyFlags(db, plan.changes);
    current = plan.becameCurrent;
  } else {
    const plan = unpublishPlan(siblings, id);
    await db.update(projectPrograms).set({ publishedAt: null, publishedBy: null, status: "unpublished" }).where(eq(projectPrograms.id, id));
    await applyFlags(db, plan.changes);
  }
  runLater(c, notifyPrograms(c.env, projectId));
  return c.json({ id, name: row.name, version: row.version, published: projish, current });
}
router.post("/:id/publish", (c) => setPublished(c, true));
router.post("/:id/unpublish", (c) => setPublished(c, false));

router.post("/pin", async (c) => {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: true });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  // Pin by hash (the build's identity); `version` is accepted for older callers and resolved to the row's hash.
  const body = await c.req.json<{ name?: unknown; hash?: unknown; version?: unknown }>().catch(() => null);
  const name = typeof body?.name === "string" ? body.name : "";
  if (!name) return c.json({ error: "name and hash (or null to unpin) are required" }, 400);
  const db = c.get("db");
  const mine = await db.select().from(projectPrograms).where(and(eq(projectPrograms.projectId, projectId), eq(projectPrograms.name, name)));
  let hash: string | null | undefined;
  if (body?.hash === null || body?.version === null) hash = null;
  else if (typeof body?.hash === "string") hash = body.hash.toLowerCase();
  else if (typeof body?.version === "string") hash = mine.find((r) => r.version === body.version)?.hash ?? "";
  if (hash === undefined) return c.json({ error: "name and hash (or null to unpin) are required" }, 400);
  const plan = pinPlan(mine, name, hash);
  if (!plan.ok) return c.json({ error: plan.error }, 404);
  await applyFlags(db, plan.changes);
  runLater(c, notifyPrograms(c.env, projectId));
  return c.json({ pins: pinsOf(mine.map((r) => ({ ...r, ...(plan.changes[r.id] ?? {}) }))) });
});

/* ------------------------------ download (engine / admin) ------------------------------ */

router.get("/:hash/download", async (c) => {
  const projectId = c.req.param("projectId")!;
  const who = await caller(c, projectId, { adminOnly: false });
  if (!who.ok) return c.json({ error: who.error }, who.status);
  const hash = (c.req.param("hash") ?? "").toLowerCase();
  const source = c.req.query("source") === "1";
  const db = c.get("db");
  const [row] = await db.select().from(projectPrograms).where(and(eq(projectPrograms.projectId, projectId), eq(projectPrograms.hash, hash))).limit(1);
  if (!row || row.status === "pending") return c.json({ error: "No such program build" }, 404);
  // Engines get live and draft builds only; a retracted build must not be re-fetched.
  if (who.caller.kind === "service" && row.status === "unpublished") return c.json({ error: "This build is unpublished" }, 410);
  const key = source ? row.sourceKey : row.key;
  if (!key) return c.json({ error: source ? "No source archive for this build" : "No archive for this build" }, 404);
  const obj = await c.env.PROGRAMS.get(key);
  if (!obj) return c.json({ error: "The archive is missing from storage" }, 404);
  return new Response(obj.body, {
    headers: {
      "content-type": "application/gzip",
      "content-length": String(obj.size),
      "content-disposition": `attachment; filename="${row.name}-${row.version}${source ? ".src" : ""}.tar.gz"`,
      "x-sa-program-hash": row.hash,
      "x-sa-program-bytes": String(source ? row.sourceBytes ?? obj.size : row.bytes),
    },
  });
});

export default router;
