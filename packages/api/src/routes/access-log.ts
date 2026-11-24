import { Hono } from "hono";
import { and, desc, eq, inArray, lt, or, type SQL } from "drizzle-orm";
import { accessLog, apps, objectRoles, objects, organizations, projects, roles, users } from "../db/schema";
import type { Database } from "../db";
import type { Env, AppVariables } from "../types";
import { authMiddleware, orgScopeGuard, requirePermission } from "../middleware/auth";

/**
 * GET /orgs/:orgId/access-log — the access log (lib/access-log.ts), newest first.
 * Needs members.history. Filters, all optional:
 *   person=<userId>    what they did, or what happened to their access
 *   target=<id>        what was done to one thing (an app, project, role, person)
 *   action=<a,b>       only these actions (e.g. grant.added,grant.removed)
 *   before, beforeId   the last entry seen, for the next page; limit=1..200 (default 50)
 */
const accessLogRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();
accessLogRouter.use("*", authMiddleware, requirePermission("members.history"), orgScopeGuard);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type LogRow = typeof accessLog.$inferSelect;
type ObjectRow = typeof objects.$inferSelect;
type Principal = { principalType?: string; principalId?: string };
type Target = { kind: string; name: string | null };

accessLogRouter.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const person = c.req.query("person");
  const target = c.req.query("target");
  const actions = c.req.query("action")?.split(",").filter(Boolean);
  const before = c.req.query("before");
  const beforeId = c.req.query("beforeId");
  const limit = Math.min(Math.max(Number(c.req.query("limit")) || 50, 1), 200);

  const conds: SQL[] = [eq(accessLog.orgId, orgId)];
  if (person) {
    if (!UUID.test(person)) return c.json({ error: "person must be a user id" }, 400);
    conds.push(or(eq(accessLog.actorId, person), eq(accessLog.subjectId, person), eq(accessLog.targetId, person))!);
  }
  if (target) conds.push(eq(accessLog.targetId, target));
  if (actions?.length) conds.push(inArray(accessLog.action, actions));
  if (before) {
    const time = new Date(before);
    if (Number.isNaN(time.getTime())) return c.json({ error: "before must be a date" }, 400);
    if (beforeId && !UUID.test(beforeId)) return c.json({ error: "beforeId must be an entry id" }, 400);
    // After the last entry seen; one at the same moment is ordered by id, so none is skipped.
    const sameTimeAfter = beforeId ? and(eq(accessLog.createdAt, time), lt(accessLog.id, beforeId)) : undefined;
    conds.push(sameTimeAfter ? or(lt(accessLog.createdAt, time), sameTimeAfter)! : lt(accessLog.createdAt, time));
  }

  const rows = await db
    .select()
    .from(accessLog)
    .where(and(...conds))
    .orderBy(desc(accessLog.createdAt), desc(accessLog.id))
    .limit(limit);

  const principalOf = (entry: LogRow): Principal => {
    const value = entry.after ?? entry.before;
    return value && typeof value === "object" ? (value as Principal) : {};
  };
  const names = await namesById(db, [
    ...rows.flatMap((r) => [r.actorId, r.subjectId]),
    ...rows.map((r) => principalOf(r).principalId),
  ]);
  const targets = await targetsOf(db, rows);
  const nameOf = (id: string | null | undefined) => (id ? names.get(id) ?? null : null);

  return c.json(
    rows.map((r) => ({
      ...r,
      actorName: nameOf(r.actorId),
      subjectName: nameOf(r.subjectId),
      principalName: nameOf(principalOf(r).principalId),
      // Named as it is now; null once it is gone.
      targetKind: targets.get(r.id)?.kind ?? r.targetType,
      targetName: targets.get(r.id)?.name ?? null,
    }))
  );
});

/** Names by id across people, org roles, sharing roles, projects and organizations (ids never collide). */
async function namesById(db: Database, ids: (string | null | undefined)[]): Promise<Map<string, string>> {
  const wanted = [...new Set(ids.filter((id): id is string => !!id && UUID.test(id)))];
  const out = new Map<string, string>();
  if (!wanted.length) return out;

  const lists = await Promise.all([
    db.select({ id: users.id, name: users.name }).from(users).where(inArray(users.id, wanted)),
    db.select({ id: roles.id, name: roles.name }).from(roles).where(inArray(roles.id, wanted)),
    db.select({ id: objectRoles.id, name: objectRoles.name }).from(objectRoles).where(inArray(objectRoles.id, wanted)),
    db.select({ id: projects.id, name: projects.name }).from(projects).where(inArray(projects.id, wanted)),
    db.select({ id: organizations.id, name: organizations.name }).from(organizations).where(inArray(organizations.id, wanted)),
  ]);
  for (const list of lists) {
    for (const row of list) out.set(row.id, row.name);
  }
  return out;
}

/** Each entry's target: its kind (dashboard, project, source, role, user…) and current name. */
async function targetsOf(db: Database, rows: LogRow[]): Promise<Map<string, Target>> {
  const objectIds = [...new Set(rows.filter((r) => r.targetType === "object" && UUID.test(r.targetId)).map((r) => r.targetId))];
  const objectRows: ObjectRow[] = objectIds.length ? await db.select().from(objects).where(inArray(objects.id, objectIds)) : [];
  const objectsById = new Map(objectRows.map((o) => [o.id, o]));

  const appIds = objectRows
    .filter((o) => o.type !== "project" && o.type !== "source" && UUID.test(o.refId))
    .map((o) => o.refId);
  const appRows = appIds.length ? await db.select({ id: apps.id, name: apps.name }).from(apps).where(inArray(apps.id, appIds)) : [];
  const appNames = new Map(appRows.map((a) => [a.id, a.name]));

  const names = await namesById(db, [
    ...objectRows.filter((o) => o.type === "project").map((o) => o.refId),
    ...rows.filter((r) => r.targetType !== "object").map((r) => r.targetId),
  ]);

  // A data source lives in its project's engine; SA-API knows only its id, which stands for its name.
  const objectName = (o: ObjectRow): string | null => {
    if (o.type === "project") return names.get(o.refId) ?? null;
    if (o.type === "source") return o.refId.slice((o.projectId?.length ?? 0) + 1);
    return appNames.get(o.refId) ?? null;
  };

  const out = new Map<string, Target>();
  for (const r of rows) {
    if (r.targetType === "route") {
      out.set(r.id, { kind: "route", name: r.targetId });
    } else if (r.targetType !== "object") {
      out.set(r.id, { kind: r.targetType, name: names.get(r.targetId) ?? null });
    } else {
      const o = objectsById.get(r.targetId);
      if (o) out.set(r.id, { kind: o.type, name: objectName(o) });
    }
  }
  return out;
}

export default accessLogRouter;
