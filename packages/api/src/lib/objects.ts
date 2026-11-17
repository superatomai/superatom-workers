/**
 * Objects and sharing: who may do what with one particular thing.
 *
 * Every app (dashboard, chat agent, report, mobile app) has an object row with
 * its owner and status, and object_grants say who else may use it and how far.
 * One function decides a caller's level on an app, so every route asks the same
 * question the same way. See ROLES-AND-PERMISSIONS.md, layer 2.
 *
 * Levels, lowest first: view < comment < edit < manage < owner.
 *   view    open and use it (for a chat agent: ask it questions)
 *   comment view, and leave comments
 *   edit    change its content
 *   manage  share it, disable it, delete it
 *   owner   everything, including handing it over (objects.owner_id, not a grant)
 */
import { and, eq, inArray, or, sql } from "drizzle-orm";
import { apps, objectGrants, objects, organizations, projectMembers, projects } from "../db/schema";
import type { Database } from "../db";
import { allowedProjects, projectAllowed } from "./project-scope";

export const LEVELS = ["view", "comment", "edit", "manage", "owner"] as const;
export type Level = (typeof LEVELS)[number];
/** What a grant may carry. Owner is never granted; it is handed over. */
export const GRANT_LEVELS: readonly Level[] = ["view", "comment", "edit", "manage"];

export const APP_OBJECT_TYPES = ["dashboard", "chat_agent", "report", "app"] as const;

const rank = (level: Level | null | undefined): number => (level ? LEVELS.indexOf(level) : -1);

/** Whether `level` reaches `needed`. */
export function atLeast(level: Level | null | undefined, needed: Level): boolean {
  return rank(level) >= rank(needed);
}

function highest(levels: (Level | null | undefined)[]): Level | null {
  let best: Level | null = null;
  for (const l of levels) if (rank(l) > rank(best)) best = l ?? null;
  return best;
}

/**
 * A level a request asks to grant: view, comment, edit or manage, and the old
 * app-permission names (`admin` reads as manage). Anything else is null.
 */
export function parseGrantLevel(value: unknown): Level | null {
  if (value === "admin") return "manage";
  return typeof value === "string" && (GRANT_LEVELS as readonly string[]).includes(value) ? (value as Level) : null;
}

/**
 * The old app-permission name for a level, so the platform and runtime keep
 * working until they read `level`: view and comment → view, edit → edit,
 * manage and owner → admin.
 */
export function legacyPermission(level: Level | null): "view" | "edit" | "admin" | null {
  if (!level) return null;
  if (level === "view" || level === "comment") return "view";
  return level === "edit" ? "edit" : "admin";
}

export type Caller = {
  userId: string;
  orgId: string | null;
  userRole: "super_admin" | "org_admin" | "member";
  roleId: string | null;
  /** For project scope (lib/project-scope.ts); absent means every project. */
  orgRole?: string | null;
  projectScope?: string | null;
};

export function callerOf(c: { get: (key: any) => any }): Caller {
  return {
    userId: c.get("userId"),
    orgId: c.get("orgId"),
    userRole: c.get("userRole"),
    roleId: c.get("roleId") ?? null,
    orgRole: c.get("orgRole") ?? null,
    projectScope: c.get("projectScope") ?? null,
  };
}

/**
 * Org Owners and Admins (both `org_admin`) and the platform super admin see and
 * change everything in the organization, whatever is shared, as they could
 * before objects existed, so nothing becomes unreachable.
 */
function isOrgAdmin(caller: Caller): boolean {
  return caller.userRole === "org_admin" || caller.userRole === "super_admin";
}

type ObjectRow = typeof objects.$inferSelect;
type AppRow = typeof apps.$inferSelect;

/**
 * The object rows for these apps, creating any that are missing (an app made
 * before objects existed, or by code that does not register one). The creator
 * becomes the owner.
 */
export async function ensureAppObjects(
  db: Database,
  rows: { app: Pick<AppRow, "id" | "type" | "projectId" | "createdBy">; orgId: string }[]
): Promise<Map<string, ObjectRow>> {
  const byApp = new Map<string, ObjectRow>();
  if (!rows.length) return byApp;
  const ids = rows.map((r) => r.app.id);
  const found = await db
    .select()
    .from(objects)
    .where(and(inArray(objects.type, [...APP_OBJECT_TYPES]), inArray(objects.refId, ids)));
  for (const o of found) byApp.set(o.refId, o);

  const missing = rows.filter((r) => !byApp.has(r.app.id));
  if (missing.length) {
    await db
      .insert(objects)
      .values(
        missing.map((r) => ({
          orgId: r.orgId,
          projectId: r.app.projectId,
          type: r.app.type,
          refId: r.app.id,
          ownerId: r.app.createdBy,
          createdBy: r.app.createdBy,
        }))
      )
      // Two requests may register the same app at once; the first one wins.
      .onConflictDoNothing({ target: [objects.type, objects.refId] });
    const created = await db
      .select()
      .from(objects)
      .where(and(inArray(objects.type, [...APP_OBJECT_TYPES]), inArray(objects.refId, missing.map((r) => r.app.id))));
    for (const o of created) byApp.set(o.refId, o);
  }
  return byApp;
}

/** Grants that apply to this caller on these objects, by object id. */
async function grantsFor(db: Database, caller: Caller, objectIds: string[]): Promise<Map<string, Level[]>> {
  const out = new Map<string, Level[]>();
  if (!objectIds.length) return out;
  const principals = [and(eq(objectGrants.principalType, "user"), eq(objectGrants.principalId, caller.userId))];
  if (caller.roleId) principals.push(and(eq(objectGrants.principalType, "role"), eq(objectGrants.principalId, caller.roleId)));
  if (caller.orgId) principals.push(and(eq(objectGrants.principalType, "org"), eq(objectGrants.principalId, caller.orgId)));
  // A grant to a project reaches the members of that project.
  const memberOf = (
    await db.select({ projectId: projectMembers.projectId }).from(projectMembers).where(eq(projectMembers.userId, caller.userId))
  ).map((r) => r.projectId);
  if (memberOf.length) principals.push(and(eq(objectGrants.principalType, "project"), inArray(objectGrants.principalId, memberOf)));
  const rows = await db
    .select({ objectId: objectGrants.objectId, level: objectGrants.level })
    .from(objectGrants)
    .where(and(inArray(objectGrants.objectId, objectIds), or(...principals)));
  for (const r of rows) {
    const list = out.get(r.objectId) ?? [];
    list.push(r.level as Level);
    out.set(r.objectId, list);
  }
  return out;
}

/**
 * The caller's level on one app given everything already loaded: admin, owner,
 * grants, and the two existing "everyone may view" switches (the app's own
 * isDefault, and the organization's landing app). A disabled app is usable
 * only by those who manage it.
 *
 * `inScope` is whether the app's project is within the caller's project scope
 * (lib/project-scope.ts). Outside it there is no level at all, for admins too:
 * the project is closed to them, so everything in it is.
 */
export function levelOf(
  caller: Caller,
  app: AppRow,
  appOrgId: string,
  object: ObjectRow,
  grants: Level[],
  orgDefaultAppId: string | null,
  inScope = true
): Level | null {
  if (caller.userRole !== "super_admin" && caller.orgId !== appOrgId) return null;
  if (!inScope) return null;
  if (isOrgAdmin(caller)) return "owner";
  const level = highest([
    object.ownerId === caller.userId ? "owner" : null,
    ...grants,
    app.isDefault ? "view" : null,
    orgDefaultAppId === app.id ? "view" : null,
  ]);
  if (object.status === "disabled" && !atLeast(level, "manage")) return null;
  return level;
}

export type AppAccess = {
  app: AppRow;
  projectName: string;
  orgId: string;
  object: ObjectRow;
  /** Null: the caller may not even view it (or it is another organization's). */
  level: Level | null;
};

/** One app with the caller's level on it, or null when there is no such app. */
export async function appAccess(db: Database, caller: Caller, appId: string): Promise<AppAccess | null> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(appId)) return null;
  const [row] = await db
    .select({ app: apps, projectName: projects.name, orgId: projects.orgId, defaultAppId: organizations.defaultAppId })
    .from(apps)
    .innerJoin(projects, eq(projects.id, apps.projectId))
    .innerJoin(organizations, eq(organizations.id, projects.orgId))
    .where(eq(apps.id, appId))
    .limit(1);
  if (!row) return null;
  const object = (await ensureAppObjects(db, [{ app: row.app, orgId: row.orgId }])).get(row.app.id)!;
  const grants = (await grantsFor(db, caller, [object.id])).get(object.id) ?? [];
  const inScope = await projectAllowed(db, caller, row.app.projectId);
  return {
    app: row.app,
    projectName: row.projectName,
    orgId: row.orgId,
    object,
    level: levelOf(caller, row.app, row.orgId, object, grants, row.defaultAppId, inScope),
  };
}

/**
 * Every active app in the caller's organization they may at least view, with
 * their level. `projectId` narrows it to one project. A super admin belongs to
 * no organization and gets none, as before.
 */
export async function accessibleApps(db: Database, caller: Caller, projectId?: string): Promise<AppAccess[]> {
  if (!caller.orgId) return [];
  const rows = await db
    .select({ app: apps, projectName: projects.name, orgId: projects.orgId })
    .from(apps)
    .innerJoin(projects, eq(projects.id, apps.projectId))
    .where(
      and(
        eq(projects.orgId, caller.orgId),
        eq(apps.isActive, true),
        projectId ? eq(apps.projectId, projectId) : sql`true`
      )
    );
  if (!rows.length) return [];
  const [org] = await db
    .select({ defaultAppId: organizations.defaultAppId })
    .from(organizations)
    .where(eq(organizations.id, caller.orgId))
    .limit(1);
  const objectsByApp = await ensureAppObjects(db, rows);
  const grants = isOrgAdmin(caller) ? new Map<string, Level[]>() : await grantsFor(db, caller, [...objectsByApp.values()].map((o) => o.id));
  // Null: every project.
  const allowed = await allowedProjects(db, caller);

  const out: AppAccess[] = [];
  for (const r of rows) {
    const object = objectsByApp.get(r.app.id);
    if (!object) continue;
    const inScope = !allowed || allowed.has(r.app.projectId);
    const level = levelOf(caller, r.app, r.orgId, object, grants.get(object.id) ?? [], org?.defaultAppId ?? null, inScope);
    if (level) out.push({ app: r.app, projectName: r.projectName, orgId: r.orgId, object, level });
  }
  return out;
}

/** The permission each kind of app needs to be created (lib/permissions.ts). */
export const CREATE_PERMISSION: Record<(typeof APP_OBJECT_TYPES)[number], string> = {
  dashboard: "dashboards.create",
  chat_agent: "chat_agents.create",
  report: "reports.create",
  app: "apps.create",
};
