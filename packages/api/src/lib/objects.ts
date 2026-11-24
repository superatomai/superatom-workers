/**
 * Object access for apps, projects and data sources.
 *
 * Grants add the actions from a reusable object role. Project grants also
 * apply to children. Matching explicit denies remove actions from every
 * grant, including ownership and organization administration. Project scope
 * and tenant boundaries are checked before returning effective actions.
 * A caller's `level` on something is a conservative summary of their actions
 * for older clients; new callers use `actions` to decide which controls to
 * show or which request to allow. A grant itself holds only its role.
 */
import { and, eq, inArray, or, sql } from "drizzle-orm";
import { apps, objectDenials, objectGrants, objectRoleActions, objectRoles, objects, organizations, projectMembers, projects } from "../db/schema";
import { OBJECT_ACTIONS, effectiveActions, isObjectAction, levelForActions, type ObjectAction } from "./object-policy";
import type { Database } from "../db";
import { allowedProjects, projectAllowed } from "./project-scope";
import type { Permission } from "./permissions";

export const LEVELS = ["view", "edit", "manage", "owner"] as const;
export type Level = (typeof LEVELS)[number];
/** What a grant may carry. Owner is never granted; it is handed over. */
export const GRANT_LEVELS: readonly Level[] = ["view", "edit", "manage"];

export const APP_OBJECT_TYPES = ["dashboard", "chat_agent", "report", "app"] as const;
/** A project and a data source can be shared too; a project's role covers what is in it. */
export const PROJECT_OBJECT = "project";
export const SOURCE_OBJECT = "source";

/**
 * A role a request asks to grant: view, edit or manage, and the old names
 * (`admin` reads as manage, `comment` as view). Anything else is null.
 */
export function parseGrantLevel(value: unknown): Level | null {
  if (value === "admin") return "manage";
  if (value === "comment") return "view";
  return typeof value === "string" && (GRANT_LEVELS as readonly string[]).includes(value) ? (value as Level) : null;
}

/**
 * The old app-permission name for a level, so the platform and runtime keep
 * working until they read `level`: view → view, edit → edit, manage and owner → admin.
 */
export function legacyPermission(level: Level | null): "view" | "edit" | "admin" | null {
  if (!level) return null;
  if (level === "view") return "view";
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
  /** The org role's permissions (lib/permissions.ts): `dashboard.view` and the like count too. */
  permissions?: readonly string[];
};

export function callerOf(c: { get: (key: any) => any }): Caller {
  return {
    userId: c.get("userId"),
    orgId: c.get("orgId"),
    userRole: c.get("userRole"),
    roleId: c.get("roleId") ?? null,
    orgRole: c.get("orgRole") ?? null,
    projectScope: c.get("projectScope") ?? null,
    permissions: c.get("permissions") ?? [],
  };
}

/** The catalogue's resource name for each kind of app. */
const RESOURCE_OF: Record<string, string> = { dashboard: "dashboard", chat_agent: "agent", report: "report", app: "app" };

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

/**
 * The object rows for these projects, creating any that are missing. The
 * project's creator becomes its owner. A project's object has itself as its
 * project, so it sits beside its own apps.
 */
export async function ensureProjectObjects(db: Database, projectIds: string[]): Promise<Map<string, ObjectRow>> {
  const byProject = new Map<string, ObjectRow>();
  const ids = [...new Set(projectIds)];
  if (!ids.length) return byProject;
  const load = async (refs: string[]) => {
    for (const o of await db.select().from(objects).where(and(eq(objects.type, PROJECT_OBJECT), inArray(objects.refId, refs)))) {
      byProject.set(o.refId, o);
    }
  };
  await load(ids);
  const missing = ids.filter((id) => !byProject.has(id));
  if (missing.length) {
    const rows = await db
      .select({ id: projects.id, orgId: projects.orgId, createdBy: projects.createdBy })
      .from(projects)
      .where(inArray(projects.id, missing));
    if (rows.length) {
      await db
        .insert(objects)
        .values(rows.map((p) => ({ orgId: p.orgId, projectId: p.id, type: PROJECT_OBJECT, refId: p.id, ownerId: p.createdBy, createdBy: p.createdBy })))
        .onConflictDoNothing({ target: [objects.type, objects.refId] });
      await load(rows.map((p) => p.id));
    }
  }
  return byProject;
}

/** A data source lives in its project's engine, so it is known by project and id together. */
const sourceRef = (projectId: string, sourceId: string) => `${projectId}:${sourceId}`;

/** Who a grant must be for to reach this caller: them, their role, a project they are in, or their org. */
async function principalsOf(db: Database, caller: Caller) {
  const principals = [and(eq(objectGrants.principalType, "user"), eq(objectGrants.principalId, caller.userId))];
  if (caller.roleId) principals.push(and(eq(objectGrants.principalType, "role"), eq(objectGrants.principalId, caller.roleId)));
  if (caller.orgId) principals.push(and(eq(objectGrants.principalType, "org"), eq(objectGrants.principalId, caller.orgId)));
  // A grant to a project reaches the members of that project.
  const memberOf = (
    await db.select({ projectId: projectMembers.projectId }).from(projectMembers).where(eq(projectMembers.userId, caller.userId))
  ).map((r) => r.projectId);
  if (memberOf.length) principals.push(and(eq(objectGrants.principalType, "project"), inArray(objectGrants.principalId, memberOf)));
  return or(...principals)!;
}

/**
 * The projects a caller reaches through sharing: a role on the project, or
 * anything inside it shared with them or owned by them. With `project.view`
 * (or as an Owner or Admin) they see every project in their scope instead.
 */
export async function projectsSharedWith(db: Database, caller: Caller): Promise<Set<string>> {
  if (!caller.orgId) return new Set();
  const granted = db.select({ id: objectGrants.objectId }).from(objectGrants).where(await principalsOf(db, caller));
  const rows = await db
    .selectDistinct({ projectId: objects.projectId })
    .from(objects)
    .where(and(eq(objects.orgId, caller.orgId), or(eq(objects.ownerId, caller.userId), inArray(objects.id, granted))));
  return new Set(rows.map((r) => r.projectId).filter((p): p is string => !!p));
}

/** A sharing role as grants use it: what it is called, where it may be given, and its actions. */
export type SharingRole = { id: string; key: string; name: string; objectType: string | null; actions: ObjectAction[] };

/** Sharing roles by id, each with its actions, in one pair of queries. */
export async function sharingRolesById(db: Database, ids: Iterable<string>): Promise<Map<string, SharingRole>> {
  const wanted = [...new Set(ids)];
  const out = new Map<string, SharingRole>();
  if (!wanted.length) return out;
  const [roles, rows] = await Promise.all([
    db.select({ id: objectRoles.id, key: objectRoles.key, name: objectRoles.name, objectType: objectRoles.objectType })
      .from(objectRoles).where(inArray(objectRoles.id, wanted)),
    db.select().from(objectRoleActions).where(inArray(objectRoleActions.roleId, wanted)),
  ]);
  for (const role of roles) out.set(role.id, { ...role, actions: [] });
  for (const row of rows) {
    if (isObjectAction(row.action)) out.get(row.roleId)?.actions.push(row.action);
  }
  return out;
}

/** The actions every grant that reaches the caller gives, per object: each grant's sharing role. */
async function grantActionsFor(db: Database, caller: Caller, objectIds: string[]): Promise<Map<string, ObjectAction[]>> {
  const out = new Map<string, ObjectAction[]>();
  if (!objectIds.length) return out;
  const grants = await db.select({ objectId: objectGrants.objectId, roleId: objectGrants.objectRoleId })
    .from(objectGrants).where(and(inArray(objectGrants.objectId, objectIds), await principalsOf(db, caller)));
  if (!grants.length) return out;
  const [roles, objectTypes] = await Promise.all([
    sharingRolesById(db, grants.map((g) => g.roleId)),
    db.select({ id: objects.id, type: objects.type }).from(objects).where(inArray(objects.id, objectIds))
      .then((rows) => new Map(rows.map((row) => [row.id, row.type] as const))),
  ]);
  for (const grant of grants) {
    const role = roles.get(grant.roleId);
    // A role limited to one kind of thing gives nothing on any other.
    if (!role || (role.objectType && role.objectType !== objectTypes.get(grant.objectId))) continue;
    out.set(grant.objectId, [...(out.get(grant.objectId) ?? []), ...role.actions]);
  }
  return out;
}

/** Denies on the object or its project remove actions from every source of access. */
async function deniedActionsFor(db: Database, caller: Caller, objectIds: string[]): Promise<Map<string, ObjectAction[]>> {
  const out = new Map<string, ObjectAction[]>();
  if (!objectIds.length) return out;
  const memberOf = (await db.select({ projectId: projectMembers.projectId }).from(projectMembers)
    .where(eq(projectMembers.userId, caller.userId))).map((r) => r.projectId);
  const principals = [and(eq(objectDenials.principalType, "user"), eq(objectDenials.principalId, caller.userId))];
  if (caller.roleId) principals.push(and(eq(objectDenials.principalType, "role"), eq(objectDenials.principalId, caller.roleId)));
  if (caller.orgId) principals.push(and(eq(objectDenials.principalType, "org"), eq(objectDenials.principalId, caller.orgId)));
  if (memberOf.length) principals.push(and(eq(objectDenials.principalType, "project"), inArray(objectDenials.principalId, memberOf)));
  const rows = await db.select({ objectId: objectDenials.objectId, action: objectDenials.action }).from(objectDenials)
    .where(and(inArray(objectDenials.objectId, objectIds), or(...principals)));
  for (const row of rows) {
    if (isObjectAction(row.action)) out.set(row.objectId, [...(out.get(row.objectId) ?? []), row.action]);
  }
  return out;
}

function catalogueActions(caller: Caller, type: string): ObjectAction[] {
  const resource = RESOURCE_OF[type] ?? type;
  return OBJECT_ACTIONS.filter((action) => caller.permissions?.includes(`${resource}.${action}`));
}

function baseActions(caller: Caller, object: ObjectRow): ObjectAction[] {
  return isOrgAdmin(caller) || object.ownerId === caller.userId ? [...OBJECT_ACTIONS] : [];
}

/**
 * The caller's actions on one app, from everything already loaded: being an
 * Owner or Admin, owning it, grants on it and on its project, their org role's
 * permissions, and "everyone may view" (isDefault, the org's landing app);
 * minus denies. Outside the caller's org or project scope: nothing. A disabled
 * app only for those who can share or disable it. Exported for its tests.
 */
export function appActions(caller: Caller, app: AppRow, orgId: string, object: ObjectRow,
  grants: ObjectAction[], denies: ObjectAction[], defaultAppId: string | null, inScope: boolean): ObjectAction[] {
  if (caller.userRole !== "super_admin" && caller.orgId !== orgId || !inScope) return [];
  const fromOrgRole = catalogueActions(caller, app.type);
  const publicView = app.isDefault || defaultAppId === app.id ? ["view" as const] : [];
  // Its own owner keeps everything: no deny rule applies to them.
  const allowed = effectiveActions([...baseActions(caller, object), ...grants, ...fromOrgRole, ...publicView], caller.userId === object.ownerId ? [] : denies);
  return object.status === "disabled" && !allowed.includes("share") && !allowed.includes("disable") ? [] : allowed;
}

/** The same for a project or data source object. Exported for its tests. */
export function objectActions(caller: Caller, object: ObjectRow, grants: ObjectAction[], denies: ObjectAction[], inScope: boolean): ObjectAction[] {
  if (caller.userRole !== "super_admin" && caller.orgId !== object.orgId || !inScope) return [];
  // project.create creates a new project at organization scope. It does not
  // grant creation of every kind of object inside an existing project.
  const catalogue = catalogueActions(caller, object.type).filter((action) => object.type !== PROJECT_OBJECT || action !== "create");
  // Its own owner keeps everything: no deny rule (on them, a role or everyone) applies to them.
  const allowed = effectiveActions([...baseActions(caller, object), ...grants, ...catalogue], caller.userId === object.ownerId ? [] : denies);
  return object.status === "disabled" && !allowed.includes("share") && !allowed.includes("disable") ? [] : allowed;
}

export type AppAccess = {
  app: AppRow;
  projectName: string;
  orgId: string;
  object: ObjectRow;
  /** Null: the caller may not even view it (or it is another organization's). */
  level: Level | null;
  actions: ObjectAction[];
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
  const projectObject = (await ensureProjectObjects(db, [row.app.projectId])).get(row.app.projectId);
  // The app's own grants, and its project's: a role on the project covers its apps.
  const ids = [object.id, ...(projectObject ? [projectObject.id] : [])];
  const [allowedActions, deniedActions] = await Promise.all([
    grantActionsFor(db, caller, ids), deniedActionsFor(db, caller, ids),
  ]);
  const inScope = await projectAllowed(db, caller, row.app.projectId);
  const actions = appActions(caller, row.app, row.orgId, object,
    ids.flatMap((id) => allowedActions.get(id) ?? []), ids.flatMap((id) => deniedActions.get(id) ?? []), row.defaultAppId, inScope);
  return {
    app: row.app,
    projectName: row.projectName,
    orgId: row.orgId,
    object,
    level: levelForActions(actions),
    actions,
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
  const projectObjects = await ensureProjectObjects(db, rows.map((r) => r.app.projectId));
  const objectIds = [...objectsByApp.values(), ...projectObjects.values()].map((o) => o.id);
  const [grants, denied] = await Promise.all([
    grantActionsFor(db, caller, objectIds), deniedActionsFor(db, caller, objectIds),
  ]);
  // Null: every project.
  const allowed = await allowedProjects(db, caller);

  const out: AppAccess[] = [];
  for (const r of rows) {
    const object = objectsByApp.get(r.app.id);
    if (!object) continue;
    const inScope = !allowed || allowed.has(r.app.projectId);
    // The app's own grants, and its project's: a role on the project covers its apps.
    const projectObject = projectObjects.get(r.app.projectId);
    const ids = [object.id, ...(projectObject ? [projectObject.id] : [])];
    const actions = appActions(caller, r.app, r.orgId, object,
      ids.flatMap((id) => grants.get(id) ?? []), ids.flatMap((id) => denied.get(id) ?? []), org?.defaultAppId ?? null, inScope);
    const level = levelForActions(actions);
    if (level) out.push({ app: r.app, projectName: r.projectName, orgId: r.orgId, object, level, actions });
  }
  return out;
}

/** A project or a data source, with the caller's role on it. */
export type ObjectAccess = {
  object: ObjectRow;
  orgId: string;
  projectId: string;
  /** Null: the caller may not even view it. */
  level: Level | null;
  actions: ObjectAction[];
};

/** An explicit project deny applies when creating a new child object. */
export async function projectActionDenied(db: Database, caller: Caller, projectId: string, action: ObjectAction): Promise<boolean> {
  const object = (await ensureProjectObjects(db, [projectId])).get(projectId);
  if (!object || caller.userId === object.ownerId) return false;
  const denied = await deniedActionsFor(db, caller, [object.id]);
  return (denied.get(object.id) ?? []).includes(action) || (denied.get(object.id) ?? []).includes("view");
}

/**
 * A project with the caller's access to it: their actions, whether it is in
 * their project scope, and what a deny rule takes from them there.
 */
export type ProjectAccess = ObjectAccess & { inScope: boolean; denied: ObjectAction[] };

/** One project with the caller's access to it, or null when there is no such project. */
export async function projectAccess(db: Database, caller: Caller, projectId: string): Promise<ProjectAccess | null> {
  return (await projectsAccess(db, caller, [projectId])).get(projectId) ?? null;
}

/**
 * Several projects with the caller's access to each, in one round of queries
 * rather than three per project (the projects list reads every one).
 */
export async function projectsAccess(db: Database, caller: Caller, projectIds: string[]): Promise<Map<string, ProjectAccess>> {
  const out = new Map<string, ProjectAccess>();
  const byProject = await ensureProjectObjects(db, projectIds.filter((id) => UUID.test(id)));
  if (!byProject.size) return out;

  const objectIds = [...byProject.values()].map((o) => o.id);
  const [grants, denied, allowed] = await Promise.all([
    grantActionsFor(db, caller, objectIds),
    deniedActionsFor(db, caller, objectIds),
    allowedProjects(db, caller),
  ]);
  for (const [projectId, object] of byProject) {
    const inScope = !allowed || allowed.has(projectId);
    const deniedHere = denied.get(object.id) ?? [];
    const actions = objectActions(caller, object, grants.get(object.id) ?? [], deniedHere, inScope);
    out.set(projectId, { object, orgId: object.orgId, projectId, level: levelForActions(actions), actions, inScope, denied: deniedHere });
  }
  return out;
}

/**
 * What someone may do to a project itself, deny rules applied (they are already
 * out of `actions`). Rename it or change its details: project.edit, or Manager
 * on it. Delete it: project.delete, or being its owner; never a shared Editor
 * or Manager, as deleting takes everything in it and cannot be undone.
 */
export function projectPowers(
  access: { actions: readonly ObjectAction[]; ownerId: string | null } | null | undefined,
  caller: { userId: string; permissions?: readonly string[] }
): { canRename: boolean; canDelete: boolean } {
  if (!access) return { canRename: false, canDelete: false };
  const holds = (permission: Permission) => caller.permissions?.includes(permission) ?? false;
  const isManager = access.actions.includes("share");
  const isOwner = access.ownerId !== null && access.ownerId === caller.userId;
  return {
    canRename: access.actions.includes("edit") && (holds("project.edit") || isManager),
    canDelete: access.actions.includes("delete") && (holds("project.delete") || isOwner),
  };
}

/**
 * One data source with the caller's role on it: its own grants and its
 * project's, the highest winning. A source nobody has shared yet has no row of
 * its own, so it simply takes the project's role; `create` makes the row (to
 * share it), with no owner: it was created in the engine, outside SA-API.
 */
export async function sourceAccess(
  db: Database,
  caller: Caller,
  projectId: string,
  sourceId: string,
  create = false
): Promise<ObjectAccess | null> {
  const project = await projectAccess(db, caller, projectId);
  if (!project || !(await projectAllowed(db, caller, projectId))) return null;
  const ref = sourceRef(projectId, sourceId);
  let [object] = await db.select().from(objects).where(and(eq(objects.type, SOURCE_OBJECT), eq(objects.refId, ref))).limit(1);
  if (!object && create) {
    await db
      .insert(objects)
      .values({ orgId: project.orgId, projectId, type: SOURCE_OBJECT, refId: ref, createdBy: caller.userId })
      .onConflictDoNothing({ target: [objects.type, objects.refId] });
    [object] = await db.select().from(objects).where(and(eq(objects.type, SOURCE_OBJECT), eq(objects.refId, ref))).limit(1);
  }
  const projectDenials = await deniedActionsFor(db, caller, [project.object.id]);
  const inherited = effectiveActions([...project.actions, ...catalogueActions(caller, SOURCE_OBJECT)],
    projectDenials.get(project.object.id) ?? []);
  if (!object) return { ...project, level: levelForActions(inherited), actions: inherited };
  const [grants, denied] = await Promise.all([
    grantActionsFor(db, caller, [object.id]), deniedActionsFor(db, caller, [object.id]),
  ]);
  const actions = effectiveActions([...inherited, ...baseActions(caller, object), ...(grants.get(object.id) ?? []), ...catalogueActions(caller, SOURCE_OBJECT)],
    [...(projectDenials.get(project.object.id) ?? []), ...(denied.get(object.id) ?? [])]);
  const visible = object.status === "disabled" && !actions.includes("share") && !actions.includes("disable") ? [] : actions;
  return { object, orgId: project.orgId, projectId, level: levelForActions(visible), actions: visible };
}

/**
 * The caller's role on every data source in a project that has its own shares,
 * by source id. Any other source takes the project's role, returned alongside.
 */
export async function sourceLevels(
  db: Database,
  caller: Caller,
  projectId: string
): Promise<{
  project: Level | null;
  projectActions: ObjectAction[];
  defaultSourceActions: ObjectAction[];
  canCreate: Record<string, boolean>;
  sources: Record<string, Level | null>;
  sourceActions: Record<string, ObjectAction[]>;
}> {
  const project = await projectAccess(db, caller, projectId);
  if (!project || !(await projectAllowed(db, caller, projectId))) {
    return { project: null, projectActions: [], defaultSourceActions: [], canCreate: {}, sources: {}, sourceActions: {} };
  }
  const rows = await db.select().from(objects).where(and(eq(objects.type, SOURCE_OBJECT), eq(objects.projectId, projectId)));
  const [grants, denied, projectDenials] = await Promise.all([
    grantActionsFor(db, caller, rows.map((o) => o.id)),
    deniedActionsFor(db, caller, rows.map((o) => o.id)),
    deniedActionsFor(db, caller, [project.object.id]),
  ]);
  const projectDenied = projectDenials.get(project.object.id) ?? [];
  const defaultSourceActions = effectiveActions([...project.actions, ...catalogueActions(caller, SOURCE_OBJECT)], projectDenied);
  const canCreate: Record<string, boolean> = {};
  for (const type of APP_OBJECT_TYPES) {
    canCreate[type] = !projectDenied.includes("view") && !projectDenied.includes("create") &&
      (project.actions.includes("create") || catalogueActions(caller, type).includes("create"));
  }
  const sources: Record<string, Level | null> = {};
  const sourceActions: Record<string, ObjectAction[]> = {};
  for (const object of rows) {
    const id = object.refId.slice(projectId.length + 1);
    const actions = effectiveActions([...defaultSourceActions, ...baseActions(caller, object), ...(grants.get(object.id) ?? []), ...catalogueActions(caller, SOURCE_OBJECT)],
      [...(projectDenials.get(project.object.id) ?? []), ...(denied.get(object.id) ?? [])]);
    const visible = object.status === "disabled" && !actions.includes("share") && !actions.includes("disable") ? [] : actions;
    sourceActions[id] = visible;
    sources[id] = levelForActions(visible);
  }
  return { project: project.level, projectActions: project.actions, defaultSourceActions, canCreate, sources, sourceActions };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The permission each kind of app needs to be created (lib/permissions.ts). */
export const CREATE_PERMISSION: Record<(typeof APP_OBJECT_TYPES)[number], Permission> = {
  dashboard: "dashboard.create",
  chat_agent: "agent.create",
  report: "report.create",
  app: "app.create",
};
