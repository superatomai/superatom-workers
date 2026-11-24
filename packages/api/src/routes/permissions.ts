import { Hono } from "hono";
import { eq, and, or, isNull, inArray, type SQL } from "drizzle-orm";
import { objectDenials, objectGrants, objectRoles, objects, organizations, rolePermissions, roles, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import { appAccess, callerOf, legacyPermission, parseGrantLevel, sharingRolesById, type AppAccess, type Level, type SharingRole } from "../lib/objects";
import { projectAllowed, scopeOfUser } from "../lib/project-scope";
import { actorOf, logAccess, logRefusal } from "../lib/access-log";
import { isObjectAction, levelForActions, type ObjectAction } from "../lib/object-policy";
import { ADMIN_ROLES, BUILT_IN_ROLES, hasFixedPower, orgRoleOf, roleAndPermissions, type BuiltInRole } from "../lib/permissions";
import type { Database } from "../db";
import { writeTogether } from "../lib/write-together";

const permissionsRouter = new Hono<{
  Bindings: Env;
  Variables: AppVariables;
}>();

/**
 * Sharing one app with people (object_grants, principal "user").
 *
 * These routes are NOT nested under /orgs/:orgId, so tenant isolation is
 * enforced per request by resolving the app and the target user back to an
 * organization. Without it, a caller who knew an appId could grant themselves
 * access to another tenant's app.
 *
 * Who may share: anyone with `manage` on the app (its owner, a manager, an org
 * Owner or Admin). The request and response keep the old `permission` field
 * (view | edit | admin, admin meaning manage) and add `level`
 * (view | comment | edit | manage).
 */
permissionsRouter.use("*", authMiddleware);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const DENIED_APP = "Not permitted for this app";
const DENIED_USER = "Not permitted for this user";

/**
 * The app's object when the caller may manage it, or the response to send
 * instead. Another organization's app reads as 403, as before.
 */
async function managedObject(c: any, appId: string): Promise<{ ok: false; response: Response } | { ok: true; access: AppAccess }> {
  if (!UUID_RE.test(appId)) return { ok: false, response: c.json({ error: "appId must be a valid UUID" }, 400) };
  const access = await appAccess(c.get("db"), callerOf(c), appId);
  if (!access) return { ok: false, response: c.json({ error: DENIED_APP }, 403) };
  if (!access.actions.includes("share")) {
    await logRefusal(c, "needs share on this app", { type: "object", id: access.object.id });
    return { ok: false, response: c.json({ error: DENIED_APP }, 403) };
  }
  if (c.get("tokenSource") === "sdk" && c.req.method !== "GET") {
    return { ok: false, response: c.json({ error: "Not available to SDK sessions" }, 403) };
  }
  return { ok: true, access };
}

/**
 * Project scope (lib/project-scope.ts): sharing with someone who cannot reach
 * the app's project would give them nothing, so it is refused with the reason
 * instead of quietly doing nothing.
 */
async function userReachesProject(db: any, userId: string, projectId: string): Promise<string | null> {
  const scope = await scopeOfUser(db, userId);
  if (scope && (await projectAllowed(db, scope, projectId))) return null;
  return "They cannot reach this app's project. Add them to the project first.";
}

/** The user being given access must belong to the app's organization, and reach its project. */
async function denyUser(c: any, userId: string, orgId: string, projectId: string): Promise<string | null> {
  const [row] = await c
    .get("db")
    .select({ orgId: users.orgId })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  if (!row || row.orgId !== orgId) return DENIED_USER;
  return userReachesProject(c.get("db"), userId, projectId);
}

/** An app as something shared, for the access log. */
const appTarget = (access: AppAccess): ShareTarget => ({ object: access.object, orgId: access.orgId, projectId: access.app.projectId, actions: access.actions });

/** The one-word summary old clients read for a sharing role: view, edit or manage; null without a role. */
const levelOf = (role: SharingRole | undefined): Level | null => (role ? levelForActions(role.actions) : null);

/** A user's share on an app, in the shape the old `/permissions` routes return. */
const grantResponse = (g: { id: string; principalId: string; createdAt: Date }, appId: string, role: SharingRole) => ({
  id: g.id,
  userId: g.principalId,
  appId,
  level: levelOf(role),
  permission: legacyPermission(levelOf(role)),
  createdAt: g.createdAt,
});

/**
 * POST /apps/:appId/permissions — { userId, permission | level }
 * Share the app with a user.
 */
permissionsRouter.post("/:appId/permissions", async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");
  const body = await c.req.json<{ userId?: string; permission?: string; level?: string }>();
  const userId = body.userId ?? "";
  const level = parseGrantLevel(body.level ?? body.permission);

  if (!userId || !level) {
    return c.json({ error: "userId and a level (view, comment, edit or manage) are required" }, 400);
  }
  if (!UUID_RE.test(userId)) {
    return c.json({ error: "userId must be a valid UUID" }, 400);
  }

  const checked = await managedObject(c, appId);
  if (!checked.ok) return checked.response;
  const { access } = checked;

  const deniedUser = await denyUser(c, userId, access.orgId, access.app.projectId);
  if (deniedUser) return c.json({ error: deniedUser }, 403);

  const [existing] = await db
    .select({ id: objectGrants.id })
    .from(objectGrants)
    .where(
      and(
        eq(objectGrants.objectId, access.object.id),
        eq(objectGrants.principalType, "user"),
        eq(objectGrants.principalId, userId)
      )
    )
    .limit(1);
  if (existing) {
    return c.json({ error: "User already has permission for this app. Use PUT to update." }, 409);
  }

  const selection = await chosenRole(db, appTarget(access), { type: "user", id: userId }, level, undefined);
  if (!selection.ok) return c.json({ error: selection.error }, 400);
  const [grant] = await db
    .insert(objectGrants)
    .values({ objectId: access.object.id, principalType: "user", principalId: userId, objectRoleId: selection.role.id, grantedBy: c.get("userId") })
    .returning();
  await logGrant(c, appTarget(access), "grant.added", grant, null, selection.role);

  return c.json(grantResponse(grant, appId, selection.role), 201);
});

/**
 * GET /apps/:appId/permissions
 * Who the app is shared with (users), with names and emails.
 */
permissionsRouter.get("/:appId/permissions", async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");

  // Carries names and email addresses, so only for those who manage the app.
  const checked = await managedObject(c, appId);
  if (!checked.ok) return checked.response;

  const grants = await db
    .select({
      id: objectGrants.id,
      userId: objectGrants.principalId,
      userName: users.name,
      userEmail: users.email,
      roleId: objectGrants.objectRoleId,
      createdAt: objectGrants.createdAt,
    })
    .from(objectGrants)
    .innerJoin(users, eq(users.id, objectGrants.principalId))
    .where(and(eq(objectGrants.objectId, checked.access.object.id), eq(objectGrants.principalType, "user")));

  const roles = await sharingRolesById(db, grants.map((g) => g.roleId));
  return c.json(
    grants.map(({ roleId, ...g }) => {
      const level = levelOf(roles.get(roleId));
      return { ...g, level, permission: legacyPermission(level) };
    })
  );
});

/**
 * PUT /apps/:appId/permissions/:userId — { permission | level }
 * Change a user's level on the app.
 */
permissionsRouter.put("/:appId/permissions/:userId", async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");
  const userId = c.req.param("userId");
  const body = await c.req.json<{ permission?: string; level?: string }>();
  const level = parseGrantLevel(body.level ?? body.permission);

  if (!level) {
    return c.json({ error: "A level (view, comment, edit or manage) is required" }, 400);
  }
  if (!UUID_RE.test(userId)) {
    return c.json({ error: "userId must be a valid UUID" }, 400);
  }

  const checked = await managedObject(c, appId);
  if (!checked.ok) return checked.response;

  // Raising a grant is a privilege change, so the target must be in-tenant too.
  const deniedUser = await denyUser(c, userId, checked.access.orgId, checked.access.app.projectId);
  if (deniedUser) return c.json({ error: deniedUser }, 403);

  const where = and(
    eq(objectGrants.objectId, checked.access.object.id),
    eq(objectGrants.principalType, "user"),
    eq(objectGrants.principalId, userId)
  );
  const [before] = await db.select().from(objectGrants).where(where).limit(1);
  if (!before) {
    return c.json({ error: "Permission not found" }, 404);
  }
  const selection = await chosenRole(db, appTarget(checked.access), { type: "user", id: userId }, level, undefined);
  if (!selection.ok) return c.json({ error: selection.error }, 400);
  const [updated] = await db.update(objectGrants).set({ objectRoleId: selection.role.id }).where(where).returning();
  if (before.objectRoleId !== selection.role.id) {
    const previous = (await sharingRolesById(db, [before.objectRoleId])).get(before.objectRoleId);
    await logGrant(c, appTarget(checked.access), "grant.changed", updated, previous ?? null, selection.role);
  }

  return c.json(grantResponse(updated, appId, selection.role));
});

/**
 * DELETE /apps/:appId/permissions/:userId
 * Stop sharing the app with a user.
 */
permissionsRouter.delete("/:appId/permissions/:userId", async (c) => {
  const appId = c.req.param("appId");
  const userId = c.req.param("userId");

  if (!UUID_RE.test(userId)) {
    return c.json({ error: "userId must be a valid UUID" }, 400);
  }

  // Only the app is checked, deliberately: revoking is a de-escalation, and a
  // manager must be able to clear a stale grant held by someone who has since
  // left the organization.
  const checked = await managedObject(c, appId);
  if (!checked.ok) return checked.response;

  const where = and(
    eq(objectGrants.objectId, checked.access.object.id),
    eq(objectGrants.principalType, "user"),
    eq(objectGrants.principalId, userId)
  );
  if (!(await stopSharing(c, appTarget(checked.access), where))) {
    return c.json({ error: "Permission not found" }, 404);
  }

  return c.json({ message: "Permission revoked" });
});

// ═══ Grants to anyone: a user, a role or the whole organization ═══
//
// The routes above share with one user at a time and keep their old shape for
// the platform and runtime. These cover every kind of recipient, by grant id:
//   user     that person
//   role     everyone holding that role (built-in or this org's custom role)
//   org      everyone in the organization
// A project's members are not a recipient: something inside a project is for
// that project's people already, and another project's members may not reach it.

const PRINCIPAL_TYPES = ["user", "role", "org"] as const;
type PrincipalType = (typeof PRINCIPAL_TYPES)[number];

/** Whether the recipient exists and belongs to the app's organization; the error when not. */
async function denyPrincipal(c: any, type: PrincipalType, id: string, orgId: string, projectId: string): Promise<string | null> {
  const db = c.get("db");
  if (type === "org") return id === orgId ? null : "The organization must be the app's own";
  if (type === "user") {
    const [u] = await db.select({ id: users.id }).from(users).where(and(eq(users.id, id), eq(users.orgId, orgId))).limit(1);
    if (!u) return DENIED_USER;
    return userReachesProject(db, id, projectId);
  }
  // A built-in role (no org) or one of this org's custom roles; never a platform role.
  const [r] = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.id, id), eq(roles.scope, "org"), or(isNull(roles.orgId), eq(roles.orgId, orgId))))
    .limit(1);
  return r ? null : "Not permitted for this role";
}

/** What a set of sharing routes acts on: an app, a project or a data source. */
export type ShareTarget = { object: typeof objects.$inferSelect; orgId: string; projectId: string; actions: ObjectAction[] };
type Resolved = { ok: false; response: Response } | { ok: true; target: ShareTarget };

/**
 * Whether whoever a share is for uses the platform, and so may be given more
 * than View. A person or role without platform.access only views (as a Viewer
 * site role caps everything shared in Tableau); so do a project's members and
 * everyone in the org, as both include such people.
 */
async function usesPlatform(db: Database, principalType: string, principalId: string): Promise<boolean> {
  if (principalType === "user") {
    const [user] = await db.select({ id: users.id, role: users.role, roleId: users.roleId }).from(users)
      .where(eq(users.id, principalId)).limit(1);
    return !!user && (await roleAndPermissions(db, user)).permissions.includes("platform.access");
  }
  if (principalType === "role") {
    const [role] = await db.select({ key: roles.key, isSystem: roles.isSystem }).from(roles)
      .where(eq(roles.id, principalId)).limit(1);
    if (!role) return false;
    if (role.isSystem) return (BUILT_IN_ROLES[role.key as BuiltInRole] ?? []).includes("platform.access");
    const [held] = await db.select({ p: rolePermissions.permission }).from(rolePermissions)
      .where(and(eq(rolePermissions.roleId, principalId), eq(rolePermissions.permission, "platform.access"))).limit(1);
    return !!held;
  }
  return false;
}

/**
 * The sharing role a request gives: `objectRoleId` (built-in or this org's own),
 * or a `level` naming a built-in (view, edit, manage). Refused when it is not
 * available on this kind of object, carries an action the sharer lacks, or
 * gives more than View to someone who does not use the platform.
 */
async function chosenRole(
  db: any,
  target: ShareTarget,
  principal: { type: string; id: string },
  levelValue: unknown,
  roleValue: unknown
): Promise<{ ok: true; role: SharingRole } | { ok: false; error: string }> {
  let roleId: string | undefined;
  if (roleValue !== undefined) {
    if (typeof roleValue !== "string" || !UUID_RE.test(roleValue)) return { ok: false, error: "Invalid objectRoleId" };
    const [row] = await db.select({ id: objectRoles.id }).from(objectRoles).where(and(
      eq(objectRoles.id, roleValue), or(isNull(objectRoles.orgId), eq(objectRoles.orgId, target.orgId)),
    )).limit(1);
    roleId = row?.id;
  } else {
    const level = parseGrantLevel(levelValue);
    if (!level) return { ok: false, error: "level must be view, edit or manage, or provide objectRoleId" };
    const [row] = await db.select({ id: objectRoles.id }).from(objectRoles)
      .where(and(isNull(objectRoles.orgId), eq(objectRoles.key, level))).limit(1);
    roleId = row?.id;
  }
  const role = roleId ? (await sharingRolesById(db, [roleId])).get(roleId) : undefined;
  if (!role || (role.objectType && role.objectType !== target.object.type)) return { ok: false, error: "Object role not available for this object" };
  if (role.actions.some((action) => !target.actions.includes(action))) return { ok: false, error: "Cannot grant actions you do not have" };
  const beyondView = role.actions.some((action) => action !== "view");
  if (beyondView && !(await usesPlatform(db, principal.type, principal.id))) {
    return { ok: false, error: "Only View can be given to someone who does not use the platform" };
  }
  return { ok: true, role };
}

/**
 * The four sharing routes (list, share, change the role, stop sharing) on any
 * kind of object, at `path`. `resolve` finds the object and refuses anyone who
 * cannot manage it, so every kind is shared by the same rules.
 */
export function shareRoutes(router: Hono<any>, path: string, resolve: (c: any) => Promise<Resolved>) {
  router.get(path, async (c) => {
    const checked = await resolve(c);
    if (!checked.ok) return checked.response;
    return c.json(await sharingOf(c.get("db"), checked.target.object));
  });

  router.post(path, async (c) => {
    const db = c.get("db");
    const checked = await resolve(c);
    if (!checked.ok) return checked.response;
    const { target } = checked;

    const body = await c.req.json<{ principalType?: unknown; principalId?: unknown; level?: unknown; objectRoleId?: unknown }>().catch(() => ({}) as any);
    const principalType = body.principalType as PrincipalType;
    const principalId = typeof body.principalId === "string" ? body.principalId : "";
    if (!(PRINCIPAL_TYPES as readonly string[]).includes(principalType)) {
      return c.json({ error: "principalType must be user, role or org" }, 400);
    }
    if (!UUID_RE.test(principalId)) return c.json({ error: "principalId must be a valid UUID" }, 400);
    const selection = await chosenRole(db, target, { type: principalType, id: principalId }, body.level, body.objectRoleId);
    if (!selection.ok) return c.json({ error: selection.error }, 400);

    const denied = await denyPrincipal(c, principalType, principalId, target.orgId, target.projectId);
    if (denied) return c.json({ error: denied }, 403);

    const [grant] = await db
      .insert(objectGrants)
      .values({ objectId: target.object.id, principalType, principalId, objectRoleId: selection.role.id, grantedBy: c.get("userId") })
      .onConflictDoNothing()
      .returning();
    if (!grant) return c.json({ error: "Already shared with them. Change the role instead." }, 409);
    await logGrant(c, target, "grant.added", grant, null, selection.role);
    return c.json(grant, 201);
  });

  router.put(`${path}/:grantId`, async (c) => {
    const db = c.get("db");
    const checked = await resolve(c);
    if (!checked.ok) return checked.response;

    const body = await c.req.json<{ level?: unknown; objectRoleId?: unknown }>().catch(() => ({}) as any);
    const grantId = c.req.param("grantId");
    if (!UUID_RE.test(grantId)) return c.json({ error: "Grant not found" }, 404);

    const where = and(eq(objectGrants.id, grantId), eq(objectGrants.objectId, checked.target.object.id));
    const [before] = await db.select().from(objectGrants).where(where).limit(1);
    if (!before) return c.json({ error: "Grant not found" }, 404);
    const principal = { type: before.principalType, id: before.principalId };
    const selection = await chosenRole(db, checked.target, principal, body.level, body.objectRoleId);
    if (!selection.ok) return c.json({ error: selection.error }, 400);
    const [updated] = await db.update(objectGrants).set({ objectRoleId: selection.role.id }).where(where).returning();
    if (before.objectRoleId !== selection.role.id) {
      const previous = (await sharingRolesById(db, [before.objectRoleId])).get(before.objectRoleId);
      await logGrant(c, checked.target, "grant.changed", updated, previous ?? null, selection.role);
    }
    return c.json(updated);
  });

  router.delete(`${path}/:grantId`, async (c) => {
    const checked = await resolve(c);
    if (!checked.ok) return checked.response;
    const grantId = c.req.param("grantId");
    if (!UUID_RE.test(grantId)) return c.json({ error: "Grant not found" }, 404);

    const where = and(eq(objectGrants.id, grantId), eq(objectGrants.objectId, checked.target.object.id));
    if (!(await stopSharing(c, checked.target, where))) return c.json({ error: "Grant not found" }, 404);
    return c.json({ message: "No longer shared" });
  });
}

/** What a sharer may take from one person: never View (stop sharing instead) or handing over (the owner's alone). */
const RESTRICTABLE: readonly ObjectAction[] = ["create", "edit", "delete", "share", "disable"];

/** Each user's org role (owner, admin, member, a custom key, or super_admin), by id. */
async function orgRolesOf(db: Database, ids: (string | null)[]): Promise<Map<string, string>> {
  const wanted = [...new Set(ids.filter((id): id is string => !!id))];
  if (!wanted.length) return new Map();
  const rows = await db
    .select({ id: users.id, role: users.role, roleKey: roles.key })
    .from(users)
    .leftJoin(roles, eq(users.roleId, roles.id))
    .where(inArray(users.id, wanted));
  return new Map(rows.map((r) => [r.id, orgRoleOf(r)]));
}

/** Whether an Owner made a deny rule; one whose maker is gone counts as the Owner's, so it stays protected. */
const byOwner = (roleOf: Map<string, string>, createdBy: string | null) =>
  !createdBy || hasFixedPower(roleOf.get(createdBy), "manageRoles");

/** Sharers' restrictions on one person here: they go when the share does. The Owner's deny rules stay. */
async function sharerRestrictions(db: Database, target: ShareTarget, userId: string) {
  const rows = await db.select().from(objectDenials).where(and(
    eq(objectDenials.objectId, target.object.id),
    eq(objectDenials.principalType, "user"),
    eq(objectDenials.principalId, userId),
  ));
  const roleOf = await orgRolesOf(db, rows.map((r) => r.createdBy));
  return rows.filter((r) => !byOwner(roleOf, r.createdBy));
}

/**
 * Removes one share, and the restrictions sharers put on that person, in one
 * step, then logs both. Null when there is no such share.
 */
async function stopSharing(c: any, target: ShareTarget, where: SQL | undefined) {
  const db: Database = c.get("db");
  const [grant] = await db.select().from(objectGrants).where(where).limit(1);
  if (!grant) return null;
  const dropped = grant.principalType === "user" ? await sharerRestrictions(db, target, grant.principalId) : [];

  await writeTogether(db, [
    db.delete(objectGrants).where(eq(objectGrants.id, grant.id)),
    dropped.length > 0 && db.delete(objectDenials).where(inArray(objectDenials.id, dropped.map((r) => r.id))),
  ]);

  const role = (await sharingRolesById(db, [grant.objectRoleId])).get(grant.objectRoleId);
  await logGrant(c, target, "grant.removed", grant, role ?? null, null);
  for (const row of dropped) {
    await logAccess(db, {
      orgId: target.orgId,
      actorId: actorOf(c),
      action: "denial.removed",
      target: { type: "object", id: target.object.id },
      subjectId: grant.principalId,
      before: { principalType: "user", principalId: grant.principalId, action: row.action, reason: "no longer shared" },
    });
  }
  return grant;
}

/**
 * Deny rules on one object. Each takes one action away, even from an Admin or
 * the owner. Two kinds share the table:
 *  - the org Owner's: on anyone (a person, a role or everyone), any
 *    action. Only an Owner adds or removes them.
 *  - a sharer's restriction: whoever can share the object narrows what one
 *    person it is shared with may do ("Editor, but not delete"), without a new
 *    role. Never on themselves, its owner, an Owner or Admin, and never View.
 * A rule an Owner made is the Owner's: a sharer cannot remove it.
 */
export function denialRoutes(router: Hono<any>, path: string, resolve: (c: any) => Promise<Resolved>) {
  type Checked = { ok: false; response: Response } | { ok: true; target: ShareTarget; isOwner: boolean };

  async function checked(c: any): Promise<Checked> {
    const resolved = await resolve(c);
    if (!resolved.ok) return resolved;
    const { target } = resolved;
    if (c.get("userRole") !== "super_admin" && c.get("orgId") !== target.orgId) {
      return { ok: false, response: c.json({ error: "Not permitted for this object" }, 403) };
    }
    if (!(await projectAllowed(c.get("db"), callerOf(c), target.projectId))) {
      return { ok: false, response: c.json({ error: "Not permitted for this project" }, 403) };
    }
    const isOwner = hasFixedPower(c.get("orgRole"), "manageRoles");
    if (!isOwner && !target.actions.includes("share")) {
      await logRefusal(c, "needs share to restrict access", { type: "object", id: target.object.id });
      return { ok: false, response: c.json({ error: "Requires share on this" }, 403) };
    }
    const refused = refuseSdkChange(c);
    return refused ? { ok: false, response: refused } : { ok: true, target, isOwner };
  }

  /** Why a sharer (not an Owner) may not add or remove this restriction; null when they may. */
  async function refuseSharer(c: any, target: ShareTarget, principalType: string, principalId: string, action: string): Promise<string | null> {
    if (principalType !== "user") return "Only the Owner can deny a role or everyone";
    if (!(RESTRICTABLE as readonly string[]).includes(action)) return "To take away View, stop sharing with them instead";
    if (principalId === c.get("userId")) return "Cannot change your own access";
    if (principalId === target.object.ownerId) return "Cannot restrict its owner";
    const role = (await orgRolesOf(c.get("db"), [principalId])).get(principalId);
    if (!role || role === "super_admin" || ADMIN_ROLES.includes(role)) return "Only the Owner can restrict an Owner or Admin";
    const [grant] = await c.get("db").select({ id: objectGrants.id }).from(objectGrants).where(and(
      eq(objectGrants.objectId, target.object.id), eq(objectGrants.principalType, "user"), eq(objectGrants.principalId, principalId),
    )).limit(1);
    return grant ? null : "Share it with them first";
  }

  router.get(path, async (c) => {
    const result = await checked(c);
    if (!result.ok) return result.response;
    const db: Database = c.get("db");
    const rows = await db.select().from(objectDenials).where(eq(objectDenials.objectId, result.target.object.id));
    const roleOf = await orgRolesOf(db, rows.map((r) => r.createdBy));
    return c.json(rows.map((r) => ({ ...r, byOwner: byOwner(roleOf, r.createdBy) })));
  });

  router.post(path, async (c) => {
    const result = await checked(c);
    if (!result.ok) return result.response;
    const body = await c.req.json<{ principalType?: unknown; principalId?: unknown; action?: unknown; reason?: unknown }>().catch(() => ({} as any));
    const principalType = body.principalType as PrincipalType;
    const principalId = typeof body.principalId === "string" ? body.principalId : "";
    if (!(PRINCIPAL_TYPES as readonly string[]).includes(principalType) || !UUID_RE.test(principalId) || !isObjectAction(body.action)) {
      return c.json({ error: "principalType, principalId and a known action are required" }, 400);
    }
    if (body.reason != null && typeof body.reason !== "string") return c.json({ error: "Invalid reason" }, 400);
    const denied = await denyPrincipal(c, principalType, principalId, result.target.orgId, result.target.projectId);
    if (denied) return c.json({ error: denied }, 403);
    // Its own owner keeps everything, whoever asks.
    if (principalType === "user" && principalId === result.target.object.ownerId) {
      return c.json({ error: "Cannot restrict its owner" }, 403);
    }
    if (!result.isOwner) {
      const refused = await refuseSharer(c, result.target, principalType, principalId, body.action);
      if (refused) {
        await logRefusal(c, refused, { type: "object", id: result.target.object.id });
        return c.json({ error: refused }, 403);
      }
    }
    const [row] = await c.get("db").insert(objectDenials).values({
      objectId: result.target.object.id, principalType, principalId,
      action: body.action, reason: body.reason as string | undefined, createdBy: c.get("userId"),
    }).onConflictDoNothing().returning();
    if (!row) return c.json({ error: "This deny already exists" }, 409);
    await logAccess(c.get("db"), { orgId: result.target.orgId, actorId: actorOf(c), action: "denial.added",
      target: { type: "object", id: result.target.object.id }, subjectId: principalType === "user" ? principalId : null,
      after: { principalType, principalId, action: body.action, reason: row.reason } });
    return c.json(row, 201);
  });

  router.delete(`${path}/:denialId`, async (c) => {
    const result = await checked(c);
    if (!result.ok) return result.response;
    const denialId = c.req.param("denialId");
    if (!UUID_RE.test(denialId)) return c.json({ error: "Deny not found" }, 404);
    const where = and(eq(objectDenials.id, denialId), eq(objectDenials.objectId, result.target.object.id));
    const [existing] = await c.get("db").select().from(objectDenials).where(where).limit(1);
    if (!existing) return c.json({ error: "Deny not found" }, 404);
    if (!result.isOwner) {
      const ownerMade = byOwner(await orgRolesOf(c.get("db"), [existing.createdBy]), existing.createdBy);
      const refused = ownerMade
        ? "Only the Owner can remove the Owner's deny rules"
        : await refuseSharer(c, result.target, existing.principalType, existing.principalId, existing.action);
      if (refused) {
        await logRefusal(c, refused, { type: "object", id: result.target.object.id });
        return c.json({ error: refused }, 403);
      }
    }
    const [row] = await c.get("db").delete(objectDenials).where(where).returning();
    if (!row) return c.json({ error: "Deny not found" }, 404);
    await logAccess(c.get("db"), { orgId: result.target.orgId, actorId: actorOf(c), action: "denial.removed",
      target: { type: "object", id: result.target.object.id }, subjectId: row.principalType === "user" ? row.principalId : null,
      before: { principalType: row.principalType, principalId: row.principalId, action: row.action, reason: row.reason } });
    return c.json({ message: "Deny removed" });
  });
}

/**
 * Logs a share: on the object, about who it is for (a person, when it is one),
 * with the role before and after by name, as it was called at the time.
 */
function logGrant(
  c: any,
  target: ShareTarget,
  action: "grant.added" | "grant.changed" | "grant.removed",
  grant: typeof objectGrants.$inferSelect,
  beforeRole: SharingRole | null,
  afterRole: SharingRole | null
) {
  const who = { principalType: grant.principalType, principalId: grant.principalId };
  const roleOf = (role: SharingRole) => ({ roleId: role.id, role: role.name, actions: role.actions });
  const before = beforeRole && roleOf(beforeRole);
  const after = afterRole && roleOf(afterRole);
  return logAccess(c.get("db"), {
    orgId: target.orgId,
    actorId: actorOf(c),
    action,
    target: { type: "object", id: target.object.id },
    subjectId: grant.principalType === "user" ? grant.principalId : null,
    before: before && { ...who, ...before },
    after: after && { ...who, ...after },
  });
}

/** Refuses SDK sessions changing access, as every other access change does. */
export function refuseSdkChange(c: any): Response | null {
  return c.get("tokenSource") === "sdk" && c.req.method !== "GET" ? c.json({ error: "Not available to SDK sessions" }, 403) : null;
}

/** An object's owner, status, and everyone it is shared with, with a name for each. */
export async function sharingOf(db: any, object: typeof objects.$inferSelect) {
  const grants = await db.select().from(objectGrants).where(eq(objectGrants.objectId, object.id));
  return { type: object.type, ownerId: object.ownerId, createdBy: object.createdBy, status: object.status, grants: await withNames(db, grants) };
}

/** Grant rows with the name (and, for a person, the email) of who they are for. */
export async function withNames(db: any, grants: (typeof objectGrants.$inferSelect)[]) {
  const idsOf = (t: PrincipalType) => grants.filter((g) => g.principalType === t).map((g) => g.principalId);
  const names = new Map<string, { name: string; email?: string }>();
  if (idsOf("user").length) {
    for (const u of await db.select({ id: users.id, name: users.name, email: users.email }).from(users).where(inArray(users.id, idsOf("user")))) names.set(u.id, { name: u.name, email: u.email });
  }
  if (idsOf("role").length) {
    for (const r of await db.select({ id: roles.id, name: roles.name }).from(roles).where(inArray(roles.id, idsOf("role")))) names.set(r.id, { name: r.name });
  }
  if (idsOf("org").length) {
    for (const o of await db.select({ id: organizations.id, name: organizations.name }).from(organizations).where(inArray(organizations.id, idsOf("org")))) names.set(o.id, { name: o.name });
  }

  return grants.map((g) => ({
    id: g.id,
    principalType: g.principalType,
    principalId: g.principalId,
    principalName: names.get(g.principalId)?.name ?? null,
    principalEmail: names.get(g.principalId)?.email ?? null,
    objectRoleId: g.objectRoleId,
    grantedBy: g.grantedBy,
    createdAt: g.createdAt,
  }));
}

/**
 * GET, POST /apps/:appId/grants and PUT, DELETE /apps/:appId/grants/:grantId:
 * share an app with a person, a role, a project's members or the whole org, as
 * Viewer, Editor or Manager (needs Manager on the app).
 */
shareRoutes(permissionsRouter, "/:appId/grants", async (c) => {
  const checked = await managedObject(c, c.req.param("appId"));
  if (!checked.ok) return checked;
  const { access } = checked;
  return { ok: true, target: appTarget(access) };
});

denialRoutes(permissionsRouter, "/:appId/denials", async (c) => {
  const access = await appAccess(c.get("db"), callerOf(c), c.req.param("appId"));
  return access ? { ok: true, target: appTarget(access) } : { ok: false, response: c.json({ error: DENIED_APP }, 403) };
});

export default permissionsRouter;
