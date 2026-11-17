import { Hono } from "hono";
import { eq, and, or, isNull, inArray } from "drizzle-orm";
import { objectGrants, organizations, projects, roles, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import { appAccess, atLeast, callerOf, legacyPermission, parseGrantLevel, type AppAccess, type Level } from "../lib/objects";
import { projectAllowed, scopeOfUser } from "../lib/project-scope";

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
  if (!atLeast(access.level, "manage")) return { ok: false, response: c.json({ error: DENIED_APP }, 403) };
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

const grantResponse = (g: { id: string; principalId: string; level: string; createdAt: Date }, appId: string) => ({
  id: g.id,
  userId: g.principalId,
  appId,
  level: g.level,
  permission: legacyPermission(g.level as Level),
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

  const [grant] = await db
    .insert(objectGrants)
    .values({ objectId: access.object.id, principalType: "user", principalId: userId, level, grantedBy: c.get("userId") })
    .returning();

  return c.json(grantResponse(grant, appId), 201);
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
      level: objectGrants.level,
      createdAt: objectGrants.createdAt,
    })
    .from(objectGrants)
    .innerJoin(users, eq(users.id, objectGrants.principalId))
    .where(and(eq(objectGrants.objectId, checked.access.object.id), eq(objectGrants.principalType, "user")));

  return c.json(grants.map((g) => ({ ...g, permission: legacyPermission(g.level as Level) })));
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

  const [updated] = await db
    .update(objectGrants)
    .set({ level })
    .where(
      and(
        eq(objectGrants.objectId, checked.access.object.id),
        eq(objectGrants.principalType, "user"),
        eq(objectGrants.principalId, userId)
      )
    )
    .returning();

  if (!updated) {
    return c.json({ error: "Permission not found" }, 404);
  }

  return c.json(grantResponse(updated, appId));
});

/**
 * DELETE /apps/:appId/permissions/:userId
 * Stop sharing the app with a user.
 */
permissionsRouter.delete("/:appId/permissions/:userId", async (c) => {
  const db = c.get("db");
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

  const [deleted] = await db
    .delete(objectGrants)
    .where(
      and(
        eq(objectGrants.objectId, checked.access.object.id),
        eq(objectGrants.principalType, "user"),
        eq(objectGrants.principalId, userId)
      )
    )
    .returning({ id: objectGrants.id });

  if (!deleted) {
    return c.json({ error: "Permission not found" }, 404);
  }

  return c.json({ message: "Permission revoked" });
});

// ═══ Grants to anyone: a user, a role, a project or the whole organization ═══
//
// The routes above share with one user at a time and keep their old shape for
// the platform and runtime. These cover every kind of recipient, by grant id:
//   user     that person
//   role     everyone holding that role (built-in or this org's custom role)
//   project  every member of that project
//   org      everyone in the organization

const PRINCIPAL_TYPES = ["user", "role", "project", "org"] as const;
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
  if (type === "project") {
    const [p] = await db.select({ id: projects.id }).from(projects).where(and(eq(projects.id, id), eq(projects.orgId, orgId))).limit(1);
    return p ? null : "Not permitted for this project";
  }
  // A built-in role (no org) or one of this org's custom roles; never a platform role.
  const [r] = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.id, id), eq(roles.scope, "org"), or(isNull(roles.orgId), eq(roles.orgId, orgId))))
    .limit(1);
  return r ? null : "Not permitted for this role";
}

/**
 * GET /apps/:appId/grants
 * Everyone the app is shared with, of every kind, with a name for each.
 */
permissionsRouter.get("/:appId/grants", async (c) => {
  const db = c.get("db");
  const checked = await managedObject(c, c.req.param("appId"));
  if (!checked.ok) return checked.response;
  const { access } = checked;

  const grants = await db.select().from(objectGrants).where(eq(objectGrants.objectId, access.object.id));
  const idsOf = (t: PrincipalType) => grants.filter((g) => g.principalType === t).map((g) => g.principalId);
  const names = new Map<string, { name: string; email?: string }>();
  if (idsOf("user").length) {
    for (const u of await db.select({ id: users.id, name: users.name, email: users.email }).from(users).where(inArray(users.id, idsOf("user")))) names.set(u.id, { name: u.name, email: u.email });
  }
  if (idsOf("role").length) {
    for (const r of await db.select({ id: roles.id, name: roles.name }).from(roles).where(inArray(roles.id, idsOf("role")))) names.set(r.id, { name: r.name });
  }
  if (idsOf("project").length) {
    for (const p of await db.select({ id: projects.id, name: projects.name }).from(projects).where(inArray(projects.id, idsOf("project")))) names.set(p.id, { name: p.name });
  }
  if (idsOf("org").length) {
    for (const o of await db.select({ id: organizations.id, name: organizations.name }).from(organizations).where(inArray(organizations.id, idsOf("org")))) names.set(o.id, { name: o.name });
  }

  return c.json({
    ownerId: access.object.ownerId,
    createdBy: access.object.createdBy,
    status: access.object.status,
    grants: grants.map((g) => ({
      id: g.id,
      principalType: g.principalType,
      principalId: g.principalId,
      principalName: names.get(g.principalId)?.name ?? null,
      principalEmail: names.get(g.principalId)?.email ?? null,
      level: g.level,
      grantedBy: g.grantedBy,
      createdAt: g.createdAt,
    })),
  });
});

/**
 * POST /apps/:appId/grants — { principalType, principalId, level }
 * Share the app with a user, a role, a project or the whole organization (needs manage).
 */
permissionsRouter.post("/:appId/grants", async (c) => {
  const db = c.get("db");
  const checked = await managedObject(c, c.req.param("appId"));
  if (!checked.ok) return checked.response;
  const { access } = checked;

  const body = await c.req.json<{ principalType?: unknown; principalId?: unknown; level?: unknown }>().catch(() => ({}) as any);
  const principalType = body.principalType as PrincipalType;
  const principalId = typeof body.principalId === "string" ? body.principalId : "";
  const level = parseGrantLevel(body.level);
  if (!(PRINCIPAL_TYPES as readonly string[]).includes(principalType)) {
    return c.json({ error: "principalType must be user, role, project or org" }, 400);
  }
  if (!UUID_RE.test(principalId)) return c.json({ error: "principalId must be a valid UUID" }, 400);
  if (!level) return c.json({ error: "level must be view, comment, edit or manage" }, 400);

  const denied = await denyPrincipal(c, principalType, principalId, access.orgId, access.app.projectId);
  if (denied) return c.json({ error: denied }, 403);

  const [grant] = await db
    .insert(objectGrants)
    .values({ objectId: access.object.id, principalType, principalId, level, grantedBy: c.get("userId") })
    .onConflictDoNothing()
    .returning();
  if (!grant) return c.json({ error: "Already shared with them. Change the level instead." }, 409);
  return c.json(grant, 201);
});

/**
 * PUT /apps/:appId/grants/:grantId — { level }
 * Change a grant's level (needs manage).
 */
permissionsRouter.put("/:appId/grants/:grantId", async (c) => {
  const db = c.get("db");
  const checked = await managedObject(c, c.req.param("appId"));
  if (!checked.ok) return checked.response;

  const body = await c.req.json<{ level?: unknown }>().catch(() => ({}) as any);
  const level = parseGrantLevel(body.level);
  if (!level) return c.json({ error: "level must be view, comment, edit or manage" }, 400);
  const grantId = c.req.param("grantId");
  if (!UUID_RE.test(grantId)) return c.json({ error: "Grant not found" }, 404);

  const [updated] = await db
    .update(objectGrants)
    .set({ level })
    .where(and(eq(objectGrants.id, grantId), eq(objectGrants.objectId, checked.access.object.id)))
    .returning();
  if (!updated) return c.json({ error: "Grant not found" }, 404);
  return c.json(updated);
});

/**
 * DELETE /apps/:appId/grants/:grantId
 * Stop sharing with that recipient (needs manage).
 */
permissionsRouter.delete("/:appId/grants/:grantId", async (c) => {
  const db = c.get("db");
  const checked = await managedObject(c, c.req.param("appId"));
  if (!checked.ok) return checked.response;
  const grantId = c.req.param("grantId");
  if (!UUID_RE.test(grantId)) return c.json({ error: "Grant not found" }, 404);

  const [deleted] = await db
    .delete(objectGrants)
    .where(and(eq(objectGrants.id, grantId), eq(objectGrants.objectId, checked.access.object.id)))
    .returning({ id: objectGrants.id });
  if (!deleted) return c.json({ error: "Grant not found" }, 404);
  return c.json({ message: "No longer shared" });
});

export default permissionsRouter;
