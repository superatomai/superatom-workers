import { Hono } from "hono";
import { eq, and } from "drizzle-orm";
import { apps, objects, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, hasPermission } from "../middleware/auth";
import {
  APP_OBJECT_TYPES,
  CREATE_PERMISSION,
  accessibleApps,
  appAccess,
  atLeast,
  callerOf,
  ensureAppObjects,
  legacyPermission,
  type AppAccess,
} from "../lib/objects";
import { projectAllowed, scopeOfRequest, scopeOfUser } from "../lib/project-scope";

const appsRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * These routes are mounted at "/" rather than under /orgs/:orgId, so there is no
 * org in the path for orgScopeGuard to check. Tenant isolation therefore has to
 * be enforced per request by resolving the project or app back to an
 * organization — without it, any authenticated user could read, and any admin
 * could modify or delete, apps belonging to any other tenant.
 *
 * What a caller may do with one app is their level on it (lib/objects.ts):
 * view to read it, edit to change its content, manage to change who sees it,
 * disable or delete it, owner to hand it over. Org Owners and Admins hold every
 * level on every app in their organization.
 */
const DENIED_PROJECT = "Not permitted for this project";
const DENIED_APP = "Not permitted for this app";

async function denyProjectAccess(c: any, projectId: string): Promise<string | null> {
  const role = c.get("userRole");
  const callerOrgId = c.get("orgId");

  if (role === "super_admin") return null;
  if (!callerOrgId) return DENIED_PROJECT;

  const db = c.get("db");
  const [row] = await db
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);

  if (!row || row.orgId !== callerOrgId) return DENIED_PROJECT;
  // Project scope (lib/project-scope.ts): a project outside it is closed to them.
  const scope = await scopeOfRequest(c);
  if (scope && !(await projectAllowed(db, scope, projectId))) return DENIED_PROJECT;
  return null;
}

/**
 * A change from an SDK session. Someone signed in through a customer's app may
 * read what their level allows, but not change apps: the customer's backend
 * chooses which user its token names (same rule as adminOnly).
 */
function isSdkWrite(c: any): boolean {
  return c.get("tokenSource") === "sdk" && c.req.method !== "GET" && c.req.method !== "HEAD";
}

/** An app as returned: the app, plus who owns it, its status and the caller's level. */
function shape(a: AppAccess) {
  return {
    ...a.app,
    projectName: a.projectName,
    ownerId: a.object.ownerId,
    createdBy: a.object.createdBy ?? a.app.createdBy,
    status: a.object.status,
    level: a.level,
    // The old name for the level, read by the platform and runtime until they move to `level`.
    permission: legacyPermission(a.level),
  };
}

/**
 * The app and the caller's level, or the response to send instead: 404 when
 * there is no such app, 403 when the caller's level is below `needed` (another
 * organization's app reads as 403 too).
 */
async function requireLevel(
  c: any,
  appId: string,
  needed: Parameters<typeof atLeast>[1]
): Promise<{ ok: false; response: Response } | { ok: true; access: AppAccess }> {
  const access = await appAccess(c.get("db"), callerOf(c), appId);
  if (!access) return { ok: false, response: c.json({ error: "App not found" }, 404) };
  if (!atLeast(access.level, needed)) return { ok: false, response: c.json({ error: DENIED_APP }, 403) };
  if (isSdkWrite(c)) return { ok: false, response: c.json({ error: "Not available to SDK sessions" }, 403) };
  return { ok: true, access };
}

/**
 * POST /projects/:projectId/apps
 * Create app in project. Needs the permission for that type of app (for
 * example dashboards.create); the creator becomes the owner.
 */
appsRouter.post("/projects/:projectId/apps", authMiddleware, async (c) => {
  const db = c.get("db");
  const projectId = c.req.param("projectId");
  const userId = c.get("userId");
  const { name, type, description, config, icon, isDefault } = await c.req.json<{
    name: string;
    type: "dashboard" | "app" | "report" | "chat_agent";
    description?: string;
    config?: Record<string, unknown>;
    icon?: string;
    isDefault?: boolean;
  }>();

  if (!name || !type) {
    return c.json({ error: "name and type are required" }, 400);
  }
  if (!(APP_OBJECT_TYPES as readonly string[]).includes(type)) {
    return c.json({ error: "Invalid type" }, 400);
  }
  if (!hasPermission(c, CREATE_PERMISSION[type])) {
    return c.json({ error: `Forbidden: requires ${CREATE_PERMISSION[type]}` }, 403);
  }
  if (isSdkWrite(c)) {
    return c.json({ error: "Not available to SDK sessions" }, 403);
  }

  const denied = await denyProjectAccess(c, projectId);
  if (denied) return c.json({ error: denied }, 403);

  const [project] = await db.select({ orgId: projects.orgId }).from(projects).where(eq(projects.id, projectId)).limit(1);
  if (!project) return c.json({ error: "Project not found" }, 404);

  const [app] = await db
    .insert(apps)
    .values({ projectId, name, type, description, config, icon, isDefault, createdBy: userId })
    .returning();

  const object = (await ensureAppObjects(db, [{ app, orgId: project.orgId }])).get(app.id)!;
  return c.json({ ...app, ownerId: object.ownerId, status: object.status, level: "owner", permission: "admin" }, 201);
});

/**
 * GET /projects/:projectId/apps
 * The project's apps the caller may at least view, with their level.
 */
appsRouter.get("/projects/:projectId/apps", authMiddleware, async (c) => {
  const db = c.get("db");
  const projectId = c.req.param("projectId");

  const denied = await denyProjectAccess(c, projectId);
  if (denied) return c.json({ error: denied }, 403);

  const list = await accessibleApps(db, callerOf(c), projectId);
  return c.json(list.map(shape));
});

/**
 * GET /apps/:appId
 * Get app details (needs view).
 */
appsRouter.get("/apps/:appId", authMiddleware, async (c) => {
  const checked = await requireLevel(c, c.req.param("appId"), "view");
  if (!checked.ok) return checked.response;
  return c.json(shape(checked.access));
});

/**
 * PUT /apps/:appId
 * Update app. Its content (name, description, icon, config) needs edit; who
 * sees it and whether it exists (isDefault, isActive, type) needs manage.
 */
appsRouter.put("/apps/:appId", authMiddleware, async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");
  const body = await c.req.json<{
    name?: string;
    type?: "dashboard" | "app" | "report" | "chat_agent";
    description?: string;
    config?: Record<string, unknown>;
    icon?: string | null;
    isActive?: boolean;
    isDefault?: boolean;
  }>();

  const needsManage = body.type !== undefined || body.isActive !== undefined || body.isDefault !== undefined;
  const checked = await requireLevel(c, appId, needsManage ? "manage" : "edit");
  if (!checked.ok) return checked.response;

  // Explicit allowlist. Spreading the body allowed setting any column —
  // including `projectId`, which would move an app into another tenant's project.
  const updates: {
    name?: string;
    type?: "dashboard" | "app" | "report" | "chat_agent";
    description?: string;
    config?: Record<string, unknown>;
    icon?: string | null;
    isActive?: boolean;
    isDefault?: boolean;
    updatedAt: Date;
  } = { updatedAt: new Date() };

  if (body.name !== undefined) {
    if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 255) {
      return c.json({ error: "Invalid name" }, 400);
    }
    updates.name = body.name;
  }
  if (body.type !== undefined) {
    if (!["dashboard", "app", "report", "chat_agent"].includes(body.type)) {
      return c.json({ error: "Invalid type" }, 400);
    }
    updates.type = body.type;
  }
  if (body.description !== undefined) {
    if (typeof body.description !== "string") {
      return c.json({ error: "Invalid description" }, 400);
    }
    updates.description = body.description;
  }
  if (body.icon !== undefined) {
    // null is a legitimate value here — it means "clear the icon", not "unset the field".
    if (body.icon !== null && typeof body.icon !== "string") {
      return c.json({ error: "Invalid icon" }, 400);
    }
    updates.icon = body.icon;
  }
  if (body.isActive !== undefined) {
    if (typeof body.isActive !== "boolean") {
      return c.json({ error: "Invalid isActive" }, 400);
    }
    updates.isActive = body.isActive;
  }
  if (body.isDefault !== undefined) {
    if (typeof body.isDefault !== "boolean") {
      return c.json({ error: "Invalid isDefault" }, 400);
    }
    updates.isDefault = body.isDefault;
  }
  if (body.config !== undefined) updates.config = body.config;

  const [updated] = await db
    .update(apps)
    .set(updates)
    .where(eq(apps.id, appId))
    .returning();

  if (!updated) {
    return c.json({ error: "App not found" }, 404);
  }
  // The object's type follows the app's, so a changed type keeps its owner and grants.
  if (updates.type && updates.type !== checked.access.object.type) {
    await db.update(objects).set({ type: updates.type, updatedAt: new Date() }).where(eq(objects.id, checked.access.object.id));
  }

  return c.json(shape({ ...checked.access, app: updated }));
});

/**
 * PUT /apps/:appId/owner — { userId }
 * Hand the app over to another active member of the same organization (needs
 * owner). The creator stays recorded as created_by.
 */
appsRouter.put("/apps/:appId/owner", authMiddleware, async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");
  const body = await c.req.json<{ userId?: unknown }>().catch(() => ({}) as { userId?: unknown });

  const checked = await requireLevel(c, appId, "owner");
  if (!checked.ok) return checked.response;

  const userId = typeof body.userId === "string" ? body.userId : "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
    return c.json({ error: "userId must be a valid UUID" }, 400);
  }
  const [target] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.id, userId), eq(users.orgId, checked.access.orgId), eq(users.isActive, true)))
    .limit(1);
  if (!target) return c.json({ error: "The new owner must be an active member of this organization" }, 400);
  // They must be able to reach the app's project, or they would own something they cannot see.
  const targetScope = await scopeOfUser(db, userId);
  if (!targetScope || !(await projectAllowed(db, targetScope, checked.access.app.projectId))) {
    return c.json({ error: "The new owner cannot reach this app's project. Add them to the project first." }, 400);
  }

  const [object] = await db
    .update(objects)
    .set({ ownerId: userId, updatedAt: new Date() })
    .where(eq(objects.id, checked.access.object.id))
    .returning();
  console.log(`[audit] app owner change: actor=${c.get("userId")} app=${appId} from=${checked.access.object.ownerId} to=${userId}`);
  return c.json(shape({ ...checked.access, object }));
});

/**
 * PUT /apps/:appId/status — { status: "active" | "disabled" }
 * Disable an app (for example a chat agent) without deleting it, or enable it
 * again (needs manage). A disabled app stays visible only to those who manage it.
 */
appsRouter.put("/apps/:appId/status", authMiddleware, async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");
  const body = await c.req.json<{ status?: unknown }>().catch(() => ({}) as { status?: unknown });
  if (body.status !== "active" && body.status !== "disabled") {
    return c.json({ error: "status must be active or disabled" }, 400);
  }

  const checked = await requireLevel(c, appId, "manage");
  if (!checked.ok) return checked.response;

  const [object] = await db
    .update(objects)
    .set({ status: body.status, updatedAt: new Date() })
    .where(eq(objects.id, checked.access.object.id))
    .returning();
  return c.json(shape({ ...checked.access, object }));
});

/**
 * DELETE /apps/:appId
 * Delete app (needs manage). Its object and every grant on it go with it.
 */
appsRouter.delete("/apps/:appId", authMiddleware, async (c) => {
  const db = c.get("db");
  const appId = c.req.param("appId");

  const checked = await requireLevel(c, appId, "manage");
  if (!checked.ok) return checked.response;

  const [deleted] = await db
    .delete(apps)
    .where(eq(apps.id, appId))
    .returning({ id: apps.id });

  if (!deleted) {
    return c.json({ error: "App not found" }, 404);
  }
  // Not a foreign key (objects can point at engine rows), so removed here; grants cascade.
  await db.delete(objects).where(eq(objects.id, checked.access.object.id));

  return c.json({ message: "App deleted" });
});

export default appsRouter;
