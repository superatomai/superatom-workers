import { Hono, type Context } from "hono";
import { eq, and } from "drizzle-orm";
import { projects, apps, projectMembers, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, requirePermission, hasPermission, orgScopeGuard } from "../middleware/auth";
import { deleteProject, projectDeleteSteps } from "../lib/project-delete";
import { allowedProjects, scopeOfRequest } from "../lib/project-scope";
import { actorOf, logAccess } from "../lib/access-log";
import { callerOf, projectAccess, projectPowers, projectsAccess, projectsSharedWith, type ProjectAccess } from "../lib/objects";

export const DEFAULT_DESIGN_SYSTEM = {
  colors: {
    primary: "#009193",
    secondary: "#FFFFFF",
  },
};

const projectsRouter = new Hono<{
  Bindings: Env;
  Variables: AppVariables;
}>();

// Read routes: any authenticated user in the org (including members)
projectsRouter.get("*", authMiddleware, orgScopeGuard);
// Write routes: platform users; each route then needs its own permission
// (project.create, project.edit, project.delete, design.edit).
projectsRouter.post("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);
projectsRouter.put("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);
projectsRouter.delete("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);

type ProjectsContext = Context<{ Bindings: Env; Variables: AppVariables }>;

/**
 * Closes a project outside the caller's scope, or whose View a deny takes away.
 * Keeps the access it looked up on the request for the route.
 */
const scopeGuard = async (c: ProjectsContext, next: () => Promise<void>) => {
  const projectId = c.req.param("projectId");
  // A service token has no scope and reaches every project.
  if (projectId && (await scopeOfRequest(c))) {
    const access = await projectAccess(c.get("db"), callerOf(c), projectId);
    if (access && (!access.inScope || access.denied.includes("view"))) {
      return c.json({ error: "Not permitted for this project" }, 403);
    }
    c.set("projectAccess", access);
  }
  await next();
};
projectsRouter.use("/:projectId", scopeGuard);
projectsRouter.use("/:projectId/*", scopeGuard);

/** The caller's access to the project in the path: the guard's, or looked up now. */
const accessFor = async (c: ProjectsContext, projectId: string) =>
  c.get("projectAccess") ?? (await projectAccess(c.get("db"), callerOf(c), projectId));

/** Whether the caller may rename or delete the project (lib/objects.ts projectPowers). */
const powersOf = (c: ProjectsContext, access: ProjectAccess | null | undefined) =>
  projectPowers(access && { actions: access.actions, ownerId: access.object.ownerId }, callerOf(c));

/** A project with the caller's actions on it and their powers over it. */
const withPowers = (c: ProjectsContext, project: typeof projects.$inferSelect, access: ProjectAccess | null | undefined) => ({
  ...project,
  actions: access?.actions ?? [],
  ...powersOf(c, access),
});

/**
 * POST /orgs/:orgId/projects
 * Create project
 */
projectsRouter.post("/", requirePermission("project.create"), async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.get("userId");
  const { name, slug, description, icon, designSystem } = await c.req.json<{
    name: string;
    slug: string;
    description?: string;
    icon?: string;
    designSystem?: Record<string, unknown>;
  }>();

  if (!name || !slug) {
    return c.json({ error: "name and slug are required" }, 400);
  }

  // Check slug uniqueness within org
  const [existing] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.orgId, orgId), eq(projects.slug, slug)))
    .limit(1);

  if (existing) {
    return c.json(
      { error: "A project with this slug already exists in the organization" },
      409
    );
  }

  const [project] = await db
    .insert(projects)
    .values({ orgId, name, slug, description, icon, designSystem: designSystem || DEFAULT_DESIGN_SYSTEM, createdBy: userId })
    .returning();

  // The creator is in the project, so someone limited to some projects can
  // reach what they just made (lib/project-scope.ts).
  await db.insert(projectMembers).values({ projectId: project.id, userId, addedBy: userId }).onConflictDoNothing();

  // As the projects list returns it.
  return c.json(withPowers(c, project, await projectAccess(db, callerOf(c), project.id)), 201);
});

/**
 * GET /orgs/:orgId/projects
 * The org's projects within the caller's project scope (all of them for an
 * Owner, a super admin, or anyone whose scope is "all"), each with the
 * caller's `actions` on it, so the platform shows only the buttons they may use.
 * Access for every project is read in one round of queries (projectsAccess).
 */
projectsRouter.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;

  const orgProjects = await db
    .select()
    .from(projects)
    .where(eq(projects.orgId, orgId));

  const scope = await scopeOfRequest(c);
  const allowed = scope ? await allowedProjects(db, scope) : null;
  const inScope = allowed ? orgProjects.filter((p) => allowed.has(p.id)) : orgProjects;
  const caller = callerOf(c);
  // Only a signed-in person has actions: a service token (no scope) gets the projects without them.
  const access = scope ? await projectsAccess(db, caller, inScope.map((p) => p.id)) : null;
  // A deny on View hides the project outright, whatever else would show it.
  const visible = inScope
    .filter((p) => !access?.get(p.id)?.denied.includes("view"))
    .map((p) => (access ? withPowers(c, p, access.get(p.id)) : p));

  // Seeing every project in scope is project.view's (an Owner and Admins hold
  // it); anyone else sees the projects something is shared with them in.
  if (!scope || c.get("userRole") === "super_admin" || hasPermission(c, "project.view")) return c.json(visible);
  const shared = await projectsSharedWith(db, caller);
  return c.json(visible.filter((p) => shared.has(p.id)));
});

/**
 * GET /orgs/:orgId/projects/:projectId
 * Get project details + its apps
 */
projectsRouter.get("/:projectId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");

  // Scoped to the org in the path. orgScopeGuard proves that :orgId matches the
  // caller's token, but says nothing about which org the PROJECT belongs to — an
  // unscoped lookup by id reaches projects in any other tenant.
  const [project] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .limit(1);

  if (!project) {
    return c.json({ error: "Project not found" }, 404);
  }

  const projectApps = await db
    .select()
    .from(apps)
    .where(and(eq(apps.projectId, projectId), eq(apps.isActive, true)));

  return c.json({ ...project, apps: projectApps });
});

/**
 * PUT /orgs/:orgId/projects/:projectId
 * Update project
 */
projectsRouter.put("/:projectId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");
  const body = await c.req.json<{ name?: string; slug?: string; description?: string; icon?: string | null; designSystem?: Record<string, unknown>; config?: Record<string, unknown> }>();

  // The design system is design.edit's; the rest needs the right to rename it.
  const access = await accessFor(c, projectId);
  const editsProject = ["name", "slug", "description", "icon", "config"].some((k) => (body as any)[k] !== undefined);
  if (editsProject && !powersOf(c, access).canRename) {
    return c.json({ error: "Not permitted to change this project" }, 403);
  }
  if (body.designSystem !== undefined && !hasPermission(c, "design.edit")) {
    return c.json({ error: "Forbidden: requires design.edit" }, 403);
  }

  // Explicit allowlist. Spreading the body allowed setting any column — notably
  // `orgId`, which would move a project into another tenant.
  const updates: {
    name?: string;
    slug?: string;
    description?: string;
    icon?: string | null;
    designSystem?: Record<string, unknown>;
    config?: Record<string, unknown>;
    updatedAt: Date;
  } = { updatedAt: new Date() };

  if (body.name !== undefined) {
    if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 255) {
      return c.json({ error: "Invalid name" }, 400);
    }
    updates.name = body.name;
  }
  if (body.slug !== undefined) {
    if (typeof body.slug !== "string" || !body.slug.trim() || body.slug.length > 100) {
      return c.json({ error: "Invalid slug" }, 400);
    }
    updates.slug = body.slug;
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
  if (body.designSystem !== undefined) updates.designSystem = body.designSystem;
  if (body.config !== undefined) updates.config = body.config;

  const [updated] = await db
    .update(projects)
    .set(updates)
    // Org-scoped: otherwise an admin can edit projects in any other tenant.
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .returning();

  if (!updated) {
    return c.json({ error: "Project not found" }, 404);
  }

  // Renaming changes nobody's access, so `access` still holds.
  return c.json(withPowers(c, updated, access));
});

/**
 * DELETE /orgs/:orgId/projects/:projectId
 * Delete project (cascades to apps + permissions via FK); revokes its API keys and LLM proxy clients.
 * For project.delete or the project's owner (projectPowers).
 */
projectsRouter.delete("/:projectId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");
  if (!powersOf(c, await accessFor(c, projectId)).canDelete) {
    return c.json({ error: "Not permitted to delete this project" }, 403);
  }

  // Org-scoped: an unscoped delete let an admin destroy another tenant's project.
  const result = await deleteProject(projectDeleteSteps(db, c.env, orgId, projectId));
  if (result.status === "not_found") {
    return c.json({ error: "Project not found" }, 404);
  }
  if (result.status === "proxy_failed") {
    return c.json({ error: `Could not disable LLM proxy client '${result.clientId}'; the project was not deleted. Retry.` }, 502);
  }

  return c.json({ message: "Project deleted" });
});

// ═══ Members ═══════════════════════════════════════════
//
// Who belongs to a project. A grant to the project (sharing an app with "this
// project") reaches exactly these people. Who may open the project in the
// platform is not decided here.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The project, when it belongs to the org in the path. */
async function projectOfOrg(c: any, orgId: string, projectId: string) {
  if (!UUID_RE.test(projectId)) return undefined;
  const [row] = await c
    .get("db")
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .limit(1);
  return row as { id: string } | undefined;
}

/**
 * GET /orgs/:orgId/projects/:projectId/members
 * The project's members, with names and emails.
 */
projectsRouter.get("/:projectId/members", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");
  if (!(await projectOfOrg(c, orgId, projectId))) return c.json({ error: "Project not found" }, 404);

  const rows = await db
    .select({ userId: users.id, name: users.name, email: users.email, isActive: users.isActive, addedAt: projectMembers.createdAt })
    .from(projectMembers)
    .innerJoin(users, eq(users.id, projectMembers.userId))
    .where(eq(projectMembers.projectId, projectId));
  return c.json(rows);
});

/**
 * POST /orgs/:orgId/projects/:projectId/members — { userId }
 * Add an active member of the organization to the project (project.edit).
 */
projectsRouter.post("/:projectId/members", requirePermission("project.edit"), async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");
  if (!(await projectOfOrg(c, orgId, projectId))) return c.json({ error: "Project not found" }, 404);

  const body = await c.req.json<{ userId?: unknown }>().catch(() => ({}) as { userId?: unknown });
  const userId = typeof body.userId === "string" ? body.userId : "";
  if (!UUID_RE.test(userId)) return c.json({ error: "userId must be a valid UUID" }, 400);
  const [user] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.id, userId), eq(users.orgId, orgId), eq(users.isActive, true)))
    .limit(1);
  if (!user) return c.json({ error: "Only an active member of this organization can be added" }, 400);

  const [added] = await db
    .insert(projectMembers)
    .values({ projectId, userId, addedBy: c.get("userId") })
    .onConflictDoNothing()
    .returning();
  if (!added) return c.json({ error: "Already a member of this project" }, 409);
  await logAccess(db, { orgId, actorId: actorOf(c), action: "project.member_added", target: { type: "project", id: projectId }, subjectId: userId });
  return c.json(added, 201);
});

/**
 * DELETE /orgs/:orgId/projects/:projectId/members/:userId
 * Remove someone from the project (project.edit). What was shared with the
 * project no longer reaches them.
 */
projectsRouter.delete("/:projectId/members/:userId", requirePermission("project.edit"), async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");
  if (!(await projectOfOrg(c, orgId, projectId))) return c.json({ error: "Project not found" }, 404);

  const [removed] = await db
    .delete(projectMembers)
    .where(and(eq(projectMembers.projectId, projectId), eq(projectMembers.userId, c.req.param("userId"))))
    .returning();
  if (!removed) return c.json({ error: "Not a member of this project" }, 404);
  await logAccess(db, { orgId, actorId: actorOf(c), action: "project.member_removed", target: { type: "project", id: projectId }, subjectId: removed.userId });
  return c.json({ message: "Removed from the project" });
});

export default projectsRouter;
