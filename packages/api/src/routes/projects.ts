import { Hono } from "hono";
import { eq, and } from "drizzle-orm";
import { projects, apps } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, orgScopeGuard } from "../middleware/auth";

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
// Write routes: admin only
projectsRouter.post("*", authMiddleware, adminOnly, orgScopeGuard);
projectsRouter.put("*", authMiddleware, adminOnly, orgScopeGuard);
projectsRouter.delete("*", authMiddleware, adminOnly, orgScopeGuard);

/**
 * POST /orgs/:orgId/projects
 * Create project
 */
projectsRouter.post("/", async (c) => {
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

  return c.json(project, 201);
});

/**
 * GET /orgs/:orgId/projects
 * List all projects in org
 */
projectsRouter.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;

  const orgProjects = await db
    .select()
    .from(projects)
    .where(eq(projects.orgId, orgId));

  return c.json(orgProjects);
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

  return c.json(updated);
});

/**
 * DELETE /orgs/:orgId/projects/:projectId
 * Delete project (cascades to apps + permissions via FK)
 */
projectsRouter.delete("/:projectId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const projectId = c.req.param("projectId");

  // Org-scoped: this cascades to apps and permissions, so an unscoped delete let
  // an admin destroy another tenant's project outright.
  const [deleted] = await db
    .delete(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .returning({ id: projects.id });

  if (!deleted) {
    return c.json({ error: "Project not found" }, 404);
  }

  return c.json({ message: "Project deleted" });
});

export default projectsRouter;
