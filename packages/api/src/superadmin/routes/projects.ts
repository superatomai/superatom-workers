import { Hono } from "hono";
import { and, asc, eq, sql } from "drizzle-orm";
import { apiKeys, organizations, projects } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { DEFAULT_DESIGN_SYSTEM } from "../../routes/projects";
// Same generator/hash the websocket worker validates against — one key format.
import { generateApiKey, getKeyPrefix, hashApiKey } from "../../../../websocket/src/api-keys/service";
import { cleanName, isUniqueViolation, isUuid, projectSlugError } from "../lib/validate";

type Vars = SuperAdminVariables & { org: { id: string; slug: string } };

/** Projects of one org and their API keys. Mounted at /api/orgs/:orgId/projects. */
const orgProjects = new Hono<{ Bindings: Env; Variables: Vars }>();

orgProjects.use("*", async (c, next) => {
  const orgId = c.req.param("orgId");
  if (!isUuid(orgId)) return c.json({ error: "Organization not found" }, 404);
  const [org] = await c.var.db
    .select({ id: organizations.id, slug: organizations.slug })
    .from(organizations)
    .where(eq(organizations.id, orgId))
    .limit(1);
  if (!org) return c.json({ error: "Organization not found" }, 404);
  c.set("org", org);
  return next();
});

// api_keys.project_id is varchar; projects.id is uuid.
const activeKeyJoin = and(eq(apiKeys.projectId, sql`${projects.id}::text`), eq(apiKeys.isActive, true));

const projectColumns = {
  id: projects.id,
  name: projects.name,
  slug: projects.slug,
  description: projects.description,
  createdAt: projects.createdAt,
  apiKey: {
    prefix: apiKeys.keyPrefix,
    createdAt: apiKeys.createdAt,
    lastUsedAt: apiKeys.lastUsedAt,
  },
};

async function findProject(c: { var: Vars }, projectId: string | undefined) {
  if (!isUuid(projectId)) return null;
  const [project] = await c.var.db
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, c.var.org.id)))
    .limit(1);
  return project ?? null;
}

/** GET /api/orgs/:orgId/projects — with each project's active key (prefix only). */
orgProjects.get("/", async (c) => {
  const rows = await c.var.db
    .select(projectColumns)
    .from(projects)
    .leftJoin(apiKeys, activeKeyJoin)
    .where(eq(projects.orgId, c.var.org.id))
    .orderBy(asc(projects.createdAt));
  return c.json({ projects: rows });
});

/** POST /api/orgs/:orgId/projects — { name, slug, description? } */
orgProjects.post("/", async (c) => {
  const body = await c.req.json<{ name?: unknown; slug?: unknown; description?: unknown }>().catch(() => null);
  const name = cleanName(body?.name);
  if (!name) return c.json({ error: "Project name is required (max 255 characters)." }, 400);
  const slug = typeof body?.slug === "string" ? body.slug.trim() : "";
  const slugError = projectSlugError(slug);
  if (slugError) return c.json({ error: slugError }, 400);
  let description: string | null = null;
  if (body?.description !== undefined && body.description !== null && body.description !== "") {
    description = cleanName(body.description, 1000);
    if (!description) return c.json({ error: "Description must be at most 1000 characters." }, 400);
  }

  const taken = `The slug "${slug}" is already used by another project in this organization.`;
  const db = c.var.db;
  const [existing] = await db
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.orgId, c.var.org.id), eq(projects.slug, slug)))
    .limit(1);
  if (existing) return c.json({ error: taken }, 409);

  try {
    const [project] = await db
      .insert(projects)
      .values({ orgId: c.var.org.id, name, slug, description, designSystem: DEFAULT_DESIGN_SYSTEM })
      .returning({
        id: projects.id,
        name: projects.name,
        slug: projects.slug,
        description: projects.description,
        createdAt: projects.createdAt,
      });
    return c.json({ project: { ...project, apiKey: null } }, 201);
  } catch (err) {
    if (isUniqueViolation(err)) return c.json({ error: taken }, 409);
    throw err;
  }
});

/**
 * POST /api/orgs/:orgId/projects/:projectId/api-key — { rotate?: boolean }
 * Returns the key ONCE (only its hash is stored). Rotation revokes the old key and
 * inserts the new one in one transaction; without `rotate`, an existing key is a 409.
 */
orgProjects.post("/:projectId/api-key", async (c) => {
  const project = await findProject(c, c.req.param("projectId"));
  if (!project) return c.json({ error: "Project not found" }, 404);
  const body = await c.req.json<{ rotate?: unknown }>().catch(() => null);
  const rotate = body?.rotate === true;

  const db = c.var.db;
  const [active] = await db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.projectId, project.id), eq(apiKeys.isActive, true)))
    .limit(1);
  if (active && !rotate) {
    return c.json({ error: "This project already has an active API key. Rotate it to issue a new one.", code: "KEY_EXISTS" }, 409);
  }

  const apiKey = generateApiKey();
  const insert = db
    .insert(apiKeys)
    .values({
      projectId: project.id,
      orgId: c.var.org.id,
      keyHash: await hashApiKey(apiKey),
      keyPrefix: getKeyPrefix(apiKey),
      createdBy: c.var.admin.email,
    })
    .returning({ prefix: apiKeys.keyPrefix, createdAt: apiKeys.createdAt });
  const revokeActive = db
    .update(apiKeys)
    .set({ isActive: false })
    .where(and(eq(apiKeys.projectId, project.id), eq(apiKeys.isActive, true)));

  try {
    const [created] = active ? (await db.batch([revokeActive, insert]))[1] : await insert;
    return c.json(
      {
        apiKey,
        prefix: created.prefix,
        createdAt: created.createdAt,
        setup: {
          SUPERATOM_PROJECT_ID: project.id,
          SUPERATOM_API_KEY: apiKey,
          SA_ORG_ID: c.var.org.id,
          SA_ORG_SLUG: c.var.org.slug,
        },
      },
      201
    );
  } catch (err) {
    // Another request created a key between our check and insert.
    if (isUniqueViolation(err)) {
      return c.json({ error: "This project already has an active API key. Rotate it to issue a new one.", code: "KEY_EXISTS" }, 409);
    }
    throw err;
  }
});

/** DELETE /api/orgs/:orgId/projects/:projectId/api-key — revoke the active key. */
orgProjects.delete("/:projectId/api-key", async (c) => {
  const project = await findProject(c, c.req.param("projectId"));
  if (!project) return c.json({ error: "Project not found" }, 404);
  const revoked = await c.var.db
    .update(apiKeys)
    .set({ isActive: false })
    .where(and(eq(apiKeys.projectId, project.id), eq(apiKeys.isActive, true)))
    .returning({ id: apiKeys.id });
  if (revoked.length === 0) return c.json({ error: "This project has no active API key." }, 404);
  return c.json({ ok: true });
});

export default orgProjects;
