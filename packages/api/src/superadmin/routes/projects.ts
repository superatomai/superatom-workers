import { Hono } from "hono";
import { and, asc, desc, eq, sql } from "drizzle-orm";
import { apiKeys, organizations, projects } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { DEFAULT_DESIGN_SYSTEM } from "../../routes/projects";
// Same generator/hash the websocket worker validates against — one key format.
import { generateApiKey, getKeyPrefix, hashApiKey } from "../../../../websocket/src/api-keys/service";
import { assignBaseline, readBaseline } from "../../lib/baseline";
import { cleanName, codeBranchError, isUniqueViolation, isUuid, projectSlugError } from "../lib/validate";
import { branchExists } from "../../install/lib";
import { projectReleases } from "../../db/schema";

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
  codeBranch: projects.codeBranch,
  pinnedVersion: projects.pinnedVersion,
  createdAt: projects.createdAt,
  apiKey: {
    prefix: apiKeys.keyPrefix,
    createdAt: apiKeys.createdAt,
    lastUsedAt: apiKeys.lastUsedAt,
  },
};

/**
 * A branch that is not on the remote yet is allowed — it may be created later —
 * but say so, because publishing from it would fail until then.
 */
async function branchWarning(env: Env, branch: string): Promise<string | undefined> {
  return (await branchExists(env, branch)) === false
    ? `Branch "${branch}" is not on the remote yet. Push it before publishing a release for this project.`
    : undefined;
}

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
/**
 * POST /:projectId/baseline — point an existing project at the current baseline, so
 * it moves from building source to pulling the platform image. Deliberate rather
 * than automatic: it changes what that client's next update installs.
 */
orgProjects.post("/:projectId/baseline", async (c) => {
  const projectId = c.req.param("projectId");
  if (!isUuid(projectId)) return c.json({ error: "Unknown project." }, 404);
  const db = c.var.db;
  const [project] = await db
    .select({ id: projects.id })
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, c.var.org.id)))
    .limit(1);
  if (!project) return c.json({ error: "Unknown project." }, 404);

  const baseline = await readBaseline(c.env);
  if (!baseline) {
    return c.json(
      { error: "No baseline is published yet. Run `pnpm publish-release --baseline` first." },
      409
    );
  }
  const version = await assignBaseline(db, c.env, projectId);
  return c.json({ version, commit: baseline.commit.slice(0, 12), branch: baseline.branch });
});

orgProjects.post("/", async (c) => {
  const body = await c.req
    .json<{ name?: unknown; slug?: unknown; description?: unknown; codeBranch?: unknown }>()
    .catch(() => null);
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

  let codeBranch: string | undefined;
  if (body?.codeBranch !== undefined && body.codeBranch !== null && body.codeBranch !== "") {
    const branchError = codeBranchError(body.codeBranch);
    if (branchError) return c.json({ error: branchError }, 400);
    codeBranch = body.codeBranch as string;
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
      .values({ orgId: c.var.org.id, name, slug, description, designSystem: DEFAULT_DESIGN_SYSTEM,
                ...(codeBranch ? { codeBranch } : {}) })
      .returning({
        id: projects.id,
        name: projects.name,
        slug: projects.slug,
        description: projects.description,
        codeBranch: projects.codeBranch,
        createdAt: projects.createdAt,
      });
    // So `curl … | sh` works for this project straight away, with no per-client
    // build. Best-effort: with no baseline published the install still works from
    // the source tarball.
    const baselineVersion = await assignBaseline(db, c.env, project.id).catch((err) => {
      console.error("[projects] baseline assignment failed:", err);
      return null;
    });
    const warning = codeBranch ? await branchWarning(c.env, codeBranch) : undefined;
    return c.json({ project: { ...project, apiKey: null }, warning, baselineVersion }, 201);
  } catch (err) {
    if (isUniqueViolation(err)) return c.json({ error: taken }, 409);
    throw err;
  }
});

/**
 * PATCH /api/orgs/:orgId/projects/:projectId — { codeBranch?, pinnedVersion? }
 * `codeBranch` is what the publish script builds. `pinnedVersion` rolls this
 * project back to a published release; null follows the newest again. Neither
 * touches a running VM — they apply on its next install or update.
 */
orgProjects.patch("/:projectId", async (c) => {
  const project = await findProject(c, c.req.param("projectId"));
  if (!project) return c.json({ error: "Project not found" }, 404);

  const body = await c.req.json<{ codeBranch?: unknown; pinnedVersion?: unknown }>().catch(() => null);
  const patch: { codeBranch?: string; pinnedVersion?: string | null; updatedAt: Date } = { updatedAt: new Date() };

  if (body?.codeBranch !== undefined) {
    const branchError = codeBranchError(body.codeBranch);
    if (branchError) return c.json({ error: branchError }, 400);
    patch.codeBranch = body.codeBranch as string;
  }
  if (body?.pinnedVersion !== undefined) {
    if (body.pinnedVersion === null || body.pinnedVersion === "") {
      patch.pinnedVersion = null;
    } else {
      const version = cleanName(body.pinnedVersion);
      if (!version) return c.json({ error: "Pinned version must be a non-empty string." }, 400);
      const [release] = await c.var.db
        .select({ id: projectReleases.id })
        .from(projectReleases)
        .where(and(eq(projectReleases.projectId, project.id), eq(projectReleases.version, version)))
        .limit(1);
      // Pinning to something unpublished would break that project's next install.
      if (!release) return c.json({ error: `Version "${version}" is not published for this project.` }, 404);
      patch.pinnedVersion = version;
    }
  }
  if (patch.codeBranch === undefined && patch.pinnedVersion === undefined) {
    return c.json({ error: "Nothing to update." }, 400);
  }

  const [updated] = await c.var.db
    .update(projects)
    .set(patch)
    .where(eq(projects.id, project.id))
    .returning({ id: projects.id, name: projects.name, slug: projects.slug,
                 codeBranch: projects.codeBranch, pinnedVersion: projects.pinnedVersion });
  console.log(`[superadmin] project updated: ${project.id} ${JSON.stringify(patch)} by=${c.var.admin.email}`);
  return c.json({
    project: updated,
    warning: patch.codeBranch ? await branchWarning(c.env, patch.codeBranch) : undefined,
  });
});

/** GET /api/orgs/:orgId/projects/:projectId/releases — newest first, for the pin picker. */
orgProjects.get("/:projectId/releases", async (c) => {
  const project = await findProject(c, c.req.param("projectId"));
  if (!project) return c.json({ error: "Project not found" }, 404);
  const releases = await c.var.db
    .select({
      version: projectReleases.version,
      branch: projectReleases.branch,
      commit: projectReleases.commit,
      imageDigest: projectReleases.imageDigest,
      migrations: projectReleases.migrations,
      publishedBy: projectReleases.publishedBy,
      publishedAt: projectReleases.publishedAt,
    })
    .from(projectReleases)
    .where(eq(projectReleases.projectId, project.id))
    .orderBy(desc(projectReleases.publishedAt))
    .limit(50);
  return c.json({ releases });
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
