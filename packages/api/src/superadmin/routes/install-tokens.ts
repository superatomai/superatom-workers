import { Hono } from "hono";
import { and, desc, eq, isNull } from "drizzle-orm";
import { apiKeys, installTokens, organizations, projects } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { sha256Hex } from "../../install/lib";
import { isUuid } from "../lib/validate";

type Vars = SuperAdminVariables & {
  project: { id: string; slug: string; orgId: string; orgSlug: string };
};

/** Install tokens of one project. Mounted at /api/orgs/:orgId/projects/:projectId/install-tokens. */
const installTokenRoutes = new Hono<{ Bindings: Env; Variables: Vars }>();

const INSTALL_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DEFAULT_EXPIRY_HOURS = 24;
const MAX_EXPIRY_HOURS = 7 * 24;

installTokenRoutes.use("*", async (c, next) => {
  const orgId = c.req.param("orgId");
  const projectId = c.req.param("projectId");
  if (!isUuid(orgId) || !isUuid(projectId)) return c.json({ error: "Project not found" }, 404);
  const [project] = await c.var.db
    .select({ id: projects.id, slug: projects.slug, orgId: organizations.id, orgSlug: organizations.slug })
    .from(projects)
    .innerJoin(organizations, eq(organizations.id, projects.orgId))
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .limit(1);
  if (!project) return c.json({ error: "Project not found" }, 404);
  c.set("project", project);
  return next();
});

function status(t: { redeemedAt: Date | null; revokedAt: Date | null; expiresAt: Date }) {
  if (t.redeemedAt) return "redeemed";
  if (t.revokedAt) return "revoked";
  return t.expiresAt.getTime() < Date.now() ? "expired" : "active";
}

function defaultInstallName(orgSlug: string, projectSlug: string): string {
  return `${orgSlug}-${projectSlug}`
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 63)
    .replace(/-$/, "");
}

/**
 * POST — { installName?, llmBudgetCents? (0 = unlimited), expiresInHours? }.
 * Returns the token ONCE; only its hash is stored.
 */
installTokenRoutes.post("/", async (c) => {
  const body = await c.req
    .json<{ installName?: unknown; llmBudgetCents?: unknown; expiresInHours?: unknown }>()
    .catch(() => ({}) as Record<string, unknown>);
  const project = c.var.project;

  const installName =
    typeof body.installName === "string" && body.installName.trim()
      ? body.installName.trim()
      : defaultInstallName(project.orgSlug, project.slug);
  if (!INSTALL_NAME.test(installName)) {
    return c.json({ error: "Install name must be 1–63 lowercase letters, digits or hyphens, not starting or ending with a hyphen." }, 400);
  }
  const budget = body.llmBudgetCents ?? 0;
  if (typeof budget !== "number" || !Number.isInteger(budget) || budget < 0) {
    return c.json({ error: "LLM budget must be a whole number of cents (0 = unlimited)." }, 400);
  }
  const hours = body.expiresInHours ?? DEFAULT_EXPIRY_HOURS;
  if (typeof hours !== "number" || !Number.isInteger(hours) || hours < 1 || hours > MAX_EXPIRY_HOURS) {
    return c.json({ error: `Expiry must be 1–${MAX_EXPIRY_HOURS} hours.` }, 400);
  }

  // Redeeming creates the project's API key, so a project that already has one can't be installed this way.
  const [active] = await c.var.db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.projectId, project.id), eq(apiKeys.isActive, true)))
    .limit(1);
  if (active) {
    return c.json({ error: "This project already has an active API key. Revoke it first to install with a token.", code: "KEY_EXISTS" }, 409);
  }

  const token = "sai_" + Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
  const [row] = await c.var.db
    .insert(installTokens)
    .values({
      tokenHash: await sha256Hex(token),
      projectId: project.id,
      orgId: project.orgId,
      installName,
      llmBudgetCents: budget,
      createdBy: c.var.admin.email,
      expiresAt: new Date(Date.now() + hours * 3600 * 1000),
    })
    .returning({ id: installTokens.id, expiresAt: installTokens.expiresAt });

  return c.json(
    {
      id: row.id,
      token,
      installName,
      llmBudgetCents: budget,
      expiresAt: row.expiresAt,
      command: `curl -fsSL https://${c.env.INSTALL_HOST} | sh`,
    },
    201
  );
});

/** GET — the project's install tokens (never the token itself). */
installTokenRoutes.get("/", async (c) => {
  const rows = await c.var.db
    .select({
      id: installTokens.id,
      installName: installTokens.installName,
      llmBudgetCents: installTokens.llmBudgetCents,
      createdBy: installTokens.createdBy,
      createdAt: installTokens.createdAt,
      expiresAt: installTokens.expiresAt,
      redeemedAt: installTokens.redeemedAt,
      redeemedIp: installTokens.redeemedIp,
      redeemedCommit: installTokens.redeemedCommit,
      revokedAt: installTokens.revokedAt,
    })
    .from(installTokens)
    .where(eq(installTokens.projectId, c.var.project.id))
    .orderBy(desc(installTokens.createdAt));
  return c.json({ tokens: rows.map((r) => ({ ...r, status: status(r) })) });
});

/** DELETE /:tokenId — revoke an unused token. */
installTokenRoutes.delete("/:tokenId", async (c) => {
  const tokenId = c.req.param("tokenId");
  if (!isUuid(tokenId)) return c.json({ error: "Install token not found" }, 404);
  const [revoked] = await c.var.db
    .update(installTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(installTokens.id, tokenId),
        eq(installTokens.projectId, c.var.project.id),
        isNull(installTokens.redeemedAt),
        isNull(installTokens.revokedAt)
      )
    )
    .returning({ id: installTokens.id });
  if (!revoked) return c.json({ error: "No unused install token with that id." }, 404);
  return c.json({ ok: true });
});

export default installTokenRoutes;
