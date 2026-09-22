import { Hono } from "hono";
import { and, eq, isNull } from "drizzle-orm";
import { createDb, type Database } from "../db";
import { apiKeys, installTokens, organizations, projects } from "../db/schema";
import type { Env } from "../types";
// Same generator/hash the websocket worker validates against — one key format.
import { generateApiKey, getKeyPrefix, hashApiKey } from "../../../websocket/src/api-keys/service";
import {
  InstallError,
  envLines,
  fetchTarball,
  installScript,
  issueProxyKey,
  latestCommit,
  sha256Hex,
  signDownload,
  verifyDownload,
} from "./lib";
import { isUniqueViolation } from "../superadmin/lib/validate";

/**
 * install.superatom.ai — what `curl -fsSL https://install.superatom.ai | sh` talks to.
 * Plain-text responses for install.sh; no CORS or cookies (only curl calls it).
 */
const install = new Hono<{ Bindings: Env; Variables: { db: Database } }>();

const TOKEN_FORMAT = /^sai_[0-9a-f]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

install.use("*", async (c, next) => {
  c.set("db", createDb(c.env.DATABASE_URL));
  await next();
  c.header("Cache-Control", "no-store");
});

async function limited(env: Env, key: string): Promise<boolean> {
  const { success } = await env.INSTALL_RATE_LIMITER.limit({ key });
  return !success;
}

function clientIp(c: { req: { header: (n: string) => string | undefined } }): string {
  return c.req.header("CF-Connecting-IP") ?? "unknown";
}

async function codeUrl(c: { req: { url: string }; env: Env }, sha: string, projectId: string): Promise<string> {
  return `${new URL(c.req.url).origin}/api/code/${await signDownload(c.env, sha, projectId)}`;
}

// install.sh's built-in default; replaced on serve so the script talks back to the host it came from.
const DEFAULT_BASE = "${SA_INSTALL_URL:-https://install.superatom.ai}";

/** GET / — the installer script itself, pointed at this host (dev vs prod). */
install.get("/", async (c) => {
  const script = await installScript(c.env);
  const origin = new URL(c.req.url).origin;
  if (!script.includes(DEFAULT_BASE)) {
    console.warn("[install] install.sh default URL line not found; serving it unchanged");
  }
  const body = script.replace(DEFAULT_BASE, "${SA_INSTALL_URL:-" + origin + "}");
  return c.body(body, 200, { "Content-Type": "text/plain; charset=utf-8" });
});

/**
 * Loads an install token and applies every precondition for redeeming it (valid, unused,
 * not revoked or expired, project has no API key). Throws InstallError otherwise.
 * Shared by token-info (read-only) and redeem, so both enforce exactly the same rules.
 */
async function usableToken(db: Database, rawToken: unknown) {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!TOKEN_FORMAT.test(token)) throw new InstallError(404, "Unknown install token");

  const [row] = await db
    .select({
      id: installTokens.id,
      installName: installTokens.installName,
      llmBudgetCents: installTokens.llmBudgetCents,
      createdBy: installTokens.createdBy,
      expiresAt: installTokens.expiresAt,
      redeemedAt: installTokens.redeemedAt,
      revokedAt: installTokens.revokedAt,
      projectId: projects.id,
      orgId: organizations.id,
      orgSlug: organizations.slug,
    })
    .from(installTokens)
    .innerJoin(projects, eq(projects.id, installTokens.projectId))
    .innerJoin(organizations, eq(organizations.id, projects.orgId))
    .where(eq(installTokens.tokenHash, await sha256Hex(token)))
    .limit(1);

  if (!row) throw new InstallError(404, "Unknown install token");
  if (row.revokedAt) throw new InstallError(410, "This install token was revoked");
  if (row.redeemedAt) throw new InstallError(410, "This install token was already used");
  if (row.expiresAt.getTime() < Date.now()) throw new InstallError(410, "This install token has expired");

  const [active] = await db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.projectId, row.projectId), eq(apiKeys.isActive, true)))
    .limit(1);
  if (active) {
    throw new InstallError(
      409,
      "This project already has an active API key. Revoke it in the super-admin console, then generate a new install token."
    );
  }
  return row;
}

/**
 * POST /api/token-info {token} — checks a token without using it, so the installer can
 * prepare the install folder before spending the one-time token.
 */
install.post("/api/token-info", async (c) => {
  if (await limited(c.env, `token-info:${clientIp(c)}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);
  const body = await c.req.json<{ token?: unknown }>().catch(() => null);
  const row = await usableToken(c.var.db, body?.token);
  return c.text(envLines({ INSTALL_NAME: row.installName }));
});

/**
 * POST /api/redeem {token} — single use. Creates the project's API key and LLM proxy key
 * and returns everything setup.sh --docker needs. The token is only marked used in the
 * same transaction that stores the API key, so any failure before that leaves it retryable.
 */
install.post("/api/redeem", async (c) => {
  const ip = clientIp(c);
  if (await limited(c.env, `redeem:${ip}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);

  const body = await c.req.json<{ token?: unknown }>().catch(() => null);
  const db = c.var.db;
  const row = await usableToken(db, body?.token);

  // An existing LLM proxy client may be reused only if this project's own install tokens created it
  // (e.g. an earlier redeem whose install then failed); anyone else's client is never touched.
  const [ownClient] = await db
    .select({ id: installTokens.id })
    .from(installTokens)
    .where(and(eq(installTokens.projectId, row.projectId), eq(installTokens.llmClientId, row.installName)))
    .limit(1);

  const sha = await latestCommit(c.env);
  const { proxyKey, created } = await issueProxyKey(c.env, row.installName, row.llmBudgetCents, !!ownClient);
  if (created) {
    await db.update(installTokens).set({ llmClientId: row.installName }).where(eq(installTokens.id, row.id));
  }

  const apiKey = generateApiKey();
  // A concurrent redeem of the same token loses on the one-active-key-per-project index.
  const [marked] = await db.batch([
    db
      .update(installTokens)
      .set({ redeemedAt: new Date(), redeemedIp: ip, redeemedCommit: sha })
      .where(and(eq(installTokens.id, row.id), isNull(installTokens.redeemedAt)))
      .returning({ id: installTokens.id }),
    db.insert(apiKeys).values({
      projectId: row.projectId,
      orgId: row.orgId,
      keyHash: await hashApiKey(apiKey),
      keyPrefix: getKeyPrefix(apiKey),
      createdBy: row.createdBy,
      description: `install token (${row.installName})`,
    }),
  ]).catch((err) => {
    if (isUniqueViolation(err)) throw new InstallError(410, "This install token was already used");
    throw err;
  });
  if (marked.length === 0) return c.text("This install token was already used", 410);

  return c.text(
    envLines({
      INSTALL_NAME: row.installName,
      CODE_URL: await codeUrl(c, sha, row.projectId),
      CODE_COMMIT: sha.slice(0, 12),
      SUPERATOM_API_KEY: apiKey,
      SUPERATOM_PROJECT_ID: row.projectId,
      SA_API_URL: c.env.INSTALL_SA_API_URL,
      SA_ORG_ID: row.orgId,
      SA_ORG_SLUG: row.orgSlug,
      SA_WEBSOCKET_URL: c.env.INSTALL_WS_URL,
      PLATFORM_UI_URL: c.env.INSTALL_PLATFORM_UI_URL?.replace("{slug}", row.orgSlug),
      USER_UI_URL: c.env.INSTALL_USER_UI_URL?.replace("{slug}", row.orgSlug),
      OPENROUTER_API_KEY: proxyKey,
      SA_INTERNAL_SERVICE_TOKEN: c.env.SA_INTERNAL_SERVICE_TOKEN,
      RESEND_API_KEY: c.env.RESEND_API_KEY,
    })
  );
});

/** POST /api/update {projectId} + Bearer <project API key> — latest code for an existing install. */
install.post("/api/update", async (c) => {
  const ip = clientIp(c);
  if (await limited(c.env, `update:${ip}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);

  const auth = c.req.header("Authorization") ?? "";
  const apiKey = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const body = await c.req.json<{ projectId?: unknown }>().catch(() => null);
  const projectId = typeof body?.projectId === "string" ? body.projectId : "";
  if (!apiKey.startsWith("sa_live_") || !UUID.test(projectId)) return c.text("Invalid API key for this project", 401);

  const [key] = await c.var.db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.projectId, projectId), eq(apiKeys.keyHash, await hashApiKey(apiKey)), eq(apiKeys.isActive, true)))
    .limit(1);
  if (!key) return c.text("Invalid API key for this project", 401);

  const sha = await latestCommit(c.env);
  return c.text(envLines({ CODE_URL: await codeUrl(c, sha, projectId), CODE_COMMIT: sha.slice(0, 12) }));
});

/** GET /api/code/<signed link> — the code tarball at the signed commit, streamed from GitHub. */
install.get("/api/code/:link", async (c) => {
  if (await limited(c.env, `code:${clientIp(c)}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);
  const sha = await verifyDownload(c.env, c.req.param("link"));
  if (!sha) return c.text("This download link is invalid or has expired. Re-run the installer.", 403);
  const upstream = await fetchTarball(c.env, sha);
  return new Response(upstream.body, {
    headers: {
      "Content-Type": "application/gzip",
      "Content-Disposition": `attachment; filename="superatom-${sha.slice(0, 12)}.tar.gz"`,
      "Cache-Control": "no-store",
    },
  });
});

install.notFound((c) => c.text("Not found", 404));

install.onError((err, c) => {
  if (err instanceof InstallError) return c.text(err.message, err.status as 400);
  console.error("[install] unhandled error:", err);
  return c.text("Internal error. Try again shortly.", 500);
});

export default install;
