import { Hono } from "hono";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { createDb, type Database } from "../db";
import { apiKeys, installTokens, organizations, projectInstalls, projectReleases, projects } from "../db/schema";
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
  signBundle,
  signDownload,
  verifyBundle,
  verifyDownload,
} from "./lib";
import { isUniqueViolation } from "../superadmin/lib/validate";
import { parseChecklistReportBody, storeChecklistReport } from "../lib/checklist-reports";
import engine from "./engine";
import { mountRegistry } from "./registry";

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
  // Engine artifacts are immutable and set their own; everything else is per-install.
  if (!c.res.headers.get("Cache-Control")) c.header("Cache-Control", "no-store");
});

// Docker Engine + compose, for VMs that cannot reach download.docker.com.
install.route("/api/engine", engine);

// OCI pulls, authenticated per project (src/install/registry.ts).
mountRegistry(install);

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
      pinnedVersion: projects.pinnedVersion,
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
 * The release a project should run: its pinned version, else the newest published.
 * Throws when nothing is published, so a token is never spent on a project that
 * has no image to install.
 */
/**
 * The release an install should be running: a super-admin pin wins, then the version
 * an admin approved for that install, then the newest. A VM never silently follows
 * "newest" once a target exists, so publishing a release does not deploy it.
 *
 * Null means this project has no releases at all — a normal state while a client is
 * being onboarded. Callers fall back to the source-tarball contract rather than
 * failing, so deploying this code cannot break an install that predates releases.
 * A pin or target naming a version that is NOT published is a misconfiguration, and
 * still 409s: silently serving a different version would be worse.
 */
async function currentRelease(
  db: Database, projectId: string, pinned: string | null, target?: string | null,
) {
  const want = pinned ?? target ?? null;
  const [release] = await db
    .select()
    .from(projectReleases)
    .where(
      want
        ? and(eq(projectReleases.projectId, projectId), eq(projectReleases.version, want))
        : eq(projectReleases.projectId, projectId)
    )
    .orderBy(desc(projectReleases.publishedAt))
    .limit(1);
  if (!release && want) {
    throw new InstallError(
      409,
      pinned
        ? `This project is pinned to version "${pinned}", which is not published. Pick another version in the super-admin console.`
        : `Version "${target}" is no longer published for this project. Choose another version to update to.`
    );
  }
  return release ?? null;
}

/** The project behind a `Bearer sa_live_…` key, or null. Used by the VM's own endpoints. */
async function projectFromKey(
  c: any, projectId: string,
): Promise<{ pinnedVersion: string | null } | null> {
  const auth = c.req.header("Authorization") ?? "";
  const apiKey = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!apiKey.startsWith("sa_live_") || !UUID.test(projectId)) return null;
  // api_keys.project_id is varchar, projects.id is uuid — hence the cast.
  const [key] = await c.var.db
    .select({ pinnedVersion: projects.pinnedVersion })
    .from(apiKeys)
    .innerJoin(projects, and(eq(projects.id, projectId), eq(apiKeys.projectId, sql`${projects.id}::text`)))
    .where(and(
      eq(apiKeys.projectId, projectId),
      eq(apiKeys.keyHash, await hashApiKey(apiKey)),
      eq(apiKeys.isActive, true),
    ))
    .limit(1);
  return key ?? null;
}

/** Records that this install is alive, and what it says it is running. */
async function touchInstall(
  db: Database, projectId: string, installName: string, current: string | null,
): Promise<void> {
  const seen = { lastSeenAt: new Date(), updatedAt: new Date() };
  const values = current ? { ...seen, releaseVersion: current } : seen;
  await db
    .insert(projectInstalls)
    .values({ projectId, installName, ...values })
    .onConflictDoUpdate({
      target: [projectInstalls.projectId, projectInstalls.installName],
      set: values,
    });
}

/** The install row for this VM, if it has reported itself before. */
async function installRow(db: Database, projectId: string, installName: string) {
  const [row] = await db
    .select()
    .from(projectInstalls)
    .where(and(eq(projectInstalls.projectId, projectId), eq(projectInstalls.installName, installName)))
    .limit(1);
  return row ?? null;
}

/** What a VM needs to pull and run a release. The registry is this worker's /v2. */
async function releaseLines(c: any, release: any) {
  const host = c.env.INSTALL_REGISTRY_HOST ?? new URL(c.req.url).host;
  // "<repo>:<tag>" — the repo is a project id, or "base" for a shared baseline.
  const repo = String(release.image).split(":")[0];
  const bundleKey = `bundles/${repo}/${release.version}/bundle.tar.gz`;
  return {
    RELEASE_VERSION: release.version,
    IMAGE: `${host}/${release.image}`,
    IMAGE_DIGEST: release.imageDigest,
    REGISTRY_HOST: host,
    BUNDLE_URL: `${new URL(c.req.url).origin}/api/bundle/${await signBundle(c.env, bundleKey)}`,
    BUNDLE_SHA256: release.bundleSha256,
    ENGINE_VERSION: release.engineVersion ?? undefined,
    COMPOSE_VERSION: release.composeVersion ?? undefined,
    CODE_COMMIT: release.commit.slice(0, 12),
  };
}

/**
 * POST /api/token-info {token} — checks a token without using it, so the installer can
 * prepare the install folder before spending the one-time token.
 */
install.post("/api/token-info", async (c) => {
  if (await limited(c.env, `token-info:${clientIp(c)}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);
  const body = await c.req.json<{ token?: unknown }>().catch(() => null);
  const row = await usableToken(c.var.db, body?.token);
  // Checked here as well, so a bad pin costs no token. No release at all is fine:
  // the install falls back to the source tarball.
  await currentRelease(c.var.db, row.projectId, row.pinnedVersion);
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

  // Before any mutation: a project with nothing published must not consume the token.
  const release = await currentRelease(db, row.projectId, row.pinnedVersion);
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
      ...(release ? await releaseLines(c, release) : { CODE_COMMIT: sha.slice(0, 12) }),
      // Transitional: an installer older than releases downloads source and builds.
      CODE_URL: await codeUrl(c, sha, row.projectId),
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

/**
 * POST /api/update {projectId, installName?} + Bearer <project API key> — the release
 * this install should be running. With an installName we answer with its approved
 * target; without one (an install made before targets existed) we answer as before.
 */
install.post("/api/update", async (c) => {
  const ip = clientIp(c);
  if (await limited(c.env, `update:${ip}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);

  const body = await c.req
    .json<{ projectId?: unknown; installName?: unknown; currentVersion?: unknown }>()
    .catch(() => null);
  const projectId = typeof body?.projectId === "string" ? body.projectId : "";
  const installName = typeof body?.installName === "string" ? body.installName.trim().slice(0, 255) : "";
  const current = typeof body?.currentVersion === "string" ? body.currentVersion.slice(0, 255) : "";
  const key = await projectFromKey(c, projectId);
  if (!key) return c.text("Invalid API key for this project", 401);

  const row = installName ? await installRow(c.var.db, projectId, installName) : null;
  // The updater's poll doubles as the heartbeat, so a quiet install still needs
  // only one request per tick to stay visibly alive.
  if (installName) await touchInstall(c.var.db, projectId, installName, current || null);
  const release = await currentRelease(c.var.db, projectId, key.pinnedVersion, row?.targetVersion);
  const sha = await latestCommit(c.env);
  return c.text(
    envLines({
      ...(release ? await releaseLines(c, release) : { CODE_COMMIT: sha.slice(0, 12) }),
      // Transitional, as in redeem.
      CODE_URL: await codeUrl(c, sha, projectId),
    })
  );
});

/**
 * POST /api/installed {projectId, installName, releaseVersion, imageDigest?, error?}
 * + Bearer <project API key> — what this VM is now running. Also the heartbeat, so
 * the UI can tell "behind" from "we have not heard from it".
 */
install.post("/api/installed", async (c) => {
  if (await limited(c.env, `installed:${clientIp(c)}`)) {
    return c.text("Too many attempts. Wait a minute and retry.", 429);
  }
  const body = await c.req
    .json<{ projectId?: unknown; installName?: unknown; releaseVersion?: unknown; imageDigest?: unknown; error?: unknown }>()
    .catch(() => null);
  const projectId = typeof body?.projectId === "string" ? body.projectId : "";
  const installName = typeof body?.installName === "string" ? body.installName.trim().slice(0, 255) : "";
  if (!installName) return c.text("installName is required", 400);
  if (!(await projectFromKey(c, projectId))) return c.text("Invalid API key for this project", 401);

  const str = (v: unknown, max: number) => (typeof v === "string" && v ? v.slice(0, max) : null);
  const values = {
    releaseVersion: str(body?.releaseVersion, 255),
    imageDigest: str(body?.imageDigest, 71),
    // Cleared whenever the updater reports without one, so a fixed install stops
    // showing yesterday's failure.
    lastError: str(body?.error, 2000),
    lastSeenAt: new Date(),
    updatedAt: new Date(),
  };
  await c.var.db
    .insert(projectInstalls)
    .values({ projectId, installName, ...values })
    .onConflictDoUpdate({
      target: [projectInstalls.projectId, projectInstalls.installName],
      set: values,
    });
  return c.text("ok");
});

/**
 * POST /api/checklist-reports {projectId, installName, checklistId, scope,
 * status, ranBy, startedAt, finishedAt, report, ...} + Bearer <project API
 * key> — a deploy checklist run (e.g. stage-1-engine-install) reported from
 * the VM. Project-scoped; a checklist with no project to be scoped to (a
 * future dev->prod merge gate) goes through POST /checklist-reports on the
 * main app instead, authenticated with the service token.
 */
install.post("/api/checklist-reports", async (c) => {
  if (await limited(c.env, `checklist-reports:${clientIp(c)}`)) {
    return c.text("Too many attempts. Wait a minute and retry.", 429);
  }
  const body = await c.req.json().catch(() => null);
  const projectId = typeof body?.projectId === "string" ? body.projectId : "";
  const key = await projectFromKey(c, projectId);
  if (!key) return c.text("Invalid API key for this project", 401);

  const parsed = parseChecklistReportBody(body);
  if (!parsed) return c.text("Invalid checklist report body", 400);

  const [project] = await c.var.db
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);

  const { id } = await storeChecklistReport(c.var.db, c.env, {
    ...parsed,
    projectId,
    orgId: project?.orgId ?? null,
  });
  return c.json({ success: true, id });
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

/** GET /api/bundle/<signed link> — the release's compose file and setup.sh. */
install.get("/api/bundle/:link", async (c) => {
  if (await limited(c.env, `bundle:${clientIp(c)}`)) return c.text("Too many attempts. Wait a minute and retry.", 429);
  const key = await verifyBundle(c.env, c.req.param("link"));
  if (!key) return c.text("This download link is invalid or has expired. Re-run the installer.", 403);
  const obj = await c.env.INSTALL_ARTIFACTS?.get(key);
  if (!obj) return c.text("The deploy bundle for this release is missing. Re-publish it.", 404);
  return new Response(obj.body, {
    headers: {
      "Content-Type": "application/gzip",
      "Content-Length": String(obj.size),
      "Content-Disposition": 'attachment; filename="bundle.tar.gz"',
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
