import { SignJWT, jwtVerify } from "jose";
import type { Env } from "../types";

const USER_AGENT = "superatom-install";
const DOWNLOAD_TTL_SECONDS = 10 * 60;
const INSTALL_SCRIPT_TTL_MS = 5 * 60 * 1000;

export class InstallError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** KEY=value lines — what install.sh parses (no JSON tooling on a fresh VM). */
export function envLines(values: Record<string, string | null | undefined>): string {
  return Object.entries(values)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${k}=${v}`)
    .join("\n") + "\n";
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── GitHub (read-only token, one repo) ──────────────────

// Overridable so local tests can stand in a fake GitHub.
function githubApi(env: Env): string {
  return env.INSTALL_GITHUB_API || "https://api.github.com";
}

function githubHeaders(env: Env, accept: string): HeadersInit {
  if (!env.GITHUB_CODE_TOKEN) throw new InstallError(503, "Installer is not configured (code source).");
  return {
    Authorization: `Bearer ${env.GITHUB_CODE_TOKEN}`,
    Accept: accept,
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

/** The commit INSTALL_CODE_REF points at right now. */
export async function latestCommit(env: Env): Promise<string> {
  const res = await fetch(`${githubApi(env)}/repos/${env.INSTALL_CODE_REPO}/commits/${env.INSTALL_CODE_REF}`, {
    headers: githubHeaders(env, "application/vnd.github.sha"),
  });
  const sha = (await res.text()).trim();
  if (!res.ok || !/^[0-9a-f]{40}$/.test(sha)) {
    console.error(`[install] commit lookup failed: ${res.status}`);
    throw new InstallError(502, "Could not look up the latest code version. Try again shortly.");
  }
  return sha;
}

/** Streams the repo tarball at `sha` (GitHub's layout: one top-level directory). */
export async function fetchTarball(env: Env, sha: string): Promise<Response> {
  const res = await fetch(`${githubApi(env)}/repos/${env.INSTALL_CODE_REPO}/tarball/${sha}`, {
    headers: githubHeaders(env, "application/vnd.github+json"),
  });
  if (!res.ok || !res.body) {
    console.error(`[install] tarball fetch failed: ${res.status}`);
    throw new InstallError(502, "Code download failed. Try again shortly.");
  }
  return res;
}

// Per-isolate cache so every `curl | sh` doesn't hit GitHub.
let scriptCache: { body: string; at: number } | null = null;

/** install.sh as it is on INSTALL_CODE_REF, so the installer always matches the code it installs. */
export async function installScript(env: Env): Promise<string> {
  if (scriptCache && Date.now() - scriptCache.at < INSTALL_SCRIPT_TTL_MS) return scriptCache.body;
  const res = await fetch(
    `${githubApi(env)}/repos/${env.INSTALL_CODE_REPO}/contents/install.sh?ref=${encodeURIComponent(env.INSTALL_CODE_REF)}`,
    { headers: githubHeaders(env, "application/vnd.github.raw") }
  );
  const body = await res.text();
  if (!res.ok || !body.startsWith("#!")) {
    console.error(`[install] install.sh fetch failed: ${res.status}`);
    if (scriptCache) return scriptCache.body; // stale beats down
    throw new InstallError(503, "Installer temporarily unavailable.");
  }
  scriptCache = { body, at: Date.now() };
  return body;
}

// ─── Short-lived signed download links ───────────────────

function downloadKey(env: Env): Uint8Array {
  if (!env.INSTALL_DOWNLOAD_SECRET || env.INSTALL_DOWNLOAD_SECRET.length < 32) {
    throw new InstallError(503, "Installer is not configured (download signing).");
  }
  return new TextEncoder().encode(env.INSTALL_DOWNLOAD_SECRET);
}

export async function signDownload(env: Env, sha: string, projectId: string): Promise<string> {
  return new SignJWT({ pid: projectId })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sha)
    .setAudience("install-code")
    .setIssuedAt()
    .setExpirationTime(`${DOWNLOAD_TTL_SECONDS}s`)
    .sign(downloadKey(env));
}

/** Returns the commit sha a download link grants, or null if invalid/expired. */
export async function verifyDownload(env: Env, token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, downloadKey(env), { audience: "install-code", algorithms: ["HS256"] });
    return typeof payload.sub === "string" && /^[0-9a-f]{40}$/.test(payload.sub) ? payload.sub : null;
  } catch {
    return null;
  }
}

// ─── LLM proxy (per-project client) ──────────────────────

async function proxyAdmin(env: Env, path: string, body: unknown): Promise<Response> {
  if (!env.LLM_PROXY || !env.LLM_PROXY_ADMIN_SECRET) {
    throw new InstallError(503, "Installer is not configured (LLM proxy).");
  }
  return env.LLM_PROXY.fetch(`https://llm-proxy/admin/clients${path}`, {
    method: "POST",
    headers: { "x-admin-secret": env.LLM_PROXY_ADMIN_SECRET, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Creates the project's LLM proxy client and returns its key (shown nowhere, sent only to the VM).
 * `mayRotate`: this project's own install token created the client earlier (an install that failed) — safe to rotate.
 * Budget 0 means unlimited, which llm-proxy spells null (0 would block every call).
 */
export async function issueProxyKey(
  env: Env,
  clientId: string,
  budgetCents: number,
  mayRotate: boolean
): Promise<{ proxyKey: string; created: boolean }> {
  if (env.INSTALL_LLM_PROXY_MODE === "dummy") {
    const rand = Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, "0")).join("");
    return { proxyKey: `sk-prox-${clientId}-dummy${rand}`, created: false };
  }
  const budget = budgetCents > 0 ? budgetCents : null;

  const created = await proxyAdmin(env, "", { clientId, budgetCents: budget });
  if (created.status === 201) {
    const { proxyKey } = (await created.json()) as { proxyKey?: string };
    if (proxyKey) return { proxyKey, created: true };
  }
  if (created.status === 409 && mayRotate) {
    const rotated = await proxyAdmin(env, `/${encodeURIComponent(clientId)}/rotate`, {});
    const { proxyKey } = (await rotated.json().catch(() => ({}))) as { proxyKey?: string };
    if (rotated.ok && proxyKey) {
      await proxyAdmin(env, `/${encodeURIComponent(clientId)}/budget`, { budgetCents: budget });
      return { proxyKey, created: false };
    }
  }
  if (created.status === 409) {
    throw new InstallError(
      409,
      `An LLM proxy client named '${clientId}' already exists. Generate a new install token with a different install name.`
    );
  }
  console.error(`[install] llm-proxy create failed: ${created.status}`);
  throw new InstallError(502, "Could not create the LLM proxy key. Try again shortly.");
}
