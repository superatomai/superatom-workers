#!/usr/bin/env node
/**
 * Seed the JWT_SECRETS KV namespace for EXISTING orgs — see PER-ORG-JWT-SECRETS-DESIGN.md §5.
 *
 *   node scripts/seed-org-secrets.mjs --namespace-id <id> [--check-token <jwt>] [--dry-run]
 *
 * For every row in `organizations` that has no `org:<id>` entry yet — and for
 * `org:__global` (super_admin) — writes the CURRENT JWT_SECRET (asked for at a hidden
 * prompt), so tokens already in flight keep verifying. Entries that already exist are
 * never touched, so the script is safe to re-run.
 *
 *   --namespace-id   the JWT_SECRETS namespace to write (dev or prod — check the id!)
 *   --check-token    a real access token from this environment; the secret you enter
 *                    must verify it, or nothing is written (catches a wrong/dev-vs-prod secret)
 *   --dry-run        show what would be written; asks for nothing, writes nothing
 *   --local <dir>    seed the LOCAL store that `wrangler dev --persist-to <dir>` uses,
 *                    instead of the real namespace on Cloudflare
 *
 * Database: DATABASE_URL from the environment, else from .dev.vars. The host is shown
 * before anything is written — make sure it is the database of the environment
 * whose namespace you are seeding.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { neon } from "@neondatabase/serverless";
import { jwtVerify } from "jose";

function fail(message) {
  console.error(`\n✘ ${message}`);
  process.exit(1);
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

/** Read a line without echoing it. */
async function readHidden(prompt) {
  if (!process.stdin.isTTY) fail("Run this in an interactive terminal (the secret is read at a hidden prompt).");
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  return new Promise((resolve) => {
    let value = "";
    const done = () => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.off("data", onData);
      process.stdout.write("\n");
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done(), resolve(value);
        if (ch === "\u0003") return done(), process.exit(130);
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function readLine(prompt) {
  process.stdout.write(prompt);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  return new Promise((resolve) =>
    process.stdin.once("data", (d) => {
      process.stdin.pause();
      resolve(String(d).trim());
    })
  );
}

/**
 * Run wrangler. One pre-built command string (every part is validated or quoted
 * here) rather than an args array with shell:true, which Node deprecates.
 *
 * With `capture`, stdout is returned and stderr is held back, shown only on
 * failure — that hides the harmless "unsafe fields" config warnings. (Not
 * WRANGLER_LOG=error: wrangler prints command results through the same logger,
 * so that would suppress the output too.)
 */
function wrangler(command, { capture = false } = {}) {
  const r = spawnSync(`npx wrangler ${command}`, {
    shell: true,
    encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (r.status !== 0) {
    if (capture && r.stderr) console.error(r.stderr);
    fail(`wrangler ${command.split(" ").slice(0, 3).join(" ")} failed (exit ${r.status}).`);
  }
  return r.stdout;
}

function databaseUrl() {
  if (process.env.DATABASE_URL) return { url: process.env.DATABASE_URL, from: "DATABASE_URL env var" };
  try {
    const line = readFileSync(".dev.vars", "utf8").split(/\r?\n/).find((l) => l.startsWith("DATABASE_URL="));
    if (line) return { url: line.slice("DATABASE_URL=".length).replace(/^["']|["']$/g, ""), from: ".dev.vars" };
  } catch {}
  fail("No DATABASE_URL in the environment or .dev.vars (run from packages/api).");
}

// ── Inputs ────────────────────────────────────────────────────────────────────
const namespaceId = arg("--namespace-id");
const checkToken = arg("--check-token");
const dryRun = process.argv.includes("--dry-run");
const localDir = arg("--local");
// Appended to every wrangler kv call: the local simulated store, or Cloudflare.
const target = localDir ? `--local --persist-to "${localDir}"` : "";
if (!namespaceId) fail("Usage: node scripts/seed-org-secrets.mjs --namespace-id <id> [--check-token <jwt>] [--dry-run]");
if (!/^[0-9a-f]{32}$/.test(namespaceId)) fail(`"${namespaceId}" is not a KV namespace id (32 hex characters).`);

// ── Orgs from the database ────────────────────────────────────────────────────
const db = databaseUrl();
const dbHost = new URL(db.url).host;
const orgs = await neon(db.url)`SELECT id, slug FROM organizations ORDER BY slug`;

// ── What KV already has ───────────────────────────────────────────────────────
const existing = new Set(
  JSON.parse(wrangler(`kv key list --namespace-id=${namespaceId} --prefix=org:${target ? " " + target : ""}`, { capture: true })).map((k) => k.name)
);
const missingOrgs = orgs.filter((o) => !existing.has(`org:${o.id}`));
const needGlobal = !existing.has("org:__global");
const keysToWrite = [...missingOrgs.map((o) => `org:${o.id}`), ...(needGlobal ? ["org:__global"] : [])];

console.log(`
Database:      ${dbHost}   (from ${db.from})
Namespace id:  ${namespaceId}   (${localDir ? `LOCAL store in ${localDir}` : "Cloudflare"})
Orgs in DB:    ${orgs.length}
Already in KV: ${orgs.length - missingOrgs.length}
To add:        ${missingOrgs.length}${missingOrgs.length ? "  → " + missingOrgs.map((o) => o.slug).join(", ") : ""}
org:__global:  ${needGlobal ? "will be added (super_admin)" : "already exists — left as is"}`);

if (!keysToWrite.length) {
  console.log("\n✔ Nothing to do — every org and org:__global already have a secret.");
  process.exit(0);
}

if (dryRun) {
  console.log(`\nDry run — would write ${keysToWrite.length} entries, all set to the current JWT_SECRET:`);
  for (const k of keysToWrite) console.log(`  ${k}`);
  console.log("\nNothing written. Run again without --dry-run to write them.");
  process.exit(0);
}

// ── The current shared secret ─────────────────────────────────────────────────
const secret = await readHidden("\nCurrent JWT_SECRET for THIS environment (hidden): ");
if (!secret) fail("No secret entered.");
console.log(`Secret: ${secret.length} characters`);

if (checkToken) {
  try {
    await jwtVerify(checkToken, new TextEncoder().encode(secret), {
      algorithms: ["HS256"],
      clockTolerance: Number.MAX_SAFE_INTEGER, // an expired token still proves the secret
    });
    console.log("✔ Secret verifies the --check-token token.");
  } catch {
    fail("That secret does NOT verify the --check-token token. Nothing written.");
  }
} else {
  console.log("(No --check-token given — the secret was not checked against a real token.)");
}

const answer = await readLine(`\nWrite ${keysToWrite.length} entries to namespace ${namespaceId}? Type "yes": `);
if (answer !== "yes") fail("Aborted. Nothing written.");

// ── Write via a temp file that is always deleted ──────────────────────────────
const entries = keysToWrite.map((key) => ({ key, value: secret }));
const dir = mkdtempSync(join(tmpdir(), "org-secrets-"));
const file = join(dir, "seed.json");
try {
  writeFileSync(file, JSON.stringify(entries), { mode: 0o600 });
  wrangler(`kv bulk put "${file}" --namespace-id=${namespaceId}${target ? " " + target : ""}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n✔ Wrote ${entries.length} entries. Run with --dry-run again: it should report "Nothing to do".`);
