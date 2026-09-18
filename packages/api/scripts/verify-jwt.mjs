#!/usr/bin/env node
/**
 * Check whether an access token was signed with a given secret (HS256), and show
 * what the token contains.
 *
 *   node scripts/verify-jwt.mjs <token>
 *
 * The secret is asked for at a hidden prompt (or read from stdin when piped), never
 * taken as an argument, so it stays out of shell history and process listings.
 *
 * Exit code: 0 = signed with this secret, 1 = not signed with it, 2 = bad input.
 */

import { decodeJwt, decodeProtectedHeader, jwtVerify, errors } from "jose";

function fail(message) {
  console.error(message);
  process.exit(2);
}

/** Read a line without echoing it. Falls back to plain stdin when piped. */
async function readSecret(prompt) {
  if (!process.stdin.isTTY) {
    let data = "";
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n$/, "");
  }

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
        if (ch === "\u0003") return done(), process.exit(130); // Ctrl+C
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

const utc = (seconds) => new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";

function minutes(ms) {
  const m = Math.round(Math.abs(ms) / 60000);
  return m < 1 ? "under a minute" : `${m} min`;
}

// ── Token ─────────────────────────────────────────────────────────────────────
const token = process.argv[2]?.trim();
if (!token) fail("Usage: node scripts/verify-jwt.mjs <token>");

let header, payload;
try {
  header = decodeProtectedHeader(token);
  payload = decodeJwt(token);
} catch {
  fail("That is not a well-formed JWT (expected three base64url parts separated by dots).");
}

console.log("\nHeader: ", JSON.stringify(header));
console.log("Payload:", JSON.stringify(payload, null, 2));
if (payload.iat) console.log("Issued: ", utc(payload.iat));
if (payload.exp) {
  const left = payload.exp * 1000 - Date.now();
  console.log("Expires:", utc(payload.exp), left > 0 ? `(valid for ${minutes(left)})` : `(expired ${minutes(left)} ago)`);
}
console.log("KV key: ", `org:${payload.orgId || "__global"}`, " ← the per-org secret that should verify it");

// ── Secret ────────────────────────────────────────────────────────────────────
const secret = await readSecret("\nSecret (hidden, paste then Enter): ");
if (!secret) fail("No secret entered.");
// Length helps spot a stray space or newline copied along with the secret.
console.log(`Secret: ${secret.length} characters`);

// ── Verdict ───────────────────────────────────────────────────────────────────
try {
  await jwtVerify(token, new TextEncoder().encode(secret), { algorithms: ["HS256"] });
  console.log("\n✔ MATCH — this token was signed with this secret, and it has not expired.");
  process.exit(0);
} catch (err) {
  // jose checks the signature before the claims, so an expiry error means the
  // signature itself was good.
  if (err instanceof errors.JWTExpired) {
    console.log("\n✔ MATCH — this token was signed with this secret (but it has expired).");
    process.exit(0);
  }
  if (err instanceof errors.JWSSignatureVerificationFailed) {
    console.log("\n✘ NO MATCH — this token was NOT signed with this secret.");
    process.exit(1);
  }
  if (err instanceof errors.JOSEAlgNotAllowed) {
    console.log(`\n✘ Token uses alg "${header.alg}", not HS256 — not one of our access tokens.`);
    process.exit(1);
  }
  fail(`Could not check the token: ${err.message}`);
}
