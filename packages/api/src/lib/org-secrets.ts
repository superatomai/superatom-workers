/**
 * Per-org JWT signing secrets — see PER-ORG-JWT-SECRETS-DESIGN.md.
 *
 * Every access token is signed with its org's own secret rather than one
 * platform-wide JWT_SECRET, so a leaked secret can only forge tokens for that
 * org's users. Secrets live in the JWT_SECRETS KV namespace, shared with the
 * sa-websocket worker, which verifies the same tokens:
 *
 *   org:<orgId>   → secret for that org
 *   org:__global  → secret for super_admin (orgId = null)
 *   sdk:<orgId>   → the org's SDK secret, held by the customer (see getSdkSecret);
 *                   never used to sign or verify our access tokens
 *
 * The token's orgId claim selects the key. That claim is untrusted until the
 * signature checks out, so every verifier must also confirm afterwards that the
 * user's org in the DATABASE maps to the same key (see isSecretBoundToUser).
 *
 * Mirrored in packages/websocket/src/auth/org-secrets.ts — keep them identical.
 */

export const GLOBAL_SECRET_ID = "__global";

/** KV key for an org's secret. A null/absent orgId is super_admin. */
export function secretKeyFor(orgId: string | null | undefined): string {
  return `org:${orgId || GLOBAL_SECRET_ID}`;
}

/**
 * True when the key that verified the token belongs to the user's actual org.
 * Without this, a holder of org A's secret could sign a token naming an org B
 * user under orgId A, and it would verify.
 */
export function isSecretBoundToUser(
  claimedOrgId: string | null | undefined,
  userOrgId: string | null | undefined
): boolean {
  return secretKeyFor(claimedOrgId) === secretKeyFor(userOrgId);
}

/**
 * Per-isolate cache. A secret for a given org changes rarely, so a short TTL
 * spares a KV read on almost every request while still picking up a changed
 * secret within a minute (on top of KV's own propagation delay).
 */
const CACHE_MS = 60_000;
const cache = new Map<string, { secret: Uint8Array; until: number }>();

/**
 * A secret from KV by its full key, or null if absent. Throws on a KV fault —
 * callers must map that to 5xx, never 401, so a KV outage does not look like an
 * expired session and sign every client out.
 */
async function readSecret(kv: KVNamespace, key: string): Promise<Uint8Array | null> {
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.secret;

  const value = await kv.get(key);
  // Misses are not cached: a secret written a moment later must be picked up
  // on the next request, not a minute later.
  if (!value) return null;

  const secret = new TextEncoder().encode(value);
  cache.set(key, { secret, until: Date.now() + CACHE_MS });
  return secret;
}

/** The org's signing secret, or null if the org has none. Throws on a KV fault. */
export async function getOrgSecret(
  kv: KVNamespace,
  orgId: string | null | undefined
): Promise<Uint8Array | null> {
  return readSecret(kv, secretKeyFor(orgId));
}

/**
 * KV key for an org's SDK secret — the one given to the CUSTOMER, which signs
 * only their own user tokens for /auth/sdk/exchange.
 *
 * Deliberately separate from `org:<orgId>`: that key signs OUR access tokens,
 * so a customer holding it could skip the exchange and mint a token in our own
 * format for any user in the org, admins included. With `sdk:<orgId>` their
 * token can only say "this is my user"; the exchange decides what that grants.
 */
export function sdkSecretKeyFor(orgId: string): string {
  return `sdk:${orgId}`;
}

/**
 * The org's SDK secret, or null when SDK sign-in is not enabled for the org
 * (there is no default — an org without one cannot use SDK sign-in).
 * Throws on a KV fault.
 */
export async function getSdkSecret(kv: KVNamespace, orgId: string): Promise<Uint8Array | null> {
  return readSecret(kv, sdkSecretKeyFor(orgId));
}

/** 32 random bytes, hex. */
function randomSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Generate and store a fresh secret for an org. The secret is never returned —
 * it only ever lives in KV.
 */
export async function createOrgSecret(kv: KVNamespace, orgId: string): Promise<void> {
  await kv.put(secretKeyFor(orgId), randomSecret());
}

/**
 * Generate and store a fresh SDK secret for an org — enabling SDK sign-in, or
 * rotating the secret if there is one. Unlike the org secret it IS returned:
 * the customer's backend must hold it to sign their tokens. The old secret stops
 * working once KV propagates (up to about a minute) and other isolates' caches
 * expire (up to CACHE_MS).
 */
export async function createSdkSecret(kv: KVNamespace, orgId: string): Promise<string> {
  const secret = randomSecret();
  await kv.put(sdkSecretKeyFor(orgId), secret);
  cache.delete(sdkSecretKeyFor(orgId));
  return secret;
}

/** Remove an org's SDK secret — turning SDK sign-in off for the org. */
export async function deleteSdkSecret(kv: KVNamespace, orgId: string): Promise<void> {
  await kv.delete(sdkSecretKeyFor(orgId));
  cache.delete(sdkSecretKeyFor(orgId));
}

/** Thrown when an org has no secret in KV — a configuration fault, not a bad credential. */
export class MissingOrgSecretError extends Error {
  constructor(orgId: string | null | undefined) {
    super(`No JWT signing secret for ${secretKeyFor(orgId)}`);
    this.name = "MissingOrgSecretError";
  }
}
