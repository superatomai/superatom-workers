/**
 * Per-org JWT signing secrets — see PER-ORG-JWT-SECRETS-DESIGN.md.
 *
 * Every access token is signed with its org's own secret rather than one
 * platform-wide JWT_SECRET, so a leaked secret can only forge tokens for that
 * org's users. Secrets live in the JWT_SECRETS KV namespace, shared with
 * sa-api, which signs the tokens this worker verifies:
 *
 *   org:<orgId>   → secret for that org
 *   org:__global  → secret for super_admin (orgId = null)
 *
 * The token's orgId claim selects the key. That claim is untrusted until the
 * signature checks out, so every verifier must also confirm afterwards that the
 * user's org in the DATABASE maps to the same key (see isSecretBoundToUser).
 *
 * Verification half of packages/api/src/lib/org-secrets.ts (this worker never
 * signs) — keep the two in step.
 */

export const GLOBAL_SECRET_ID = '__global';

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
 * The org's signing secret, or null if the org has none.
 * Throws on a KV fault — callers must map that to 5xx, never 401, so a KV
 * outage does not look like an expired session and sign every client out.
 */
export async function getOrgSecret(
	kv: KVNamespace,
	orgId: string | null | undefined
): Promise<Uint8Array | null> {
	const key = secretKeyFor(orgId);
	const hit = cache.get(key);
	if (hit && hit.until > Date.now()) return hit.secret;

	const value = await kv.get(key);
	// Misses are not cached: an org whose secret is written a moment later must
	// pick it up on the next request, not a minute later.
	if (!value) return null;

	const secret = new TextEncoder().encode(value);
	cache.set(key, { secret, until: Date.now() + CACHE_MS });
	return secret;
}
