/**
 * Browser session verification for WebSocket connections.
 *
 * Browser clients ('runtime', 'admin') cannot hold the per-project API key —
 * they load from public bundles — so they authenticate with the same JWT that
 * sa-api issues at login.
 *
 * Three checks, in order:
 *   1. the token's signature is valid — this establishes WHO is calling
 *   2. the account is looked up in the database for its CURRENT role and active
 *      status — the token's `role`/`orgId` claims are a login-time snapshot and
 *      are never used for authorization, so a demotion or deactivation takes
 *      effect on the next connection rather than at token expiry
 *   3. that organization actually owns the project being connected to
 *
 * All three matter: a valid token alone only proves the caller was logged in
 * SOMEWHERE at some point, which would still let one tenant open another
 * tenant's project channel. This mirrors authMiddleware in
 * packages/api/src/middleware/auth.ts so the two surfaces cannot drift on what
 * constitutes a valid session.
 */

import { decodeJwt, jwtVerify } from 'jose';
import { executeQuery } from '../api-keys/service';
import { getOrgSecret, isSecretBoundToUser, secretKeyFor } from './org-secrets';

export type UserRole = 'super_admin' | 'org_admin' | 'member';

export interface VerifiedSession {
	userId: string;
	orgId: string | null;
	role: UserRole;
	/**
	 * The user's data-access config, verbatim from the users table.
	 *
	 * Resolved HERE for the same reason role is: the data plane needs to know
	 * what a caller may see, and the only trustworthy answer comes from the
	 * database, not from anything the browser sends. Stamped onto every relayed
	 * message so a DATA_REQ (dashboard hydration) carries the same policy a
	 * USER_PROMPT does — they arrive in either order, and one of them used to
	 * arrive with no policy at all.
	 */
	config: unknown;
}

export type SessionResult =
	| { ok: true; session: VerifiedSession }
	| { ok: false; status: 401 | 403 | 500; reason: string };

export interface VerifyBrowserSessionOptions {
	/** Raw JWT from ?token= or the Authorization header. */
	token: string | null;
	projectId: string;
	/** JWT_SECRETS KV namespace — per-org signing secrets, see org-secrets.ts. */
	jwtSecrets: KVNamespace | undefined;
	databaseUrl: string | undefined;
}

/**
 * Extract the session token. Browsers cannot set headers on a WebSocket
 * handshake, so the query parameter is the practical path; the header is
 * accepted for non-browser callers and tests.
 */
export function extractToken(request: Request, url: URL): string | null {
	const authHeader = request.headers.get('Authorization');
	if (authHeader?.startsWith('Bearer ')) return authHeader.slice(7);
	return url.searchParams.get('token');
}

/**
 * Verify a browser session and authorize it for the requested project.
 * Never throws — all failures are returned so the caller can decide whether to
 * enforce or merely log them during staged rollout.
 */
export async function verifyBrowserSession(
	options: VerifyBrowserSessionOptions
): Promise<SessionResult> {
	const { token, projectId, jwtSecrets, databaseUrl } = options;

	if (!token) {
		return { ok: false, status: 401, reason: 'missing_token' };
	}

	// Fail closed on misconfiguration: without the secrets we cannot verify
	// anything, and treating that as "authenticated" would defeat the check.
	if (!jwtSecrets) {
		console.error('[auth] JWT_SECRETS KV binding is not configured on this worker');
		return { ok: false, status: 500, reason: 'jwt_secrets_not_configured' };
	}

	// The unverified orgId claim picks the org's secret. It is not trusted beyond
	// that: the binding check after the users query compares it with the
	// account's real org.
	let claimedOrgId: string | null;
	try {
		claimedOrgId = (decodeJwt(token).orgId as string | null | undefined) ?? null;
	} catch {
		return { ok: false, status: 401, reason: 'invalid_or_expired_token' };
	}

	let secret: Uint8Array | null;
	try {
		secret = await getOrgSecret(jwtSecrets, claimedOrgId);
	} catch (error: any) {
		console.error('[auth] signing secret lookup failed:', error?.message);
		return { ok: false, status: 500, reason: 'signing_secret_lookup_failed' };
	}
	if (!secret) {
		console.warn(`[auth] no signing secret for ${secretKeyFor(claimedOrgId)}`);
		return { ok: false, status: 401, reason: 'unknown_signing_org' };
	}

	let userId: string;
	let issuedAt: number | undefined;
	try {
		// Pin the algorithm so the token header cannot choose how it is verified.
		const { payload } = await jwtVerify(token, secret, { algorithms: ['HS256'] });

		userId = payload.userId as string;
		issuedAt = payload.iat;
		if (!userId) {
			return { ok: false, status: 401, reason: 'invalid_token_payload' };
		}
	} catch {
		// Covers bad signature, malformed token and expiry alike.
		return { ok: false, status: 401, reason: 'invalid_or_expired_token' };
	}

	if (!databaseUrl) {
		console.error('[auth] DATABASE_URL is not configured on this worker');
		return { ok: false, status: 500, reason: 'database_not_configured' };
	}

	// Resolve role and account status from the database, never from the token's
	// claims: those are a login-time snapshot, so a demoted or deactivated user
	// would otherwise keep WebSocket access until the token expired. Mirrors the
	// authMiddleware behaviour in sa-api so both surfaces agree.
	let session: VerifiedSession;
	try {
		const rows = await executeQuery<{
			org_id: string | null;
			role: UserRole;
			is_active: boolean;
			tokens_valid_after: string | null;
			config: unknown;
		}>(
			databaseUrl,
			'SELECT org_id, role, is_active, tokens_valid_after, config FROM users WHERE id = $1',
			[userId]
		);

		if (rows.length === 0) {
			return { ok: false, status: 401, reason: 'user_not_found' };
		}

		const account = rows[0];

		// The secret that verified the token must be the account's own org's.
		// Otherwise a holder of one org's secret could sign a token naming another
		// org's user. Mirrors authenticateRequest in sa-api.
		if (!isSecretBoundToUser(claimedOrgId, account.org_id)) {
			return { ok: false, status: 401, reason: 'token_org_mismatch' };
		}

		if (!account.is_active) {
			return { ok: false, status: 401, reason: 'account_deactivated' };
		}

		// Logout stamps a revocation cutoff; a token minted before it is dead even
		// though its signature and expiry still check out. Without this a
		// logged-out token could still open a socket after sa-api started
		// rejecting it.
		if (account.tokens_valid_after) {
			const cutoffSeconds = Math.floor(new Date(account.tokens_valid_after).getTime() / 1000);
			if (!Number.isNaN(cutoffSeconds) && (issuedAt === undefined || issuedAt < cutoffSeconds)) {
				return { ok: false, status: 401, reason: 'session_revoked' };
			}
		}

		// orgId is required for everyone except super_admin.
		if (account.role !== 'super_admin' && !account.org_id) {
			return { ok: false, status: 401, reason: 'invalid_account_state' };
		}

		session = { userId, orgId: account.org_id, role: account.role, config: account.config ?? null };
	} catch (error: any) {
		console.error('[auth] account lookup failed:', error?.message);
		return { ok: false, status: 500, reason: 'account_lookup_failed' };
	}

	// super_admin may reach any project, matching orgScopeGuard in sa-api.
	if (session.role === 'super_admin') {
		return { ok: true, session };
	}

	try {
		const rows = await executeQuery<{ org_id: string }>(
			databaseUrl,
			'SELECT org_id FROM projects WHERE id = $1',
			[projectId]
		);

		if (rows.length === 0) {
			// Do not distinguish "no such project" from "not yours" to the caller;
			// that difference is a tenant-enumeration oracle.
			return { ok: false, status: 403, reason: 'project_not_accessible' };
		}

		if (rows[0].org_id !== session.orgId) {
			return { ok: false, status: 403, reason: 'project_org_mismatch' };
		}

		return { ok: true, session };
	} catch (error: any) {
		console.error('[auth] project authorization lookup failed:', error?.message);
		return { ok: false, status: 500, reason: 'authorization_lookup_failed' };
	}
}
