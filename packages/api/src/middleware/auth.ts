import { createMiddleware } from "hono/factory";
import type { Context } from "hono";
import { decodeJwt, jwtVerify } from "jose";
import { eq, sql } from "drizzle-orm";
import { users, refreshTokens } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { getOrgSecret, isSecretBoundToUser, secretKeyFor } from "../lib/org-secrets";

type AuthContext = Context<{ Bindings: Env; Variables: AppVariables }>;

export type AuthResult =
  | {
      ok: true;
      userId: string;
      orgId: string | null;
      role: AppVariables["userRole"];
      /** The login session (refresh-token family) the token belongs to; null for pre-`sid` tokens. */
      sessionId: string | null;
      /** "sdk" for a token from the SDK exchange (always acts as a member); "app" otherwise. */
      tokenSource: AppVariables["tokenSource"];
    }
  | { ok: false; status: 401 | 503; error: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Authenticate the request's access token — verifies it, then resolves the
 * caller's role and account status FROM THE DATABASE on every request.
 *
 * The token's `role` and `orgId` claims are deliberately ignored for
 * authorization. They are a snapshot from login, and with a long token lifetime
 * a demotion or deactivation would otherwise have no effect until expiry: a
 * downgraded admin kept full access, could re-escalate themselves, and a
 * deactivated account could still act. The signature proves *who* is calling;
 * the database decides *what they may do*.
 *
 * The one use of the `orgId` claim is choosing which org's secret verifies the
 * signature (see lib/org-secrets.ts) — and it is then checked against the
 * user's real org before anything is trusted.
 *
 * Exported for routes that accept either a user token or a service token and
 * so cannot mount authMiddleware directly (routes/source-upload.ts).
 */
export async function authenticateRequest(c: AuthContext): Promise<AuthResult> {
  const authHeader = c.req.header("Authorization");
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : c.req.query("token");

  if (!token) {
    return { ok: false, status: 401, error: "Missing authorization token" };
  }

  // The unverified orgId claim picks the secret. It is not trusted beyond that:
  // the binding check below compares it with the user's org in the database.
  let claimedOrgId: string | null;
  try {
    claimedOrgId = (decodeJwt(token).orgId as string | null | undefined) ?? null;
  } catch {
    return { ok: false, status: 401, error: "Invalid or expired token" };
  }

  let secret: Uint8Array | null;
  try {
    secret = await getOrgSecret(c.env.JWT_SECRETS, claimedOrgId);
  } catch (error) {
    // A KV fault is ours, not the caller's — 503 so clients do not sign out.
    console.error("[auth] signing secret lookup failed:", error);
    return { ok: false, status: 503, error: "Authorization service unavailable" };
  }
  if (!secret) {
    console.warn(`[auth] no signing secret for ${secretKeyFor(claimedOrgId)}`);
    return { ok: false, status: 401, error: "Invalid or expired token" };
  }

  let userId: string;
  let issuedAt: number | undefined;
  let sessionId: string | null;
  let tokenSource: AppVariables["tokenSource"];
  try {
    // Pin the algorithm so the token header cannot choose how it is verified.
    const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });

    userId = payload.userId as string;
    issuedAt = payload.iat;
    if (!userId) {
      return { ok: false, status: 401, error: "Invalid token payload" };
    }
    // `sid` is the login session. Absent on tokens minted before it existed
    // (those expire within 15 minutes); malformed means a bad token.
    sessionId = typeof payload.sid === "string" ? payload.sid : null;
    if (payload.sid !== undefined && (!sessionId || !UUID.test(sessionId))) {
      return { ok: false, status: 401, error: "Invalid token payload" };
    }
    // Set only by the SDK exchange, inside a token signed with our own key.
    tokenSource = payload.src === "sdk" ? "sdk" : "app";
  } catch {
    return { ok: false, status: 401, error: "Invalid or expired token" };
  }

  // Authoritative lookup. Kept outside the try above so a database fault cannot
  // be mistaken for a bad token.
  let user:
    | {
        orgId: string | null;
        role: AppVariables["userRole"];
        isActive: boolean;
        tokensValidAfter: Date | null;
        sessionActive: boolean;
      }
    | undefined;
  try {
    const db = c.get("db");
    [user] = await db
      .select({
        orgId: users.orgId,
        role: users.role,
        isActive: users.isActive,
        tokensValidAfter: users.tokensValidAfter,
        // Folded into the same query so ending one session costs no extra round
        // trip: a session is active while any token of its family is unrevoked.
        sessionActive: sessionId
          ? sql<boolean>`exists (select 1 from ${refreshTokens} where ${refreshTokens.familyId} = ${sessionId} and ${refreshTokens.revokedAt} is null)`
          : sql<boolean>`true`,
      })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
  } catch (error) {
    // Fail closed, but as 503 rather than 401: a transient DB fault must not
    // look like an expired session, or every client signs the user out.
    console.error("[auth] role lookup failed:", error);
    return { ok: false, status: 503, error: "Authorization service unavailable" };
  }

  if (!user) {
    return { ok: false, status: 401, error: "Invalid or expired token" };
  }

  // The secret that verified the token must be the user's own org's. Otherwise a
  // holder of one org's secret could sign a token naming another org's user.
  if (!isSecretBoundToUser(claimedOrgId, user.orgId)) {
    console.warn(
      `[auth] token org does not match user org: user=${userId} ` +
        `token=${secretKeyFor(claimedOrgId)} actual=${secretKeyFor(user.orgId)}`
    );
    return { ok: false, status: 401, error: "Invalid or expired token" };
  }

  // Deactivation takes effect immediately, without waiting for token expiry.
  if (!user.isActive) {
    return { ok: false, status: 401, error: "Account is deactivated" };
  }

  // Session revocation: logout stamps a cutoff, so tokens minted before it are
  // dead even though their signature and expiry are still valid. Compared at
  // second granularity because that is all `iat` carries — a token issued in the
  // same second as the logout is treated as newer, not stale.
  if (user.tokensValidAfter) {
    const cutoffSeconds = Math.floor(user.tokensValidAfter.getTime() / 1000);
    if (issuedAt === undefined || issuedAt < cutoffSeconds) {
      return { ok: false, status: 401, error: "Session has been revoked, please sign in again" };
    }
  }

  // Logout ends one session by revoking its refresh-token family; tokens that
  // belong to it stop working here at once, while the user's other sessions
  // (other apps, browsers, devices) carry on.
  if (!user.sessionActive) {
    return { ok: false, status: 401, error: "Session has ended, please sign in again" };
  }

  // orgId is required for non-super_admin users
  if (user.role !== "super_admin" && !user.orgId) {
    return { ok: false, status: 401, error: "Invalid account state" };
  }

  // An SDK session keeps the role we hold for the user, so promoting someone in
  // the platform also gives them the admin VIEW inside the customer's app. What
  // it cannot do is CHANGE the org: adminOnly and superAdminOnly refuse anything
  // but a read from an SDK token (see below).
  //
  // Why reads but not writes: the customer's backend chooses which user their
  // token names, so whoever holds the SDK secret can sign in as any user of
  // their own org, an org_admin included. Reading that org's own data is what
  // the SDK is for; creating users or rotating keys is not.
  //
  // A super_admin belongs to no single org and never arrives this way.
  if (tokenSource === "sdk" && (user.role === "super_admin" || !user.orgId)) {
    return { ok: false, status: 401, error: "Invalid token payload" };
  }

  return { ok: true, userId, orgId: user.orgId, role: user.role, sessionId, tokenSource };
}

/** JWT auth middleware — see authenticateRequest. */
export const authMiddleware = createMiddleware<{
  Bindings: Env;
  Variables: AppVariables;
}>(async (c, next) => {
  const result = await authenticateRequest(c);
  if (!result.ok) {
    return c.json({ error: result.error }, result.status);
  }

  c.set("userId", result.userId);
  c.set("orgId", result.orgId);
  c.set("userRole", result.role);
  c.set("sessionId", result.sessionId);
  c.set("tokenSource", result.tokenSource);

  await next();
});

/**
 * Middleware that requires the user to be an org_admin or super_admin.
 * Must be used after authMiddleware.
 */
export const adminOnly = createMiddleware<{
  Bindings: Env;
  Variables: AppVariables;
}>(async (c, next) => {
  const role = c.get("userRole");
  if (role !== "org_admin" && role !== "super_admin") {
    return c.json({ error: "Forbidden: admin role required" }, 403);
  }
  if (isSdkWrite(c)) {
    return c.json({ error: "Not available to SDK sessions" }, 403);
  }
  await next();
});

/**
 * A change requested with an SDK token. An admin signed in through a customer's
 * app may READ everything their role allows, but the org's setup — users,
 * projects, SSO, API keys — changes only from a real login on our platform,
 * because the customer's backend decides which user their token names.
 */
function isSdkWrite(c: { get: (k: "tokenSource") => AppVariables["tokenSource"]; req: { method: string } }): boolean {
  return c.get("tokenSource") === "sdk" && c.req.method !== "GET" && c.req.method !== "HEAD";
}

/**
 * Middleware that requires the user to be a super_admin.
 * Must be used after authMiddleware.
 */
export const superAdminOnly = createMiddleware<{
  Bindings: Env;
  Variables: AppVariables;
}>(async (c, next) => {
  const role = c.get("userRole");
  if (role !== "super_admin") {
    return c.json({ error: "Forbidden: super_admin role required" }, 403);
  }
  // Belt and braces: a super_admin cannot reach here through the SDK anyway.
  if (c.get("tokenSource") === "sdk") {
    return c.json({ error: "Not available to SDK sessions" }, 403);
  }
  await next();
});

/**
 * Middleware that ensures org_admin users can only access resources in their own org.
 * Super admins bypass this check. Expects :orgId route parameter.
 * Must be used after authMiddleware.
 */
export const orgScopeGuard = createMiddleware<{
  Bindings: Env;
  Variables: AppVariables;
}>(async (c, next) => {
  const role = c.get("userRole");
  if (role === "super_admin") {
    await next();
    return;
  }
  const routeOrgId = c.req.param("orgId");
  const userOrgId = c.get("orgId");
  if (routeOrgId && routeOrgId !== userOrgId) {
    return c.json({ error: "Forbidden: cannot access another organization" }, 403);
  }
  await next();
});
