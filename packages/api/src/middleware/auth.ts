import { createMiddleware } from "hono/factory";
import type { Context } from "hono";
import { decodeJwt, jwtVerify } from "jose";
import { eq } from "drizzle-orm";
import { users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { getOrgSecret, isSecretBoundToUser, secretKeyFor } from "../lib/org-secrets";

type AuthContext = Context<{ Bindings: Env; Variables: AppVariables }>;

export type AuthResult =
  | {
      ok: true;
      userId: string;
      orgId: string | null;
      role: AppVariables["userRole"];
    }
  | { ok: false; status: 401 | 503; error: string };

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
  try {
    // Pin the algorithm so the token header cannot choose how it is verified.
    const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });

    userId = payload.userId as string;
    issuedAt = payload.iat;
    if (!userId) {
      return { ok: false, status: 401, error: "Invalid token payload" };
    }
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

  // orgId is required for non-super_admin users
  if (user.role !== "super_admin" && !user.orgId) {
    return { ok: false, status: 401, error: "Invalid account state" };
  }

  return { ok: true, userId, orgId: user.orgId, role: user.role };
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
  await next();
});

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
