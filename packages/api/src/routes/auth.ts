import { Hono } from "hono";
import { eq, and, inArray, sql } from "drizzle-orm";
import { users, organizations, appPermissions, apps, projects } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import { verifyTurnstile } from "../lib/turnstile";
import { mintAccessToken } from "../lib/access-token";
import {
  issueRefreshToken,
  rotateRefreshToken,
  revokeAllForUser,
} from "../lib/refresh-tokens";
import {
  setRefreshCookie,
  readRefreshCookie,
  readLegacyRefreshCookie,
  clearRefreshCookie,
} from "../lib/refresh-cookie";

const auth = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// Neon's HTTP SQL endpoint occasionally returns 520 or hangs when routed
// through certain Cloudflare colos. Bound each call and retry once so a
// transient blip doesn't strand the user on a 95-second spinner.
async function withDbRetry<T>(
  label: string,
  fn: () => Promise<T>,
  opts: { timeoutMs?: number; retries?: number } = {}
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 6000;
  const retries = opts.retries ?? 1;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await Promise.race([
        fn(),
        new Promise<T>((_, reject) =>
          setTimeout(
            () => reject(new Error(`db:${label} timed out after ${timeoutMs}ms`)),
            timeoutMs
          )
        ),
      ]);
    } catch (err) {
      lastErr = err;
      console.warn(`db:${label} attempt ${attempt + 1} failed`, err);
    }
  }
  throw lastErr;
}

/**
 * POST /auth/login
 * Login with email/password, returns JWT
 */
auth.post("/login", async (c) => {
  const db = c.get("db");
  const { email, password, orgSlug, turnstileToken } = await c.req.json<{
    email?: string;
    password: string;
    orgSlug?: string;
    turnstileToken?: string;
  }>();

  // Captcha check before any credential work, to throttle brute force and
  // credential stuffing. No-ops until TURNSTILE_SECRET_KEY is configured.
  const captchaError = await verifyTurnstile(
    c.env,
    turnstileToken,
    c.req.header("CF-Connecting-IP")
  );
  if (captchaError) {
    const status = captchaError.includes("unavailable") ? 503 : 400;
    return c.json({ error: captchaError }, status);
  }

  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  // Compare case-insensitively: users.ts stores a lowercased email on
  // creation, but existing rows created before that fix (or via SSO
  // provisioning) may still hold mixed case — a case-sensitive match here
  // would silently reject a correct password.
  const normalizedEmail = email.trim().toLowerCase();

  // Hash the incoming password once for comparison
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(password));
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  try {
    let matchedUsers: (typeof users.$inferSelect)[] = [];

    if (orgSlug) {
      // Org-scoped lookup — email is unique per org
      const [org] = await withDbRetry("login:org-by-slug", () =>
        db
          .select({ id: organizations.id })
          .from(organizations)
          .where(eq(organizations.slug, orgSlug))
          .limit(1)
      );
      if (!org) return c.json({ error: "Organization not found" }, 404);

      const [found] = await withDbRetry("login:user-by-email-org", () =>
        db
          .select()
          .from(users)
          .where(and(sql`lower(${users.email}) = ${normalizedEmail}`, eq(users.orgId, org.id), eq(users.isActive, true)))
          .limit(1)
      );
      if (found) matchedUsers = [found];
    } else {
      // No org context — find all active users with this email across orgs
      matchedUsers = await withDbRetry("login:users-by-email", () =>
        db
          .select()
          .from(users)
          .where(and(sql`lower(${users.email}) = ${normalizedEmail}`, eq(users.isActive, true)))
      );
    }

    // Filter to users whose password matches
    const validUsers = matchedUsers.filter((u) => u.passwordHash === hashHex);

    if (validUsers.length === 0) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    // Log into the first matched user; also return all their orgs
    const user = validUsers[0];

    const allOrgIds = validUsers.map((u) => u.orgId).filter(Boolean) as string[];
    // Role lives on the per-org user row, not on organizations — the caller
    // (the multi-org picker) needs it to filter out orgs this email can't
    // actually get into before ever showing them.
    const roleByOrgId = new Map(validUsers.map((u) => [u.orgId, u.role]));
    const orgRows = allOrgIds.length
      ? await withDbRetry("login:orgs-by-ids", () =>
          db
            .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, icon: organizations.icon })
            .from(organizations)
            .where(inArray(organizations.id, allOrgIds))
        )
      : [];
    const orgs = orgRows.map((o) => ({ ...o, role: roleByOrgId.get(o.id) }));

    // Short-lived access token (15m) plus a rotating refresh token held in an
    // httpOnly cookie — see lib/access-token.ts and lib/refresh-cookie.ts.
    // Minted before the refresh row so a missing org secret fails the login
    // cleanly (503 below) instead of leaving an orphan refresh token.
    const token = await mintAccessToken(user, c.env.JWT_SECRETS);

    const refresh = await issueRefreshToken(db, user.id, {
      userAgent: c.req.header("User-Agent"),
    });
    // Per-org cookie so a second org login in the same browser does not
    // overwrite this one. super_admin (no org) gets the base cookie.
    setRefreshCookie(c, refresh.token, user.orgId ?? undefined);

    return c.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        orgId: user.orgId,
      },
      orgs,
    });
  } catch (err) {
    console.error("login failed", err);
    return c.json(
      { error: "Login is temporarily unavailable. Please try again." },
      503
    );
  }
});

/**
 * POST /auth/logout
 * Revokes every token issued to this user up to now.
 *
 * A JWT stays cryptographically valid until it expires, so clearing it from
 * localStorage only makes the browser forget it — anyone holding a copy could
 * keep using it for the remainder of its lifetime. Stamping a cutoff on the user
 * row lets authMiddleware reject tokens issued before it, which is what actually
 * ends the session.
 *
 * Truncated to whole seconds because `iat` has second granularity: a fresh login
 * in the same second as a logout must not be rejected as stale.
 */
auth.post("/logout", authMiddleware, async (c) => {
  const db = c.get("db");
  const userId = c.get("userId");
  const orgId = c.get("orgId");

  const cutoff = new Date(Math.floor(Date.now() / 1000) * 1000);

  try {
    await db
      .update(users)
      .set({ tokensValidAfter: cutoff, updatedAt: new Date() })
      .where(eq(users.id, userId));

    // Kill the refresh side too. Without this the access token would die at the
    // cutoff but the cookie could still mint new ones, so logout would not stick.
    await revokeAllForUser(db, userId);
  } catch (error) {
    console.error("[auth] logout revocation failed:", error);
    // Surface the failure: reporting success would leave the caller believing
    // the session was ended when the token is still usable.
    return c.json({ error: "Logout failed, please try again" }, 503);
  }

  // Clear only THIS org's cookie — a Superatom staffer logged into another org
  // in another tab must stay signed in there. revokeAllForUser above only kills
  // this user's families, and a user belongs to one org, so this is exact.
  clearRefreshCookie(c, orgId ?? undefined);

  return c.json({ message: "Logged out successfully" });
});

/**
 * POST /auth/refresh
 * Exchange the refresh cookie for a new access token, rotating the cookie.
 *
 * Deliberately NOT behind authMiddleware: the whole point is that it works when
 * the access token has expired. The refresh cookie is the credential here.
 *
 * CSRF is covered by SameSite=Lax, which stops another site POSTing here with
 * the cookie attached. The response carries only the access token; the refresh
 * token never becomes readable by JavaScript.
 */
auth.post("/refresh", async (c) => {
  const db = c.get("db");

  // The tab tells us which session it wants: its projectId (runtime UIs) or
  // orgId (admin UI). One browser can hold several org cookies, so without this
  // hint we would not know which to rotate. The body is optional — an old client
  // that posts nothing falls back to the base cookie below.
  let hintOrgId: string | null = null;
  try {
    const body = await c.req.json<{ projectId?: string; orgId?: string; orgSlug?: string }>();
    hintOrgId = body?.orgId ?? null;
    if (!hintOrgId && body?.projectId) {
      const [p] = await db
        .select({ orgId: projects.orgId })
        .from(projects)
        .where(eq(projects.id, body.projectId))
        .limit(1);
      hintOrgId = p?.orgId ?? null;
    }
    if (!hintOrgId && body?.orgSlug) {
      const [o] = await db
        .select({ id: organizations.id })
        .from(organizations)
        .where(eq(organizations.slug, body.orgSlug))
        .limit(1);
      hintOrgId = o?.id ?? null;
    }
  } catch {
    // No/invalid body — fall through to the base cookie.
  }

  // Prefer the org-scoped cookie; fall back to the base cookie for super_admin
  // sessions and for sessions issued before per-org cookies existed. Track which
  // one we actually used so a failure clears exactly that cookie.
  let usedOrgId: string | null | undefined;
  let presented = hintOrgId ? readRefreshCookie(c, hintOrgId) : undefined;
  if (presented) {
    usedOrgId = hintOrgId;
  } else {
    presented = readLegacyRefreshCookie(c);
    if (presented) usedOrgId = null;
  }

  if (!presented) {
    return c.json({ error: "No refresh token" }, 401);
  }

  const result = await rotateRefreshToken(db, presented, c.req.header("User-Agent"));

  if (!result.ok) {
    // Clear whichever cookie we read from so the browser stops replaying it.
    clearRefreshCookie(c, usedOrgId ?? undefined);
    const message =
      result.reason === "reuse_detected"
        ? "Session revoked, please sign in again"
        : "Session expired, please sign in again";
    return c.json({ error: message }, 401);
  }

  // Re-read the user: role, active status and the logout cutoff must all be
  // re-checked here, or refresh would become a way to keep minting tokens for a
  // deactivated or demoted account.
  const [user] = await db
    .select({
      id: users.id,
      orgId: users.orgId,
      role: users.role,
      isActive: users.isActive,
      tokensValidAfter: users.tokensValidAfter,
    })
    .from(users)
    .where(eq(users.id, result.userId))
    .limit(1);

  if (!user || !user.isActive) {
    await revokeAllForUser(db, result.userId);
    clearRefreshCookie(c, user?.orgId ?? usedOrgId ?? undefined);
    return c.json({ error: "Account is not active" }, 401);
  }

  // Rotate the cookie under the user's actual org. When we fell back to the base
  // cookie for an org user (a pre-per-org session), this migrates it onto the
  // suffixed name.
  setRefreshCookie(c, result.token, user.orgId ?? undefined);

  // If we just migrated an org user OFF the legacy base cookie, drop the base
  // cookie now. Otherwise it lingers holding the token we just consumed, and a
  // later hint-less refresh would replay it and trip reuse detection — revoking
  // the whole family (a hard logout of every session). super_admin keeps the
  // base cookie (it has no org and legitimately uses it), hence the org guard.
  if (usedOrgId === null && user.orgId) {
    clearRefreshCookie(c);
  }

  // The refresh token has already rotated and its cookie is set on this
  // response, so a signing fault must still return THIS response (503, cookie
  // included). Throwing instead would drop the new cookie, leave the browser on
  // the consumed token, and trip reuse detection on its next refresh.
  let token: string;
  try {
    token = await mintAccessToken(user, c.env.JWT_SECRETS);
  } catch (error) {
    console.error("[auth] refresh: access token signing failed:", error);
    return c.json({ error: "Authorization service unavailable" }, 503);
  }

  return c.json({ token });
});

/**
 * GET /auth/me
 * Get current user + org + list of permitted apps
 */
auth.get("/me", authMiddleware, async (c) => {
  const db = c.get("db");
  const userId = c.get("userId");

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  // Super admin: no org, no app list
  if (user.role === "super_admin") {
    return c.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        config: user.config,
      },
      organization: null,
      apps: [],
    });
  }

  const [org] = user.orgId
    ? await db
        .select()
        .from(organizations)
        .where(eq(organizations.id, user.orgId))
        .limit(1)
    : [null];

  // Get permitted apps
  let permittedApps;
  if (user.role === "org_admin") {
    // Admin sees all active apps in the org
    permittedApps = await db
      .select({
        id: apps.id,
        name: apps.name,
        type: apps.type,
        projectId: apps.projectId,
        projectName: projects.name,
        isDefault: apps.isDefault,
        permission: appPermissions.permission,
      })
      .from(apps)
      .innerJoin(projects, eq(projects.id, apps.projectId))
      .leftJoin(
        appPermissions,
        and(
          eq(appPermissions.appId, apps.id),
          eq(appPermissions.userId, userId)
        )
      )
      .where(and(eq(projects.orgId, user.orgId!), eq(apps.isActive, true)));
  } else {
    // Member sees explicitly permitted apps + org's default app
    permittedApps = await db
      .select({
        id: apps.id,
        name: apps.name,
        type: apps.type,
        projectId: apps.projectId,
        projectName: projects.name,
        isDefault: apps.isDefault,
        permission: appPermissions.permission,
      })
      .from(appPermissions)
      .innerJoin(apps, eq(apps.id, appPermissions.appId))
      .innerJoin(projects, eq(projects.id, apps.projectId))
      .where(
        and(eq(appPermissions.userId, userId), eq(apps.isActive, true))
      );

    // Include org's default app if not already in the list
    if (org?.defaultAppId && !permittedApps.find((a) => a.id === org.defaultAppId)) {
      const [defaultApp] = await db
        .select({
          id: apps.id,
          name: apps.name,
          type: apps.type,
          projectId: apps.projectId,
          projectName: projects.name,
          isDefault: apps.isDefault,
        })
        .from(apps)
        .innerJoin(projects, eq(projects.id, apps.projectId))
        .where(and(eq(apps.id, org.defaultAppId), eq(apps.isActive, true)))
        .limit(1);

      if (defaultApp) {
        permittedApps.unshift({ ...defaultApp, permission: "view" });
      }
    }
  }

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      config: user.config,
    },
    organization: org
      ? { id: org.id, name: org.name, slug: org.slug, icon: org.icon, defaultAppId: org.defaultAppId }
      : null,
    apps: permittedApps,
  });
});

export default auth;
