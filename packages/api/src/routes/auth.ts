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
  revokeFamily,
} from "../lib/refresh-tokens";
import { getCookie } from "hono/cookie";
import {
  type AppKey,
  appFromOrigin,
  setRefreshCookie,
  readCookie,
  clearCookie,
  refreshCookieName,
  listAppOrgCookies,
} from "../lib/refresh-cookie";

const auth = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * One log line per refresh that did not end in a new token, with enough to
 * tell the causes apart afterwards: which hint the tab sent, which cookie was
 * used, and which refresh cookies the browser sent at all. Cookie NAMES only —
 * they carry an org id, never a credential; values are never logged.
 *
 * Without this, a refresh 401 is indistinguishable from any other, and a user
 * who "keeps getting logged out" cannot be diagnosed from the logs.
 */
function logRefreshOutcome(
  c: any,
  outcome: string,
  details: {
    app: AppKey;
    hint: string;
    usedCookie: string | null;
    userId?: string;
  }
): void {
  const sent = Object.keys(getCookie(c))
    .filter((name) => name.startsWith("sa_refresh"))
    .sort();
  console.warn(
    `[auth] refresh ${outcome}: app=${details.app} hint=${details.hint} cookie=${details.usedCookie ?? "none"} ` +
      `sent=[${sent.join(",")}]` +
      (details.userId ? ` user=${details.userId}` : "") +
      ` origin=${c.req.header("Origin") ?? "none"}`
  );
}

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
      // No org context — find all active users with this email across orgs.
      // Ordered so a super_admin row wins ties on validUsers[0] below.
      matchedUsers = await withDbRetry("login:users-by-email", () =>
        db
          .select()
          .from(users)
          .where(and(sql`lower(${users.email}) = ${normalizedEmail}`, eq(users.isActive, true)))
          .orderBy(sql`case when ${users.role} = 'super_admin' then 0 else 1 end`)
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
    // One id for this login session: the JWT carries it as `sid` and the refresh
    // token's family is created with it, so logout can end exactly this session.
    const sessionId = crypto.randomUUID();
    const token = await mintAccessToken(user, c.env.JWT_SECRETS, sessionId);

    const refresh = await issueRefreshToken(db, user.id, {
      familyId: sessionId,
      userAgent: c.req.header("User-Agent"),
    });
    // One cookie per app and org: this login replaces only this app's session
    // for this org. super_admin (no org) gets the base cookie.
    setRefreshCookie(c, refresh.token, appFromOrigin(c.req.header("Origin")), user.orgId);

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
 * POST /auth/logout            — ends THIS session only
 * POST /auth/logout?all=true   — ends every session of the user (all apps, devices)
 *
 * A JWT stays cryptographically valid until it expires, so clearing it from
 * storage only makes the browser forget it — anyone holding a copy could keep
 * using it. Logout therefore has to be enforced server-side:
 *
 *  - one session: revoke its refresh-token family (the token's `sid`). The
 *    cookie can no longer mint tokens, and authMiddleware / the relay reject
 *    every access token carrying that `sid` at once. The user's other sessions —
 *    another app, browser or device — are untouched.
 *  - all sessions (`?all=true`, or a token from before `sid` existed, which
 *    cannot name one session): stamp a cutoff on the user row so every token
 *    issued before it is rejected, and revoke every refresh token of the user.
 *    The cutoff is truncated to whole seconds because `iat` has second
 *    granularity: a fresh login in the same second must not be rejected as stale.
 */
auth.post("/logout", authMiddleware, async (c) => {
  const db = c.get("db");
  const userId = c.get("userId");
  const orgId = c.get("orgId");
  const sessionId = c.get("sessionId");
  const everywhere = c.req.query("all") === "true" || !sessionId;

  try {
    if (everywhere) {
      const cutoff = new Date(Math.floor(Date.now() / 1000) * 1000);
      await db
        .update(users)
        .set({ tokensValidAfter: cutoff, updatedAt: new Date() })
        .where(eq(users.id, userId));
      // Kill the refresh side too. Without this the access token would die at the
      // cutoff but the cookie could still mint new ones, so logout would not stick.
      await revokeAllForUser(db, userId);
    } else {
      await revokeFamily(db, sessionId);
    }
  } catch (error) {
    console.error("[auth] logout revocation failed:", error);
    // Surface the failure: reporting success would leave the caller believing
    // the session was ended when the token is still usable.
    return c.json({ error: "Logout failed, please try again" }, 503);
  }

  // Clear only THIS app's cookie for this org — another app, or another org in
  // this app, keeps its own session.
  clearCookie(c, refreshCookieName(c.req.url, appFromOrigin(c.req.header("Origin")), orgId));

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
  // hint we would not know which to rotate. The body is optional — see the
  // cookie choice below for what happens without one.
  let hintOrgId: string | null = null;
  // What the tab sent and how it resolved, for the outcome log only.
  let hint = "none";
  try {
    const body = await c.req.json<{ projectId?: string; orgId?: string; orgSlug?: string }>();
    if (body?.orgId) hint = `orgId:${body.orgId}`;
    else if (body?.projectId) hint = `projectId:${body.projectId}`;
    else if (body?.orgSlug) hint = `orgSlug:${body.orgSlug}`;
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
    // No/invalid body — treated as no hint.
  }
  if (hint !== "none" && !hintOrgId) hint += "(unresolved)";

  // Choose the cookie. Each app has its own (`<base>_<app>_<orgId>`), picked by
  // the app the request comes from — so runtime never sees the platform UI's
  // session, and the reverse, even for two users of the same org:
  //
  //   analytics (super-admin app) → the base cookie ONLY, whatever the body says.
  //                                 Someone who is both a super_admin and an org
  //                                 member must never get their org session here.
  //   other app, org hint         → that app's cookie for that org, nothing else
  //   other app, no hint          → that app's only org cookie; several is
  //                                 ambiguous, so sign in again rather than guess
  //   local, nothing else found   → the base cookie (local super_admin development)
  //
  // Runtime and platform never get the base cookie: it is shared across
  // *.superatom.ai, so falling back to it handed an org tab a super_admin token,
  // or logged it out when that session was dead.
  const app = appFromOrigin(c.req.header("Origin"));
  let usedCookie: string | null = null;
  if (app === "analytics") {
    usedCookie = refreshCookieName(c.req.url, app);
  } else if (hintOrgId) {
    usedCookie = refreshCookieName(c.req.url, app, hintOrgId);
  } else {
    const orgCookies = listAppOrgCookies(c, app);
    if (orgCookies.length > 1) {
      logRefreshOutcome(c, "rejected reason=multiple_org_sessions", { app, hint, usedCookie: null });
      // 401, not 409: clients already treat 401 as "show login" and anything
      // else as a transient error to retry.
      return c.json({ error: "Several organizations are signed in, please sign in again" }, 401);
    }
    if (orgCookies.length === 1) usedCookie = refreshCookieName(c.req.url, app, orgCookies[0]);
    else if (app === "local") usedCookie = refreshCookieName(c.req.url, app);
  }

  const presented = usedCookie ? readCookie(c, usedCookie) : undefined;
  if (!presented) {
    logRefreshOutcome(c, "rejected reason=no_cookie", { app, hint, usedCookie: null });
    return c.json({ error: "No refresh token" }, 401);
  }

  const result = await rotateRefreshToken(db, presented, c.req.header("User-Agent"));

  if (!result.ok) {
    logRefreshOutcome(c, `rejected reason=${result.reason}`, { app, hint, usedCookie });
    // Clear whichever cookie we read from so the browser stops replaying it.
    clearCookie(c, usedCookie!);
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
    logRefreshOutcome(c, "rejected reason=inactive", { app, hint, usedCookie, userId: result.userId });
    await revokeAllForUser(db, result.userId);
    clearCookie(c, usedCookie!);
    return c.json({ error: "Account is not active" }, 401);
  }

  // Rotate the cookie under this app and the user's actual org. If that is a
  // different name from the one we read (a session in the base cookie that turns
  // out to belong to an org user), drop the old one: it now holds a consumed
  // token, and replaying it later would trip reuse detection.
  setRefreshCookie(c, result.token, app, user.orgId);
  if (refreshCookieName(c.req.url, app, user.orgId) !== usedCookie) {
    clearCookie(c, usedCookie!);
  }

  // The refresh token has already rotated and its cookie is set on this
  // response, so a signing fault must still return THIS response (503, cookie
  // included). Throwing instead would drop the new cookie, leave the browser on
  // the consumed token, and trip reuse detection on its next refresh.
  let token: string;
  try {
    token = await mintAccessToken(user, c.env.JWT_SECRETS, result.familyId);
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
