/**
 * Refresh-token cookie.
 *
 * The refresh token lives in an httpOnly cookie rather than localStorage, which
 * is the entire point of the split: an XSS payload can read the access token
 * (15 minutes) but cannot read the refresh token (30 days). Putting both in
 * localStorage would keep rotation's detection benefit and throw away its
 * containment benefit.
 *
 * This works because every front-end is under superatom.ai, so a cookie scoped
 * to `.superatom.ai` is same-site for live.superatom.ai → sa-api.superatom.ai
 * and SameSite=Lax applies. Lax also blocks cross-site POSTs, which is the CSRF
 * control for /auth/refresh.
 *
 * One cookie per APP and org: `<base>_<app>_<orgId>`. A `.superatom.ai` cookie
 * is shared by every subdomain, so a name without the app made runtime and the
 * platform UI share one session: logging into one as another user switched the
 * other to that user, and logging in or out in one changed the other. With the
 * app in the name each app keeps its own session; the org suffix lets several
 * orgs coexist within one app. super_admin has no org and uses the unsuffixed
 * base name. See AUTH-AND-SDK-DESIGN.md §3.6.
 */

import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { REFRESH_TOKEN_TTL_MS } from "./refresh-tokens";

/** The front-end a session belongs to. */
export type AppKey = "runtime" | "platform" | "analytics" | "local";

/**
 * Base cookie name, scoped per environment.
 *
 * The Domain attribute below is `.superatom.ai`, which is shared by BOTH API
 * hosts — sa-api.superatom.ai and sa-api-dev.superatom.ai — while each has its
 * own database. A single base name therefore collides across environments: the
 * browser sends a dev-issued refresh token to prod, prod cannot find that row
 * in its own refresh_tokens table, and the user is signed out. Distinct bases
 * let the two environments hold sessions side by side.
 */
function refreshCookieBase(requestUrl: string): string {
  try {
    const host = new URL(requestUrl).hostname;
    // Any non-production API host gets its own base. Matching on the prod host
    // (rather than looking for "dev") means a new environment added later is
    // isolated by default instead of silently sharing prod's cookie.
    return host === "sa-api.superatom.ai" ? "sa_refresh" : "sa_refresh_dev";
  } catch {
    return "sa_refresh_dev";
  }
}

/**
 * The super-admin apps. Their refresh uses the base (super_admin) cookie only —
 * never an org cookie, even for someone who is also an org member.
 * (superadmin.superatom.ai has its own session and never calls /auth/refresh.)
 */
const SUPER_ADMIN_APP_HOSTS = new Set(["analytics.superatom.ai", "dev.analytics.superatom.ai"]);

function appFromHost(host: string): AppKey {
  if (SUPER_ADMIN_APP_HOSTS.has(host)) return "analytics";
  if (host === "platform.superatom.ai" || host.endsWith(".platform.superatom.ai")) return "platform";
  if (host === "localhost" || host === "127.0.0.1") return "local";
  // live., dev.live., and client subdomains (bluelinx.superatom.ai …).
  return "runtime";
}

/**
 * Which app a request comes from, by its Origin header — set by the browser, not
 * by page script. Requests without one (server-to-server) count as runtime.
 */
export function appFromOrigin(origin: string | null | undefined): AppKey {
  if (!origin) return "runtime";
  try {
    return appFromHost(new URL(origin).hostname);
  } catch {
    return "runtime";
  }
}

/**
 * Which app a front-end URL belongs to. Used by the SSO/SAML callbacks: there the
 * browser arrives from the identity provider, so Origin names the IdP (or is
 * absent), and the app is the verified front-end the user is being sent back to.
 */
export function appFromUrl(url: string | null | undefined): AppKey {
  if (!url) return "runtime";
  try {
    return appFromHost(new URL(url).hostname);
  } catch {
    return "runtime";
  }
}

/**
 * Cookie name for a session: `<base>_<app>_<orgId>`, or the bare base for
 * super_admin (no org).
 */
export function refreshCookieName(requestUrl: string, app: AppKey, orgId?: string | null): string {
  const base = refreshCookieBase(requestUrl);
  return orgId ? `${base}_${app}_${orgId}` : base;
}

/**
 * Restricting the path means the cookie is only attached to auth endpoints —
 * it is never sent on ordinary API calls, so it cannot leak through an
 * unrelated handler or a proxy log.
 */
const COOKIE_PATH = "/auth";

/**
 * Scope to the registrable domain so a cookie set on sa-api.superatom.ai is
 * sent from every subdomain front-end. Omitted on localhost: browsers reject a
 * Domain attribute that is not a suffix of the request host, which would
 * silently break local development.
 */
function cookieDomain(requestUrl: string): string | undefined {
  try {
    const host = new URL(requestUrl).hostname;
    return host.endsWith("superatom.ai") ? ".superatom.ai" : undefined;
  } catch {
    return undefined;
  }
}

/** Secure cookies are dropped over plaintext, so allow http only on localhost. */
function isSecureContext(requestUrl: string): boolean {
  try {
    return new URL(requestUrl).protocol === "https:";
  } catch {
    return true;
  }
}

/**
 * Attributes shared by set and delete. They must match, or the browser keeps the
 * original cookie and a logout silently fails to clear it.
 */
function cookieOptions(requestUrl: string) {
  return {
    path: COOKIE_PATH,
    domain: cookieDomain(requestUrl),
    secure: isSecureContext(requestUrl),
    sameSite: "Lax" as const,
  };
}

/** Set the refresh cookie for an app's session in an org (no org → super_admin). */
export function setRefreshCookie(c: any, token: string, app: AppKey, orgId?: string | null): void {
  setCookie(c, refreshCookieName(c.req.url, app, orgId), token, {
    ...cookieOptions(c.req.url),
    httpOnly: true,
    maxAge: Math.floor(REFRESH_TOKEN_TTL_MS / 1000),
  });

  // A browser that previously talked to the OTHER environment still holds its
  // cookie on the shared .superatom.ai domain. Drop the matching cookie from the
  // other environment on the way in, so a stale cross-environment token cannot be
  // presented on a later request.
  const otherBase = refreshCookieBase(c.req.url) === "sa_refresh" ? "sa_refresh_dev" : "sa_refresh";
  deleteCookie(c, orgId ? `${otherBase}_${app}_${orgId}` : otherBase, cookieOptions(c.req.url));

  // Tidy the pre-per-app, app-less org cookie (`<base>_<orgId>`). Nothing reads it
  // any more; drop it so it does not sit in the browser for another 30 days.
  if (orgId) deleteCookie(c, `${refreshCookieBase(c.req.url)}_${orgId}`, cookieOptions(c.req.url));
}

/** Read a refresh cookie by its full name. */
export function readCookie(c: any, name: string): string | undefined {
  return getCookie(c, name);
}

/** Clear a refresh cookie by its full name. */
export function clearCookie(c: any, name: string): void {
  deleteCookie(c, name, cookieOptions(c.req.url));
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Org ids of every refresh cookie of `app` this environment's browser sent.
 * Exact `<base>_<app>_<uuid>` match, so on prod (`sa_refresh`) dev cookies
 * (`sa_refresh_dev_…`) are not included.
 */
export function listAppOrgCookies(c: any, app: AppKey): string[] {
  const prefix = `${refreshCookieBase(c.req.url)}_${app}_`;
  return Object.keys(getCookie(c))
    .filter((name) => name.startsWith(prefix))
    .map((name) => name.slice(prefix.length))
    .filter((orgId) => UUID.test(orgId));
}
