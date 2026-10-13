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
 * ONE COOKIE PER SITE: `<base>_<site>`, where the site is the front-end the
 * request comes from (dev.live → `dev-live`, dev.platform → `dev-platform`,
 * bluelinx.superatom.ai → `bluelinx`). A `.superatom.ai` cookie is shared by
 * every subdomain, so the name is what keeps sessions apart:
 *
 *  - Earlier names shared one cookie across apps (`<base>_<orgId>`), so logging
 *    into one app as someone else switched the other app to that user.
 *  - Then names carried app AND org (`<base>_<app>_<orgId>`), so choosing a
 *    second org in the same app added a second cookie, and a new tab — which has
 *    no token to say which org it wants — could not tell them apart.
 *
 * Keyed by site alone, each site has exactly one session: signing in, or picking
 * another org, replaces it; a new tab always finds its site's single cookie.
 * The super-admin app (analytics) keeps the bare base name. See
 * AUTH-AND-SDK-DESIGN.md §3.6.
 */

import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { REFRESH_TOKEN_TTL_MS } from "./refresh-tokens";

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
 * The super-admin app. Its session uses the bare base cookie and nothing else —
 * never a site cookie, even for someone who is also an org member.
 * (superadmin.superatom.ai has its own session and never calls /auth/refresh.)
 */
export const SUPER_ADMIN_SITE = "analytics";
const SUPER_ADMIN_APP_HOSTS = new Set(["analytics.superatom.ai", "dev.analytics.superatom.ai"]);

function siteFromParsed(url: URL): string {
  const host = url.hostname.toLowerCase();
  if (SUPER_ADMIN_APP_HOSTS.has(host)) return SUPER_ADMIN_SITE;
  // Local front-ends differ only by port (runtime and platform side by side).
  if (host === "localhost" || host === "127.0.0.1") return `local-${url.port || "80"}`;
  const name = host.endsWith(".superatom.ai") ? host.slice(0, -".superatom.ai".length) : host;
  return name.replace(/[^a-z0-9-]/g, "-") || "root";
}

/**
 * The site a request comes from, by its Origin header — set by the browser, not
 * by page script. Requests without one (server-to-server) get a site of their
 * own that no browser session uses.
 */
export function siteFromOrigin(origin: string | null | undefined): string {
  if (!origin) return "none";
  try {
    return siteFromParsed(new URL(origin));
  } catch {
    return "none";
  }
}

/**
 * The site a front-end URL belongs to. Used by the SSO/SAML callbacks: there the
 * browser arrives from the identity provider, so Origin names the IdP (or is
 * absent), and the site is the verified front-end the user is being sent back to.
 */
export function siteFromUrl(url: string | null | undefined): string {
  if (!url) return "none";
  try {
    return siteFromParsed(new URL(url));
  } catch {
    return "none";
  }
}

/** Cookie name for a site's session: `<base>_<site>`; the super-admin app uses `<base>`. */
export function refreshCookieName(requestUrl: string, site: string): string {
  const base = refreshCookieBase(requestUrl);
  return site === SUPER_ADMIN_SITE ? base : `${base}_${site}`;
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

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/**
 * Names used by earlier cookie schemes, in this environment: `<base>_<orgId>` and
 * `<base>_<app>_<orgId>`. Nothing reads them any more; they are deleted whenever
 * a session cookie is set so they do not linger in the browser for 30 days.
 */
function obsoleteCookieNames(c: any): string[] {
  const base = refreshCookieBase(c.req.url);
  const obsolete = new RegExp(`^${base}_(?:(?:runtime|platform|local)_)?${UUID}$`, "i");
  return Object.keys(getCookie(c)).filter((name) => obsolete.test(name));
}

/** Set (replace) the site's refresh cookie. */
export function setRefreshCookie(c: any, token: string, site: string): void {
  const options = cookieOptions(c.req.url);
  setCookie(c, refreshCookieName(c.req.url, site), token, {
    ...options,
    httpOnly: true,
    maxAge: Math.floor(REFRESH_TOKEN_TTL_MS / 1000),
  });

  // A browser that previously talked to the OTHER environment still holds its
  // cookie on the shared .superatom.ai domain. Drop the matching cookie from the
  // other environment on the way in, so a stale cross-environment token cannot be
  // presented on a later request.
  const otherBase = refreshCookieBase(c.req.url) === "sa_refresh" ? "sa_refresh_dev" : "sa_refresh";
  deleteCookie(c, site === SUPER_ADMIN_SITE ? otherBase : `${otherBase}_${site}`, options);

  for (const name of obsoleteCookieNames(c)) deleteCookie(c, name, options);
}

/** Read a refresh cookie by its full name. */
export function readCookie(c: any, name: string): string | undefined {
  return getCookie(c, name);
}

/** Clear a refresh cookie by its full name. */
export function clearCookie(c: any, name: string): void {
  deleteCookie(c, name, cookieOptions(c.req.url));
}
