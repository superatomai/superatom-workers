/**
 * First-party origin allowlist.
 *
 * Single source of truth for "is this one of our own front-ends". SSO redirect
 * validation (isAllowedRedirect, below) is now its only caller: the CORS policy
 * in index.ts answers ANY origin, because the SDK runs on customer domains we
 * do not know in advance. So do not read a request reaching a route as having
 * come from one of these — see the comment on that middleware.
 *
 * Nothing here has loosened. A redirect destination still has to be ours: the
 * SSO callback appends `?token=<jwt>` to the URL it is given, so this allowlist
 * is the entire protection against handing a live session to another site.
 *
 * Subdomains are matched at ANY depth, because the product uses several levels:
 *   runtime   — live.superatom.ai, <client>.superatom.ai, dev.live.superatom.ai
 *   admin     — platform.superatom.ai, <client>.platform.superatom.ai, dev.platform…
 *   analytics — analytics.superatom.ai
 *
 * The trailing `$` anchor is what makes this safe: `superatom.ai.evil.com` and
 * `evilsuperatom.ai` do not match.
 */

const FIRST_PARTY_ORIGIN = /^https:\/\/([a-z0-9-]+\.)+superatom\.ai$/i;
const LOCAL_DEV_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

export interface OriginEnv {
  PLATFORM_UI_URL?: string;
  ALLOWED_ORIGINS?: string;
}

/** Extra origins configured at deploy time, for non-superatom.ai front-ends. */
function configuredOrigins(env: OriginEnv): string[] {
  const extra = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((o: string) => o.trim())
    .filter(Boolean);

  if (env.PLATFORM_UI_URL) {
    try {
      extra.push(new URL(env.PLATFORM_UI_URL).origin);
    } catch {
      // Misconfigured binding — ignore it rather than allowing everything.
    }
  }

  return extra;
}

/** True when `origin` (scheme://host[:port]) is one of our own front-ends. */
export function isAllowedOrigin(origin: string, env: OriginEnv): boolean {
  if (!origin) return false;
  if (FIRST_PARTY_ORIGIN.test(origin) || LOCAL_DEV_ORIGIN.test(origin)) return true;
  return configuredOrigins(env).includes(origin);
}

/**
 * True when a full URL is safe to redirect a browser to after authentication.
 *
 * This matters more than a normal open redirect: the SSO callback appends the
 * session token to this URL (`?token=<jwt>`), so an unvalidated value hands a
 * working session to whoever controls the destination.
 *
 * Validates the PARSED origin rather than the raw string, so tricks that fool
 * naive prefix checks — `https://live.superatom.ai@evil.com` and userinfo or
 * backslash variants — are normalised by the URL parser first and then rejected.
 *
 * Relative and protocol-relative values (`/foo`, `//evil.com`) throw here
 * because no base is supplied, so they are rejected too: this parameter is
 * documented as an absolute front-end URL.
 */
export function isAllowedRedirect(target: string | undefined | null, env: OriginEnv): boolean {
  if (!target) return false;

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return false;
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") return false;

  return isAllowedOrigin(url.origin, env);
}
