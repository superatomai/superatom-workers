import { Hono } from "hono";
import { eq, and, sql } from "drizzle-orm";
import { SignJWT, jwtVerify, createRemoteJWKSet } from "jose";
import { users, organizations, ssoConfigs } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly } from "../middleware/auth";
import {
  generateRequestId,
  buildAuthnRequest,
  deflateAndEncode,
} from "../lib/saml";
import { isAllowedRedirect } from "../lib/origins";
import { mintAccessToken } from "../lib/access-token";
import { issueRefreshToken } from "../lib/refresh-tokens";
import { setRefreshCookie } from "../lib/refresh-cookie";

const sso = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// ─── Types ──────────────────────────────────────────────

interface OIDCDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  issuer: string;
}

interface OIDCTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in?: number;
}

// ─── Helpers ────────────────────────────────────────────

/**
 * Fetch OIDC discovery document from the issuer's well-known endpoint.
 */
async function fetchDiscovery(issuerUrl: string): Promise<OIDCDiscovery> {
  const url = issuerUrl.replace(/\/+$/, "") + "/.well-known/openid-configuration";
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch OIDC discovery from ${url}: ${res.status}`);
  }
  return res.json();
}

/**
 * Generate a signed state JWT containing orgId, nonce, and optional redirectTo.
 * Used to maintain state across the OIDC redirect flow (stateless Workers).
 */
async function createStateToken(
  orgId: string,
  nonce: string,
  jwtSecret: string,
  redirectTo?: string
): Promise<string> {
  const secret = new TextEncoder().encode(jwtSecret);
  const claims: Record<string, string> = { orgId, nonce };
  if (redirectTo) {
    claims.redirectTo = redirectTo;
  }
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(secret);
}

/**
 * Verify and decode the state JWT.
 */
async function verifyStateToken(
  state: string,
  jwtSecret: string
): Promise<{ orgId: string; nonce: string; redirectTo?: string }> {
  const secret = new TextEncoder().encode(jwtSecret);
  const { payload } = await jwtVerify(state, secret);
  return {
    orgId: payload.orgId as string,
    nonce: payload.nonce as string,
    redirectTo: payload.redirectTo as string | undefined,
  };
}

/**
 * Generate a random string for use as a nonce.
 */
function generateNonce(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Hash a password using SHA-256 (Web Crypto API).
 */
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Public SSO Endpoints ───────────────────────────────

/**
 * GET /auth/sso/authorize?org_slug=acme&redirect_to=https://app.example.com/sso-callback
 * Initiates the OIDC authorization code flow.
 * Redirects the browser to the enterprise IdP login page.
 *
 * @param org_slug - The organization's slug (required)
 * @param redirect_to - The frontend URL to redirect to after SSO (optional, falls back to PLATFORM_UI_URL)
 */
sso.get("/authorize", async (c) => {
  const db = c.get("db");
  const orgSlug = c.req.query("org_slug");
  const redirectTo = c.req.query("redirect_to");

  if (!orgSlug) {
    return c.json({ error: "org_slug query parameter is required" }, 400);
  }

  // Reject a hostile redirect target before any IdP round-trip. This is not a
  // plain open redirect: the callback appends the session token to this URL
  // (`?token=<jwt>`), so an unvalidated value hands a fully authenticated
  // session to whoever controls the destination — after the victim completes a
  // genuine login at their real IdP.
  if (redirectTo && !isAllowedRedirect(redirectTo, c.env)) {
    return c.json({ error: "redirect_to is not an allowed URL" }, 400);
  }

  // Look up org by slug
  const [org] = await db
    .select()
    .from(organizations)
    .where(eq(organizations.slug, orgSlug))
    .limit(1);

  if (!org) {
    return c.json({ error: "Organization not found" }, 404);
  }

  // Look up SSO config for this org
  const [config] = await db
    .select()
    .from(ssoConfigs)
    .where(and(eq(ssoConfigs.orgId, org.id), eq(ssoConfigs.isActive, true)))
    .limit(1);

  if (!config) {
    return c.json({ error: "SSO is not configured for this organization" }, 404);
  }

  // ─── Route based on protocol ───
  if (config.protocol === "saml") {
    // Delegate to SAML login flow
    if (!config.samlIdpSsoUrl) {
      return c.json({ error: "SAML SSO is misconfigured for this organization" }, 500);
    }

    const requestId = generateRequestId();
    const baseUrl = new URL(c.req.url);
    const acsUrl = `${baseUrl.protocol}//${baseUrl.host}/auth/sso/saml/acs`;
    const spEntityId = `${baseUrl.protocol}//${baseUrl.host}/auth/sso/saml/metadata`;

    const authnRequest = buildAuthnRequest({
      requestId,
      acsUrl,
      spEntityId,
      idpSsoUrl: config.samlIdpSsoUrl,
    });

    // Create RelayState JWT
    const secret = new TextEncoder().encode(c.env.JWT_SECRET);
    const claims: Record<string, string> = { orgId: org.id, requestId };
    if (redirectTo) claims.redirectTo = redirectTo;
    const relayState = await new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(secret);

    const encodedRequest = await deflateAndEncode(authnRequest);

    const samlRedirectUrl = new URL(config.samlIdpSsoUrl);
    samlRedirectUrl.searchParams.set("SAMLRequest", decodeURIComponent(encodedRequest));
    samlRedirectUrl.searchParams.set("RelayState", relayState);

    return c.redirect(samlRedirectUrl.toString());
  }

  // ─── OIDC Flow (existing) ───
  if (!config.issuerUrl || !config.clientId) {
    return c.json({ error: "OIDC SSO is misconfigured for this organization" }, 500);
  }

  // Fetch OIDC discovery
  const discovery = await fetchDiscovery(config.issuerUrl);

  // Generate state and nonce (embed redirectTo in state so we know where to send the user back)
  const nonce = generateNonce();
  const state = await createStateToken(org.id, nonce, c.env.JWT_SECRET, redirectTo);

  // Build the callback URL (points back to this SA-API worker)
  const callbackUrl = new URL(c.req.url);
  callbackUrl.pathname = "/auth/sso/callback";
  callbackUrl.search = "";

  // Build authorization URL
  const authUrl = new URL(discovery.authorization_endpoint);
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("redirect_uri", callbackUrl.toString());
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", config.scopes || "openid email profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("nonce", nonce);

  return c.redirect(authUrl.toString());
});

/**
 * Minimal escaping for text interpolated into the small HTML error page below.
 */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Rendered in place (no redirect) when an SSO callback fails and there is no
 * verified, allow-listed front-end to send the browser back to. Falling back
 * to one fixed URL here would mean guessing a single org's domain for every
 * org's failed logins — instead of guessing, just say what happened.
 */
function ssoErrorPage(message: string): Response {
  return new Response(
    `<!DOCTYPE html>
<html>
  <head><meta charset="utf-8"><title>Sign-in failed</title></head>
  <body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; text-align: center;">
    <h2>Sign-in failed</h2>
    <p>${escapeHtml(message)}</p>
    <p>Please close this tab and try signing in again from your application.</p>
  </body>
</html>`,
    { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

/**
 * GET /auth/sso/callback?code=...&state=...
 * Handles the IdP redirect after user authentication.
 * Exchanges the authorization code for tokens, creates/matches user, issues JWT.
 */
sso.get("/callback", async (c) => {
  const db = c.get("db");
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");
  const errorDescription = c.req.query("error_description");

  // Decode `state` up front so we know where to send the user back to even
  // when the IdP reports an error — it echoes `state` back on error redirects
  // too, so it is just as recoverable here as on the success path. If it
  // can't be recovered (missing, expired, tampered), we have no way to know
  // which org's front-end this login was for, so every error below renders
  // an in-place message via respondError instead of guessing a destination.
  let stateData: { orgId: string; nonce: string; redirectTo?: string } | null = null;
  if (state) {
    try {
      stateData = await verifyStateToken(state, c.env.JWT_SECRET);
    } catch {
      // Expired/invalid/tampered state — treated as unrecoverable below.
    }
  }

  // Re-validate on the way out as well as on the way in. The state token is
  // signed, which proves WE minted it — not that its contents are safe, since
  // the value came from a query parameter in the first place. Re-checking here
  // makes any state token already issued with a hostile URL inert.
  const safeRedirectTo =
    stateData?.redirectTo && isAllowedRedirect(stateData.redirectTo, c.env)
      ? stateData.redirectTo
      : null;

  const respondError = (msg: string) =>
    safeRedirectTo
      ? c.redirect(`${safeRedirectTo}?error=${encodeURIComponent(msg)}`)
      : ssoErrorPage(msg);

  if (error) {
    return respondError(errorDescription || error);
  }

  if (!code || !stateData) {
    return respondError("Missing code or state parameter");
  }

  const { orgId, nonce } = stateData;

  try {
    // Look up SSO config for this org
    const [config] = await db
      .select()
      .from(ssoConfigs)
      .where(and(eq(ssoConfigs.orgId, orgId), eq(ssoConfigs.isActive, true)))
      .limit(1);

    if (!config) {
      return respondError("SSO configuration not found");
    }

    if (!config.issuerUrl || !config.clientId || !config.clientSecret) {
      return respondError("OIDC SSO is misconfigured");
    }

    // Fetch OIDC discovery
    const discovery = await fetchDiscovery(config.issuerUrl);

    // Build callback URL (same as in /authorize)
    const callbackUrl = new URL(c.req.url);
    callbackUrl.pathname = "/auth/sso/callback";
    callbackUrl.search = "";

    // Exchange code for tokens
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: callbackUrl.toString(),
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error("[SSO] Token exchange failed:", errBody);
      console.error("[SSO] redirect_uri used:", callbackUrl.toString());
      return respondError("Token exchange failed: " + errBody);
    }

    const tokens: OIDCTokenResponse = await tokenRes.json();

    // Validate the id_token using the IdP's JWKS
    const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
    const { payload: idToken } = await jwtVerify(tokens.id_token, jwks, {
      issuer: discovery.issuer,
      audience: config.clientId,
    });

    // Verify nonce
    if (idToken.nonce !== nonce) {
      return respondError("Invalid nonce");
    }

    // Extract user identity from id_token
    const sub = idToken.sub as string;
    // Stored as the IdP returns it — the lookup below and login's own
    // comparison are both case-insensitive, so this doesn't need normalizing.
    const email = (idToken.email as string) || "";
    const name =
      (idToken.name as string) ||
      `${idToken.given_name || ""} ${idToken.family_name || ""}`.trim() ||
      email.split("@")[0];

    if (!sub || !email) {
      return respondError("IdP did not return email or subject");
    }

    // Find or create user
    // First try by ssoSubject + orgId
    let [user] = await db
      .select()
      .from(users)
      .where(and(eq(users.orgId, orgId), eq(users.ssoSubject, sub)))
      .limit(1);

    if (!user) {
      // Try by email scoped to this org
      [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.orgId, orgId), sql`lower(${users.email}) = lower(${email})`))
        .limit(1);

      if (user) {
        // Existing user — link their SSO subject
        await db
          .update(users)
          .set({ ssoSubject: sub, updatedAt: new Date() })
          .where(eq(users.id, user.id));
      } else {
        // New user — auto-provision
        const [newUser] = await db
          .insert(users)
          .values({
            orgId,
            email,
            name,
            ssoSubject: sub,
            role: "member",
            isActive: true,
          })
          .returning();
        user = newUser;
      }
    }

    if (!user.isActive) {
      return respondError("Account is deactivated");
    }

    // Issue SA-API JWT, signed with the user's org secret (lib/org-secrets.ts)
    const saToken = await mintAccessToken(user, c.env.JWT_SECRETS);

    // The refresh token goes in an httpOnly cookie; only the 15-minute access
    // token travels in the URL. That bounds the damage if this redirect leaks
    // into browser history or an access log.
    const refresh = await issueRefreshToken(db, user.id, {
      userAgent: c.req.header("User-Agent"),
    });
    setRefreshCookie(c, refresh.token, user.orgId ?? undefined);

    if (!safeRedirectTo) {
      // Login succeeded but there is no verified destination to deliver the
      // session token to — never hand a live token to a guessed URL.
      return ssoErrorPage(
        "Signed in successfully, but no valid return address was provided. Please return to your application."
      );
    }

    // Redirect to the frontend that initiated SSO with the token
    return c.redirect(`${safeRedirectTo}?token=${saToken}`);
  } catch (err: any) {
    console.error("[SSO] Callback error:", err);
    return respondError("SSO authentication failed");
  }
});

// ─── Admin SSO Config Endpoints ─────────────────────────

/**
 * GET /auth/sso/config
 * Get the SSO configuration for the current user's org.
 */
sso.get("/config", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const orgId = c.get("orgId");
  if (!orgId) {
    return c.json({ error: "SSO config requires an organization context" }, 400);
  }

  const [config] = await db
    .select({
      id: ssoConfigs.id,
      provider: ssoConfigs.provider,
      protocol: ssoConfigs.protocol,
      clientId: ssoConfigs.clientId,
      issuerUrl: ssoConfigs.issuerUrl,
      scopes: ssoConfigs.scopes,
      samlIdpEntityId: ssoConfigs.samlIdpEntityId,
      samlIdpSsoUrl: ssoConfigs.samlIdpSsoUrl,
      isActive: ssoConfigs.isActive,
      createdAt: ssoConfigs.createdAt,
      updatedAt: ssoConfigs.updatedAt,
    })
    .from(ssoConfigs)
    .where(eq(ssoConfigs.orgId, orgId))
    .limit(1);

  if (!config) {
    return c.json({ configured: false }, 200);
  }

  return c.json({ configured: true, ...config });
});

/**
 * POST /auth/sso/config
 * Create or update SSO configuration for the current user's org.
 */
sso.post("/config", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const orgId = c.get("orgId");
  if (!orgId) {
    return c.json({ error: "SSO config requires an organization context" }, 400);
  }
  const body = await c.req.json<{
    // Common
    provider: "microsoft_entra" | "okta" | "generic_oidc" | "saml";
    protocol?: "oidc" | "saml";
    // OIDC fields
    clientId?: string;
    clientSecret?: string;
    issuerUrl?: string;
    scopes?: string;
    // SAML fields
    samlIdpEntityId?: string;
    samlIdpSsoUrl?: string;
    samlIdpCertificates?: string[];
  }>();

  const protocol = body.protocol || (body.provider === "saml" ? "saml" : "oidc");

  // Validate based on protocol
  if (protocol === "saml") {
    if (!body.samlIdpEntityId || !body.samlIdpSsoUrl || !body.samlIdpCertificates?.length) {
      return c.json(
        { error: "samlIdpEntityId, samlIdpSsoUrl, and samlIdpCertificates are required for SAML" },
        400
      );
    }

    // Validate SSO URL is HTTPS
    try {
      const ssoUrl = new URL(body.samlIdpSsoUrl);
      if (ssoUrl.protocol !== "https:") {
        return c.json({ error: "samlIdpSsoUrl must use HTTPS" }, 400);
      }
    } catch {
      return c.json({ error: "samlIdpSsoUrl is not a valid URL" }, 400);
    }
  } else {
    // OIDC validation
    if (!body.provider || !body.clientId || !body.clientSecret || !body.issuerUrl) {
      return c.json(
        { error: "provider, clientId, clientSecret, and issuerUrl are required for OIDC" },
        400
      );
    }

    // Validate the issuer URL by fetching discovery
    try {
      await fetchDiscovery(body.issuerUrl);
    } catch {
      return c.json(
        { error: "Could not reach OIDC discovery endpoint at the provided issuerUrl" },
        400
      );
    }
  }

  // Check if config already exists
  const [existing] = await db
    .select({ id: ssoConfigs.id })
    .from(ssoConfigs)
    .where(eq(ssoConfigs.orgId, orgId))
    .limit(1);

  const configData =
    protocol === "saml"
      ? {
          provider: body.provider as "saml",
          protocol: "saml" as const,
          samlIdpEntityId: body.samlIdpEntityId!,
          samlIdpSsoUrl: body.samlIdpSsoUrl!,
          samlIdpCertificates: body.samlIdpCertificates!,
          // Clear OIDC fields
          clientId: null,
          clientSecret: null,
          issuerUrl: null,
          scopes: null,
          isActive: true,
          updatedAt: new Date(),
        }
      : {
          provider: body.provider as "microsoft_entra" | "okta" | "generic_oidc",
          protocol: "oidc" as const,
          clientId: body.clientId!,
          clientSecret: body.clientSecret!,
          issuerUrl: body.issuerUrl!,
          scopes: body.scopes || "openid email profile",
          // Clear SAML fields
          samlIdpEntityId: null,
          samlIdpSsoUrl: null,
          samlIdpCertificates: null,
          isActive: true,
          updatedAt: new Date(),
        };

  if (existing) {
    const [updated] = await db
      .update(ssoConfigs)
      .set(configData)
      .where(eq(ssoConfigs.id, existing.id))
      .returning({
        id: ssoConfigs.id,
        provider: ssoConfigs.provider,
        protocol: ssoConfigs.protocol,
        clientId: ssoConfigs.clientId,
        issuerUrl: ssoConfigs.issuerUrl,
        scopes: ssoConfigs.scopes,
        samlIdpEntityId: ssoConfigs.samlIdpEntityId,
        samlIdpSsoUrl: ssoConfigs.samlIdpSsoUrl,
        isActive: ssoConfigs.isActive,
      });

    return c.json({ message: "SSO configuration updated", ...updated });
  }

  const [created] = await db
    .insert(ssoConfigs)
    .values({ orgId, ...configData })
    .returning({
      id: ssoConfigs.id,
      provider: ssoConfigs.provider,
      protocol: ssoConfigs.protocol,
      clientId: ssoConfigs.clientId,
      issuerUrl: ssoConfigs.issuerUrl,
      scopes: ssoConfigs.scopes,
      samlIdpEntityId: ssoConfigs.samlIdpEntityId,
      samlIdpSsoUrl: ssoConfigs.samlIdpSsoUrl,
      isActive: ssoConfigs.isActive,
    });

  return c.json({ message: "SSO configuration created", ...created }, 201);
});

/**
 * DELETE /auth/sso/config
 * Remove SSO configuration for the current user's org.
 */
sso.delete("/config", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const orgId = c.get("orgId");
  if (!orgId) {
    return c.json({ error: "SSO config requires an organization context" }, 400);
  }

  const result = await db
    .delete(ssoConfigs)
    .where(eq(ssoConfigs.orgId, orgId))
    .returning({ id: ssoConfigs.id });

  if (result.length === 0) {
    return c.json({ error: "No SSO configuration found" }, 404);
  }

  return c.json({ message: "SSO configuration deleted" });
});

export default sso;
