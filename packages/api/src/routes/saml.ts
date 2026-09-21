import { Hono } from "hono";
import { eq, and, sql } from "drizzle-orm";
import { SignJWT, jwtVerify } from "jose";
import { users, organizations, ssoConfigs } from "../db/schema";
import type { Env, AppVariables } from "../types";
import {
  generateRequestId,
  buildAuthnRequest,
  deflateAndEncode,
  buildSpMetadata,
  validateSamlResponse,
  parseIdpMetadata,
  SamlError,
} from "../lib/saml";
import { authMiddleware, adminOnly } from "../middleware/auth";
import { isAllowedRedirect } from "../lib/origins";
import { mintAccessToken } from "../lib/access-token";
import { issueRefreshToken } from "../lib/refresh-tokens";
import { setRefreshCookie, appFromUrl } from "../lib/refresh-cookie";
import { DOMParser } from"@xmldom/xmldom";


const saml = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// ─── Helpers ────────────────────────────────────────────

/**
 * Get the base URL of the SA-API from the current request.
 */
function getBaseUrl(reqUrl: string): string {
  const url = new URL(reqUrl);
  return `${url.protocol}//${url.host}`;
}

function getAcsUrl(reqUrl: string): string {
  return `${getBaseUrl(reqUrl)}/auth/sso/saml/acs`;
}

function getSpEntityId(reqUrl: string): string {
  return `${getBaseUrl(reqUrl)}/auth/sso/saml/metadata`;
}

/**
 * Create a RelayState JWT for SP-initiated SAML flow.
 */
async function createSamlStateToken(
  orgId: string,
  requestId: string,
  jwtSecret: string,
  redirectTo?: string
): Promise<string> {
  const secret = new TextEncoder().encode(jwtSecret);
  const claims: Record<string, string> = { orgId, requestId };
  if (redirectTo) claims.redirectTo = redirectTo;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(secret);
}

/**
 * Verify and decode the RelayState JWT.
 */
async function verifySamlStateToken(
  state: string,
  jwtSecret: string
): Promise<{ orgId: string; requestId: string; redirectTo?: string }> {
  const secret = new TextEncoder().encode(jwtSecret);
  const { payload } = await jwtVerify(state, secret);
  return {
    orgId: payload.orgId as string,
    requestId: payload.requestId as string,
    redirectTo: payload.redirectTo as string | undefined,
  };
}

// ─── Public Endpoints ───────────────────────────────────

/**
 * GET /auth/sso/saml/metadata
 * Returns SP metadata XML for IdP configuration.
 */
saml.get("/metadata", (c) => {
  const acsUrl = getAcsUrl(c.req.url);
  const spEntityId = getSpEntityId(c.req.url);
  const xml = buildSpMetadata(acsUrl, spEntityId);

  return c.body(xml, 200, {
    "Content-Type": "application/xml",
  });
});

/**
 * GET /auth/sso/saml/login?org_slug=xxx&redirect_to=xxx
 * Initiates SP-initiated SAML login flow.
 */
saml.get("/login", async (c) => {
  const db = c.get("db");
  const orgSlug = c.req.query("org_slug");
  const redirectTo = c.req.query("redirect_to");

  if (!orgSlug) {
    return c.json({ error: "org_slug query parameter is required" }, 400);
  }

  // Reject a hostile redirect target before the IdP round-trip — the ACS
  // handler appends the session token to this URL. Only affects the
  // SP-initiated flow; IdP-initiated logins carry no RelayState and never
  // reach this route.
  if (redirectTo && !isAllowedRedirect(redirectTo, c.env)) {
    return c.json({ error: "redirect_to is not an allowed URL" }, 400);
  }

  // Look up org
  const [org] = await db
    .select()
    .from(organizations)
    .where(eq(organizations.slug, orgSlug))
    .limit(1);

  if (!org) {
    return c.json({ error: "Organization not found" }, 404);
  }

  // Look up SAML SSO config
  const [config] = await db
    .select()
    .from(ssoConfigs)
    .where(
      and(
        eq(ssoConfigs.orgId, org.id),
        eq(ssoConfigs.isActive, true),
        eq(ssoConfigs.protocol, "saml")
      )
    )
    .limit(1);

  if (!config || !config.samlIdpSsoUrl) {
    return c.json({ error: "SAML SSO is not configured for this organization" }, 404);
  }

  // Generate AuthnRequest
  const requestId = generateRequestId();
  const acsUrl = getAcsUrl(c.req.url);
  const spEntityId = getSpEntityId(c.req.url);

  const authnRequest = buildAuthnRequest({
    requestId,
    acsUrl,
    spEntityId,
    idpSsoUrl: config.samlIdpSsoUrl,
  });

  // Create RelayState JWT
  const relayState = await createSamlStateToken(
    org.id,
    requestId,
    c.env.JWT_SECRET,
    redirectTo
  );

  // DEFLATE + Base64 + URL-encode
  const encodedRequest = await deflateAndEncode(authnRequest);

  // Build redirect URL
  const redirectUrl = new URL(config.samlIdpSsoUrl);
  redirectUrl.searchParams.set("SAMLRequest", decodeURIComponent(encodedRequest));
  redirectUrl.searchParams.set("RelayState", relayState);

  return c.redirect(redirectUrl.toString());
});

/**
 * POST /auth/sso/saml/acs
 * Assertion Consumer Service — handles both SP-initiated and IdP-initiated flows.
 */

function extractIssuerFromSamlResponse(xmlString: string): string|null {
  const doc = new DOMParser().parseFromString(xmlString, "application/xml");
  const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
  // Use namespace-aware lookup to match <saml:Issuer>, <saml2:Issuer>, etc.
  const issuerNodes = doc.getElementsByTagNameNS(SAML_ASSERTION_NS, "Issuer");
  const issuer = issuerNodes[0]?.textContent?.trim() || null;
  return issuer;
}

saml.post("/acs", async (c) => {
  const db = c.get("db");
  const fallbackUrl = c.env.PLATFORM_UI_URL || "";
  const defaultRedirect = `${fallbackUrl}/sso-callback`;

  // Determine the redirect URL for errors (updated as we learn more)
  let errorRedirectUrl = defaultRedirect;

  try {
    // Parse form body
    const body = await c.req.parseBody();
    const samlResponseB64 = body["SAMLResponse"] as string | undefined;
    const relayState = body["RelayState"] as string | undefined;

    if (!samlResponseB64) {
      return c.redirect(
        `${errorRedirectUrl}?error=${encodeURIComponent("Missing SAMLResponse in the request")}`
      );
    }

    // Base64 decode the SAML Response
    const samlResponseXml = atob(samlResponseB64);

    const acsUrl = getAcsUrl(c.req.url);
    const spEntityId = getSpEntityId(c.req.url);

    let orgId: string;
    let expectedRequestId: string | undefined;

    if (relayState) {
      // ─── SP-Initiated Flow ───
      try {
        const stateData = await verifySamlStateToken(relayState, c.env.JWT_SECRET);
        orgId = stateData.orgId;
        expectedRequestId = stateData.requestId;
        // Re-validate: a signed RelayState proves WE minted it, not that its
        // contents are safe — the value originally came from a query parameter.
        // Anything not allowlisted falls back to the platform URL.
        if (stateData.redirectTo && isAllowedRedirect(stateData.redirectTo, c.env)) {
          errorRedirectUrl = stateData.redirectTo;
        }
      } catch {
        return c.redirect(
          `${errorRedirectUrl}?error=${encodeURIComponent("Invalid or expired SSO session")}`
        );
      }
    } else {
      // ─── IdP-Initiated Flow ───
      // Extract Issuer from the SAML Response to identify the org
      // const issuerMatch = samlResponseXml.match(
      //   /<saml[p]?:Issuer[^>]*>([^<]+)<\/saml[p]?:Issuer>/
      // );
      const responseIssuer = extractIssuerFromSamlResponse(samlResponseXml);
      
      console.log("Extracted Issuer from SAML Response:", responseIssuer);
      if (!responseIssuer) {
        return c.redirect(
          `${errorRedirectUrl}?error=${encodeURIComponent("Could not determine identity provider from SAML Response")}`
        );
      }

      // Look up config by IdP entity ID
      const [config] = await db
        .select()
        .from(ssoConfigs)
        .where(
          and(
            eq(ssoConfigs.samlIdpEntityId, responseIssuer),
            eq(ssoConfigs.isActive, true),
            eq(ssoConfigs.protocol, "saml")
          )
        )
        .limit(1);

      if (!config) {
        return c.redirect(
          `${errorRedirectUrl}?error=${encodeURIComponent("SSO is not configured for this organization")}`
        );
      }

      orgId = config.orgId;
    }

    // Load SSO config for the org
    const [config] = await db
      .select()
      .from(ssoConfigs)
      .where(
        and(
          eq(ssoConfigs.orgId, orgId),
          eq(ssoConfigs.isActive, true),
          eq(ssoConfigs.protocol, "saml")
        )
      )
      .limit(1);

    if (!config || !config.samlIdpCertificates) {
      return c.redirect(
        `${errorRedirectUrl}?error=${encodeURIComponent("SSO is not configured for this organization")}`
      );
    }

    const certificates = config.samlIdpCertificates as string[];

    // Validate the SAML Response (signature, conditions, audience, identity)
    const { identity } = await validateSamlResponse({
      samlResponseXml,
      certificates,
      expectedAcsUrl: acsUrl,
      expectedAudience: spEntityId,
      expectedRequestId,
    });

    // ─── Find or Create User (same logic as OIDC) ───

    // First try by ssoSubject + orgId
    let [user] = await db
      .select()
      .from(users)
      .where(and(eq(users.orgId, orgId), eq(users.ssoSubject, identity.ssoSubject)))
      .limit(1);

    if (!user) {
      // Try by email scoped to this org
      [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.orgId, orgId), sql`lower(${users.email}) = lower(${identity.email})`))
        .limit(1);

      if (user) {
        // Existing user — link their SSO subject
        await db
          .update(users)
          .set({ ssoSubject: identity.ssoSubject, updatedAt: new Date() })
          .where(eq(users.id, user.id));
      } else {
        // New user — auto-provision
        const [newUser] = await db
          .insert(users)
          .values({
            orgId,
            email: identity.email,
            name: identity.name,
            ssoSubject: identity.ssoSubject,
            role: "member",
            isActive: true,
          })
          .returning();
        user = newUser;
      }
    }

    if (!user.isActive) {
      return c.redirect(
        `${errorRedirectUrl}?error=${encodeURIComponent("Account is deactivated")}`
      );
    }

    // Issue SA-API JWT, signed with the user's org secret (lib/org-secrets.ts)
    // One id for this login session: the JWT's `sid` and the refresh family.
    const sessionId = crypto.randomUUID();
    const saToken = await mintAccessToken(user, c.env.JWT_SECRETS, sessionId);

    // Refresh token in an httpOnly cookie; only the 15-minute access token goes
    // in the URL below. Applies to both the SP-initiated and IdP-initiated
    // flows, which both terminate here.
    const refresh = await issueRefreshToken(db, user.id, {
      familyId: sessionId,
      userAgent: c.req.header("User-Agent"),
    });
    // Redirect target: the verified RelayState front-end (SP-initiated) or the
    // platform default (IdP-initiated). The IdP posts here, so Origin names the
    // IdP, not our app — the front-end we send the user back to decides the cookie.
    const frontendCallbackUrl = relayState ? errorRedirectUrl : defaultRedirect;
    setRefreshCookie(c, refresh.token, appFromUrl(frontendCallbackUrl), user.orgId);

    // Redirect to frontend with token
    return c.redirect(`${frontendCallbackUrl}?token=${saToken}`);
  } catch (err: any) {
    console.error("[SAML] ACS error:", err);

    const message =
      err instanceof SamlError
        ? err.message
        : "SAML authentication failed";

    return c.redirect(`${errorRedirectUrl}?error=${encodeURIComponent(message)}`);
  }
});

// ─── Admin Endpoints ────────────────────────────────────

/**
 * POST /auth/sso/saml/from-metadata
 * Parse a SAML metadata URL and extract IdP configuration.
 */
saml.post("/from-metadata", authMiddleware, adminOnly, async (c) => {
  const body = await c.req.json<{ metadataUrl: string }>();

  if (!body.metadataUrl) {
    return c.json({ error: "metadataUrl is required" }, 400);
  }

  try {
    const res = await fetch(body.metadataUrl);
    if (!res.ok) {
      return c.json(
        { error: `Failed to fetch metadata: ${res.status} ${res.statusText}` },
        400
      );
    }

    const metadataXml = await res.text();
    const result = parseIdpMetadata(metadataXml);

    return c.json(result);
  } catch (err: any) {
    return c.json({ error: `Failed to parse metadata: ${err.message}` }, 400);
  }
});

export default saml;
