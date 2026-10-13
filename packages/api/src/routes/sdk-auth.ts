/**
 * SDK sign-in — exchange a customer-signed JWT for a Superatom access token.
 *
 * POST /auth/sdk/exchange { projectId, token } → { token, user }
 *
 * A customer embedding the SDK has its own login. Its backend signs a
 * short-lived JWT for its user with the org's secret (`org:<orgId>`, the one key
 * an org has); the SDK sends it here with the project it is connecting to, and
 * gets back OUR 15-minute access token — the same kind the API and the relay
 * already verify, so neither changes.
 *
 * Why an exchange rather than accepting the customer's token directly:
 *  - It names THEIR user (`sub`), not our `users.id`. We map it to ours here —
 *    creating the user on first sign-in — once, instead of in every verifier.
 *  - All the rules live in one place: claim checks, lifetime cap, refusing
 *    deactivated accounts.
 *  - Their token carries no role and no session id, so only what we mint here is
 *    accepted by the API and the relay.
 *
 * The customer holds the key that signs our tokens, so these checks bind only
 * those who come through this door.
 *
 * There is no refresh token in this mode. The customer's own session is the
 * long-lived one: to renew, the SDK asks the customer's backend for a fresh
 * customer JWT and exchanges it again. When their user signs out or is removed on
 * their side, they stop issuing tokens and our access ends within 15 minutes.
 *
 * Tokens issued here carry no `sid`: there is no refresh family to end. Deactivating
 * the user in our platform still takes effect at once (authMiddleware and the relay
 * check `is_active` on every request).
 *
 * CORS is open for this path only (see index.ts): it reads no cookies and is
 * authenticated solely by the signed token in the body.
 *
 * See AUTH-AND-SDK-DESIGN.md §5.
 */

import { Hono } from "hono";
import { and, eq, sql } from "drizzle-orm";
import { jwtVerify, errors } from "jose";
import { users, projects } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { getOrgSecret } from "../lib/org-secrets";
import { mintAccessToken } from "../lib/access-token";
import { buildFiltersConfig, sendsFilters } from "../lib/sdk-access";

const sdkAuth = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/** `aud` a customer token must carry, so a token meant for another service — or one of our own — is refused. */
const AUDIENCE = "superatom";

/** Longest lifetime (`exp − iat`) accepted. Customers should issue 5–15 minutes. */
const MAX_TOKEN_LIFETIME_S = 60 * 60;

/** Clock difference tolerated between the customer's servers and ours. */
const CLOCK_SKEW_S = 60;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Bounds on the optional `roles` claim, so a bad token cannot fill the database. */
const MAX_ROLES = 20;
const MAX_ROLE_LENGTH = 100;

/**
 * Longest `access` we will carry in the token, as JSON.
 *
 * The token goes in the WebSocket handshake query string, and base64 inflates it
 * by about a third — so 4 KB here is roughly a 6 KB token and a handshake URL
 * comfortably under the 8 KB many proxies allow. That is hundreds of filter
 * values: far more than a real policy uses.
 */
const MAX_ACCESS_BYTES = 4096;

/**
 * The customer's `roles` claim as a clean list, or null if it is malformed.
 *
 * Generic on purpose: accepts one role as a string or several as a list, and
 * always returns a list — trimmed, empties dropped, duplicates removed. Missing
 * means "no roles" ([]), so a role removed on their side disappears here too.
 * Anything that is not strings, or exceeds the bounds, is rejected rather than
 * partly kept.
 */
function parseRoles(value: unknown): string[] | null {
  if (value === undefined || value === null) return [];
  const list = typeof value === "string" ? [value] : value;
  if (!Array.isArray(list) || list.length > MAX_ROLES) return null;

  const roles: string[] = [];
  for (const item of list) {
    if (typeof item !== "string") return null;
    const role = item.trim();
    if (role.length > MAX_ROLE_LENGTH) return null;
    if (role && !roles.includes(role)) roles.push(role);
  }
  return roles;
}

/**
 * `reason` also goes back to the caller as `code`. The SDK needs to tell apart
 * "this user's session ended" from "this token was built wrong" — the first is
 * something to tell the user, the second is for whoever wrote the integration —
 * and it cannot do that from the message alone.
 */
function reject(c: any, status: 400 | 401 | 403 | 503, error: string, reason: string, detail = "") {
  console.warn(`[sdk-auth] exchange rejected: reason=${reason}${detail ? " " + detail : ""}`);
  return c.json({ error, code: reason }, status);
}

sdkAuth.post("/exchange", async (c) => {
  const db = c.get("db");

  const body = await c.req.json<{ projectId?: unknown; token?: unknown }>().catch(() => null);
  const projectId = typeof body?.projectId === "string" ? body.projectId : "";
  const token = typeof body?.token === "string" ? body.token : "";
  if (!projectId || !token) {
    return reject(c, 400, "projectId and token are required", "bad_request");
  }
  if (!UUID.test(projectId)) {
    return reject(c, 401, "Invalid project or token", "bad_project_id");
  }

  // The project decides the org, and so the secret. The customer never has to
  // know — or send — our org id.
  const [project] = await db
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);
  // Same answer for "no such project" and "bad token": the difference would let a
  // caller probe which project ids exist.
  if (!project?.orgId) {
    return reject(c, 401, "Invalid project or token", "unknown_project", `project=${projectId}`);
  }
  const orgId = project.orgId;

  // One key per org: it verifies the customer's token here and signs ours at the
  // end. Read before any user is created, so signing cannot fail afterwards and
  // leave a user who never got signed in.
  let secret: Uint8Array | null;
  try {
    secret = await getOrgSecret(c.env.JWT_SECRETS, orgId);
  } catch (error) {
    console.error("[sdk-auth] secret lookup failed:", error);
    return c.json({ error: "Sign-in service unavailable" }, 503);
  }
  if (!secret) {
    // A setup fault on our side, not a bad token.
    return reject(c, 503, "Sign-in service unavailable", "org_secret_missing", `org=${orgId}`);
  }

  // Signature, algorithm, audience and expiry — jose checks these together.
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(token, secret, {
      algorithms: ["HS256"],
      audience: AUDIENCE,
      clockTolerance: CLOCK_SKEW_S,
      requiredClaims: ["sub", "iat", "exp"],
    }));
  } catch (err) {
    if (err instanceof errors.JWTExpired) {
      return reject(c, 401, "Token has expired", "expired", `org=${orgId}`);
    }
    if (err instanceof errors.JWTClaimValidationFailed) {
      return reject(c, 401, "Invalid project or token", `claim_${err.claim}`, `org=${orgId}`);
    }
    return reject(c, 401, "Invalid project or token", "bad_signature", `org=${orgId}`);
  }

  // Lifetime rules jose does not cover: a token issued in the future, or one
  // meant to live longer than we allow.
  const now = Math.floor(Date.now() / 1000);
  const iat = payload.iat as number;
  const exp = payload.exp as number;
  if (iat > now + CLOCK_SKEW_S) {
    return reject(c, 401, "Invalid project or token", "issued_in_future", `org=${orgId}`);
  }
  if (exp - iat > MAX_TOKEN_LIFETIME_S) {
    return reject(c, 401, `Token lifetime must not exceed ${MAX_TOKEN_LIFETIME_S / 60} minutes`, "lifetime_too_long", `org=${orgId}`);
  }

  // Identity claims.
  const sub = typeof payload.sub === "string" ? payload.sub.trim() : "";
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
  const rawName = typeof payload.name === "string" ? payload.name.trim() : "";
  if (!sub || sub.length > 500) {
    return reject(c, 401, "Token must carry a sub (the user's id in your system)", "bad_sub", `org=${orgId}`);
  }
  if (!email || email.length > 255 || !EMAIL.test(email)) {
    return reject(c, 401, "Token must carry a valid email", "bad_email", `org=${orgId}`);
  }
  const name = (rawName || email).slice(0, 255);

  // Their own role names — stored as external_roles, never our permissions.
  const roles = parseRoles(payload.roles);
  if (roles === null) {
    return reject(
      c,
      401,
      `roles must be a string or a list of up to ${MAX_ROLES} strings, each up to ${MAX_ROLE_LENGTH} characters`,
      "bad_roles",
      `org=${orgId}`
    );
  }

  // Which data they may see. The customer writes it, either as plain row filters
  // (one data source, nothing to disambiguate) or as whole policies naming a
  // source each (lib/sdk-access.ts). We check it; nothing is read from the
  // project and no source id is inferred.
  //
  // It then rides in the access token and is never written to the user, so the
  // customer's latest word wins on every sign-in and nothing here goes stale.
  // `users.config` is the platform's own column: set by an admin, and used only
  // when a token carries no access at all.
  let accessConfig: unknown = null;
  if (payload.access !== undefined && payload.access !== null) {
    if (!sendsFilters(payload.access)) {
      return reject(
        c,
        401,
        'access must be a list of filters, e.g. [{ "table": "orders", "column": "customer_id", "op": "in", "values": [12] }]',
        "bad_access",
        `org=${orgId}`
      );
    }
    const access = buildFiltersConfig(payload.access);
    if (!access.ok) return reject(c, 401, access.error, access.reason, `org=${orgId}`);
    accessConfig = access.config;

    // The token travels in the WebSocket handshake URL, so the claim has a
    // ceiling. Refused rather than dropped: a dropped claim falls back to
    // whatever is stored, which for an SDK user is usually nothing — the user
    // would connect UNRESTRICTED, the one outcome worth failing loudly to avoid.
    if (accessConfig !== null) {
      const size = JSON.stringify(accessConfig).length;
      if (size > MAX_ACCESS_BYTES) {
        return reject(
          c,
          401,
          `access is too large (${size} characters, limit ${MAX_ACCESS_BYTES}) — send fewer filters or fewer values`,
          "access_too_large",
          `org=${orgId}`
        );
      }
    }
  }

  // Find the user: by their id in the customer's system first, then — once — by
  // email, to link an account that already exists (e.g. created by our admins).
  // Linking never takes over an account already tied to a different identity.
  let [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.orgId, orgId), eq(users.ssoSubject, sub)))
    .limit(1);

  if (!user) {
    const [byEmail] = await db
      .select()
      .from(users)
      .where(and(eq(users.orgId, orgId), sql`lower(${users.email}) = ${email}`))
      .limit(1);

    if (byEmail) {
      if (byEmail.ssoSubject && byEmail.ssoSubject !== sub) {
        return reject(c, 401, "This email is already linked to another identity", "email_linked_elsewhere", `org=${orgId}`);
      }
      // Linking an account that already exists here: stamp the identity so we
      // recognise them next time, and nothing else. The account predates this
      // sign-in, so its roles and access are the platform's to say, not the
      // token's.
      await db
        .update(users)
        .set({ ssoSubject: sub, updatedAt: new Date() })
        .where(eq(users.id, byEmail.id));
      user = { ...byEmail, ssoSubject: sub };
    } else {
      try {
        [user] = await db
          .insert(users)
          // No `config`: what the customer sends rides in the token and is never
          // written down. `users.config` belongs to the platform alone, so an
          // admin's edit there is the only thing that can end up in this column.
          .values({ orgId, email, name, ssoSubject: sub, externalRoles: roles, role: "member", isActive: true })
          .returning();
      } catch {
        // Two first sign-ins racing: the other request created the row. Use it.
        [user] = await db
          .select()
          .from(users)
          .where(and(eq(users.orgId, orgId), eq(users.ssoSubject, sub)))
          .limit(1);
        if (!user) {
          return reject(c, 401, "Could not create the user", "create_failed", `org=${orgId}`);
        }
      }
    }
  }

  // Deactivated in our platform: refuse — never re-activate or re-create.
  if (!user.isActive) {
    return reject(c, 401, "Account is deactivated", "inactive", `org=${orgId} user=${user.id}`);
  }

  // Their role names are written once, when we create the user, and never
  // again: an admin may edit them in the platform afterwards, and a later
  // sign-in must not quietly undo that. Data access is not written at all.

  // Marked `src: "sdk"`: the API and the relay treat this session as a member,
  // whatever the account's role — even an org_admin linked by email above.
  //
  // The access travels in the token, so THIS sign-in uses what the customer just
  // sent, not what is stored. When they send none, the claim is absent and the
  // relay falls back to `users.config` — the platform's copy.
  let accessToken: string;
  try {
    accessToken = await mintAccessToken(user, c.env.JWT_SECRETS, undefined, "sdk", accessConfig);
  } catch (error) {
    console.error("[sdk-auth] access token signing failed:", error);
    return c.json({ error: "Sign-in service unavailable" }, 503);
  }

  return c.json({
    token: accessToken,
    // `role` is OUR role for this user (new users are members; an admin promoted
    // in the platform stays an admin and sees the admin view, though admin
    // CHANGES are refused for SDK sessions — see middleware/auth.ts).
    // `externalRoles` is what we stored from their `roles` claim.
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      externalRoles: roles,
    },
  });
});

export default sdkAuth;
