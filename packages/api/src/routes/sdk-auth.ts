/**
 * SDK sign-in — exchange a customer-signed JWT for a Superatom access token.
 *
 * POST /auth/sdk/exchange { projectId, token } → { token, user }
 *
 * A customer embedding the SDK has its own login. Its backend signs a
 * short-lived JWT for its user with the org's SDK secret (`sdk:<orgId>` — never
 * `org:<orgId>`, which signs our own tokens); the SDK sends it here with the
 * project it is connecting to, and gets back OUR 15-minute access token — the same
 * kind the API and the relay already verify, so neither changes.
 *
 * Why an exchange rather than accepting the customer's token directly:
 *  - It names THEIR user (`sub`), not our `users.id`. We map it to ours here —
 *    creating the user on first sign-in — once, instead of in every verifier.
 *  - All the rules live in one place: claim checks, lifetime cap, refusing
 *    deactivated accounts.
 *  - A customer token is accepted by this endpoint only; it cannot be presented
 *    to the API or the relay as-is.
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
import { getOrgSecret, getSdkSecret } from "../lib/org-secrets";
import { mintAccessToken } from "../lib/access-token";
import { readAccessMapping, buildAccessConfig, unmappedWarning, type AccessMapping } from "../lib/sdk-access";

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

/** Longest `access` claim (as JSON) we store, so a bad token cannot fill the column. */
const MAX_ACCESS_LENGTH = 8000;

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

/** Same roles in the same order — used to skip a database write when nothing changed. */
function sameRoles(a: unknown, b: string[]): boolean {
  return Array.isArray(a) && a.length === b.length && a.every((role, i) => role === b[i]);
}

/**
 * Same config, ignoring key order — Postgres stores jsonb keys in its own order,
 * so the config read back never matches ours key-for-key.
 */
function sameJson(a: unknown, b: unknown): boolean {
  const canonical = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(canonical)
      : v && typeof v === "object"
        ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical((v as Record<string, unknown>)[k])]))
        : v;
  return JSON.stringify(canonical(a ?? null)) === JSON.stringify(canonical(b ?? null));
}

function reject(c: any, status: 400 | 401 | 403 | 503, error: string, reason: string, detail = "") {
  console.warn(`[sdk-auth] exchange rejected: reason=${reason}${detail ? " " + detail : ""}`);
  return c.json({ error }, status);
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
    .select({ orgId: projects.orgId, config: projects.config })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);
  // Same answer for "no such project" and "bad token": the difference would let a
  // caller probe which project ids exist.
  if (!project?.orgId) {
    return reject(c, 401, "Invalid project or token", "unknown_project", `project=${projectId}`);
  }
  const orgId = project.orgId;

  // The customer's token is checked with the org's SDK secret, never with
  // `org:<orgId>` (which signs our own tokens — see lib/org-secrets.ts). No SDK
  // secret means SDK sign-in is not enabled for this org: off by default.
  //
  // The org's own secret (`org:<orgId>`) is checked here too, though it is only
  // used at the end to sign our token: without it signing would fail AFTER the
  // user was created or linked, leaving a user who never got signed in.
  let secret: Uint8Array | null;
  let orgSecret: Uint8Array | null;
  try {
    [secret, orgSecret] = await Promise.all([
      getSdkSecret(c.env.JWT_SECRETS, orgId),
      getOrgSecret(c.env.JWT_SECRETS, orgId),
    ]);
  } catch (error) {
    console.error("[sdk-auth] secret lookup failed:", error);
    return c.json({ error: "Sign-in service unavailable" }, 503);
  }
  if (!secret) {
    return reject(c, 403, "SDK sign-in is not enabled for this organization", "sdk_not_enabled", `org=${orgId}`);
  }
  if (!orgSecret) {
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

  // Which data they may see: the `access` claim's values, placed on the tables
  // and columns the project's mapping names (lib/sdk-access.ts). A project with
  // no mapping has SDK access filtering off, and its users' config is left alone.
  let mapping: AccessMapping | null;
  try {
    mapping = readAccessMapping(project.config);
  } catch (error) {
    // Our configuration, not their token.
    return reject(c, 503, "Sign-in service unavailable", "access_mapping_invalid", `project=${projectId} ${(error as Error).message}`);
  }
  let accessConfig: unknown = null;
  const warnings: string[] = [];
  const sentAccess =
    payload.access && typeof payload.access === "object" && !Array.isArray(payload.access) ? payload.access : null;
  if (mapping) {
    const access = buildAccessConfig(payload.access, mapping);
    if (!access.ok) return reject(c, 401, access.error, access.reason, `org=${orgId}`);
    accessConfig = access.config;
    warnings.push(...access.warnings);
  } else if (sentAccess) {
    // No mapping yet (they come at onboarding): nothing can be enforced, so the
    // claim is stored exactly as sent — visible, and ready to be mapped later.
    const names = Object.keys(sentAccess);
    if (names.length) warnings.push(unmappedWarning(names));
    if (JSON.stringify(sentAccess).length <= MAX_ACCESS_LENGTH) {
      accessConfig = sentAccess;
    } else {
      warnings.push(`access is larger than ${MAX_ACCESS_LENGTH} characters, so it was not stored`);
    }
  }
  if (warnings.length) {
    console.warn(`[sdk-auth] exchange warning: project=${projectId} ${warnings.join("; ")}`);
  }
  const configUpdate = { config: accessConfig };

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
      await db
        .update(users)
        .set({ ssoSubject: sub, externalRoles: roles, ...configUpdate, updatedAt: new Date() })
        .where(eq(users.id, byEmail.id));
      user = { ...byEmail, ssoSubject: sub, externalRoles: roles, ...configUpdate };
    } else {
      try {
        [user] = await db
          .insert(users)
          .values({ orgId, email, name, ssoSubject: sub, externalRoles: roles, ...configUpdate, role: "member", isActive: true })
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

  // Keep their roles and data access current: overwritten on every sign-in —
  // including config an admin set by hand — so changes on their side reach us.
  // Written only when something actually changed, so a normal sign-in costs no
  // extra write. (New and just-linked users already have them.)
  const changes = {
    ...(sameRoles(user.externalRoles, roles) ? {} : { externalRoles: roles }),
    ...(sameJson(user.config, accessConfig) ? {} : { config: accessConfig }),
  };
  if (Object.keys(changes).length) {
    await db
      .update(users)
      .set({ ...changes, updatedAt: new Date() })
      .where(eq(users.id, user.id));
    user = { ...user, ...changes };
  }

  // Marked `src: "sdk"`: the API and the relay treat this session as a member,
  // whatever the account's role — even an org_admin linked by email above.
  let accessToken: string;
  try {
    accessToken = await mintAccessToken(user, c.env.JWT_SECRETS, undefined, "sdk");
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
    // Things in their token we accepted but could not apply, e.g. an access
    // field not mapped yet. Present only when there are any.
    ...(warnings.length ? { warnings } : {}),
  });
});

export default sdkAuth;
