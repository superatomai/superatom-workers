import { Hono } from "hono";
import { eq, and, sql, desc, inArray } from "drizzle-orm";
import { accessConfigs, users, appPermissions, apps } from "../db/schema";
import { validatePassword } from "../lib/password-policy";
import { orgRequiresSso } from "../lib/sso-required";
import { revokeAllForUser } from "../lib/refresh-tokens";
import { buildFiltersConfig } from "../lib/sdk-access";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, orgScopeGuard } from "../middleware/auth";

const usersRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * `users.config` is data access, so it gets the same check an SDK token's
 * `access` claim gets at sign-in — the one validator, so the two ways of
 * stating a user's access cannot drift into accepting different shapes.
 *
 * Worth doing because an unreadable policy is not ignored downstream: the
 * policy gate refuses every query against that whole source rather than
 * guessing. Written unchecked, a typo here looks fine until someone asks a
 * question and gets refused, with nothing connecting the two.
 *
 * Returns the NORMALISED config to store, matching what the token path keeps,
 * so the relay only ever reads a shape the validator has passed. `null` means
 * no restriction and is left alone.
 */
function checkedConfig(config: unknown): { ok: true; config: unknown } | { ok: false; error: string } {
  if (config === undefined || config === null) return { ok: true, config: null };
  const result = buildFiltersConfig(config);
  return result.ok ? { ok: true, config: result.config } : { ok: false, error: result.error };
}

usersRouter.use("*", authMiddleware, adminOnly, orgScopeGuard);

/**
 * Hash a password using SHA-256 (same as auth login check)
 */
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * POST /orgs/:orgId/users
 * Create/invite user to org
 */
usersRouter.post("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const { email, name, password, role, config } = await c.req.json<{
    email: string;
    name: string;
    password?: string;
    role?: "super_admin" | "org_admin" | "member";
    config?: unknown;
  }>();

  if (!email || !name) {
    return c.json({ error: "email and name are required" }, 400);
  }
  // SSO-only users get no password, even if one is sent (the form may still send it).
  const ssoOnly = await orgRequiresSso(db, orgId, email);
  if (!ssoOnly && !password) {
    return c.json({ error: "email, name, and password are required" }, 400);
  }

  // Stored as typed — comparisons (below and at login) are case-insensitive,
  // so this doesn't need to be normalized to match later.

  // Enforce password strength on creation. Login is not gated, so existing
  // accounts with older passwords keep working.
  const pwError = ssoOnly ? null : validatePassword(password);
  if (pwError) {
    return c.json({ error: pwError }, 400);
  }

  // Nobody should create super_admin via this endpoint
  if (role === "super_admin") {
    return c.json({ error: "Cannot create super_admin users via this endpoint" }, 403);
  }

  // Only super_admin or org_admin can create org_admin users
  if (role === "org_admin" && !["super_admin", "org_admin"].includes(c.get("userRole"))) {
    return c.json({ error: "Only admins can create org_admin users" }, 403);
  }

  const checked = checkedConfig(config);
  if (!checked.ok) {
    return c.json({ error: `config is not valid data access: ${checked.error}` }, 400);
  }

  // Case-insensitive email lookup within this org
  const [existing] = await db
    .select()
    .from(users)
    .where(and(sql`lower(${users.email}) = lower(${email})`, eq(users.orgId, orgId)))
    .limit(1);

  if (existing) {
    if (!existing.isActive) {
      // Reactivate with new credentials
      const passwordHash = ssoOnly ? null : await hashPassword(password!);
      const [reactivated] = await db
        .update(users)
        .set({ name, passwordHash, role: role || "member", config: checked.config, isActive: true, updatedAt: new Date() })
        .where(eq(users.id, existing.id))
        .returning({
          id: users.id,
          orgId: users.orgId,
          email: users.email,
          name: users.name,
          role: users.role,
          config: users.config,
          isActive: users.isActive,
          createdAt: users.createdAt,
        });
      return c.json(reactivated, 200);
    }
    return c.json({ error: "A user with this email already exists in this organization" }, 409);
  }

  const passwordHash = ssoOnly ? null : await hashPassword(password!);

  const [user] = await db
    .insert(users)
    .values({
      orgId,
      email,
      name,
      passwordHash,
      role: role || "member",
      config: checked.config,
    })
    .returning({
      id: users.id,
      orgId: users.orgId,
      email: users.email,
      name: users.name,
      role: users.role,
      config: users.config,
      isActive: users.isActive,
      createdAt: users.createdAt,
    });

  return c.json(user, 201);
});

/**
 * GET /orgs/:orgId/users
 * List all users in org
 */
usersRouter.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;

  const orgUsers = await db
    .select({
      id: users.id,
      email: users.email,
      name: users.name,
      role: users.role,
      config: users.config,
      // Their role names in the customer's own system, from an SDK sign-in.
      // Read-only: the token owns them and overwrites them on every sign-in.
      externalRoles: users.externalRoles,
      isActive: users.isActive,
      createdAt: users.createdAt,
    })
    .from(users)
    .where(eq(users.orgId, orgId));

  return c.json(orgUsers);
});

/**
 * GET /orgs/:orgId/users/:userId
 * Get user details + their app permissions
 */
/**
 * GET /orgs/:orgId/users/:userId/access-history[?hash=a,b,c]
 *
 * Deliberately not `/access`: that reads as the user's CURRENT access, which is
 * `users.config` and a different thing. This is the record of what they have
 * had, by fingerprint.
 *
 * What this user was allowed to see, by fingerprint. The feedback screen gets a
 * hash from the answer's own conversation row — which lives in the CLIENT's
 * database, so it cannot join to this one — and resolves it here.
 *
 * Several hashes per call because a thread is read beside one answer: showing
 * where access changed between questions means resolving a few at once. With no
 * `hash`, every config this user has ever had, newest first.
 *
 * Keyed on (user_id, access_hash), the table's own primary key, so knowing a
 * hash is not enough to read another user's — or another org's — access.
 */
usersRouter.get("/:userId/access-history", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");

  // The user must be in the org in the path. orgScopeGuard proves the caller
  // owns the ROUTE's org, not that the target user belongs to it.
  const [owner] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .limit(1);
  if (!owner) return c.json({ error: "User not found" }, 404);

  const hashes = (c.req.query("hash") || "")
    .split(",")
    .map((h) => h.trim())
    .filter((h) => /^[0-9a-f]{64}$/.test(h));
  if (c.req.query("hash") !== undefined && hashes.length === 0) {
    return c.json({ error: "hash must be one or more 64-character hex fingerprints" }, 400);
  }

  const conditions = [eq(accessConfigs.userId, userId)];
  if (hashes.length) conditions.push(inArray(accessConfigs.accessHash, hashes));

  const rows = await db
    .select({
      accessHash: accessConfigs.accessHash,
      config: accessConfigs.config,
      firstSeenAt: accessConfigs.firstSeenAt,
    })
    .from(accessConfigs)
    .where(and(...conditions))
    .orderBy(desc(accessConfigs.firstSeenAt));

  // A hash with no row is not an error: the caller holds a fingerprint from
  // somewhere else, and "we have never seen this one" is the answer.
  return c.json(rows);
});

usersRouter.get("/:userId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");

  const [user] = await db
    .select({
      id: users.id,
      email: users.email,
      name: users.name,
      role: users.role,
      config: users.config,
      externalRoles: users.externalRoles,
      isActive: users.isActive,
      createdAt: users.createdAt,
    })
    .from(users)
    // Scope to the org in the path. orgScopeGuard proves the ROUTE orgId matches
    // the caller's token, but says nothing about which org the TARGET user is in,
    // so an unscoped lookup by id reaches users in any other tenant.
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .limit(1);

  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  // Get user's app permissions
  const permissions = await db
    .select({
      appId: appPermissions.appId,
      appName: apps.name,
      appType: apps.type,
      permission: appPermissions.permission,
      createdAt: appPermissions.createdAt,
    })
    .from(appPermissions)
    .innerJoin(apps, eq(apps.id, appPermissions.appId))
    .where(eq(appPermissions.userId, userId));

  return c.json({ ...user, permissions });
});

/**
 * PUT /orgs/:orgId/users/:userId
 * Update user (role, name, active status)
 */
usersRouter.put("/:userId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const actorRole = c.get("userRole");
  const actorId = c.get("userId");

  // `role` is deliberately typed as string, not "org_admin" | "member":
  // c.req.json<T>() is an unchecked assertion over arbitrary JSON, not
  // validation. The narrow type used to read like a constraint while permitting
  // any value at runtime — which is exactly how super_admin got through.
  const body = await c.req.json<{
    name?: string;
    email?: string;
    role?: string;
    isActive?: boolean;
    config?: unknown;
  }>();

  // Narrowed only after validation below; stays undefined when role is absent,
  // which leaves the stored role untouched.
  let validatedRole: "org_admin" | "member" | undefined;

  if (body.role !== undefined) {
    // Mirrors the POST guard this path never had. Unconditional: super_admin is
    // granted via the database, never over the API.
    if (body.role === "super_admin") {
      return c.json({ error: "Cannot assign super_admin via this endpoint" }, 403);
    }

    // Whitelist, so a role added later is rejected until explicitly allowed.
    if (body.role !== "org_admin" && body.role !== "member") {
      return c.json({ error: "Invalid role" }, 400);
    }

    // Only super_admin or org_admin can promote to org_admin
    if (body.role === "org_admin" && !["super_admin", "org_admin"].includes(actorRole)) {
      return c.json({ error: "Only admins can assign org_admin role" }, 403);
    }

    // No self-promotion — the reported attack was an org_admin editing its own row.
    if (userId === actorId && actorRole !== "super_admin") {
      return c.json({ error: "Cannot change your own role" }, 403);
    }

    console.log(
      `[audit] role change: actor=${actorId} target=${userId} newRole=${body.role}`
    );

    validatedRole = body.role;
  }

  // Explicit allowlist. Spreading the request body let a caller set ANY column on
  // `users`: passwordHash (account takeover — login compares the same SHA-256),
  // orgId (move a user into another tenant), email or ssoSubject (hijack the SSO
  // identity mapping). Unknown keys are now ignored instead of written.
  const updates: {
    name?: string;
    email?: string;
    role?: "org_admin" | "member";
    isActive?: boolean;
    config?: unknown;
    updatedAt: Date;
  } = { updatedAt: new Date() };

  if (body.name !== undefined) {
    if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 255) {
      return c.json({ error: "Invalid name" }, 400);
    }
    updates.name = body.name;
  }

  // Email is the login identity, so a change here is how this user signs in from
  // now on. Taken on the admin's word — there is no confirmation to the new
  // address — which means a typo locks the account out, since nothing else
  // identifies it. Worth a confirm step in the UI.
  if (body.email !== undefined) {
    const email = typeof body.email === "string" ? body.email.trim() : "";
    if (!email || email.length > 255 || !email.includes("@")) {
      return c.json({ error: "Invalid email" }, 400);
    }
    // Case-insensitive within the org, matching how login looks an address up —
    // otherwise two rows could differ only by case and either could win.
    const [clash] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(sql`lower(${users.email}) = lower(${email})`, eq(users.orgId, orgId)))
      .limit(1);
    if (clash && clash.id !== userId) {
      return c.json({ error: "A user with this email already exists in this organization" }, 409);
    }
    updates.email = email;
  }

  if (body.isActive !== undefined) {
    if (typeof body.isActive !== "boolean") {
      return c.json({ error: "Invalid isActive" }, 400);
    }
    updates.isActive = body.isActive;
  }

  if (body.config !== undefined) {
    // `null` is how an admin clears a restriction, so it stays allowed.
    const checked = checkedConfig(body.config);
    if (!checked.ok) {
      return c.json({ error: `config is not valid data access: ${checked.error}` }, 400);
    }
    updates.config = checked.config;
  }

  // Role comes from the validated variable, never straight off the body.
  if (validatedRole !== undefined) {
    updates.role = validatedRole;
  }

  const [updated] = await db
    .update(users)
    .set(updates)
    // Org-scoped: without this, an admin can edit users in any other tenant,
    // since orgScopeGuard only validates the ROUTE orgId against the token.
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .returning({
      id: users.id,
      email: users.email,
      name: users.name,
      role: users.role,
      config: users.config,
      isActive: users.isActive,
      updatedAt: users.updatedAt,
    });

  if (!updated) {
    return c.json({ error: "User not found" }, 404);
  }

  return c.json(updated);
});

/**
 * POST /orgs/:orgId/users/:userId/password
 * Set a user's password. No current password: this is an admin resetting someone
 * else's, which is the case where they do not have it.
 *
 * Its own route rather than a field on PUT, so an ordinary profile save never
 * carries a password and cannot change one by accident.
 *
 * Every session of that user ends — the same cutoff logout uses. A reset exists
 * because something is wrong with the account; leaving the old sessions alive
 * would mean the password changed but whoever was already in stayed in.
 */
usersRouter.post("/:userId/password", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");

  const body = await c.req.json<{ password?: unknown }>().catch(() => ({}) as { password?: unknown });
  const pwError = validatePassword(body.password);
  if (pwError) return c.json({ error: pwError }, 400);

  const [updated] = await db
    .update(users)
    .set({
      passwordHash: await hashPassword(body.password as string),
      // Seconds, matching the `iat` resolution tokens are compared against.
      tokensValidAfter: new Date(Math.floor(Date.now() / 1000) * 1000),
      updatedAt: new Date(),
    })
    // Org-scoped: orgScopeGuard only proves the caller owns the ROUTE's org.
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .returning({ id: users.id, email: users.email });

  if (!updated) return c.json({ error: "User not found" }, 404);

  // The access token dies at the cutoff; without this the refresh cookie could
  // still mint new ones and the reset would not stick.
  await revokeAllForUser(db, userId);

  console.log(`[audit] password reset: actor=${c.get("userId")} target=${userId}`);
  return c.json({ success: true });
});

/**
 * DELETE /orgs/:orgId/users/:userId
 * Deactivate user (sets isActive = false, revokes all app access)
 */
usersRouter.delete("/:userId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");

  // Deactivate user. Org-scoped so an admin cannot deactivate users in another
  // tenant; the permission revoke below only runs once this matched in-org.
  const [deactivated] = await db
    .update(users)
    .set({ isActive: false, updatedAt: new Date() })
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .returning({ id: users.id });

  if (!deactivated) {
    return c.json({ error: "User not found" }, 404);
  }

  // Revoke all app permissions
  await db
    .delete(appPermissions)
    .where(eq(appPermissions.userId, userId));

  return c.json({ message: "User deactivated and all permissions revoked" });
});

export default usersRouter;
