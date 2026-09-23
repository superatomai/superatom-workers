import { Hono } from "hono";
import { eq, and, sql } from "drizzle-orm";
import { users, appPermissions, apps } from "../db/schema";
import { validatePassword } from "../lib/password-policy";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, orgScopeGuard } from "../middleware/auth";

const usersRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

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
    password: string;
    role?: "super_admin" | "org_admin" | "member";
    config?: unknown;
  }>();

  if (!email || !name || !password) {
    return c.json({ error: "email, name, and password are required" }, 400);
  }

  // Stored as typed — comparisons (below and at login) are case-insensitive,
  // so this doesn't need to be normalized to match later.

  // Enforce password strength on creation. Login is not gated, so existing
  // accounts with older passwords keep working.
  const pwError = validatePassword(password);
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

  // Case-insensitive email lookup within this org
  const [existing] = await db
    .select()
    .from(users)
    .where(and(sql`lower(${users.email}) = lower(${email})`, eq(users.orgId, orgId)))
    .limit(1);

  if (existing) {
    if (!existing.isActive) {
      // Reactivate with new credentials
      const passwordHash = await hashPassword(password);
      const [reactivated] = await db
        .update(users)
        .set({ name, passwordHash, role: role || "member", config, isActive: true, updatedAt: new Date() })
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

  const passwordHash = await hashPassword(password);

  const [user] = await db
    .insert(users)
    .values({
      orgId,
      email,
      name,
      passwordHash,
      role: role || "member",
      config,
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

  if (body.isActive !== undefined) {
    if (typeof body.isActive !== "boolean") {
      return c.json({ error: "Invalid isActive" }, 400);
    }
    updates.isActive = body.isActive;
  }

  if (body.config !== undefined) {
    updates.config = body.config;
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
