import { Hono } from "hono";
import { eq, and, sql, desc, inArray } from "drizzle-orm";
import { accessConfigs, users, apps, roles, objects, objectGrants, projects, projectMembers } from "../db/schema";
import { PROJECT_SCOPES, allowedProjects, projectAllowed, scopeOfRequest, scopeOfUser } from "../lib/project-scope";
import { legacyPermission, type Level } from "../lib/objects";
import type { Database } from "../db";
import { validatePassword } from "../lib/password-policy";
import { orgRequiresSso } from "../lib/sso-required";
import { revokeAllForUser } from "../lib/refresh-tokens";
import { buildFiltersConfig } from "../lib/sdk-access";
import {
  ADMIN_ROLES,
  activeOwnersExcept,
  mayGrantRole,
  orgRoleOf,
  recordRoleChange,
  resolveRole,
  type ResolvedRole,
} from "../lib/permissions";
import type { Env, AppVariables } from "../types";
import { authMiddleware, requirePermission, orgScopeGuard, hasPermission } from "../middleware/auth";

const usersRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/** A user of this org with their organization role, or undefined. */
async function loadMember(db: Database, orgId: string, userId: string) {
  const [row] = await db
    .select({ id: users.id, role: users.role, roleKey: roles.key, isActive: users.isActive })
    .from(users)
    .leftJoin(roles, eq(roles.id, users.roleId))
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .limit(1);
  return row ? { ...row, orgRole: orgRoleOf(row) } : undefined;
}

/**
 * Admins and Owners are managed only by whoever holds `admins.manage` (the
 * Owner). Everyone else may act on them only when acting on themselves.
 */
function mayActOn(c: { get: (k: "permissions") => readonly string[] }, target: { orgRole: string }, isSelf: boolean): boolean {
  return isSelf || !ADMIN_ROLES.includes(target.orgRole) || hasPermission(c, "admins.manage");
}

/**
 * Sets someone's project scope (lib/project-scope.ts): `all`, or `selected` with
 * exactly the projects in `projectIds` (their project_members rows, which also
 * decide who a project-wide grant reaches). `projectIds` alone replaces the
 * list and leaves the scope as it is.
 *
 * Rules: an Owner always reaches every project, so cannot be limited; and
 * someone who is limited themselves can only give projects they reach, never
 * "all", so nobody hands out more than they have.
 *
 * Returns the error to send, or null once applied.
 */
async function applyProjectScope(
  c: any,
  db: Database,
  orgId: string,
  target: { id: string; orgRole: string },
  scope: unknown,
  projectIds: unknown,
  /** Only check, write nothing: so a create can be refused before the user exists. */
  checkOnly = false
): Promise<{ error: string; status: 400 | 403 } | null> {
  if (scope === undefined && projectIds === undefined) return null;
  if (scope !== undefined && !(PROJECT_SCOPES as readonly unknown[]).includes(scope)) {
    return { error: "projectScope must be all or selected", status: 400 };
  }
  if (scope === "selected" && target.orgRole === "owner") {
    return { error: "An Owner always reaches every project", status: 400 };
  }

  let ids: string[] | undefined;
  if (projectIds !== undefined) {
    if (!Array.isArray(projectIds) || projectIds.some((p) => typeof p !== "string" || !/^[0-9a-f-]{36}$/i.test(p))) {
      return { error: "projectIds must be a list of project ids", status: 400 };
    }
    ids = [...new Set(projectIds as string[])];
    if (ids.length) {
      const found = await db.select({ id: projects.id }).from(projects).where(and(eq(projects.orgId, orgId), inArray(projects.id, ids)));
      if (found.length !== ids.length) return { error: "Every project must belong to this organization", status: 400 };
    }
  }

  // Someone limited to some projects gives only those, never "all".
  const callerScope = await scopeOfRequest(c);
  const callerReach = callerScope ? await allowedProjects(db, callerScope) : null;
  if (callerReach) {
    if (scope === "all") return { error: "You can only give projects you can reach yourself", status: 403 };
    if (ids?.some((p) => !callerReach.has(p))) return { error: "You can only give projects you can reach yourself", status: 403 };
  }
  if (checkOnly) return null;

  if (scope !== undefined) {
    await db.update(users).set({ projectScope: scope as string, updatedAt: new Date() }).where(eq(users.id, target.id));
  }
  if (ids !== undefined) {
    const current = (await db.select({ projectId: projectMembers.projectId }).from(projectMembers).where(eq(projectMembers.userId, target.id))).map((r) => r.projectId);
    // A limited caller can only change memberships in projects they reach.
    const removable = current.filter((p) => !ids!.includes(p) && (!callerReach || callerReach.has(p)));
    if (removable.length) {
      await db.delete(projectMembers).where(and(eq(projectMembers.userId, target.id), inArray(projectMembers.projectId, removable)));
    }
    const added = ids.filter((p) => !current.includes(p));
    if (added.length) {
      await db.insert(projectMembers).values(added.map((projectId) => ({ projectId, userId: target.id, addedBy: c.get("userId") }))).onConflictDoNothing();
    }
  }
  console.log(`[audit] project scope: actor=${c.get("userId")} target=${target.id} scope=${scope ?? "(unchanged)"} projects=${ids ? ids.join(",") : "(unchanged)"}`);
  return null;
}

/**
 * Everything a member owns (objects: today every kind of app), with each one's
 * name and project, so whoever removes them can see what will be handed over.
 */
async function ownedBy(db: Database, userId: string) {
  return db
    .select({
      objectId: objects.id,
      type: objects.type,
      refId: objects.refId,
      projectId: objects.projectId,
      name: apps.name,
      status: objects.status,
    })
    .from(objects)
    .leftJoin(apps, sql`${apps.id}::text = ${objects.refId}`)
    .where(eq(objects.ownerId, userId));
}

/**
 * Hands over everything `fromUserId` owns to `toUserId` (or, when not given,
 * to whoever is removing them), so nothing is left without an owner. The new
 * owner must be an active member of the org other than the one leaving, and
 * reach every item's project; otherwise nothing moves and the reason is returned.
 */
async function handOverOwned(
  c: any,
  db: Database,
  orgId: string,
  fromUserId: string,
  toUserId: unknown
): Promise<{ error: string; status: 400 } | { moved: number; to: string | null }> {
  const owned = await ownedBy(db, fromUserId);
  if (!owned.length) return { moved: 0, to: null };

  const to = typeof toUserId === "string" && toUserId ? toUserId : (c.get("userId") as string);
  if (to === fromUserId) return { error: "Hand their items to someone other than them", status: 400 };
  if (!/^[0-9a-f-]{36}$/i.test(to)) return { error: "transferTo must be a user id", status: 400 };
  const [recipient] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.id, to), eq(users.orgId, orgId), eq(users.isActive, true)))
    .limit(1);
  if (!recipient) return { error: "Their items must go to an active member of this organization", status: 400 };

  const scope = await scopeOfUser(db, to);
  const unreachable: string[] = [];
  for (const o of owned) {
    if (o.projectId && !(scope && (await projectAllowed(db, scope, o.projectId)))) unreachable.push(o.name ?? o.refId);
  }
  if (unreachable.length) {
    return { error: `The new owner cannot reach the project of: ${unreachable.join(", ")}. Add them to it, or choose someone else.`, status: 400 };
  }

  await db.update(objects).set({ ownerId: to, updatedAt: new Date() }).where(eq(objects.ownerId, fromUserId));
  console.log(`[audit] handed over on removal: actor=${c.get("userId")} from=${fromUserId} to=${to} items=${owned.length}`);
  return { moved: owned.length, to };
}

/** A member's project scope and the projects they belong to. */
async function scopeOf(db: Database, userId: string) {
  const [u] = await db.select({ projectScope: users.projectScope }).from(users).where(eq(users.id, userId)).limit(1);
  const rows = await db.select({ projectId: projectMembers.projectId }).from(projectMembers).where(eq(projectMembers.userId, userId));
  return { projectScope: u?.projectScope ?? "all", projectIds: rows.map((r) => r.projectId) };
}

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

// Reading the member list is for anyone on the platform (other screens show
// names from it); changing members needs members.manage, and each route adds
// its own rules (admins and Owners, roles, data access).
usersRouter.use("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);
usersRouter.post("*", requirePermission("members.manage"));
usersRouter.put("*", requirePermission("members.manage"));
usersRouter.delete("*", requirePermission("members.manage"));

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
  const { email, name, password, role, config, projectScope, projectIds } = await c.req.json<{
    email: string;
    name: string;
    password?: string;
    // member, admin, owner, the old org_admin (read as admin), or a custom
    // role's key or id. Typed as a string because the body is unchecked JSON;
    // resolveRole validates it.
    role?: string;
    config?: unknown;
    // all, or selected with projectIds (lib/project-scope.ts). Someone limited
    // to some projects themselves creates only limited users.
    projectScope?: unknown;
    projectIds?: unknown;
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

  // A built-in role (member, admin, owner) or one of this org's custom roles.
  const resolved = await resolveRole(db, orgId, role ?? "member");
  if (!resolved) {
    return c.json({ error: "Invalid role" }, 400);
  }
  const orgRole = resolved.key;
  const roleId = resolved.id;

  // Admins and Owners are added only by the Owner: an admin cannot make another admin.
  if (ADMIN_ROLES.includes(orgRole) && !hasPermission(c, "admins.manage")) {
    return c.json({ error: "Only an Owner can add admins" }, 403);
  }
  // No one gives a role carrying more than they hold.
  if (!mayGrantRole(c.get("permissions"), resolved)) {
    return c.json({ error: "You can only give a role whose permissions you hold yourself" }, 403);
  }
  if (orgRole === "owner" && !roleId) {
    return c.json({ error: "The Owner role is not set up yet; run the roles migration" }, 400);
  }
  // Data access rules are access.manage's, not just members.manage's.
  if (config !== undefined && config !== null && !hasPermission(c, "access.manage")) {
    return c.json({ error: "Forbidden: setting data access requires access.manage" }, 403);
  }

  const checked = checkedConfig(config);
  if (!checked.ok) {
    return c.json({ error: `config is not valid data access: ${checked.error}` }, 400);
  }

  // Project scope. Someone limited to some projects creates only limited users;
  // checked now, before anyone is created, and applied once they exist.
  const creatorScope = await scopeOfRequest(c);
  const creatorLimited = !!creatorScope && !!(await allowedProjects(db, creatorScope));
  const startScope = projectScope ?? (creatorLimited ? "selected" : undefined);
  const scopeError = await applyProjectScope(c, db, orgId, { id: "", orgRole }, startScope, projectIds, true);
  if (scopeError) return c.json({ error: scopeError.error }, scopeError.status);

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
      const before = await loadMember(db, orgId, existing.id);
      const [reactivated] = await db
        .update(users)
        .set({ name, passwordHash, role: resolved.kind, roleId, config: checked.config, isActive: true, updatedAt: new Date() })
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
      if (before?.orgRole !== orgRole) {
        await recordRoleChange(db, { orgId, userId: existing.id, changedBy: c.get("userId"), fromRole: before?.orgRole ?? null, toRole: orgRole });
      }
      await applyProjectScope(c, db, orgId, { id: existing.id, orgRole }, startScope, projectIds);
      return c.json({ ...reactivated, orgRole, ...(await scopeOf(db, existing.id)) }, 200);
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
      role: resolved.kind,
      roleId,
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

  await recordRoleChange(db, { orgId, userId: user.id, changedBy: c.get("userId"), fromRole: null, toRole: orgRole });
  await applyProjectScope(c, db, orgId, { id: user.id, orgRole }, startScope, projectIds);
  return c.json({ ...user, orgRole, ...(await scopeOf(db, user.id)) }, 201);
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
      roleKey: roles.key,
      config: users.config,
      // Their role names in the customer's own system, from an SDK sign-in.
      // Read-only: the token owns them and overwrites them on every sign-in.
      externalRoles: users.externalRoles,
      projectScope: users.projectScope,
      isActive: users.isActive,
      createdAt: users.createdAt,
    })
    .from(users)
    .leftJoin(roles, eq(roles.id, users.roleId))
    .where(eq(users.orgId, orgId));

  // Each member's projects, in one query, for the "only these projects" ones.
  const memberships = await db
    .select({ userId: projectMembers.userId, projectId: projectMembers.projectId })
    .from(projectMembers)
    .innerJoin(projects, eq(projects.id, projectMembers.projectId))
    .where(eq(projects.orgId, orgId));

  return c.json(
    orgUsers.map(({ roleKey, ...u }) => ({
      ...u,
      orgRole: orgRoleOf({ role: u.role, roleKey }),
      projectIds: memberships.filter((m) => m.userId === u.id).map((m) => m.projectId),
    }))
  );
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
      roleKey: roles.key,
      config: users.config,
      externalRoles: users.externalRoles,
      isActive: users.isActive,
      createdAt: users.createdAt,
    })
    .from(users)
    .leftJoin(roles, eq(roles.id, users.roleId))
    // Scope to the org in the path. orgScopeGuard proves the ROUTE orgId matches
    // the caller's token, but says nothing about which org the TARGET user is in,
    // so an unscoped lookup by id reaches users in any other tenant.
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .limit(1);

  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  // The apps shared with this user directly (object_grants), with their level.
  const grants = await db
    .select({
      appId: apps.id,
      appName: apps.name,
      appType: apps.type,
      level: objectGrants.level,
      createdAt: objectGrants.createdAt,
    })
    .from(objectGrants)
    .innerJoin(objects, eq(objects.id, objectGrants.objectId))
    .innerJoin(apps, sql`${apps.id}::text = ${objects.refId}`)
    .where(and(eq(objectGrants.principalType, "user"), eq(objectGrants.principalId, userId)));
  const permissions = grants.map((g) => ({ ...g, permission: legacyPermission(g.level as Level) }));

  const { roleKey, ...rest } = user;
  return c.json({ ...rest, orgRole: orgRoleOf({ role: user.role, roleKey }), ...(await scopeOf(db, userId)), permissions });
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
    // all, or selected; projectIds replaces the list (lib/project-scope.ts).
    projectScope?: unknown;
    projectIds?: unknown;
    // Deactivating: who gets what they own (default: whoever deactivates them).
    transferTo?: unknown;
  }>();

  const target = await loadMember(db, orgId, userId);
  if (!target) {
    return c.json({ error: "User not found" }, 404);
  }
  const isSelf = userId === actorId;

  // Admins and Owners are changed only by the Owner, except a person editing themselves.
  if (!mayActOn(c, target, isSelf)) {
    return c.json({ error: "Only an Owner can change an admin or Owner" }, 403);
  }

  // Resolved only after validation below; stays undefined when role is absent
  // or unchanged, which leaves the stored role untouched.
  let validatedRole: ResolvedRole | undefined;

  if (body.role !== undefined) {
    // Mirrors the POST guard this path never had. Unconditional: super_admin is
    // granted via the database, never over the API.
    if (body.role === "super_admin") {
      return c.json({ error: "Cannot assign super_admin via this endpoint" }, 403);
    }

    // Whitelist: a built-in role or one of this org's custom roles, nothing else.
    const requested = await resolveRole(db, orgId, body.role);
    if (!requested) {
      return c.json({ error: "Invalid role" }, 400);
    }

    // No self-promotion — the reported attack was an org_admin editing its own row.
    if (isSelf && actorRole !== "super_admin") {
      return c.json({ error: "Cannot change your own role" }, 403);
    }

    if (requested.key !== target.orgRole) {
      // Making or unmaking an admin or Owner is the Owner's alone.
      if ((ADMIN_ROLES.includes(requested.key) || ADMIN_ROLES.includes(target.orgRole)) && !hasPermission(c, "admins.manage")) {
        return c.json({ error: "Only an Owner can make or change an admin" }, 403);
      }
      // No one hands out, or strips, more than they hold themselves.
      const current = await resolveRole(db, orgId, target.orgRole);
      if (!mayGrantRole(c.get("permissions"), requested) || (current && !mayGrantRole(c.get("permissions"), current))) {
        return c.json({ error: "You can only give or take away a role whose permissions you hold yourself" }, 403);
      }
      // An organization always keeps an Owner.
      if (target.orgRole === "owner" && target.isActive && (await activeOwnersExcept(db, orgId, userId)) === 0) {
        return c.json({ error: "This is the only Owner. Make someone else Owner first." }, 409);
      }
      if (requested.key === "owner" && !requested.id) {
        return c.json({ error: "The Owner role is not set up yet; run the roles migration" }, 400);
      }
      validatedRole = requested;
    }
  }

  // Data access rules are access.manage's, not just members.manage's.
  if (body.config !== undefined && !hasPermission(c, "access.manage")) {
    return c.json({ error: "Forbidden: changing data access requires access.manage" }, 403);
  }

  if (body.isActive === false && target.isActive) {
    if (isSelf) {
      return c.json({ error: "Cannot deactivate yourself" }, 403);
    }
    if (target.orgRole === "owner" && (await activeOwnersExcept(db, orgId, userId)) === 0) {
      return c.json({ error: "This is the only Owner. Make someone else Owner first." }, 409);
    }
  }

  // Project scope: never your own (that would let someone widen their reach),
  // and checked before anything is written.
  const changesScope = body.projectScope !== undefined || body.projectIds !== undefined;
  if (changesScope && isSelf && actorRole !== "super_admin") {
    return c.json({ error: "Cannot change your own projects" }, 403);
  }
  const roleAfter = validatedRole?.key ?? target.orgRole;
  if (changesScope) {
    const scopeError = await applyProjectScope(c, db, orgId, { id: userId, orgRole: roleAfter }, body.projectScope, body.projectIds, true);
    if (scopeError) return c.json({ error: scopeError.error }, scopeError.status);
  }

  // Deactivating: what they own goes to someone else first, as on removal.
  if (body.isActive === false && target.isActive) {
    const handed = await handOverOwned(c, db, orgId, userId, body.transferTo);
    if ("error" in handed) return c.json({ error: handed.error }, handed.status);
  }

  // Explicit allowlist. Spreading the request body let a caller set ANY column on
  // `users`: passwordHash (account takeover — login compares the same SHA-256),
  // orgId (move a user into another tenant), email or ssoSubject (hijack the SSO
  // identity mapping). Unknown keys are now ignored instead of written.
  const updates: {
    name?: string;
    email?: string;
    role?: "org_admin" | "member";
    roleId?: string | null;
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
    updates.role = validatedRole.kind;
    updates.roleId = validatedRole.id;
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

  if (validatedRole !== undefined) {
    await recordRoleChange(db, { orgId, userId, changedBy: actorId, fromRole: target.orgRole, toRole: validatedRole.key });
  }
  if (changesScope) {
    await applyProjectScope(c, db, orgId, { id: userId, orgRole: roleAfter }, body.projectScope, body.projectIds);
  }

  return c.json({ ...updated, orgRole: roleAfter, ...(await scopeOf(db, userId)) });
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

  const target = await loadMember(db, orgId, userId);
  if (!target) return c.json({ error: "User not found" }, 404);
  // An admin's or Owner's password is reset only by the Owner, or by themselves.
  if (!mayActOn(c, target, userId === c.get("userId"))) {
    return c.json({ error: "Only an Owner can set an admin's or Owner's password" }, 403);
  }

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
 * GET /orgs/:orgId/users/:userId/owned
 * What the member owns, which is handed over when they are removed.
 */
usersRouter.get("/:userId/owned", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  if (!(await loadMember(db, orgId, userId))) return c.json({ error: "User not found" }, 404);
  return c.json(await ownedBy(db, userId));
});

/**
 * DELETE /orgs/:orgId/users/:userId — optional { transferTo: userId }
 * Deactivate user (sets isActive = false, revokes all app access). Everything
 * they own is handed over first: to `transferTo`, or to whoever removes them.
 */
usersRouter.delete("/:userId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const body = await c.req.json<{ transferTo?: unknown }>().catch(() => ({}) as { transferTo?: unknown });

  const target = await loadMember(db, orgId, userId);
  if (!target) return c.json({ error: "User not found" }, 404);
  if (userId === c.get("userId")) {
    return c.json({ error: "Cannot remove yourself" }, 403);
  }
  if (!mayActOn(c, target, false)) {
    return c.json({ error: "Only an Owner can remove an admin or Owner" }, 403);
  }
  if (target.orgRole === "owner" && target.isActive && (await activeOwnersExcept(db, orgId, userId)) === 0) {
    return c.json({ error: "This is the only Owner. Make someone else Owner first." }, 409);
  }

  // What they own goes to someone else first, so nothing is left without an owner.
  const handed = await handOverOwned(c, db, orgId, userId, body.transferTo);
  if ("error" in handed) return c.json({ error: handed.error }, handed.status);

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

  // Revoke everything shared with them directly.
  await db
    .delete(objectGrants)
    .where(and(eq(objectGrants.principalType, "user"), eq(objectGrants.principalId, userId)));

  return c.json({
    message: "User deactivated and all permissions revoked",
    handedOver: handed.moved,
    handedOverTo: handed.to,
  });
});

export default usersRouter;
