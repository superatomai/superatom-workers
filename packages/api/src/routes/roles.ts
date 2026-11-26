import { Hono } from "hono";
import { and, count, eq, inArray, isNull, or } from "drizzle-orm";
import { rolePermissions, roles, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, orgScopeGuard, requireFixed, requirePermission } from "../middleware/auth";
import { BUILT_IN_ROLES, PERMISSIONS, PERMISSION_CATALOGUE, missingDependency, type BuiltInRole } from "../lib/permissions";
import { actorOf, logAccess } from "../lib/access-log";
import { writeTogether } from "../lib/write-together";

/**
 * Organization roles: the built-in ones (Owner, Admin, Member) and the org's
 * custom roles, each a named set of permissions from PERMISSION_CATALOGUE.
 * Mounted at /orgs/:orgId/roles.
 *
 * Anyone on the platform may read them (the members screen needs the list);
 * creating, editing and deleting a custom role is fixed to the Owner (FIXED in
 * lib/permissions.ts), never a permission a role could carry. Built-in roles
 * cannot be edited or deleted.
 */
const rolesRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

rolesRouter.use("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);
rolesRouter.post("*", requireFixed("manageRoles"));
rolesRouter.put("*", requireFixed("manageRoles"));
rolesRouter.delete("*", requireFixed("manageRoles"));

export const RESERVED_KEYS = ["owner", "admin", "member", "org_admin", "super_admin"];

/** A key from a name: "Data Lead" → "data_lead". */
export const keyFrom = (name: string) =>
  name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64);

/** The permissions a request asks for, or the reason they are refused. */
export function checkedPermissions(value: unknown): { ok: true; permissions: string[] } | { ok: false; error: string } {
  if (!Array.isArray(value)) return { ok: false, error: "permissions must be a list" };
  const list = [...new Set(value.map(String))];
  const unknown = list.filter((p) => !(PERMISSIONS as readonly string[]).includes(p));
  if (unknown.length) return { ok: false, error: `Unknown permissions: ${unknown.join(", ")}` };
  const missing = missingDependency(list);
  if (missing) return { ok: false, error: missing };
  return { ok: true, permissions: list };
}

/** A custom role of this org, or undefined. */
async function customRole(db: any, orgId: string, roleId: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(roleId)) return undefined;
  const [row] = await db
    .select()
    .from(roles)
    .where(and(eq(roles.id, roleId), eq(roles.orgId, orgId)))
    .limit(1);
  return row as typeof roles.$inferSelect | undefined;
}

/**
 * GET /orgs/:orgId/roles/catalogue
 * Every permission, grouped by module, with what it allows and whether only an
 * Owner may hold it. What a role screen offers.
 */
rolesRouter.get("/catalogue", (c) => c.json({ modules: PERMISSION_CATALOGUE }));

/**
 * GET /orgs/:orgId/roles
 * The built-in roles and this org's custom roles, each with its permissions
 * and how many active members hold it.
 */
rolesRouter.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;

  const rows = await db
    .select()
    .from(roles)
    // Only organization roles: super_admin (scope platform) is never offered to an org.
    .where(and(eq(roles.scope, "org"), or(isNull(roles.orgId), eq(roles.orgId, orgId))))
    .orderBy(roles.isSystem, roles.name);
  const ids = rows.map((r) => r.id);

  const perms = ids.length
    ? await db.select().from(rolePermissions).where(inArray(rolePermissions.roleId, ids))
    : [];
  const counts = ids.length
    ? await db
        .select({ roleId: users.roleId, n: count() })
        .from(users)
        .where(and(eq(users.orgId, orgId), eq(users.isActive, true), inArray(users.roleId, ids)))
        .groupBy(users.roleId)
    : [];

  return c.json(
    rows
      // Built-in first (Owner, Admin, Member), then custom roles by name.
      .sort((a, b) => Number(b.isSystem) - Number(a.isSystem) || ["owner", "admin", "member"].indexOf(a.key) - ["owner", "admin", "member"].indexOf(b.key))
      .map((r) => ({
        id: r.id,
        key: r.key,
        name: r.name,
        description: r.description,
        isSystem: r.isSystem,
        permissions: r.isSystem
          ? [...(BUILT_IN_ROLES[r.key as BuiltInRole] ?? [])]
          : perms.filter((p) => p.roleId === r.id).map((p) => p.permission),
        members: Number(counts.find((x) => x.roleId === r.id)?.n ?? 0),
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
      }))
  );
});

/**
 * POST /orgs/:orgId/roles — { name, description?, permissions: string[] }
 * Create a custom role. Its key is made from the name and is unique in the org.
 */
rolesRouter.post("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const body = await c.req.json<{ name?: unknown; description?: unknown; permissions?: unknown }>().catch(() => ({}) as any);

  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!name || name.length > 255) return c.json({ error: "name is required (at most 255 characters)" }, 400);
  if (body.description !== undefined && body.description !== null && typeof body.description !== "string") {
    return c.json({ error: "description must be text" }, 400);
  }
  const checked = checkedPermissions(body.permissions ?? []);
  if (!checked.ok) return c.json({ error: checked.error }, 400);

  const key = keyFrom(name);
  if (!key || RESERVED_KEYS.includes(key)) return c.json({ error: `"${name}" is reserved for a built-in role` }, 400);
  const [clash] = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.orgId, orgId), eq(roles.key, key)))
    .limit(1);
  if (clash) return c.json({ error: `A role named "${name}" already exists` }, 409);

  // The id is made here so the role and its permissions are saved together.
  const roleId = crypto.randomUUID();
  const description = (body.description as string | undefined) ?? null;
  await writeTogether(db, [
    db.insert(roles).values({ id: roleId, orgId, key, name, description, isSystem: false, createdBy: c.get("userId") }),
    checked.permissions.length > 0 &&
      db.insert(rolePermissions).values(checked.permissions.map((permission) => ({ roleId, permission }))),
  ]);
  const [role] = await db.select().from(roles).where(eq(roles.id, roleId)).limit(1);
  await logAccess(db, {
    orgId,
    actorId: actorOf(c),
    action: "role.created",
    target: { type: "role", id: role.id },
    after: { key, name: role.name, permissions: checked.permissions },
  });
  return c.json({ ...role, permissions: checked.permissions, members: 0 }, 201);
});

/**
 * PUT /orgs/:orgId/roles/:roleId — { name?, description?, permissions? }
 * Edit a custom role. Its members get the new permissions on their next request.
 */
rolesRouter.put("/:roleId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const role = await customRole(db, orgId, c.req.param("roleId"));
  if (!role) return c.json({ error: "Role not found" }, 404);
  if (role.isSystem) return c.json({ error: "Built-in roles cannot be edited" }, 400);

  const body = await c.req.json<{ name?: unknown; description?: unknown; permissions?: unknown }>().catch(() => ({}) as any);
  const updates: { name?: string; description?: string | null; updatedAt: Date } = { updatedAt: new Date() };
  if (body.name !== undefined) {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > 255) return c.json({ error: "name is required (at most 255 characters)" }, 400);
    updates.name = name;
  }
  if (body.description !== undefined) {
    if (body.description !== null && typeof body.description !== "string") return c.json({ error: "description must be text" }, 400);
    updates.description = body.description as string | null;
  }
  let permissions: string[] | undefined;
  if (body.permissions !== undefined) {
    const checked = checkedPermissions(body.permissions);
    if (!checked.ok) return c.json({ error: checked.error }, 400);
    permissions = checked.permissions;
  }

  const previous = (await db.select().from(rolePermissions).where(eq(rolePermissions.roleId, role.id))).map((p) => p.permission);
  await writeTogether(db, [
    db.update(roles).set(updates).where(eq(roles.id, role.id)),
    permissions && db.delete(rolePermissions).where(eq(rolePermissions.roleId, role.id)),
    !!permissions?.length && db.insert(rolePermissions).values(permissions.map((permission) => ({ roleId: role.id, permission }))),
  ]);
  const [updated] = await db.select().from(roles).where(eq(roles.id, role.id)).limit(1);
  const current = permissions ?? previous;
  await logAccess(db, {
    orgId,
    actorId: actorOf(c),
    action: "role.edited",
    target: { type: "role", id: role.id },
    before: { name: role.name, description: role.description, permissions: previous },
    after: { name: updated.name, description: updated.description, permissions: current },
  });
  return c.json({ ...updated, permissions: current });
});

/**
 * DELETE /orgs/:orgId/roles/:roleId
 * Delete a custom role. Refused while active members hold it: give them
 * another role first, so nobody is left without one.
 */
rolesRouter.delete("/:roleId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const role = await customRole(db, orgId, c.req.param("roleId"));
  if (!role) return c.json({ error: "Role not found" }, 404);
  if (role.isSystem) return c.json({ error: "Built-in roles cannot be deleted" }, 400);

  const [{ n }] = await db
    .select({ n: count() })
    .from(users)
    .where(and(eq(users.roleId, role.id), eq(users.isActive, true)));
  if (Number(n) > 0) {
    return c.json({ error: `${n} active member(s) have this role. Give them another role first.` }, 409);
  }

  const permissions = (await db.select().from(rolePermissions).where(eq(rolePermissions.roleId, role.id))).map((p) => p.permission);
  await db.delete(roles).where(eq(roles.id, role.id));
  await logAccess(db, {
    orgId,
    actorId: actorOf(c),
    action: "role.deleted",
    target: { type: "role", id: role.id },
    before: { key: role.key, name: role.name, permissions },
  });
  return c.json({ message: "Role deleted" });
});

export default rolesRouter;
