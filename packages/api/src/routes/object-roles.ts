import { Hono } from "hono";
import { and, eq, inArray, isNull, or } from "drizzle-orm";
import { objectGrants, objectRoleActions, objectRoles } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, orgScopeGuard, requireFixed, requirePermission } from "../middleware/auth";
import { OBJECT_ACTIONS, isObjectAction, type ObjectAction } from "../lib/object-policy";
import { keyFrom } from "./roles";
import { actorOf, logAccess } from "../lib/access-log";
import { writeTogether } from "../lib/write-together";

const router = new Hono<{ Bindings: Env; Variables: AppVariables }>();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TYPES = ["project", "source", "dashboard", "chat_agent", "report", "app"];
const SYSTEM_KEYS = ["view", "edit", "manage", "owner", "admin", "super_admin"];

router.use("*", authMiddleware, requirePermission("platform.access"), orgScopeGuard);
router.post("*", requireFixed("manageRoles"));
router.put("*", requireFixed("manageRoles"));
router.delete("*", requireFixed("manageRoles"));

function checkedActions(value: unknown): ObjectAction[] | null {
  if (!Array.isArray(value) || !value.every(isObjectAction)) return null;
  const actions = [...new Set(value)];
  if (actions.includes("handover")) return null; // Ownership stays with the owner field.
  if (actions.some((a) => a !== "view") && !actions.includes("view")) return null;
  return actions;
}

async function withActions(db: any, roles: (typeof objectRoles.$inferSelect)[]) {
  const rows = roles.length
    ? await db.select().from(objectRoleActions).where(inArray(objectRoleActions.roleId, roles.map((r) => r.id)))
    : [];
  return roles.map((role) => ({
    ...role,
    actions: OBJECT_ACTIONS.filter((action) => rows.some((row: typeof objectRoleActions.$inferSelect) => row.roleId === role.id && row.action === action)),
  }));
}

router.get("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const roles = await db.select().from(objectRoles)
    .where(or(isNull(objectRoles.orgId), eq(objectRoles.orgId, orgId)))
    .orderBy(objectRoles.isSystem, objectRoles.name);
  return c.json(await withActions(db, roles.sort((a, b) => Number(b.isSystem) - Number(a.isSystem))));
});

router.get("/catalogue", (c) => c.json({ actions: OBJECT_ACTIONS, objectTypes: TYPES }));

router.post("/", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const body = await c.req.json<{ name?: unknown; description?: unknown; objectType?: unknown; actions?: unknown }>().catch(() => ({} as { name?: unknown; description?: unknown; objectType?: unknown; actions?: unknown }));
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const key = keyFrom(name);
  const actions = checkedActions(body.actions);
  if (!name || name.length > 255 || !key || SYSTEM_KEYS.includes(key)) return c.json({ error: "Invalid role name" }, 400);
  if (!actions) return c.json({ error: "actions must be known actions, with view included; handover is reserved for owners" }, 400);
  if (body.description != null && typeof body.description !== "string") return c.json({ error: "Invalid description" }, 400);
  if (body.objectType != null && !TYPES.includes(String(body.objectType))) return c.json({ error: "Invalid objectType" }, 400);
  const [exists] = await db.select({ id: objectRoles.id }).from(objectRoles)
    .where(and(eq(objectRoles.orgId, orgId), eq(objectRoles.key, key))).limit(1);
  if (exists) return c.json({ error: "An object role with this name already exists" }, 409);
  // The id is made here so the role and its actions are saved together.
  const roleId = crypto.randomUUID();
  await writeTogether(db, [
    db.insert(objectRoles).values({
      id: roleId, orgId, key, name, description: body.description as string | undefined,
      objectType: body.objectType as string | undefined, createdBy: c.get("userId"),
    }),
    actions.length > 0 && db.insert(objectRoleActions).values(actions.map((action) => ({ roleId, action }))),
  ]);
  const [role] = await db.select().from(objectRoles).where(eq(objectRoles.id, roleId)).limit(1);
  await logAccess(db, { orgId, actorId: actorOf(c), action: "role.created",
    target: { type: "role", id: role.id }, after: { kind: "object", name, objectType: role.objectType, actions } });
  return c.json({ ...role, actions }, 201);
});

router.put("/:roleId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const roleId = c.req.param("roleId");
  if (!UUID.test(roleId)) return c.json({ error: "Role not found" }, 404);
  const [before] = await db.select().from(objectRoles)
    .where(and(eq(objectRoles.id, roleId), eq(objectRoles.orgId, orgId), eq(objectRoles.isSystem, false))).limit(1);
  if (!before) return c.json({ error: "Role not found" }, 404);
  const body = await c.req.json<{ name?: unknown; description?: unknown; actions?: unknown }>().catch(() => ({} as { name?: unknown; description?: unknown; actions?: unknown }));
  const name = body.name === undefined ? before.name : typeof body.name === "string" ? body.name.trim() : "";
  const key = keyFrom(name);
  const actions = body.actions === undefined ? undefined : checkedActions(body.actions);
  if (!name || name.length > 255 || !key || SYSTEM_KEYS.includes(key)) return c.json({ error: "Invalid role name" }, 400);
  if (actions === null) return c.json({ error: "Invalid actions" }, 400);
  if (body.description != null && typeof body.description !== "string") return c.json({ error: "Invalid description" }, 400);
  const [conflict] = await db.select({ id: objectRoles.id }).from(objectRoles)
    .where(and(eq(objectRoles.orgId, orgId), eq(objectRoles.key, key))).limit(1);
  if (conflict && conflict.id !== roleId) return c.json({ error: "An object role with this name already exists" }, 409);
  const existing = actions ? await db.select().from(objectRoleActions).where(eq(objectRoleActions.roleId, roleId)) : [];
  const remove = actions ? existing.filter((row) => !actions.includes(row.action as ObjectAction)).map((row) => row.action) : [];
  const add = actions ? actions.filter((action) => !existing.some((row) => row.action === action)) : [];
  await writeTogether(db, [
    db.update(objectRoles)
      .set({ name, key, description: body.description as string | undefined, updatedAt: new Date() })
      .where(eq(objectRoles.id, roleId)),
    remove.length > 0 &&
      db.delete(objectRoleActions).where(and(eq(objectRoleActions.roleId, roleId), inArray(objectRoleActions.action, remove))),
    add.length > 0 && db.insert(objectRoleActions).values(add.map((action) => ({ roleId, action }))),
  ]);
  const [role] = await db.select().from(objectRoles).where(eq(objectRoles.id, roleId)).limit(1);
  const updated = (await withActions(db, [role]))[0];
  await logAccess(db, { orgId, actorId: actorOf(c), action: "role.edited",
    target: { type: "role", id: roleId }, before: { kind: "object", name: before.name },
    after: { kind: "object", name: role.name, actions: updated.actions } });
  return c.json(updated);
});

router.delete("/:roleId", async (c) => {
  const db = c.get("db");
  const orgId = c.req.param("orgId")!;
  const roleId = c.req.param("roleId");
  if (!UUID.test(roleId)) return c.json({ error: "Role not found" }, 404);
  const [role] = await db.select().from(objectRoles)
    .where(and(eq(objectRoles.id, roleId), eq(objectRoles.orgId, orgId), eq(objectRoles.isSystem, false))).limit(1);
  if (!role) return c.json({ error: "Role not found" }, 404);
  const [assigned] = await db.select({ id: objectGrants.id }).from(objectGrants).where(eq(objectGrants.objectRoleId, roleId)).limit(1);
  if (assigned) return c.json({ error: "Remove this role from all grants first" }, 409);
  const [withItsActions] = await withActions(db, [role]);
  await db.delete(objectRoles).where(eq(objectRoles.id, roleId));
  // The name and actions are kept in the log: the role itself is gone.
  await logAccess(db, { orgId, actorId: actorOf(c), action: "role.deleted",
    target: { type: "role", id: roleId },
    before: { kind: "object", name: role.name, objectType: role.objectType, actions: withItsActions.actions } });
  return c.json({ message: "Object role deleted" });
});

export default router;
