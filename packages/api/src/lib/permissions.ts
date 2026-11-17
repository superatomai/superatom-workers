/**
 * Organization roles and permissions.
 *
 * Code checks PERMISSIONS, never role names, so a custom role (a named set of
 * permissions) needs no new checks. The built-in roles' permissions are defined
 * here rather than in role_permissions, so they cannot drift between databases.
 *
 * `users.role` stays the coarse kind other services read (super_admin, org_admin,
 * member). The organization role is `users.role_id`: an Owner is an org_admin
 * whose role_id is the built-in `owner` role. See ROLES-IMPLEMENTATION.md.
 */
import { and, count, eq, isNull, ne } from "drizzle-orm";
import { roleChanges, rolePermissions, roles, users } from "../db/schema";
import type { Database } from "../db";

/**
 * Every permission there is, as `module.action`, grouped by module with what
 * each one allows. A role is a set of these; this is the list a role screen
 * offers. Built-in roles take theirs from BUILT_IN_ROLES below.
 */
export const PERMISSION_CATALOGUE = [
  {
    module: "platform",
    label: "Platform",
    permissions: [{ key: "platform.access", label: "Sign in to the platform" }],
  },
  {
    module: "organization",
    label: "Organization",
    permissions: [
      { key: "org.edit", label: "Edit the organization's name, icon and landing app" },
      { key: "org.settings", label: "Change SSO and sign-in rules", ownerOnly: true },
      { key: "roles.manage", label: "Create and edit roles", ownerOnly: true },
      { key: "admins.manage", label: "Add, promote, demote and remove admins and Owners", ownerOnly: true },
    ],
  },
  {
    module: "members",
    label: "Members",
    permissions: [
      { key: "members.manage", label: "Add, edit and deactivate members, and give them roles" },
      { key: "access.manage", label: "Edit members' data access rules" },
    ],
  },
  {
    module: "projects",
    label: "Projects",
    permissions: [
      { key: "projects.create", label: "Create projects" },
      { key: "projects.edit", label: "Edit projects and their members" },
      { key: "projects.delete", label: "Delete projects" },
    ],
  },
  {
    module: "sources",
    label: "Data sources",
    permissions: [{ key: "sources.manage", label: "Connect, edit and delete data sources" }],
  },
  {
    module: "apps",
    label: "Dashboards, chat agents, reports and apps",
    permissions: [
      { key: "dashboards.create", label: "Create dashboards" },
      { key: "chat_agents.create", label: "Create chat agents" },
      { key: "reports.create", label: "Create reports" },
      { key: "apps.create", label: "Create mobile apps" },
    ],
  },
  {
    module: "data_model",
    label: "Data model",
    permissions: [
      { key: "graph.manage", label: "Edit, review and publish the composition graph" },
      { key: "concepts.create", label: "Create concepts" },
      { key: "intents.create", label: "Create intents" },
    ],
  },
  {
    module: "design",
    label: "Design system",
    permissions: [{ key: "design.edit", label: "Edit the design system" }],
  },
  {
    module: "follow_up",
    label: "Feedback, analytics and emails",
    permissions: [
      { key: "feedback.triage", label: "Set feedback resolutions" },
      { key: "analytics.view", label: "See analytics, usage and checklist reports" },
      { key: "emails.manage", label: "Send organization emails and manage their settings" },
    ],
  },
  {
    module: "releases",
    label: "Programs and updates",
    permissions: [
      { key: "programs.publish", label: "Publish, unpublish and pin dashboard programs" },
      { key: "updates.manage", label: "Update the project's engine servers" },
    ],
  },
] as const;

/** Every permission there is, as `module.action`. */
export const PERMISSIONS = PERMISSION_CATALOGUE.flatMap((m) => m.permissions.map((p) => p.key));

export type Permission = (typeof PERMISSION_CATALOGUE)[number]["permissions"][number]["key"];

/** Only an Owner holds these; a custom role can never carry them. */
export const OWNER_ONLY: readonly Permission[] = PERMISSION_CATALOGUE.flatMap((m) =>
  m.permissions.filter((p) => "ownerOnly" in p && p.ownerOnly).map((p) => p.key)
);

export type BuiltInRole = "owner" | "admin" | "member";

/** What each built-in role may do. Members use the runtime only, so they hold none. */
export const BUILT_IN_ROLES: Record<BuiltInRole, readonly Permission[]> = {
  owner: PERMISSIONS,
  admin: PERMISSIONS.filter((p) => !OWNER_ONLY.includes(p)),
  member: [],
};

/** Roles that may manage other members, and so need `admins.manage` to be acted on. */
export const ADMIN_ROLES: readonly string[] = ["owner", "admin"];

export type UserRoleKind = "super_admin" | "org_admin" | "member";

/**
 * A user's organization role: the key of their role row, or, when role_id is
 * empty, what `users.role` implies.
 */
export function orgRoleOf(user: { role: UserRoleKind; roleKey?: string | null }): string {
  if (user.role === "super_admin") return "super_admin";
  if (user.roleKey) return user.roleKey;
  return user.role === "org_admin" ? "admin" : "member";
}

/**
 * The permissions a user holds. The platform super admin holds all of them; a
 * built-in role holds its list from BUILT_IN_ROLES; a custom role holds its rows
 * (passed in as `customPermissions`), minus anything Owner-only.
 */
export function permissionsOf(user: {
  role: UserRoleKind;
  roleKey?: string | null;
  roleIsSystem?: boolean | null;
  customPermissions?: readonly string[] | null;
}): Permission[] {
  if (user.role === "super_admin") return [...PERMISSIONS];
  const key = orgRoleOf(user);
  if (!user.roleKey || user.roleIsSystem) {
    return [...(BUILT_IN_ROLES[key as BuiltInRole] ?? [])];
  }
  return (user.customPermissions ?? []).filter(
    (p): p is Permission => (PERMISSIONS as readonly string[]).includes(p) && !OWNER_ONLY.includes(p as Permission)
  );
}

/** The `users.role` value an organization role is stored with. */
export function roleKindFor(orgRole: BuiltInRole): "org_admin" | "member" {
  return orgRole === "member" ? "member" : "org_admin";
}

/**
 * Reads the organization role a request asks for: `member`, `admin`, `owner`, and
 * the old `org_admin` (read as `admin`). Anything else is null.
 */
export function parseOrgRole(value: unknown): BuiltInRole | null {
  if (value === "org_admin") return "admin";
  if (value === "member" || value === "admin" || value === "owner") return value;
  return null;
}

/** A role a request names, resolved: built-in (owner, admin, member) or one of the org's custom roles. */
export type ResolvedRole = {
  key: string;
  id: string | null;
  /** The users.role it is stored with: org_admin for Owner and Admin, member for everything else. */
  kind: "org_admin" | "member";
  isSystem: boolean;
  permissions: Permission[];
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The role a request names: a built-in key (owner, admin, member, or the old
 * org_admin), or a custom role of this org by its key or id. Null when there is
 * no such role. A custom role is stored with users.role = member, so services
 * that only know the old kinds treat its holders as members; what they may do
 * on top comes from its permissions.
 */
export async function resolveRole(db: Database, orgId: string, value: unknown): Promise<ResolvedRole | null> {
  const builtIn = parseOrgRole(value);
  if (builtIn) {
    return {
      key: builtIn,
      id: await builtInRoleId(db, builtIn),
      kind: roleKindFor(builtIn),
      isSystem: true,
      permissions: [...BUILT_IN_ROLES[builtIn]],
    };
  }
  if (typeof value !== "string" || !value) return null;
  const [row] = await db
    .select({ id: roles.id, key: roles.key })
    .from(roles)
    .where(and(eq(roles.orgId, orgId), eq(roles.isSystem, false), UUID_RE.test(value) ? eq(roles.id, value) : eq(roles.key, value)))
    .limit(1);
  if (!row) return null;
  const custom = (await db.select({ p: rolePermissions.permission }).from(rolePermissions).where(eq(rolePermissions.roleId, row.id))).map((r) => r.p);
  return {
    key: row.key,
    id: row.id,
    kind: "member",
    isSystem: false,
    permissions: permissionsOf({ role: "member", roleKey: row.key, roleIsSystem: false, customPermissions: custom }),
  };
}

/**
 * Whether someone holding `held` may give a role, or take it away: only when
 * they hold every permission it carries, so no one can hand out (or strip) more
 * than they have themselves.
 */
export function mayGrantRole(held: readonly string[], role: { permissions: readonly string[] }): boolean {
  return role.permissions.every((p) => held.includes(p));
}

/** The id of a built-in role's row; null when the migration has not added it yet. */
export async function builtInRoleId(db: Database, key: BuiltInRole): Promise<string | null> {
  const [row] = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(isNull(roles.orgId), eq(roles.key, key)))
    .limit(1);
  return row?.id ?? null;
}

/**
 * A user's organization role and permissions, for code that has a user row but
 * did not come through authMiddleware (the login response).
 */
export async function roleAndPermissions(
  db: Database,
  user: { role: UserRoleKind; roleId?: string | null }
): Promise<{ orgRole: string; permissions: Permission[] }> {
  let roleKey: string | null = null;
  let roleIsSystem: boolean | null = null;
  let customPermissions: string[] | null = null;
  if (user.roleId) {
    const [row] = await db
      .select({ key: roles.key, isSystem: roles.isSystem })
      .from(roles)
      .where(eq(roles.id, user.roleId))
      .limit(1);
    roleKey = row?.key ?? null;
    roleIsSystem = row?.isSystem ?? null;
    if (row && !row.isSystem) {
      customPermissions = (
        await db.select({ p: rolePermissions.permission }).from(rolePermissions).where(eq(rolePermissions.roleId, user.roleId))
      ).map((r) => r.p);
    }
  }
  const resolved = { role: user.role, roleKey, roleIsSystem, customPermissions };
  return { orgRole: orgRoleOf(resolved), permissions: permissionsOf(resolved) };
}

/** How many active Owners an organization has, leaving one user out (the one being changed). */
export async function activeOwnersExcept(db: Database, orgId: string, exceptUserId: string): Promise<number> {
  const ownerId = await builtInRoleId(db, "owner");
  if (!ownerId) return 0;
  const [row] = await db
    .select({ n: count() })
    .from(users)
    .where(and(eq(users.orgId, orgId), eq(users.roleId, ownerId), eq(users.isActive, true), ne(users.id, exceptUserId)));
  return Number(row?.n ?? 0);
}

/** Records a change of a user's organization role. */
export async function recordRoleChange(
  db: Database,
  change: { orgId: string; userId: string; changedBy: string | null; fromRole: string | null; toRole: string | null }
): Promise<void> {
  await db.insert(roleChanges).values(change);
}
