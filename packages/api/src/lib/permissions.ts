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
import { rolePermissions, roles, userPermissionLimits, users } from "../db/schema";
import type { Database } from "../db";
import { logAccess } from "./access-log";
import { writeTogether } from "./write-together";

/** The same four actions on every kind of object. */
const crud = <R extends string>(resource: R, label: string) =>
  [
    { key: `${resource}.view` as `${R}.view`, label: `View ${label}` },
    { key: `${resource}.create` as `${R}.create`, label: `Create ${label}` },
    { key: `${resource}.edit` as `${R}.edit`, label: `Edit ${label}` },
    { key: `${resource}.delete` as `${R}.delete`, label: `Delete ${label}` },
  ] as const;

/**
 * Every permission a role can carry, as `resource.action`, grouped by module
 * with what each one allows: the list a role screen offers. Built-in roles take
 * theirs from BUILT_IN_ROLES below.
 *
 * Managing people (members.*) is here, so the Owner can give it deliberately,
 * but only the Owner can put it in a role or give such a role (routes/roles.ts,
 * routes/users.ts), and nobody acts on Admins, the Owner or themselves.
 *
 * Deliberately NOT here, and so never part of any role: managing admins and
 * roles, and the organization's settings and SSO. Those are fixed to the Owner
 * (and Admins, for org settings) in code (see FIXED below).
 */
export const PERMISSION_CATALOGUE = [
  {
    module: "platform",
    label: "Platform",
    permissions: [{ key: "platform.access", label: "Sign in to the platform" }],
  },
  {
    module: "members",
    label: "Members",
    permissions: [
      { key: "members.view", label: "See members, their data rules and access history" },
      { key: "members.history", label: "See the access log: who gave or took away whose access, and when" },
      { key: "members.create", label: "Add members" },
      { key: "members.edit", label: "Change members' name and email, deactivate and reactivate them" },
      { key: "members.assign", label: "Give members a role and choose their projects" },
      { key: "members.data_rules", label: "Set members' data access rules" },
      { key: "members.reset_password", label: "Reset members' passwords" },
    ],
  },
  { module: "projects", label: "Projects", permissions: crud("project", "projects") },
  { module: "sources", label: "Data sources", permissions: crud("source", "data sources") },
  { module: "dashboards", label: "Dashboards", permissions: crud("dashboard", "dashboards") },
  { module: "reports", label: "Reports", permissions: crud("report", "reports") },
  { module: "agents", label: "Chat agents", permissions: crud("agent", "chat agents") },
  { module: "apps", label: "Apps", permissions: crud("app", "mobile apps") },
  {
    module: "model",
    label: "Data model",
    permissions: [
      { key: "model.view", label: "View the data model (graph, concepts, intents)" },
      { key: "model.edit", label: "Edit, review and publish the data model" },
    ],
  },
  {
    module: "design",
    label: "Design system",
    permissions: [
      { key: "design.view", label: "View the design system" },
      { key: "design.edit", label: "Edit the design system" },
    ],
  },
  {
    module: "releases",
    label: "Programs and updates",
    permissions: [
      { key: "program.view", label: "View dashboard programs" },
      { key: "program.publish", label: "Publish, unpublish and pin dashboard programs" },
      { key: "update.view", label: "View the project's engine updates" },
      { key: "update.apply", label: "Update the project's engine servers" },
    ],
  },
  {
    module: "feedback",
    label: "Feedback",
    permissions: [
      { key: "feedback.view", label: "View feedback" },
      { key: "feedback.triage", label: "Set feedback resolutions" },
    ],
  },
  {
    module: "analytics",
    label: "Analytics",
    permissions: [
      { key: "analytics.view", label: "See analytics, usage and checklist reports" },
      { key: "analytics.export", label: "Export analytics" },
    ],
  },
  {
    module: "emails",
    label: "Emails",
    permissions: [
      { key: "email.view", label: "View organization emails" },
      { key: "email.send", label: "Write, schedule and send organization emails" },
    ],
  },
] as const;

/** Every permission a role can carry. */
export const PERMISSIONS = PERMISSION_CATALOGUE.flatMap((m) => m.permissions.map((p) => p.key));

export type Permission = (typeof PERMISSION_CATALOGUE)[number]["permissions"][number]["key"];

export type BuiltInRole = "owner" | "admin" | "member";

/**
 * What an Admin holds, written out on purpose rather than "everything": a
 * permission added to the catalogue later goes to the Owner only, until someone
 * deliberately adds it here (or to ADMIN_WITHHELD). A test checks every
 * permission is in one list or the other, so none is decided by accident.
 */
const ADMIN_PERMISSIONS: readonly Permission[] = [
  "platform.access",
  "members.view", "members.history", "members.create", "members.edit", "members.assign", "members.data_rules", "members.reset_password",
  "project.view", "project.create", "project.edit", "project.delete",
  "source.view", "source.create", "source.edit", "source.delete",
  "dashboard.view", "dashboard.create", "dashboard.edit", "dashboard.delete",
  "report.view", "report.create", "report.edit", "report.delete",
  "agent.view", "agent.create", "agent.edit", "agent.delete",
  "app.view", "app.create", "app.edit", "app.delete",
  "model.view", "model.edit",
  "design.view", "design.edit",
  "program.view", "program.publish",
  "update.view", "update.apply",
  "feedback.view", "feedback.triage",
  "analytics.view", "analytics.export",
  "email.view", "email.send",
];

/** Permissions deliberately kept from Admins (the Owner's alone). None today. */
export const ADMIN_WITHHELD: readonly Permission[] = [];

/**
 * What each built-in role may do from the catalogue. The Owner holds all of it;
 * an Admin holds ADMIN_PERMISSIONS; what else separates them is FIXED, below.
 * Members use the runtime only. One Admin can hold less: the Owner's per-person
 * limits (user_permission_limits).
 */
export const BUILT_IN_ROLES: Record<BuiltInRole, readonly Permission[]> = {
  owner: PERMISSIONS,
  admin: ADMIN_PERMISSIONS,
  member: [],
};

/** The people powers: what a new Admin starts WITHOUT, until the Owner ticks them. */
export const PEOPLE_PERMISSIONS = PERMISSIONS.filter((p) => p.startsWith("members.")) as Permission[];

/** Roles that manage other members; only the Owner gives, changes or removes them. */
export const ADMIN_ROLES: readonly string[] = ["owner", "admin"];

/**
 * Powers fixed to the built-in roles in code, never part of any role. Each maps
 * to the org roles allowed (the platform super admin is always allowed).
 * Nobody may use any of them on themselves; routes/users.ts enforces that.
 */
export const FIXED = {
  /** Make, change or remove Admins and Owners, and set an Admin's limits. */
  manageAdmins: ["owner"],
  /** Create, edit and delete custom roles. */
  manageRoles: ["owner"],
  /** The organization's name, icon and landing app. */
  editOrg: ["owner", "admin"],
  /** SSO and sign-in rules. */
  orgSettings: ["owner"],
} as const satisfies Record<string, readonly BuiltInRole[]>;

export type FixedPower = keyof typeof FIXED;

/** Whether an org role (or the platform super admin) has a fixed power. */
export function hasFixedPower(orgRole: string | null | undefined, power: FixedPower): boolean {
  return orgRole === "super_admin" || (FIXED[power] as readonly string[]).includes(orgRole ?? "");
}

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
 * (passed in as `customPermissions`).
 */
export function permissionsOf(user: {
  role: UserRoleKind;
  roleKey?: string | null;
  roleIsSystem?: boolean | null;
  customPermissions?: readonly string[] | null;
  /** Per-person limits (user_permission_limits): removed, applied to Admins only. */
  limits?: readonly string[] | null;
}): Permission[] {
  if (user.role === "super_admin") return [...PERMISSIONS];
  const key = orgRoleOf(user);
  if (!user.roleKey || user.roleIsSystem) {
    const builtIn = [...(BUILT_IN_ROLES[key as BuiltInRole] ?? [])];
    // Limits only narrow an Admin; an Owner always holds everything.
    return key === "admin" && user.limits?.length ? builtIn.filter((p) => !user.limits!.includes(p)) : builtIn;
  }
  // Only what is still in the catalogue: a permission renamed or retired since
  // the role was saved grants nothing.
  return (user.customPermissions ?? []).filter((p): p is Permission => (PERMISSIONS as readonly string[]).includes(p));
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
  user: { id?: string; role: UserRoleKind; roleId?: string | null }
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
  const limits = user.id && orgRoleOf({ role: user.role, roleKey }) === "admin" ? await limitsOf(db, user.id) : [];
  const resolved = { role: user.role, roleKey, roleIsSystem, customPermissions, limits };
  return { orgRole: orgRoleOf(resolved), permissions: permissionsOf(resolved) };
}

/** One person's limits: the permissions their role carries that they do not get. */
export async function limitsOf(db: Database, userId: string): Promise<string[]> {
  return (await db.select({ p: userPermissionLimits.permission }).from(userPermissionLimits).where(eq(userPermissionLimits.userId, userId))).map(
    (r) => r.p
  );
}

/**
 * Sets one Admin's limits to exactly `limits` (permissions they do not get).
 * Only ever narrows: every entry must be a permission the Admin role carries.
 */
export async function setLimits(db: Database, userId: string, limits: readonly string[], setBy: string | null): Promise<void> {
  await writeTogether(db, [
    db.delete(userPermissionLimits).where(eq(userPermissionLimits.userId, userId)),
    limits.length > 0 &&
      db.insert(userPermissionLimits).values(limits.map((permission) => ({ userId, permission, createdBy: setBy }))),
  ]);
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

/** Records a change of a user's organization role in the access log (a new member: fromRole null). */
export async function recordRoleChange(
  db: Database,
  change: { orgId: string; userId: string; changedBy: string | null; fromRole: string | null; toRole: string | null }
): Promise<void> {
  await logAccess(db, {
    orgId: change.orgId,
    actorId: change.changedBy,
    action: change.fromRole === null ? "member.added" : "member.role_changed",
    target: { type: "user", id: change.userId },
    subjectId: change.userId,
    before: change.fromRole === null ? null : { role: change.fromRole },
    after: { role: change.toRole },
  });
}
