/**
 * "Why can Ravi do this?": a person's role on a project and on everything in
 * it, with every reason behind each role, so any access can be traced to the
 * one thing that gave it (like Google Cloud's Policy Troubleshooter).
 *
 * The same rules as lib/objects.ts, written out as reasons instead of folded
 * into a single level. The highest reason wins, as there.
 */
import { and, eq, inArray } from "drizzle-orm";
import { apps, objectDenials, objectGrants, objects, organizations, projectMembers, projects, roles, users } from "../db/schema";
import type { Database } from "../db";
import { SOURCE_OBJECT, appAccess, ensureAppObjects, ensureProjectObjects, projectAccess, sharingRolesById, sourceAccess, type Caller, type Level } from "./objects";
import { levelForActions } from "./object-policy";
import { orgRoleOf, roleAndPermissions } from "./permissions";
import { projectAllowed } from "./project-scope";

export type Reason = { level: Level | null; text: string };
export type Explained = { type: string; id: string; name: string | null; level: Level | null; actions: string[]; reasons: Reason[] };

/** A person's access to a project and everything in it, with reasons; null when they are not in this org. */
export async function explainAccess(db: Database, orgId: string, projectId: string, userId: string) {
  const [u] = await db
    .select({ id: users.id, name: users.name, role: users.role, roleId: users.roleId, roleKey: roles.key, roleName: roles.name, projectScope: users.projectScope, isActive: users.isActive })
    .from(users)
    .leftJoin(roles, eq(roles.id, users.roleId))
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)))
    .limit(1);
  if (!u) return null;
  const orgRole = orgRoleOf(u);
  const { permissions } = await roleAndPermissions(db, u);
  const person = { id: u.id, name: u.name, role: u.roleName ?? orgRole, isActive: u.isActive };

  if (!u.isActive) return { person, project: { level: null, actions: [], reasons: [{ level: "view" as Level, text: "Removed from the organization: no access" }] }, items: [] };
  const inScope = await projectAllowed(db, { userId: u.id, userRole: u.role, orgRole, projectScope: u.projectScope }, projectId);
  if (!inScope) {
    return { person, project: { level: null, actions: [], reasons: [], blocked: "Limited to other projects, so nothing in this project is open to them, whatever is shared" }, items: [] };
  }
  const caller: Caller = {
    userId: u.id, orgId, userRole: u.role as Caller["userRole"], roleId: u.roleId,
    orgRole, projectScope: u.projectScope, permissions,
  };
  const projectDecision = await projectAccess(db, caller, projectId);

  // Grants that reach them, with how: directly, their role, a project they are in, or everyone.
  const memberOf = (await db.select({ p: projectMembers.projectId }).from(projectMembers).where(eq(projectMembers.userId, u.id))).map((r) => r.p);
  const projectObject = (await ensureProjectObjects(db, [projectId])).get(projectId)!;
  const appRows = await db.select({ app: apps, orgId: projects.orgId }).from(apps).innerJoin(projects, eq(projects.id, apps.projectId)).where(eq(apps.projectId, projectId));
  const appObjects = await ensureAppObjects(db, appRows);
  const sourceObjects = await db.select().from(objects).where(and(eq(objects.projectId, projectId), eq(objects.type, SOURCE_OBJECT)));
  const objectIds = [projectObject.id, ...[...appObjects.values()].map((o) => o.id), ...sourceObjects.map((o) => o.id)];
  const grants = (await db.select().from(objectGrants).where(inArray(objectGrants.objectId, objectIds))).filter(
    (g) =>
      (g.principalType === "user" && g.principalId === u.id) ||
      (g.principalType === "role" && g.principalId === u.roleId) ||
      (g.principalType === "org" && g.principalId === orgId) ||
      (g.principalType === "project" && memberOf.includes(g.principalId))
  );
  const denials = (await db.select().from(objectDenials).where(inArray(objectDenials.objectId, objectIds))).filter(
    (d) => (d.principalType === "user" && d.principalId === u.id) ||
      (d.principalType === "role" && d.principalId === u.roleId) ||
      (d.principalType === "org" && d.principalId === orgId) ||
      (d.principalType === "project" && memberOf.includes(d.principalId))
  );
  const names = await namesFor(db, [
    ...grants.flatMap((g) => [g.grantedBy, g.principalType === "project" ? g.principalId : null]),
    ...denials.map((d) => d.createdBy),
  ]);
  // A grant gives its sharing role's actions.
  const sharingRoles = await sharingRolesById(db, grants.map((g) => g.objectRoleId));
  const nameOf = (id: string | null) => (id ? names.get(id) : undefined);
  const denialReasons = (objectId: string, prefix = ""): Reason[] =>
    denials
      .filter((d) => d.objectId === objectId)
      .map((d) => {
        const by = nameOf(d.createdBy) ? ` by ${nameOf(d.createdBy)}` : "";
        const why = d.reason ? ` (${d.reason})` : "";
        return { level: null, text: `${prefix}Can't ${d.action}: taken away${by}${why}` };
      });
  const how = (g: (typeof grants)[number]) =>
    g.principalType === "user"
      ? "shared with them directly"
      : g.principalType === "role"
        ? `shared with their role ${person.role}`
        : g.principalType === "org"
          ? "shared with everyone in the organization"
          : `shared with the members of ${names.get(g.principalId) ?? "a project"}`;
  const by = (g: (typeof grants)[number]) => (g.grantedBy && names.get(g.grantedBy) ? ` by ${names.get(g.grantedBy)}` : "");
  const grantReasons = (objectId: string, prefix: string): Reason[] =>
    grants
      .filter((g) => g.objectId === objectId)
      .map((g) => {
        const role = sharingRoles.get(g.objectRoleId);
        const name = role?.name ?? "Unknown role";
        const can = role?.actions.length ? ` (can ${role.actions.join(", ")})` : "";
        return { level: levelForActions(role?.actions ?? []), text: `${prefix}${name}${can}: ${how(g)}${by(g)}` };
      });

  const projectReasons: Reason[] = [
    ...(projectObject.ownerId === u.id ? [{ level: "owner" as Level, text: "Owns the project" }] : []),
    ...grantReasons(projectObject.id, ""),
    ...denialReasons(projectObject.id),
    ...(u.role === "org_admin" ? [{ level: "owner" as Level, text: `${orgRole} of the organization` }] : []),
    ...(permissions.includes("project.view") ? [{ level: "view" as Level, text: `Their role ${person.role} has project.view: sees every project they reach` }] : []),
  ];
  // A role on the project carries to everything in it (its own role, not project.view).
  const projectGrants = grantReasons(projectObject.id, "Through the project: ").filter((r) => r.level);
  const projectOwned: Reason[] = projectObject.ownerId === u.id ? [{ level: "owner", text: "Through the project: owns the project" }] : [];

  const [org] = await db.select({ defaultAppId: organizations.defaultAppId }).from(organizations).where(eq(organizations.id, orgId)).limit(1);
  const items: Explained[] = [];
  for (const { app } of appRows) {
    const o = appObjects.get(app.id);
    if (!o) continue;
    const resource = app.type === "chat_agent" ? "agent" : app.type;
    const orgActions = permissions.filter((permission) => permission.startsWith(`${resource}.`));
    const reasons: Reason[] = [
      ...(o.ownerId === u.id ? [{ level: "owner" as Level, text: "Owns it" }] : []),
      ...grantReasons(o.id, ""),
      ...denialReasons(o.id),
      ...denialReasons(projectObject.id, "Through the project: "),
      ...projectGrants,
      ...projectOwned,
      ...(u.role === "org_admin" ? [{ level: "owner" as Level, text: `${orgRole} of the organization` }] : []),
      ...(orgActions.length ? [{ level: null, text: `Their role ${person.role} has ${orgActions.join(", ")}` }] : []),
      ...(app.isDefault ? [{ level: "view" as Level, text: "Open to everyone in the organization" }] : []),
      ...(org?.defaultAppId === app.id ? [{ level: "view" as Level, text: "The organization's landing app" }] : []),
    ];
    const decision = await appAccess(db, caller, app.id);
    if (o.status === "disabled" && !decision?.actions.includes("view")) {
      reasons.push({ level: null, text: "Disabled: unavailable without management access" });
    }
    if (reasons.length) items.push({ type: app.type, id: app.id, name: app.name,
      level: decision?.level ?? null, actions: decision?.actions ?? [], reasons });
  }
  for (const o of sourceObjects) {
    const id = o.refId.slice(projectId.length + 1);
    const reasons: Reason[] = [...grantReasons(o.id, ""), ...projectGrants, ...projectOwned,
      ...denialReasons(projectObject.id, "Through the project: "), ...denialReasons(o.id)];
    const decision = await sourceAccess(db, caller, projectId, id);
    if (reasons.length) items.push({ type: "source", id, name: null,
      level: decision?.level ?? null, actions: decision?.actions ?? [], reasons });
  }

  return { person, project: { level: projectDecision?.level ?? null, actions: projectDecision?.actions ?? [], reasons: projectReasons }, items };
}

async function namesFor(db: Database, ids: (string | null)[]) {
  const wanted = [...new Set(ids.filter((x): x is string => !!x))];
  const out = new Map<string, string>();
  if (!wanted.length) return out;
  for (const u of await db.select({ id: users.id, name: users.name }).from(users).where(inArray(users.id, wanted))) out.set(u.id, u.name);
  for (const p of await db.select({ id: projects.id, name: projects.name }).from(projects).where(inArray(projects.id, wanted))) out.set(p.id, p.name);
  return out;
}
