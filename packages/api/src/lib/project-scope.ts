/**
 * Project scope: which projects someone may reach at all.
 *
 * Each user has `project_scope`: `all`, or `selected` (only the projects they
 * are a member of, project_members). It is strict: a project outside someone's
 * scope is closed to them, and so is everything in it, whatever is shared. A
 * project is a data boundary (its own sources and engine), so one dashboard
 * let through would show exactly the data the limit keeps out.
 *
 * An Owner and the platform super admin always reach every project.
 *
 * Applied on top of everything else: a role says what someone may do, the
 * scope says where, and sharing says which apps.
 */
import { and, eq } from "drizzle-orm";
import { projectMembers, roles, users } from "../db/schema";
import type { Database } from "../db";
import { orgRoleOf } from "./permissions";

export const PROJECT_SCOPES = ["all", "selected"] as const;

export type ScopeCaller = {
  userId: string;
  userRole: "super_admin" | "org_admin" | "member";
  orgRole?: string | null;
  projectScope?: string | null;
};

/** Whether this caller reaches every project, with no need to look up their memberships. */
export function reachesAllProjects(caller: ScopeCaller): boolean {
  return caller.userRole === "super_admin" || caller.orgRole === "owner" || caller.projectScope !== "selected";
}

/** The projects a caller may reach: null means all of them. */
export async function allowedProjects(db: Database, caller: ScopeCaller): Promise<Set<string> | null> {
  if (reachesAllProjects(caller)) return null;
  const rows = await db
    .select({ projectId: projectMembers.projectId })
    .from(projectMembers)
    .where(eq(projectMembers.userId, caller.userId));
  return new Set(rows.map((r) => r.projectId));
}

/** Whether a caller may reach one project. */
export async function projectAllowed(db: Database, caller: ScopeCaller, projectId: string): Promise<boolean> {
  if (reachesAllProjects(caller)) return true;
  const [row] = await db
    .select({ projectId: projectMembers.projectId })
    .from(projectMembers)
    .where(and(eq(projectMembers.userId, caller.userId), eq(projectMembers.projectId, projectId)))
    .limit(1);
  return !!row;
}

/**
 * The scope of a user by id, for checks about someone other than the caller
 * (sharing with them, handing something over to them). Undefined: no such user.
 */
export async function scopeOfUser(db: Database, userId: string): Promise<ScopeCaller | undefined> {
  const [u] = await db
    .select({ id: users.id, role: users.role, roleKey: roles.key, projectScope: users.projectScope })
    .from(users)
    .leftJoin(roles, eq(roles.id, users.roleId))
    .where(eq(users.id, userId))
    .limit(1);
  if (!u) return undefined;
  return { userId: u.id, userRole: u.role, orgRole: orgRoleOf(u), projectScope: u.projectScope };
}

/**
 * The caller's scope from the request: what authMiddleware set, or, for a route
 * that authenticated on its own, looked up by user id. Undefined when there is
 * no user (a service token), which project scope does not apply to.
 */
export async function scopeOfRequest(c: { get: (k: any) => any }): Promise<ScopeCaller | undefined> {
  const userId = c.get("userId");
  if (!userId) return undefined;
  const projectScope = c.get("projectScope");
  if (projectScope !== undefined) {
    return { userId, userRole: c.get("userRole"), orgRole: c.get("orgRole"), projectScope };
  }
  return scopeOfUser(c.get("db"), userId);
}
