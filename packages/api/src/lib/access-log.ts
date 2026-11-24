/**
 * The access audit log (db/schema.ts access_log): every change to who can do
 * what, appended and never edited, so the history cannot be rewritten.
 *
 * Actions, as thing.verb:
 *   member.added, member.removed, member.reactivated, member.role_changed,
 *   member.projects_changed, member.access_changed (data access rules),
 *   member.password_reset, member.limits_changed (what one Admin may not do),
 *   role.created, role.edited, role.deleted,
 *   grant.added, grant.changed, grant.removed,
 *   object.handed_over, object.status_changed,
 *   project.member_added, project.member_removed
 */
import { accessLog } from "../db/schema";
import type { Database } from "../db";

export type AccessAction =
  | "member.added"
  | "member.removed"
  | "member.reactivated"
  | "member.role_changed"
  | "member.projects_changed"
  | "member.access_changed"
  | "member.password_reset"
  | "member.limits_changed"
  | "role.created"
  | "role.edited"
  | "role.deleted"
  | "grant.added"
  | "grant.changed"
  | "grant.removed"
  | "denial.added"
  | "denial.removed"
  | "object.handed_over"
  | "object.status_changed"
  | "project.member_added"
  | "project.member_removed"
  | "access.refused";

export type AccessEntry = {
  orgId: string;
  /** Who did it; null for the system or a service token. */
  actorId: string | null;
  action: AccessAction;
  target: { type: "user" | "role" | "object" | "project" | "route"; id: string };
  /** The person whose access changed, when there is one. */
  subjectId?: string | null;
  before?: unknown;
  after?: unknown;
};

/**
 * Appends one entry. A failure to log never undoes the change it describes (the
 * change is already made); it is reported, so a gap in the log is visible.
 */
export async function logAccess(db: Database, entry: AccessEntry): Promise<void> {
  try {
    await db.insert(accessLog).values({
      orgId: entry.orgId,
      actorId: entry.actorId,
      action: entry.action,
      targetType: entry.target.type,
      targetId: entry.target.id,
      subjectId: entry.subjectId ?? null,
      before: entry.before ?? null,
      after: entry.after ?? null,
    });
  } catch (err) {
    console.error(JSON.stringify({ ev: "access_log_failed", action: entry.action, target: entry.target, error: String(err) }));
  }
}

/** The actor of a request: the signed-in user, or null for a service token. */
export const actorOf = (c: { get: (k: any) => any }): string | null => c.get("userId") ?? null;

/**
 * Records a refused attempt (access.refused): who tried what, and why. Only for
 * a signed-in user of an organization; the request's own response is unchanged.
 * `on`: the object refused, when there is one; otherwise the route itself.
 */
export async function logRefusal(
  c: { get: (k: any) => any; req: { method: string; path: string } },
  reason: string,
  on?: { type: "object" | "project" | "user"; id: string }
): Promise<void> {
  const orgId = c.get("orgId");
  const db = c.get("db");
  if (!orgId || !db) return;
  await logAccess(db, {
    orgId,
    actorId: actorOf(c),
    action: "access.refused",
    target: on ?? { type: "route", id: `${c.req.method} ${c.req.path}`.slice(0, 255) },
    subjectId: actorOf(c),
    after: { reason, method: c.req.method, path: c.req.path },
  });
}
