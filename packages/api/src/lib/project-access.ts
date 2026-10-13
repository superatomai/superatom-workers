import type { Context } from "hono";
import { eq } from "drizzle-orm";
import { projects } from "../db/schema";
import type { Env, AppVariables } from "../types";

export type AppContext = Context<{ Bindings: Env; Variables: AppVariables }>;

export type ProjectAccess =
  | { ok: true; orgId: string }
  | { ok: false; status: 403 | 404; error: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The project must belong to the caller's org (super admins reach any); returns the project's org. */
export async function assertProjectAccess(c: AppContext, projectId: string): Promise<ProjectAccess> {
  // A malformed id would otherwise reach Postgres as an invalid uuid and 500.
  if (!UUID.test(projectId)) return { ok: false, status: 404, error: "Project not found" };

  const [row] = await c
    .get("db")
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);

  if (!row) return { ok: false, status: 404, error: "Project not found" };
  if (c.get("userRole") !== "super_admin" && row.orgId !== c.get("orgId")) {
    return { ok: false, status: 403, error: "Not permitted for this project" };
  }
  return { ok: true, orgId: row.orgId };
}
