import { Hono } from "hono";
import { and, eq, inArray, ne } from "drizzle-orm";
import { apps, objectGrants, objects } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import { PROJECT_OBJECT, SOURCE_OBJECT, callerOf, projectAccess, sourceAccess, sourceLevels } from "../lib/objects";
import { denialRoutes, refuseSdkChange, shareRoutes, withNames } from "./permissions";
import { explainAccess } from "../lib/explain";
import { logRefusal } from "../lib/access-log";

/**
 * Access to a project and to its data sources. Mounted at /projects.
 *
 * A role on a project (Viewer, Editor, Manager) covers everything inside it:
 * its dashboards, reports, chat agents, apps and data sources. A role on one
 * of those can raise that, never lower it. Sharing needs Manager on what is
 * shared (an org Owner or Admin always has it).
 *
 * Data sources live in the project's engine, so SA-API knows them only by id:
 * a share is saved here, and the platform uses it to show or hide what someone
 * can do. The engine enforcing it comes later.
 */
const accessRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();
// Only these paths: other routers serve the rest of /projects/:projectId/….
for (const path of ["/:projectId/grants", "/:projectId/grants/*", "/:projectId/denials", "/:projectId/denials/*", "/:projectId/sources/*", "/:projectId/access", "/:projectId/access/*", "/:projectId/my-access"]) {
  accessRouter.use(path, authMiddleware);
}

const SOURCE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const DENIED = "Not permitted for this project";

/**
 * GET, POST /projects/:projectId/grants and PUT, DELETE …/grants/:grantId:
 * give a person, a role or the whole org a role on the project.
 */
shareRoutes(
  accessRouter,
  "/:projectId/grants",
  async (c) => {
    const refused = refuseSdkChange(c);
    if (refused) return { ok: false, response: refused };
    const access = await projectAccess(c.get("db"), callerOf(c), c.req.param("projectId"));
    if (!access || !access.actions.includes("share")) {
      if (access) await logRefusal(c, "needs share on this project", { type: "object", id: access.object.id });
      return { ok: false, response: c.json({ error: DENIED }, 403) };
    }
    return { ok: true, target: access };
  }
);

/**
 * GET, POST /projects/:projectId/sources/:sourceId/grants and PUT, DELETE …/:grantId:
 * give someone a role on one data source.
 */
shareRoutes(accessRouter, "/:projectId/sources/:sourceId/grants", async (c) => {
  const refused = refuseSdkChange(c);
  if (refused) return { ok: false, response: refused };
  const sourceId = c.req.param("sourceId");
  if (!SOURCE_ID.test(sourceId)) return { ok: false, response: c.json({ error: "Data source not found" }, 404) };
  const access = await sourceAccess(c.get("db"), callerOf(c), c.req.param("projectId"), sourceId, true);
  if (!access || !access.actions.includes("share")) {
    if (access) await logRefusal(c, "needs share on this data source", { type: "object", id: access.object.id });
    return { ok: false, response: c.json({ error: DENIED }, 403) };
  }
  return { ok: true, target: access };
});

denialRoutes(accessRouter, "/:projectId/denials", async (c) => {
  const access = await projectAccess(c.get("db"), callerOf(c), c.req.param("projectId"));
  return access ? { ok: true, target: access } : { ok: false, response: c.json({ error: DENIED }, 403) };
});

denialRoutes(accessRouter, "/:projectId/sources/:sourceId/denials", async (c) => {
  const sourceId = c.req.param("sourceId");
  if (!SOURCE_ID.test(sourceId)) return { ok: false, response: c.json({ error: "Data source not found" }, 404) };
  const access = await sourceAccess(c.get("db"), callerOf(c), c.req.param("projectId"), sourceId, true);
  return access ? { ok: true, target: access } : { ok: false, response: c.json({ error: DENIED }, 403) };
});

/**
 * GET /projects/:projectId/my-access
 * The caller's role on the project, and on each data source that has its own
 * shares (any other takes the project's). For the platform to show only what
 * someone can do.
 */
accessRouter.get("/:projectId/my-access", async (c) => {
  const levels = await sourceLevels(c.get("db"), callerOf(c), c.req.param("projectId"));
  if (!levels.project && !levels.defaultSourceActions.includes("view") && !Object.values(levels.canCreate).some(Boolean) && !Object.values(levels.sourceActions).some((actions) => actions.includes("view"))) return c.json({ error: DENIED }, 403);
  return c.json(levels);
});

/**
 * GET /projects/:projectId/access
 * Who has a role on the project, and on each thing in it that is shared on its
 * own (apps by name, data sources by id: their names are in the engine). For
 * the project's Access view; needs Manager on the project.
 */
accessRouter.get("/:projectId/access", async (c) => {
  const db = c.get("db");
  const projectId = c.req.param("projectId");
  const access = await projectAccess(db, callerOf(c), projectId);
  if (!access || !access.actions.includes("share")) return c.json({ error: DENIED }, 403);

  const inside = await db
    .select()
    .from(objects)
    .where(and(eq(objects.projectId, projectId), ne(objects.type, PROJECT_OBJECT)));
  const ids = [access.object.id, ...inside.map((o) => o.id)];
  const grants = await db.select().from(objectGrants).where(inArray(objectGrants.objectId, ids));
  const named = await withNames(db, grants);
  const grantsOf = (objectId: string) => named.filter((g, i) => grants[i].objectId === objectId);

  const appIds = inside.filter((o) => o.type !== SOURCE_OBJECT).map((o) => o.refId);
  const appNames = new Map(
    appIds.length ? (await db.select({ id: apps.id, name: apps.name }).from(apps).where(inArray(apps.id, appIds))).map((a) => [a.id, a.name]) : []
  );

  return c.json({
    project: { ownerId: access.object.ownerId, grants: grantsOf(access.object.id) },
    objects: inside
      .map((o) => ({
        type: o.type,
        id: o.type === SOURCE_OBJECT ? o.refId.slice(projectId.length + 1) : o.refId,
        name: o.type === SOURCE_OBJECT ? null : appNames.get(o.refId) ?? null,
        ownerId: o.ownerId,
        status: o.status,
        grants: grantsOf(o.id),
      }))
      .filter((o) => o.grants.length),
  });
});

/**
 * GET /projects/:projectId/access/explain?userId=…
 * "Why can Ravi do this?": their role on the project and on everything in it,
 * with every reason behind each (lib/explain.ts). Needs Manager on the project.
 */
accessRouter.get("/:projectId/access/explain", async (c) => {
  const db = c.get("db");
  const projectId = c.req.param("projectId");
  const userId = c.req.query("userId") ?? "";
  const access = await projectAccess(db, callerOf(c), projectId);
  if (!access || !access.actions.includes("share")) return c.json({ error: DENIED }, 403);
  if (!/^[0-9a-f-]{36}$/i.test(userId)) return c.json({ error: "userId must be a user id" }, 400);
  const explained = await explainAccess(db, access.orgId, projectId, userId);
  if (!explained) return c.json({ error: "Not a member of this organization" }, 404);
  return c.json(explained);
});

export default accessRouter;
