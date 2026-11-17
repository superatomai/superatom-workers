import { Hono } from "hono";
import type { Env, AppVariables } from "../types";
import { authMiddleware } from "../middleware/auth";
import { accessibleApps, appAccess, atLeast, callerOf, legacyPermission, type AppAccess } from "../lib/objects";

const myApps = new Hono<{ Bindings: Env; Variables: AppVariables }>();

myApps.use("*", authMiddleware);

/**
 * The runtime's view of an app. `permission` keeps the old name for the
 * caller's level (view | edit | admin); `level` is the new one
 * (view | comment | edit | manage | owner).
 */
function shape(a: AppAccess) {
  return {
    ...a.app,
    projectName: a.projectName,
    status: a.object.status,
    ownerId: a.object.ownerId,
    level: a.level,
    permission: legacyPermission(a.level),
  };
}

/**
 * GET /my/apps
 * Every app the signed-in user may use (lib/objects.ts accessibleApps): all of
 * the organization's for an Owner or Admin; otherwise what they own, what is
 * shared with them, their role or the organization, and anything open to
 * everyone. A super admin belongs to no organization and gets none, as before.
 */
myApps.get("/", async (c) => {
  const list = await accessibleApps(c.get("db"), callerOf(c));
  return c.json(list.map(shape));
});

/**
 * GET /my/apps/:appId
 * One app, only when the user may at least view it.
 */
myApps.get("/:appId", async (c) => {
  const access = await appAccess(c.get("db"), callerOf(c), c.req.param("appId"));
  if (!access) {
    return c.json({ error: "App not found" }, 404);
  }
  if (!atLeast(access.level, "view")) {
    return c.json({ error: "Forbidden" }, 403);
  }
  return c.json(shape(access));
});

export default myApps;
