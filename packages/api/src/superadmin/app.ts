import { Hono } from "hono";
import { createDb } from "../db";
import type { Env } from "../types";
import type { SuperAdminVariables } from "./types";
import { requireSuperAdmin, sameOrigin } from "./middleware";
import authRoutes from "./routes/auth";
import orgRoutes from "./routes/orgs";
import orgAdminRoutes from "./routes/org-admins";
import orgProjectRoutes from "./routes/projects";
import overviewRoutes from "./routes/overview";
import installTokenRoutes from "./routes/install-tokens";

/**
 * Super-admin console API, served only on SUPERADMIN_HOST under /api.
 * A separate Hono instance: none of sa-api's middleware (CORS, auth) or routes apply here.
 */
const superadmin = new Hono<{ Bindings: Env; Variables: SuperAdminVariables }>().basePath("/api");

superadmin.use("*", async (c, next) => {
  c.set("db", createDb(c.env.DATABASE_URL));
  await next();
  c.header("Cache-Control", "no-store");
});
superadmin.use("*", sameOrigin);

superadmin.route("/auth", authRoutes);

// Everything except /auth needs a signed-in super admin.
superadmin.use("/orgs", requireSuperAdmin);
superadmin.use("/orgs/*", requireSuperAdmin);
superadmin.use("/overview", requireSuperAdmin);
superadmin.route("/overview", overviewRoutes);
superadmin.route("/orgs", orgRoutes);
superadmin.route("/orgs/:orgId/admins", orgAdminRoutes);
superadmin.route("/orgs/:orgId/projects/:projectId/install-tokens", installTokenRoutes);
superadmin.route("/orgs/:orgId/projects", orgProjectRoutes);

superadmin.notFound((c) => c.json({ error: "Not found" }, 404));

superadmin.onError((err, c) => {
  console.error("[superadmin] unhandled error:", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default superadmin;
