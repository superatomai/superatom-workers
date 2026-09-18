import { Hono } from "hono";
import { cors } from "hono/cors";
import { createDb } from "./db";
import { isAllowedOrigin } from "./lib/origins";
import { serveUi } from "./lib/serve-ui";
import superadminApp from "./superadmin/app";
import type { Env, AppVariables } from "./types";

import authRoutes from "./routes/auth";
import ssoRoutes from "./routes/sso";
import samlRoutes from "./routes/saml";
import bootstrapRoutes from "./routes/bootstrap";
import orgRoutes from "./routes/orgs";
import usersRoutes from "./routes/users";
import projectsRoutes from "./routes/projects";
import appsRoutes from "./routes/apps";
import permissionsRoutes from "./routes/permissions";
import myAppsRoutes from "./routes/my-apps";
import uploadRoutes from "./routes/upload";
import sourceUploadRoutes from "./routes/source-upload";
import analyticsRoutes from "./routes/analytics";
import speechRoutes from "./routes/speech";
import answerFeedbackRoutes from "./routes/answer-feedback";
import feedbackRoutes from "./routes/product-feedback";

const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// ─── CORS ────────────────────────────────────────────────
/**
 * Only first-party origins may read authenticated responses.
 *
 * The previous bare `cors()` defaulted to `Access-Control-Allow-Origin: *` on
 * every route — including /auth/me — so any website could read the response.
 * Auth is Bearer-header based rather than cookie based, so this was token
 * replay rather than cookie CSRF: a JWT lifted from localStorage could be used
 * to exfiltrate user and org data straight from an attacker's own page.
 *
 * Matches subdomains at ANY depth under superatom.ai, because the product uses
 * several levels:
 *   runtime   — live.superatom.ai, <client>.superatom.ai, dev.live.superatom.ai
 *   admin     — platform.superatom.ai, <client>.platform.superatom.ai, dev.platform…
 *   analytics — analytics.superatom.ai
 * A single-label pattern would silently break the admin UI for every client and
 * both dev environments.
 *
 * The allowlist itself lives in lib/origins.ts, shared with SSO redirect
 * validation so the two cannot drift apart.
 */
app.use(
  "*",
  cors({
    origin: (origin, c) => {
      // Non-browser callers (curl, server-to-server) send no Origin at all —
      // CORS is irrelevant to them, so there is nothing to allow or deny.
      if (!origin) return undefined;

      // Returning undefined omits Access-Control-Allow-Origin, so the browser
      // blocks the response. allowHeaders/allowMethods stay at Hono's defaults,
      // which reflect the request — safe now that origin is bounded.
      return isAllowedOrigin(origin, c.env) ? origin : undefined;
    },
    // Required for the httpOnly refresh cookie to be sent on /auth/refresh.
    // Only safe because the origin above is now a specific echo rather than "*"
    // — browsers reject credentials combined with a wildcard origin outright.
    credentials: true,
    maxAge: 86400,
  })
);

// ─── Inject DB into context ──────────────────────────────
app.use("*", async (c, next) => {
  const db = createDb(c.env.DATABASE_URL);
  c.set("db", db);
  await next();
});

// ─── Health check ────────────────────────────────────────
app.get("/health", (c) =>
  c.json({
    status: "healthy",
    worker: "sa-api",
    timestamp: Date.now(),
  })
);

// ─── Routes ──────────────────────────────────────────────
app.route("/auth", authRoutes);
app.route("/auth/sso", ssoRoutes);
app.route("/auth/sso/saml", samlRoutes);
app.route("/auth", bootstrapRoutes);
app.route("/orgs", orgRoutes);
app.route("/orgs/:orgId/users", usersRoutes);
app.route("/orgs/:orgId/projects", projectsRoutes);
// More specific prefix first — Hono matches in registration order.
app.route("/upload/source-file", sourceUploadRoutes);
app.route("/upload", uploadRoutes);
app.route("/my/apps", myAppsRoutes); // must be before appsRoutes (mounted at /) to avoid adminOnly middleware
app.route("/apps", permissionsRoutes); // handles /apps/:appId/permissions
app.route("/", appsRoutes); // handles /projects/:projectId/apps and /apps/:appId
app.route("/answer-feedback", answerFeedbackRoutes); // feedback 1: server-to-server (service token auth)
app.route("/feedback", feedbackRoutes); // feedback 2: product feedback (public + superadmin list)
app.route("/", analyticsRoutes); // handles /analytics/chat
app.route("/speech", speechRoutes);

// ─── 404 fallback ────────────────────────────────────────
app.notFound((c) =>
  c.json({ error: "Not found", path: c.req.path }, 404)
);

// ─── Error handler ───────────────────────────────────────
app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json({ error: "Internal server error" }, 500);
});

// ─── Host dispatch ───────────────────────────────────────
// The super-admin host gets its own app, so sa-api's credentialed *.superatom.ai
// CORS and routes never apply there. Everything else is sa-api, unchanged.
export default {
  fetch(request, env, ctx) {
    const { hostname, pathname } = new URL(request.url);
    if (env.SUPERADMIN_HOST && hostname === env.SUPERADMIN_HOST) {
      return pathname === "/api" || pathname.startsWith("/api/")
        ? superadminApp.fetch(request, env, ctx)
        : serveUi(env.FRONTEND_BUILDS, "superadmin", request);
    }
    return app.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
