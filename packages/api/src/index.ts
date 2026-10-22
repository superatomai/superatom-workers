import { Hono } from "hono";
import { cors } from "hono/cors";
import { createDb } from "./db";
// Parked with the allowlist CORS policy below — restore both together.
// import { isAllowedOrigin } from "./lib/origins";
import { serveUi } from "./lib/serve-ui";
import superadminApp from "./superadmin/app";
import installApp from "./install/app";
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
import chatAttachmentUploadRoutes from "./routes/chat-attachment-upload";
import filesRoutes from "./routes/files";
import analyticsRoutes from "./routes/analytics";
import speechRoutes from "./routes/speech";
import answerFeedbackRoutes from "./routes/answer-feedback";
import feedbackRoutes from "./routes/product-feedback";
import sdkAuthRoutes from "./routes/sdk-auth";
import graphRoutes from "./routes/graph";
import releaseRoutes from "./routes/releases";

const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// ─── CORS ────────────────────────────────────────────────
/**
 * Any origin may call us.
 *
 * The SDK runs on CUSTOMER sites, whose domains we do not know in advance, and
 * every route it needs is one a first-party allowlist would block. Keeping a
 * list meant a deploy on our side each time a client shipped on a new domain,
 * so there is no list: an origin check is not what protects these routes.
 *
 * What protects them is the Bearer token. CORS only decides whether a BROWSER
 * PAGE may read a response — it is no obstacle to curl or a server, so an
 * attacker holding a token was never stopped by it, and one without a token
 * gains nothing from being answered.
 *
 * THE ONE THING THIS DEPENDS ON: the refresh token is the only credential a
 * browser attaches by itself, and its cookie is `sameSite: "Lax"`
 * (lib/refresh-cookie.ts). That is what stops another site POSTing to
 * /auth/refresh in a signed-in user's browser — the cookie is simply not sent.
 * Change it to "None" and open CORS turns into a readable session token on any
 * page the user visits. Keep it Lax, or put /auth/refresh back behind an
 * allowlist in the same change.
 *
 * SSO redirects are NOT governed by this. lib/origins.ts still validates those
 * (isAllowedRedirect), because the callback appends `?token=<jwt>` to the URL
 * it is given, and that must stay first-party.
 */
app.use(
  "*",
  cors({
    // The caller's own origin echoed back, never "*": `credentials: true` below
    // is required for the refresh cookie on /auth/refresh, and browsers reject
    // credentials combined with a wildcard origin outright.
    origin: (origin) => origin || undefined,
    credentials: true,
    maxAge: 86400,
  })
);

/*
 * THE POLICY THIS REPLACED — kept so going back is one block, not a rewrite.
 *
 * First-party origins only, with /auth/sdk/exchange exempted because SDK
 * sign-in is called from customer sites. The exemption is what made the
 * asymmetry: sign-in answered any origin while the nine other routes the SDK
 * calls were blocked, so a client on their own domain signed in and then
 * failed on the first app fetch.
 *
 * To restore: uncomment this, delete the middleware above, and uncomment the
 * `isAllowedOrigin` import at the top. ALLOWED_ORIGINS and PLATFORM_UI_URL
 * still feed it — see lib/origins.ts, which is unchanged.
 *
 * const SDK_EXCHANGE_PATH = "/auth/sdk/exchange";
 *
 * app.use(
 *   "*",
 *   cors({
 *     origin: (origin, c) => {
 *       // Non-browser callers (curl, server-to-server) send no Origin at all —
 *       // CORS is irrelevant to them, so there is nothing to allow or deny.
 *       if (!origin) return undefined;
 *
 *       if (c.req.path === SDK_EXCHANGE_PATH) return origin;
 *
 *       // Returning undefined omits Access-Control-Allow-Origin, so the browser
 *       // blocks the response. allowHeaders/allowMethods stay at Hono's defaults,
 *       // which reflect the request — safe now that origin is bounded.
 *       return isAllowedOrigin(origin, c.env) ? origin : undefined;
 *     },
 *     // Required for the httpOnly refresh cookie to be sent on /auth/refresh.
 *     credentials: true,
 *     maxAge: 86400,
 *   })
 * );
 */

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
app.route("/auth/sdk", sdkAuthRoutes);
app.route("/auth", bootstrapRoutes);
app.route("/orgs", orgRoutes);
app.route("/orgs/:orgId/users", usersRoutes);
app.route("/orgs/:orgId/projects", projectsRoutes);
// More specific prefix first — Hono matches in registration order.
app.route("/upload/source-file", sourceUploadRoutes);
app.route("/upload/chat-attachment", chatAttachmentUploadRoutes);
app.route("/upload", uploadRoutes);
app.route("/files", filesRoutes); // agent output files (service token) and downloads (user)
app.route("/my/apps", myAppsRoutes); // must be before appsRoutes (mounted at /) to avoid adminOnly middleware
app.route("/apps", permissionsRoutes); // handles /apps/:appId/permissions
app.route("/projects/:projectId/graph", graphRoutes); // composition graph (org admins only)
app.route("/projects/:projectId/release", releaseRoutes); // release status + the Update button (org admins)
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
// The super-admin and install hosts get their own apps, so sa-api's credentialed
// any-origin CORS and routes never apply there. Everything else is sa-api, unchanged.
export default {
  fetch(request, env, ctx) {
    const { hostname, pathname } = new URL(request.url);
    if (env.SUPERADMIN_HOST && hostname === env.SUPERADMIN_HOST) {
      return pathname === "/api" || pathname.startsWith("/api/")
        ? superadminApp.fetch(request, env, ctx)
        : serveUi(env.FRONTEND_BUILDS, "superadmin", request);
    }
    // curl-only installer host (`curl -fsSL https://install.superatom.ai | sh`).
    if (env.INSTALL_HOST && hostname === env.INSTALL_HOST) {
      return installApp.fetch(request, env, ctx);
    }
    return app.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
