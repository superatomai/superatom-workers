import { createMiddleware } from "hono/factory";
import { eq } from "drizzle-orm";
import { superAdmins } from "../db/schema";
import type { Env } from "../types";
import type { SuperAdminVariables } from "./types";
import { clearSessionCookie, readSessionCookie, verifySession } from "./lib/session";

type SuperAdminEnv = { Bindings: Env; Variables: SuperAdminVariables };

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Rejects state-changing requests not sent from the console itself. Every
 * *.superatom.ai subdomain is the same site, so SameSite cookies alone don't stop them.
 */
export const sameOrigin = createMiddleware<SuperAdminEnv>(async (c, next) => {
  if (SAFE_METHODS.has(c.req.method)) return next();

  let origin: URL | null = null;
  try {
    const header = c.req.header("Origin");
    origin = header ? new URL(header) : null;
  } catch {
    origin = null;
  }
  // Plain http is only tolerated for local development on *.localhost.
  const secureScheme =
    origin?.protocol === "https:" ||
    (origin?.protocol === "http:" && origin.hostname.endsWith(".localhost"));
  if (!origin || !secureScheme || origin.hostname !== c.env.SUPERADMIN_HOST) {
    return c.json({ error: "Forbidden" }, 403);
  }
  return next();
});

/** Requires a valid session for an active super admin; sets `admin`. */
export const requireSuperAdmin = createMiddleware<SuperAdminEnv>(async (c, next) => {
  const token = readSessionCookie(c);
  const session = token ? await verifySession(token, c.env.SUPERADMIN_JWT_SECRET) : null;
  if (!session) {
    if (token) clearSessionCookie(c);
    return c.json({ error: "Not signed in" }, 401);
  }

  const [admin] = await c.var.db
    .select({
      id: superAdmins.id,
      email: superAdmins.email,
      name: superAdmins.name,
      isActive: superAdmins.isActive,
      tokensValidAfter: superAdmins.tokensValidAfter,
    })
    .from(superAdmins)
    .where(eq(superAdmins.id, session.adminId))
    .limit(1);

  const revoked =
    admin?.tokensValidAfter != null && session.issuedAt * 1000 < admin.tokensValidAfter.getTime();
  if (!admin || !admin.isActive || revoked) {
    clearSessionCookie(c);
    return c.json({ error: "Not signed in" }, 401);
  }

  c.set("admin", { id: admin.id, email: admin.email, name: admin.name });
  return next();
});
