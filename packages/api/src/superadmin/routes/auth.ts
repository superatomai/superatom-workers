import { Hono } from "hono";
import { eq, sql } from "drizzle-orm";
import { superAdmins } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { requireSuperAdmin } from "../middleware";
import { getDummyHash, verifyPassword } from "../lib/password";
import {
  clearSessionCookie,
  readSessionCookie,
  revocationCutoff,
  setSessionCookie,
  signSession,
  verifySession,
} from "../lib/session";

const auth = new Hono<{ Bindings: Env; Variables: SuperAdminVariables }>();

/** POST /api/auth/login — email + password → session cookie. */
auth.post("/login", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  const body = await c.req.json<{ email?: unknown; password?: unknown }>().catch(() => null);
  const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body?.password === "string" ? body.password : "";
  if (!email || !password || email.length > 255 || password.length > 256) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  // Per IP, and per IP+email so one address can't be hammered from a single source.
  const limiter = c.env.SUPERADMIN_LOGIN_LIMITER;
  const [byIp, byIpEmail] = await Promise.all([
    limiter.limit({ key: `ip:${ip}` }),
    limiter.limit({ key: `ip-email:${ip}:${email}` }),
  ]);
  if (!byIp.success || !byIpEmail.success) {
    return c.json({ error: "Too many attempts. Try again in a minute." }, 429);
  }

  const [admin] = await c.var.db
    .select()
    .from(superAdmins)
    .where(sql`lower(${superAdmins.email}) = ${email}`)
    .limit(1);

  const valid = await verifyPassword(password, admin?.passwordHash ?? (await getDummyHash()));
  if (!admin || !valid || !admin.isActive) {
    return c.json({ error: "Invalid email or password" }, 401);
  }

  setSessionCookie(c, await signSession(admin.id, c.env.SUPERADMIN_JWT_SECRET));
  return c.json({ admin: { id: admin.id, email: admin.email, name: admin.name } });
});

/** POST /api/auth/logout — ends every session of this admin, on all browsers. */
auth.post("/logout", async (c) => {
  const token = readSessionCookie(c);
  const session = token ? await verifySession(token, c.env.SUPERADMIN_JWT_SECRET) : null;
  if (session) {
    await c.var.db
      .update(superAdmins)
      .set({ tokensValidAfter: revocationCutoff(), updatedAt: new Date() })
      .where(eq(superAdmins.id, session.adminId));
  }
  clearSessionCookie(c);
  return c.json({ ok: true });
});

/** GET /api/auth/me — the signed-in admin. */
auth.get("/me", requireSuperAdmin, (c) => c.json({ admin: c.var.admin }));

export default auth;
