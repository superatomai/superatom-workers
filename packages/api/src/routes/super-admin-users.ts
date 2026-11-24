import { Hono } from "hono";
import { and, isNull, sql } from "drizzle-orm";
import { users } from "../db/schema";
import { validatePassword } from "../lib/password-policy";
import type { Env, AppVariables } from "../types";
import { authMiddleware, superAdminOnly } from "../middleware/auth";

const superAdminUsersRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

// Only a signed-in super admin can add another one — no org route does this
// (POST /orgs/:orgId/users refuses the role), and /auth/bootstrap only works
// while none exists. These are `users` rows (sa-api login, Analytics), not the
// separate `super_admins` table the super-admin console signs in with.
superAdminUsersRouter.use("*", authMiddleware, superAdminOnly);

/** SHA-256 hex, the same hash login compares against (see routes/users.ts, bootstrap.ts). */
async function hashPassword(password: string): Promise<string> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * POST /admin/super-admins
 * Creates a super_admin user (no org). Super admin only.
 *
 * Body: { email, name, password }
 */
superAdminUsersRouter.post("/", async (c) => {
  const db = c.get("db");
  const body = await c.req.json<{ email?: string; name?: string; password?: string }>().catch(() => null);
  const email = body?.email?.trim();
  const name = body?.name?.trim();

  if (!email || !name || !body?.password) {
    return c.json({ error: "email, name, and password are all required" }, 400);
  }
  const pwError = validatePassword(body.password);
  if (pwError) return c.json({ error: pwError }, 400);

  // Super admins have no org, so uniqueness is among the org-less users.
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(isNull(users.orgId), sql`lower(${users.email}) = lower(${email})`))
    .limit(1);
  if (existing) {
    return c.json({ error: "A user with this email already exists without an organization" }, 409);
  }

  const [admin] = await db
    .insert(users)
    .values({
      orgId: null,
      email,
      name,
      passwordHash: await hashPassword(body.password),
      role: "super_admin",
      isActive: true,
    })
    .returning({ id: users.id, email: users.email, name: users.name, role: users.role });

  console.log(`[super-admin] ${c.get("userId")} created super_admin ${admin.id}`);
  return c.json(admin, 201);
});

export default superAdminUsersRouter;
