import { Hono } from "hono";
import { and, asc, eq, isNull, sql } from "drizzle-orm";
import { organizations, refreshTokens, users } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { validatePassword } from "../../lib/password-policy";
import { revocationCutoff } from "../lib/session";
import { cleanEmail, cleanName, isUniqueViolation, isUuid, orgUserPasswordHash } from "../lib/validate";

/** Org admins of one org (rows in `users` with role org_admin). Mounted at /api/orgs/:orgId/admins, behind requireSuperAdmin. */
const orgAdmins = new Hono<{ Bindings: Env; Variables: SuperAdminVariables }>();

// 404s unknown or malformed org ids before any handler runs.
orgAdmins.use("*", async (c, next) => {
  const orgId = c.req.param("orgId");
  if (!isUuid(orgId)) return c.json({ error: "Organization not found" }, 404);
  const [org] = await c.var.db
    .select({ id: organizations.id })
    .from(organizations)
    .where(eq(organizations.id, orgId))
    .limit(1);
  if (!org) return c.json({ error: "Organization not found" }, 404);
  return next();
});

const adminColumns = {
  id: users.id,
  email: users.email,
  name: users.name,
  isActive: users.isActive,
  sso: sql<boolean>`${users.ssoSubject} is not null`,
  createdAt: users.createdAt,
};

function adminWhere(orgId: string, userId: string) {
  return and(eq(users.id, userId), eq(users.orgId, orgId), eq(users.role, "org_admin"));
}

async function isOrgAdmin(db: SuperAdminVariables["db"], orgId: string, userId: string): Promise<boolean> {
  const [row] = await db.select({ id: users.id }).from(users).where(adminWhere(orgId, userId)).limit(1);
  return !!row;
}

/** Ends the user's sa-api sessions: access tokens via the cutoff, refresh tokens via revocation. */
function endSessions(db: SuperAdminVariables["db"], userId: string) {
  return db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)));
}

/** GET /api/orgs/:orgId/admins */
orgAdmins.get("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const rows = await c.var.db
    .select(adminColumns)
    .from(users)
    .where(and(eq(users.orgId, orgId), eq(users.role, "org_admin")))
    .orderBy(asc(users.createdAt));
  return c.json({ admins: rows });
});

/** POST /api/orgs/:orgId/admins — { name, email, password } */
orgAdmins.post("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const body = await c.req.json<{ name?: unknown; email?: unknown; password?: unknown }>().catch(() => null);
  const name = cleanName(body?.name);
  const email = cleanEmail(body?.email);
  if (!name || !email) return c.json({ error: "Name and a valid email are required." }, 400);
  const pwError = validatePassword(body?.password);
  if (pwError) return c.json({ error: pwError }, 400);

  const db = c.var.db;
  const [existing] = await db
    .select({ role: users.role, isActive: users.isActive })
    .from(users)
    .where(and(eq(users.orgId, orgId), sql`lower(${users.email}) = ${email}`))
    .limit(1);
  if (existing) {
    const detail =
      existing.role !== "org_admin"
        ? `is already a ${existing.role} in this organization`
        : existing.isActive
          ? "is already an org admin here"
          : "is a deactivated org admin here — reactivate them instead";
    return c.json({ error: `${email} ${detail}.` }, 409);
  }

  try {
    const [admin] = await db
      .insert(users)
      .values({
        orgId,
        email,
        name,
        passwordHash: await orgUserPasswordHash(body!.password as string),
        role: "org_admin",
      })
      .returning(adminColumns);
    return c.json({ admin }, 201);
  } catch (err) {
    if (isUniqueViolation(err)) return c.json({ error: `${email} already exists in this organization.` }, 409);
    throw err;
  }
});

/** PATCH /api/orgs/:orgId/admins/:userId — { isActive }. Deactivating ends their sessions. */
orgAdmins.patch("/:userId", async (c) => {
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const body = await c.req.json<{ isActive?: unknown }>().catch(() => null);
  if (!isUuid(userId)) return c.json({ error: "Org admin not found" }, 404);
  if (typeof body?.isActive !== "boolean") return c.json({ error: "isActive (boolean) is required." }, 400);

  const db = c.var.db;
  // Checked first so session revocation below can't touch a user outside this org.
  if (!(await isOrgAdmin(db, orgId, userId))) return c.json({ error: "Org admin not found" }, 404);
  const update = db
    .update(users)
    .set({
      isActive: body.isActive,
      updatedAt: new Date(),
      ...(body.isActive ? {} : { tokensValidAfter: revocationCutoff() }),
    })
    .where(adminWhere(orgId, userId))
    .returning(adminColumns);

  const [admin] = body.isActive ? await update : (await db.batch([update, endSessions(db, userId)]))[0];
  if (!admin) return c.json({ error: "Org admin not found" }, 404);
  return c.json({ admin });
});

/** POST /api/orgs/:orgId/admins/:userId/reset-password — { password }. Ends their sessions. */
orgAdmins.post("/:userId/reset-password", async (c) => {
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const body = await c.req.json<{ password?: unknown }>().catch(() => null);
  if (!isUuid(userId)) return c.json({ error: "Org admin not found" }, 404);
  const pwError = validatePassword(body?.password);
  if (pwError) return c.json({ error: pwError }, 400);

  const db = c.var.db;
  if (!(await isOrgAdmin(db, orgId, userId))) return c.json({ error: "Org admin not found" }, 404);
  const [[admin]] = await db.batch([
    db
      .update(users)
      .set({
        passwordHash: await orgUserPasswordHash(body!.password as string),
        tokensValidAfter: revocationCutoff(),
        updatedAt: new Date(),
      })
      .where(adminWhere(orgId, userId))
      .returning(adminColumns),
    endSessions(db, userId),
  ]);
  if (!admin) return c.json({ error: "Org admin not found" }, 404);
  return c.json({ admin });
});

export default orgAdmins;
