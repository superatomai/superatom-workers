import { Hono } from "hono";
import { and, asc, eq, isNull, ne, sql } from "drizzle-orm";
import { organizations, refreshTokens, roles, users } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { validatePassword } from "../../lib/password-policy";
import { revocationCutoff } from "../lib/session";
import { orgRequiresSso } from "../../lib/sso-required";
import { cleanEmail, cleanName, isUniqueViolation, isUuid, orgUserPasswordHash } from "../lib/validate";
import { builtInRoleId, recordRoleChange } from "../../lib/permissions";

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
  /** owner or admin (an org admin row without a role yet counts as admin). */
  orgRole: sql<"owner" | "admin">`coalesce((select ${roles.key} from ${roles} where ${roles.id} = ${users.roleId}), 'admin')`,
};

/** Active Owners of the org other than `exceptUserId`. */
async function otherActiveOwners(db: SuperAdminVariables["db"], orgId: string, exceptUserId: string): Promise<number> {
  const ownerRoleId = await builtInRoleId(db, "owner");
  if (!ownerRoleId) return 0;
  const [row] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(users)
    .where(and(eq(users.orgId, orgId), eq(users.roleId, ownerRoleId), eq(users.isActive, true), ne(users.id, exceptUserId)));
  return row?.n ?? 0;
}

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

/**
 * POST /api/orgs/:orgId/admins — { name, email, password, role? }
 * `role`: "owner" or "admin". Without it, the org's first one becomes its Owner
 * and later ones Admins. Only the super admin makes Owners (inside the
 * organization nobody can).
 */
orgAdmins.post("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const body = await c.req.json<{ name?: unknown; email?: unknown; password?: unknown; role?: unknown }>().catch(() => null);
  const name = cleanName(body?.name);
  const email = cleanEmail(body?.email);
  if (!name || !email) return c.json({ error: "Name and a valid email are required." }, 400);
  if (body?.role !== undefined && body.role !== "owner" && body.role !== "admin") {
    return c.json({ error: 'role must be "owner" or "admin".' }, 400);
  }
  const db = c.var.db;
  // SSO-only admins get no password, even if one is sent.
  const ssoOnly = await orgRequiresSso(db, orgId, email);
  const pwError = ssoOnly ? null : validatePassword(body?.password);
  if (pwError) return c.json({ error: pwError }, 400);

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

  // The organization's first admin becomes its Owner unless told otherwise:
  // someone has to be able to manage admins, and only an Owner can.
  const ownerRoleId = await builtInRoleId(db, "owner");
  if (body?.role === "owner" && !ownerRoleId) {
    return c.json({ error: "The Owner role is not set up yet; run the roles migration." }, 400);
  }
  const [hasOwner] = ownerRoleId
    ? await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.orgId, orgId), eq(users.roleId, ownerRoleId), eq(users.isActive, true)))
        .limit(1)
    : [undefined];
  const orgRole: "owner" | "admin" = (body?.role as "owner" | "admin" | undefined) ?? (ownerRoleId && !hasOwner ? "owner" : "admin");
  const roleId = orgRole === "owner" ? ownerRoleId : await builtInRoleId(db, "admin");

  try {
    const [admin] = await db
      .insert(users)
      .values({
        orgId,
        email,
        name,
        passwordHash: ssoOnly ? null : await orgUserPasswordHash(body!.password as string),
        role: "org_admin",
        roleId,
      })
      .returning(adminColumns);
    // No changedBy: a super admin is not a user of this organization.
    await recordRoleChange(db, { orgId, userId: admin.id, changedBy: null, fromRole: null, toRole: orgRole });
    return c.json({ admin: { ...admin, orgRole } }, 201);
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
  // An organization always keeps an active Owner.
  if (!body.isActive) {
    const [row] = await db.select({ orgRole: adminColumns.orgRole, isActive: users.isActive }).from(users).where(adminWhere(orgId, userId)).limit(1);
    if (row?.orgRole === "owner" && row.isActive && (await otherActiveOwners(db, orgId, userId)) === 0) {
      return c.json({ error: "This is the organization's only active Owner. Make someone else Owner first." }, 409);
    }
  }
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

/**
 * PATCH /api/orgs/:orgId/admins/:userId/role — { role: "owner" | "admin" }
 * Promotes an Admin to Owner, or makes an Owner an Admin again. Only the super
 * admin can (inside the organization nobody makes or changes an Owner). The
 * organization always keeps an active Owner.
 */
orgAdmins.patch("/:userId/role", async (c) => {
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const body = await c.req.json<{ role?: unknown }>().catch(() => null);
  if (!isUuid(userId)) return c.json({ error: "Org admin not found" }, 404);
  if (body?.role !== "owner" && body?.role !== "admin") return c.json({ error: 'role must be "owner" or "admin".' }, 400);
  const toRole = body.role;

  const db = c.var.db;
  const [current] = await db
    .select({ orgRole: adminColumns.orgRole, isActive: users.isActive })
    .from(users)
    .where(adminWhere(orgId, userId))
    .limit(1);
  if (!current) return c.json({ error: "Org admin not found" }, 404);
  if (current.orgRole === toRole) {
    const [admin] = await db.select(adminColumns).from(users).where(adminWhere(orgId, userId)).limit(1);
    return c.json({ admin });
  }
  if (current.orgRole === "owner" && current.isActive && (await otherActiveOwners(db, orgId, userId)) === 0) {
    return c.json({ error: "This is the organization's only active Owner. Make someone else Owner first." }, 409);
  }
  const roleId = await builtInRoleId(db, toRole);
  if (!roleId) return c.json({ error: "The roles are not set up yet; run the roles migration." }, 400);

  const [admin] = await db
    .update(users)
    .set({ roleId, updatedAt: new Date() })
    .where(adminWhere(orgId, userId))
    .returning(adminColumns);
  if (!admin) return c.json({ error: "Org admin not found" }, 404);
  // No changedBy: a super admin is not a user of this organization.
  await recordRoleChange(db, { orgId, userId, changedBy: null, fromRole: current.orgRole, toRole });
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
  const [target] = await db.select({ email: users.email }).from(users).where(adminWhere(orgId, userId)).limit(1);
  if (target && (await orgRequiresSso(db, orgId, target.email))) {
    return c.json({ error: "This admin signs in with the organization's SSO; passwords aren't used." }, 400);
  }
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
