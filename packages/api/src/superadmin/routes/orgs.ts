import { Hono } from "hono";
import { asc, eq, sql } from "drizzle-orm";
import { organizations, projects, users } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";
import { validatePassword } from "../../lib/password-policy";
import { createOrgSecret } from "../../lib/org-secrets";
import {
  cleanEmail,
  cleanName,
  isUniqueViolation,
  isUuid,
  orgSlugError,
  orgUserPasswordHash,
} from "../lib/validate";

const orgs = new Hono<{ Bindings: Env; Variables: SuperAdminVariables }>();

const orgSummary = {
  id: organizations.id,
  name: organizations.name,
  slug: organizations.slug,
  createdAt: organizations.createdAt,
  // Aliased + table-qualified: drizzle drops the table prefix in single-table selects,
  // which would make these correlate against the subquery's own table.
  adminCount: sql<number>`(select count(*)::int from ${users} u where u.org_id = ${organizations}.id and u.role = 'org_admin' and u.is_active)`,
  projectCount: sql<number>`(select count(*)::int from ${projects} p where p.org_id = ${organizations}.id)`,
};

/** GET /api/orgs — every org with its active org-admin and project counts. */
orgs.get("/", async (c) => {
  const rows = await c.var.db.select(orgSummary).from(organizations).orderBy(asc(organizations.name));
  return c.json({ orgs: rows });
});

/** POST /api/orgs — create an org, optionally with its first org admin, in one transaction. */
orgs.post("/", async (c) => {
  const body = await c.req
    .json<{ name?: unknown; slug?: unknown; admin?: { name?: unknown; email?: unknown; password?: unknown } }>()
    .catch(() => null);

  const name = cleanName(body?.name);
  if (!name) return c.json({ error: "Organization name is required (max 255 characters)." }, 400);
  const slug = typeof body?.slug === "string" ? body.slug.trim() : "";
  const slugError = orgSlugError(slug);
  if (slugError) return c.json({ error: slugError }, 400);

  let admin: { name: string; email: string; passwordHash: string } | null = null;
  if (body?.admin) {
    const adminName = cleanName(body.admin.name);
    const adminEmail = cleanEmail(body.admin.email);
    if (!adminName || !adminEmail) return c.json({ error: "Org admin name and a valid email are required." }, 400);
    const pwError = validatePassword(body.admin.password);
    if (pwError) return c.json({ error: pwError }, 400);
    admin = { name: adminName, email: adminEmail, passwordHash: await orgUserPasswordHash(body.admin.password as string) };
  }

  const db = c.var.db;
  const [taken] = await db
    .select({ id: organizations.id })
    .from(organizations)
    .where(eq(organizations.slug, slug))
    .limit(1);
  if (taken) return c.json({ error: `The slug "${slug}" is already used by another organization.` }, 409);

  // An org can't log in without its signing secret, so store it before the row exists
  // (same order as sa-api's POST /orgs): a failed insert leaves only an unused KV entry.
  const orgId = crypto.randomUUID();
  try {
    await createOrgSecret(c.env.JWT_SECRETS, orgId);
  } catch (err) {
    console.error("[superadmin] could not store the new org's signing secret:", err);
    return c.json({ error: "Could not create organization, please try again." }, 503);
  }
  const insertOrg = db.insert(organizations).values({ id: orgId, name, slug }).returning();
  try {
    if (!admin) {
      const [org] = await insertOrg;
      return c.json({ organization: org, admin: null }, 201);
    }
    const [[org], [orgAdmin]] = await db.batch([
      insertOrg,
      db
        .insert(users)
        .values({ orgId, email: admin.email, name: admin.name, passwordHash: admin.passwordHash, role: "org_admin" })
        .returning({ id: users.id, email: users.email, name: users.name, role: users.role }),
    ]);
    return c.json({ organization: org, admin: orgAdmin }, 201);
  } catch (err) {
    if (isUniqueViolation(err)) {
      return c.json({ error: `The slug "${slug}" is already used by another organization.` }, 409);
    }
    throw err;
  }
});

/** GET /api/orgs/:orgId — one org with its counts. */
orgs.get("/:orgId", async (c) => {
  const orgId = c.req.param("orgId");
  if (!isUuid(orgId)) return c.json({ error: "Organization not found" }, 404);
  const [org] = await c.var.db.select(orgSummary).from(organizations).where(eq(organizations.id, orgId)).limit(1);
  if (!org) return c.json({ error: "Organization not found" }, 404);
  return c.json({ organization: org });
});

export default orgs;
