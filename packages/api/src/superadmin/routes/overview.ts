import { Hono } from "hono";
import { desc, sql } from "drizzle-orm";
import { organizations } from "../../db/schema";
import type { Env } from "../../types";
import type { SuperAdminVariables } from "../types";

/** Platform-wide totals and follow-ups for the console's overview page. Mounted at /api/overview. */
const overview = new Hono<{ Bindings: Env; Variables: SuperAdminVariables }>();

const ATTENTION_LIMIT = 10;

type Totals = {
  orgs: number;
  projects: number;
  org_admins: number;
  active_keys: number;
  unused_keys: number;
  projects_without_key: number;
  unlinked_unused_keys: number;
};
type ProjectRef = { org_id: string; org_name: string; project_id: string; project_name: string };

overview.get("/", async (c) => {
  const db = c.var.db;
  const [totals, withoutKey, unusedKeys, recent] = await Promise.all([
    db.execute<Totals>(sql`select
      (select count(*)::int from organizations) as orgs,
      (select count(*)::int from projects) as projects,
      (select count(*)::int from users where role = 'org_admin' and is_active) as org_admins,
      (select count(*)::int from api_keys where is_active) as active_keys,
      (select count(*)::int from api_keys where is_active and last_used_at is null) as unused_keys,
      (select count(*)::int from projects p where not exists (
        select 1 from api_keys k where k.project_id = p.id::text and k.is_active)) as projects_without_key,
      (select count(*)::int from api_keys k where k.is_active and k.last_used_at is null and not exists (
        select 1 from projects p where p.id::text = k.project_id)) as unlinked_unused_keys`),
    db.execute<ProjectRef>(sql`select o.id as org_id, o.name as org_name, p.id as project_id, p.name as project_name
      from projects p join organizations o on o.id = p.org_id
      where not exists (select 1 from api_keys k where k.project_id = p.id::text and k.is_active)
      order by p.created_at desc limit ${ATTENTION_LIMIT}`),
    // Keys whose project_id matches no project (older keys) count in totals but can't be linked.
    db.execute<ProjectRef & { key_prefix: string; created_at: string }>(sql`select o.id as org_id, o.name as org_name,
        p.id as project_id, p.name as project_name, k.key_prefix, k.created_at
      from api_keys k join projects p on p.id::text = k.project_id join organizations o on o.id = p.org_id
      where k.is_active and k.last_used_at is null
      order by k.created_at desc limit ${ATTENTION_LIMIT}`),
    db
      .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, createdAt: organizations.createdAt })
      .from(organizations)
      .orderBy(desc(organizations.createdAt))
      .limit(5),
  ]);

  const t = totals.rows[0];
  const ref = (r: ProjectRef) => ({ orgId: r.org_id, orgName: r.org_name, projectId: r.project_id, projectName: r.project_name });
  return c.json({
    totals: {
      orgs: t.orgs,
      projects: t.projects,
      orgAdmins: t.org_admins,
      activeKeys: t.active_keys,
      unusedKeys: t.unused_keys,
      projectsWithoutKey: t.projects_without_key,
      unlinkedUnusedKeys: t.unlinked_unused_keys,
    },
    attention: {
      projectsWithoutKey: withoutKey.rows.map(ref),
      unusedKeys: unusedKeys.rows.map((r) => ({ ...ref(r), prefix: r.key_prefix, createdAt: r.created_at })),
    },
    recentOrgs: recent,
  });
});

export default overview;
