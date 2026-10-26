import { Hono } from "hono";
import { and, desc, eq, gte, lte } from "drizzle-orm";
import { checklistRuns } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly } from "../middleware/auth";
import { parseChecklistReportBody, storeChecklistReport } from "../lib/checklist-reports";

const checklistReportsRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/** The backend's service token — the same header every other service-to-service route checks. */
function hasServiceToken(c: any): boolean {
  const token = c.req.header("X-SA-Service-Token");
  return Boolean(token) && token === c.env.SA_INTERNAL_SERVICE_TOKEN;
}

/**
 * POST /checklist-reports — a checklist run with no project to be scoped to
 * (today: none; later, e.g. a dev->prod merge-gate checklist run from CI).
 * A project-scoped deploy checklist reports via POST /api/checklist-reports
 * on the install host instead, authenticated with that project's API key.
 */
checklistReportsRouter.post("/checklist-reports", async (c) => {
  if (!hasServiceToken(c)) return c.json({ error: "Invalid service token" }, 401);

  const body = await c.req.json().catch(() => null);
  const parsed = parseChecklistReportBody(body);
  if (!parsed) return c.json({ error: "Invalid checklist report body" }, 400);

  const db = c.get("db");
  const { id } = await storeChecklistReport(db, c.env, {
    ...parsed,
    orgId: typeof body?.orgId === "string" ? body.orgId : null,
    projectId: typeof body?.projectId === "string" ? body.projectId : null,
  });
  return c.json({ success: true, id }, 201);
});

/**
 * GET /checklist-reports?checklistId=&orgId=&projectId=&status=&from=&to=&limit=&offset=
 * List runs for the analytics/reports page (admin only). Index-only — no R2 reads.
 */
checklistReportsRouter.get("/checklist-reports", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const checklistId = c.req.query("checklistId");
  const orgId = c.req.query("orgId") || c.get("orgId");
  const projectId = c.req.query("projectId");
  const status = c.req.query("status");
  const from = c.req.query("from");
  const to = c.req.query("to");
  const limit = Math.min(Number(c.req.query("limit") || 50), 200);
  const offset = Number(c.req.query("offset") || 0);

  const conditions = [];
  if (checklistId) conditions.push(eq(checklistRuns.checklistId, checklistId));
  if (orgId) conditions.push(eq(checklistRuns.orgId, orgId));
  if (projectId) conditions.push(eq(checklistRuns.projectId, projectId));
  if (status && status !== "all") conditions.push(eq(checklistRuns.status, status as "pass" | "fail" | "partial"));
  if (from) conditions.push(gte(checklistRuns.createdAt, new Date(from)));
  if (to) conditions.push(lte(checklistRuns.createdAt, new Date(to)));

  const runs = await db
    .select()
    .from(checklistRuns)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(checklistRuns.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json(runs);
});

/**
 * GET /checklist-reports/:id — the index row plus its full report JSON from
 * R2, for the run-detail view (admin only). Registered after the list route
 * above so ":id" never shadows a more specific literal segment later added.
 */
checklistReportsRouter.get("/checklist-reports/:id", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const id = c.req.param("id");

  const [run] = await db.select().from(checklistRuns).where(eq(checklistRuns.id, id)).limit(1);
  if (!run) return c.json({ error: "Checklist run not found" }, 404);

  const obj = await c.env.CHECKLIST_REPORTS.get(run.r2Key);
  if (!obj) return c.json({ error: "Report body is missing in storage" }, 404);
  const report = await obj.json();

  return c.json({ ...run, report });
});

export default checklistReportsRouter;
