/**
 * Shared by every writer of a checklist run report: the install host's
 * /api/checklist-reports (project-scoped, deploy checklists) and the main
 * app's /checklist-reports (service-token writes — a future dev->prod
 * merge-gate checklist has no project to be scoped to). Full report body
 * goes to R2; checklist_runs (Postgres) is what list/filter queries hit.
 */
import { checklistRuns } from "../db/schema";
import type { Database } from "../db";
import type { Env } from "../types";

export type ChecklistRunStatus = "pass" | "fail" | "partial";
export type ChecklistRanBy = "agent" | "human";

export interface ChecklistReportInput {
  checklistId: string;
  // {orgSlug, projectId} for a deploy checklist today; {repo, commit} (or
  // anything else) for a future checklist type — stored as-is, not parsed.
  scope: Record<string, unknown>;
  orgId?: string | null;
  projectId?: string | null;
  status: ChecklistRunStatus;
  ranBy: ChecklistRanBy;
  summary?: string | null;
  findingsCount?: number;
  failedCount?: number;
  version?: string | null;
  startedAt: string;
  finishedAt: string;
  // Full report body (per-item results etc.) — opaque here, written verbatim to R2.
  report: unknown;
}

function slugify(value: unknown): string {
  return String(value ?? "unscoped")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 100);
}

/** `reports/<checklistId>/<scopeKey>/<yyyy-mm-dd>/<timestamp>-<runId>.json` */
function reportKey(checklistId: string, scope: Record<string, unknown>, runId: string, at: Date): string {
  const scopeKey = slugify(scope.projectId ?? scope.repo ?? scope.orgSlug ?? "unscoped");
  const day = at.toISOString().slice(0, 10);
  return `reports/${slugify(checklistId)}/${scopeKey}/${day}/${at.getTime()}-${runId}.json`;
}

const STATUSES: ChecklistRunStatus[] = ["pass", "fail", "partial"];
const RAN_BY: ChecklistRanBy[] = ["agent", "human"];

/**
 * Validates the body shape both writers accept, before either attaches its
 * own orgId/projectId (from the authenticated project, or from the body for
 * service-token writers) and calls storeChecklistReport.
 */
export function parseChecklistReportBody(body: any): Omit<ChecklistReportInput, "orgId" | "projectId"> | null {
  if (!body || typeof body !== "object") return null;
  const { checklistId, scope, status, ranBy, startedAt, finishedAt, report } = body;
  if (typeof checklistId !== "string" || !checklistId) return null;
  if (!scope || typeof scope !== "object") return null;
  if (!STATUSES.includes(status)) return null;
  if (!RAN_BY.includes(ranBy)) return null;
  if (typeof startedAt !== "string" || Number.isNaN(Date.parse(startedAt))) return null;
  if (typeof finishedAt !== "string" || Number.isNaN(Date.parse(finishedAt))) return null;
  if (report === undefined) return null;

  return {
    checklistId,
    scope,
    status,
    ranBy,
    summary: typeof body.summary === "string" ? body.summary.slice(0, 2000) : null,
    findingsCount: Number.isFinite(body.findingsCount) ? body.findingsCount : 0,
    failedCount: Number.isFinite(body.failedCount) ? body.failedCount : 0,
    version: typeof body.version === "string" ? body.version.slice(0, 255) : null,
    startedAt,
    finishedAt,
    report,
  };
}

export async function storeChecklistReport(
  db: Database,
  env: Env,
  input: ChecklistReportInput
): Promise<{ id: string; r2Key: string }> {
  // Id generated up front so the R2 key can include it and both writes need
  // only one DB round trip (insert, not insert-then-update).
  const id = crypto.randomUUID();
  const r2Key = reportKey(input.checklistId, input.scope, id, new Date());

  await env.CHECKLIST_REPORTS.put(r2Key, JSON.stringify(input.report), {
    httpMetadata: { contentType: "application/json" },
  });

  await db.insert(checklistRuns).values({
    id,
    checklistId: input.checklistId,
    scope: input.scope,
    orgId: input.orgId || null,
    projectId: input.projectId || null,
    status: input.status,
    ranBy: input.ranBy,
    summary: input.summary || null,
    findingsCount: input.findingsCount ?? 0,
    failedCount: input.failedCount ?? 0,
    version: input.version || null,
    r2Key,
    startedAt: new Date(input.startedAt),
    finishedAt: new Date(input.finishedAt),
  });

  return { id, r2Key };
}
