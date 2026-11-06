import { Hono } from "hono";
import { eq, and, sql, desc, gt, gte, lte, count } from "drizzle-orm";
import { chatAnalytics, organizations, projects, users } from "../db/schema";
import { typeCondition, statusCondition, attachmentNamesSql } from "../lib/analytics-filters";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, scopedOrgId } from "../middleware/auth";

const analyticsExportRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * GET /analytics/export?type=&orgId=&projectId=&userId=&status=&minLatencyMs=&from=&to=&limit=&offset=
 * Lean rows for the analytics UI's Excel export (admin only). Same filters and
 * org scoping as GET /analytics/chat, but joined to org/project/user names and
 * trimmed to what a spreadsheet needs — no tokens, cost, sources, SQL or the
 * rest of `response` — so one call carries far more rows than the list route
 * (limit up to 300, vs 200 — rows carry the full analysis text, so they are large).
 * `answer` is the extracted answer text; `analysis` is returned in full.
 * Returns { total, rows }. `total` (the count of ALL rows matching the filters)
 * is only computed on the first page (offset 0) and is null after that — the UI
 * uses it for a progress percentage. Page with limit/offset until `rows` has
 * fewer than `limit` entries.
 */
analyticsExportRouter.get("/", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const orgId = scopedOrgId(c);
  const projectId = c.req.query("projectId");
  const userId = c.req.query("userId");
  const status = c.req.query("status");
  const from = c.req.query("from");
  const to = c.req.query("to");
  const limit = Math.min(Math.max(Number(c.req.query("limit") || 300), 1), 300);
  const offset = Math.max(Number(c.req.query("offset") || 0), 0);
  // Only runs slower than this (milliseconds). Unset / invalid / 0 = no filter.
  const minLatencyMs = Number(c.req.query("minLatencyMs"));

  const conditions = [];
  if (Number.isFinite(minLatencyMs) && minLatencyMs > 0) conditions.push(gt(chatAnalytics.latencyMs, minLatencyMs));
  const typeCond = typeCondition(c.req.query("type"));
  if (typeCond) conditions.push(typeCond);
  if (orgId) conditions.push(eq(chatAnalytics.orgId, orgId));
  if (projectId) conditions.push(eq(chatAnalytics.projectId, projectId));
  if (userId) conditions.push(eq(chatAnalytics.userId, userId));
  const statusCond = statusCondition(status);
  if (statusCond) conditions.push(statusCond);
  if (from) conditions.push(gte(chatAnalytics.createdAt, new Date(from)));
  if (to) conditions.push(lte(chatAnalytics.createdAt, new Date(to)));

  const rows = await db
    .select({
      id: chatAnalytics.id,
      createdAt: chatAnalytics.createdAt,
      type: chatAnalytics.type,
      status: chatAnalytics.status,
      latencyMs: chatAnalytics.latencyMs,
      orgId: chatAnalytics.orgId,
      orgName: organizations.name,
      projectId: chatAnalytics.projectId,
      projectName: projects.name,
      userId: chatAnalytics.userId,
      userName: users.name,
      userEmail: users.email,
      threadId: chatAnalytics.threadId,
      messageIndex: chatAnalytics.messageIndex,
      question: sql<string | null>`coalesce(${chatAnalytics.question}, ${chatAnalytics.response}->>'user_prompt')`,
      // chat rows: the component tree — reduced to answer text below, not sent
      component: sql<unknown>`${chatAnalytics.response}->'component'`,
      analysis: sql<string | null>`${chatAnalytics.response}->>'analysis'`,
      // dashboard / report rows: plain text
      responseText: sql<string | null>`${chatAnalytics.response}->>'response_text'`,
      // Names of the chat attachments uploaded for THIS question (after the previous question on
      // its thread, up to this one), comma-separated; null when none.
      attachments: attachmentNamesSql,
    })
    .from(chatAnalytics)
    .innerJoin(users, eq(users.id, chatAnalytics.userId))
    .innerJoin(projects, eq(projects.id, chatAnalytics.projectId))
    .leftJoin(organizations, eq(organizations.id, chatAnalytics.orgId))
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    // id as tiebreaker so rows with the same timestamp don't shuffle between pages
    .orderBy(desc(chatAnalytics.createdAt), desc(chatAnalytics.id))
    .limit(limit)
    .offset(offset);

  let total: number | null = null;
  if (offset === 0) {
    const [{ n }] = await db
      .select({ n: count() })
      .from(chatAnalytics)
      .where(conditions.length > 0 ? and(...conditions) : undefined);
    total = Number(n);
  }

  return c.json({
    total,
    rows: rows.map(({ component, responseText, ...r }) => ({
      ...r,
      answer: responseText ?? extractAnswerText(component),
    })),
  });
});

// Mirrors the UI's extractMarkdown (ConversationResponseView): the answer prose
// inside a component tree — strings under well-known keys, else every string.
const ANSWER_KEYS = new Set(["content", "markdown", "md", "text", "body", "answer", "response"]);
function extractAnswerText(raw: unknown): string {
  let component = raw;
  if (typeof raw === "string") {
    try { component = JSON.parse(raw); } catch { return ""; }
  }
  const keyed: string[] = [];
  const all: string[] = [];
  const walk = (v: unknown, key?: string) => {
    if (typeof v === "string") {
      if (v.length < 10) return;
      all.push(v);
      if (key && ANSWER_KEYS.has(key)) keyed.push(v);
    } else if (Array.isArray(v)) {
      v.forEach((x) => walk(x, key));
    } else if (v && typeof v === "object") {
      Object.entries(v).forEach(([k, x]) => walk(x, k));
    }
  };
  walk(component);
  return [...new Set(keyed.length ? keyed : all)].join("\n\n");
}

export default analyticsExportRouter;
