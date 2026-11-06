import { Hono } from "hono";
import { eq, and, sql, desc, gt, gte, lte, count, sum, avg, getTableColumns } from "drizzle-orm";
import { chatAnalytics } from "../db/schema";
import { typeCondition, statusCondition, attachmentCountSql } from "../lib/analytics-filters";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, scopedOrgId } from "../middleware/auth";

const analyticsRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * POST /analytics/chat
 * Ingest an analytics event — chat, dashboard-agent, or report-generation
 * usage, distinguished by `type` (called by the SDK server-to-server, no
 * auth required). One ingest path for all three types rather than separate
 * routes per type; `type` defaults to "chat_agent" when omitted so SDK builds
 * that predate this field keep working unchanged.
 */
analyticsRouter.post("/analytics/chat", async (c) => {
  const db = c.get("db");
  const body = await c.req.json<{
    type?: "chat_agent" | "dashboard" | "report";
    userId: string;
    orgId?: string;
    projectId: string;
    threadId?: string;
    messageIndex?: number;
    question?: string;
    sourcesUsed?: { sourceId: string; sourceName: string; sourceType: string }[];
    sqlGenerated?: string;
    // The full saved-conversation response object — same shape as fusion-5's
    // user_conversations.response — mirrored centrally, same pattern as
    // answer_feedback.answerSnapshot. Optional/nullable.
    response?: Record<string, any>;
    // Dashboard/report identifier — null for chat_agent rows (chat has no
    // per-message "app" concept to point at; see appId column comment).
    appId?: string;
    // Row id of the saved conversation in the main backend's own Postgres
    // (user_conversations / dashboard_agent_conversations / reports_conversations).
    // Optional — older SDK versions won't send it.
    conversationId?: number;
    model: string;
    inputTokens: number;
    outputTokens: number;
    cost: string; // numeric as string for precision
    latencyMs: number;
    status: "success" | "error" | "aborted";
    errorMessage?: string;
  }>();

  const type = body.type || "chat_agent";

  if (!body.userId || !body.projectId || !body.model) {
    return c.json({ error: "userId, projectId, and model are required" }, 400);
  }
  if (type === "chat_agent" && !body.question) {
    return c.json({ error: "question is required for type=chat_agent" }, 400);
  }

  const [event] = await db
    .insert(chatAnalytics)
    .values({
      type,
      userId: body.userId,
      orgId: body.orgId || null,
      projectId: body.projectId,
      threadId: body.threadId || null,
      messageIndex: body.messageIndex ?? null,
      question: body.question || null,
      sourcesUsed: body.sourcesUsed || null,
      sqlGenerated: body.sqlGenerated || null,
      response: body.response || null,
      appId: body.appId || null,
      conversationId: body.conversationId ?? null,
      model: body.model,
      inputTokens: body.inputTokens,
      outputTokens: body.outputTokens,
      cost: body.cost,
      latencyMs: body.latencyMs,
      status: body.status,
      errorMessage: body.errorMessage || null,
    })
    .returning({ id: chatAnalytics.id, conversationId: chatAnalytics.conversationId });

  return c.json({ success: true, id: event.id, conversationId: event.conversationId }, 201);
});

/**
 * PATCH /analytics/chat/:id/feedback
 * Update feedback for a chat analytics event (no auth — called from frontend via SDK)
 */
analyticsRouter.patch("/analytics/chat/:id/feedback", async (c) => {
  const db = c.get("db");
  const id = c.req.param("id");
  const { feedback } = await c.req.json<{ feedback: "thumbs_up" | "thumbs_down" }>();

  if (!feedback || !["thumbs_up", "thumbs_down"].includes(feedback)) {
    return c.json({ error: "feedback must be 'thumbs_up' or 'thumbs_down'" }, 400);
  }

  const [updated] = await db
    .update(chatAnalytics)
    .set({ feedback })
    .where(eq(chatAnalytics.id, id))
    .returning({ id: chatAnalytics.id });

  if (!updated) {
    return c.json({ error: "Analytics event not found" }, 404);
  }

  return c.json({ success: true });
});

/**
 * GET /analytics/chat?type=&orgId=&projectId=&from=&to=&userId=&limit=&offset=
 * Query analytics events (admin only). `type` is one of "chat_agent" |
 * "dashboard" | "report" | "all" — defaults to "chat_agent" when omitted so
 * existing callers that predate dashboard/report tracking see the same rows
 * they always have.
 */
analyticsRouter.get("/analytics/chat", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const orgId = scopedOrgId(c);
  const projectId = c.req.query("projectId");
  const userId = c.req.query("userId");
  const status = c.req.query("status");
  const from = c.req.query("from");
  const to = c.req.query("to");
  const limit = Math.min(Number(c.req.query("limit") || 50), 200);
  const offset = Number(c.req.query("offset") || 0);
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

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const events = await db
    .select({
      ...getTableColumns(chatAnalytics),
      // Ready chat attachments uploaded for THIS question: on its thread, after the previous
      // question on that thread and up to this one (0 when none, or no thread). A thread can hold
      // several uploads — e.g. the same question re-asked after deleting the earlier one.
      attachmentCount: attachmentCountSql,
    })
    .from(chatAnalytics)
    .where(where)
    .orderBy(desc(chatAnalytics.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json(events);
});

// Shared by /summary and /trends — same org/project/date/type scoping logic,
// so both routes filter identically without duplicating the condition-building.
function parseScopeParams(c: any) {
  const type = c.req.query("type") || "chat_agent";
  const orgId = scopedOrgId(c);
  const projectId = c.req.query("projectId");
  const from = c.req.query("from");
  const to = c.req.query("to");

  const scopeConditions = [];
  if (orgId) scopeConditions.push(eq(chatAnalytics.orgId, orgId));
  if (projectId) scopeConditions.push(eq(chatAnalytics.projectId, projectId));
  if (from) scopeConditions.push(gte(chatAnalytics.createdAt, new Date(from)));
  if (to) scopeConditions.push(lte(chatAnalytics.createdAt, new Date(to)));

  const conditions = [...scopeConditions];
  if (type !== "all") conditions.push(eq(chatAnalytics.type, type as "chat_agent" | "dashboard" | "report"));

  return {
    type, orgId, projectId, from, to,
    where: conditions.length > 0 ? and(...conditions) : undefined,
    whereWithoutType: scopeConditions.length > 0 ? and(...scopeConditions) : undefined,
  };
}

/**
 * GET /analytics/chat/summary?type=&orgId=&projectId=&from=&to=
 * Aggregated summary: total queries, total cost, avg latency, model breakdown
 * (admin only). Same `type` semantics as GET /analytics/chat above.
 */
analyticsRouter.get("/analytics/chat/summary", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const { where, whereWithoutType } = parseScopeParams(c);

  // typeBreakdown deliberately omits `type` from its own where-clause so it
  // always reflects every type that has data in this scope, regardless of
  // which type is currently selected.
  const typeBreakdown = await db
    .select({
      type: chatAnalytics.type,
      queryCount: count(),
    })
    .from(chatAnalytics)
    .where(whereWithoutType)
    .groupBy(chatAnalytics.type)
    .orderBy(desc(count()));

  // Overall summary
  const [overall] = await db
    .select({
      totalQueries: count(),
      totalCost: sum(chatAnalytics.cost),
      avgLatencyMs: avg(chatAnalytics.latencyMs),
      totalInputTokens: sum(chatAnalytics.inputTokens),
      totalOutputTokens: sum(chatAnalytics.outputTokens),
      successCount: count(
        sql`CASE WHEN ${chatAnalytics.status} = 'success' THEN 1 END`
      ),
      errorCount: count(
        sql`CASE WHEN ${chatAnalytics.status} = 'error' THEN 1 END`
      ),
      uniqueUsers: sql<number>`COUNT(DISTINCT ${chatAnalytics.userId})`,
    })
    .from(chatAnalytics)
    .where(where);

  // Per-model breakdown
  const modelBreakdown = await db
    .select({
      model: chatAnalytics.model,
      queryCount: count(),
      totalCost: sum(chatAnalytics.cost),
      avgLatencyMs: avg(chatAnalytics.latencyMs),
      totalInputTokens: sum(chatAnalytics.inputTokens),
      totalOutputTokens: sum(chatAnalytics.outputTokens),
    })
    .from(chatAnalytics)
    .where(where)
    .groupBy(chatAnalytics.model)
    .orderBy(desc(count()));

  // Per-user breakdown
  const userBreakdown = await db
    .select({
      userId: chatAnalytics.userId,
      queryCount: count(),
      totalCost: sum(chatAnalytics.cost),
      avgLatencyMs: avg(chatAnalytics.latencyMs),
    })
    .from(chatAnalytics)
    .where(where)
    .groupBy(chatAnalytics.userId)
    .orderBy(desc(count()))
    .limit(20);

  return c.json({
    overall,
    modelBreakdown,
    userBreakdown,
    typeBreakdown,
  });
});

// Widest allowed span between `from` and `to` — dailyBreakdown returns one row
// per day, so an unbounded range is an unbounded response. 366 covers a full
// year (leap-safe); anything wider gets rejected rather than silently huge.
const MAX_TRENDS_SPAN_DAYS = 366;

/**
 * GET /analytics/chat/trends?type=&orgId=&projectId=&from=&to=
 * Per-day and per-status breakdowns for trend/outcome charts (admin only).
 * Split out from /summary because callers scope this differently (e.g. a
 * fixed last-30-days window vs. whatever date range /summary is filtered
 * to) — bundling them would mean every call computes aggregates it doesn't
 * use. Same `type` semantics as GET /analytics/chat above.
 */
analyticsRouter.get("/analytics/chat/trends", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const { where, from, to } = parseScopeParams(c);

  if (from && to) {
    const spanDays = (new Date(to).getTime() - new Date(from).getTime()) / 86400000;
    if (spanDays > MAX_TRENDS_SPAN_DAYS) {
      return c.json({ error: `from/to span too wide — max ${MAX_TRENDS_SPAN_DAYS} days` }, 400);
    }
  }

  // Aggregated server-side (not raw rows bucketed client-side — GET
  // /analytics/chat caps limit at 200, which would drop older days once
  // volume passes that). UTC day buckets to match createdAt's storage.
  const dailyBreakdown = await db
    .select({
      date: sql<string>`to_char(${chatAnalytics.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`,
      queryCount: count(),
    })
    .from(chatAnalytics)
    .where(where)
    .groupBy(sql`to_char(${chatAnalytics.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`)
    .orderBy(sql`to_char(${chatAnalytics.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`);

  const statusBreakdown = await db
    .select({
      status: chatAnalytics.status,
      queryCount: count(),
    })
    .from(chatAnalytics)
    .where(where)
    .groupBy(chatAnalytics.status)
    .orderBy(desc(count()));

  return c.json({ dailyBreakdown, statusBreakdown });
});

/**
 * GET /analytics/chat/:id
 * Fetch a single analytics event's full row (including `analysis`), for the
 * chat debug detail view (admin only). Registered after the more specific
 * /summary and /trends paths above so those literal segments are never
 * shadowed by this parametric route. Scoped by org the same way GET
 * /analytics/chat is (scopedOrgId: only super admins may pass `orgId`), so a
 * non-super-admin can't fetch another org's event by guessing its id.
 */
analyticsRouter.get("/analytics/chat/:id", authMiddleware, adminOnly, async (c) => {
  const db = c.get("db");
  const id = c.req.param("id");
  const orgId = scopedOrgId(c);

  const conditions = [eq(chatAnalytics.id, id)];
  if (orgId) conditions.push(eq(chatAnalytics.orgId, orgId));

  const [event] = await db
    .select()
    .from(chatAnalytics)
    .where(and(...conditions))
    .limit(1);

  if (!event) {
    return c.json({ error: "Analytics event not found" }, 404);
  }

  return c.json(event);
});

export default analyticsRouter;
