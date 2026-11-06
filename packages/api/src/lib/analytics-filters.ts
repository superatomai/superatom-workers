import { eq, inArray, sql } from "drizzle-orm";
import { chatAnalytics, files } from "../db/schema";

// The type / status filters and the attachment lookups shared by GET /analytics/chat and GET /analytics/export.

const TYPES = ["chat_agent", "dashboard", "report"] as const;
type AnalyticsType = (typeof TYPES)[number];

/**
 * `type` is one type, a comma-separated list ("chat_agent,report"), or "all".
 * Omitted = chat_agent, so callers that predate dashboard/report tracking see the same rows.
 * Unknown values are ignored.
 */
export function typeCondition(param: string | undefined) {
  const raw = param || "chat_agent";
  if (raw === "all") return undefined;
  const list = raw
    .split(",")
    .map((t) => t.trim())
    .filter((t): t is AnalyticsType => (TYPES as readonly string[]).includes(t));
  if (list.length === 0) return undefined;
  return list.length === 1 ? eq(chatAnalytics.type, list[0]) : inArray(chatAnalytics.type, list);
}

const STATUSES = ["success", "error", "aborted"] as const;
type AnalyticsStatus = (typeof STATUSES)[number];

/**
 * `status` is one status, a comma-separated list ("error,aborted"), or "all"/empty = no filter.
 * Unknown values are ignored.
 */
export function statusCondition(param: string | undefined) {
  if (!param || param === "all") return undefined;
  const list = param
    .split(",")
    .map((t) => t.trim())
    .filter((t): t is AnalyticsStatus => (STATUSES as readonly string[]).includes(t));
  if (list.length === 0) return undefined;
  return list.length === 1 ? eq(chatAnalytics.status, list[0]) : inArray(chatAnalytics.status, list);
}

// The chat attachments that belong to THIS question: uploaded on its thread, after the
// previous question on that thread and up to this one. (Same rule everywhere it's used.)
// Written with explicit table names so it reads the same with or without joins.
const attachmentsWhere = sql`
  "files"."kind" = 'chat_attachment' and "files"."status" = 'ready'
  and "files"."owner_type" = 'thread' and "files"."owner_id" = "chat_analytics"."thread_id"
  and "files"."created_at" <= "chat_analytics"."created_at"
  and "files"."created_at" > coalesce(
    (select max(p.created_at) from chat_analytics p
      where p.thread_id = "chat_analytics"."thread_id" and p.created_at < "chat_analytics"."created_at"),
    '-infinity'::timestamptz)`;

/** How many attachments this question has (0 when none, or no thread). */
export const attachmentCountSql = sql<number>`(select count(*)::int from ${files} where ${attachmentsWhere})`;

/** Their file names, comma-separated; null when none. */
export const attachmentNamesSql = sql<string | null>`(
  select string_agg("files"."file_name", ', ' order by "files"."created_at") from ${files} where ${attachmentsWhere})`;
