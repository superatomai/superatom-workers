/**
 * Announcement campaigns: who receives one, what it looks like, and the send loop
 * shared by "Send now" (waitUntil) and the cron (scheduled sends + stalled retries).
 */
import { and, eq, gte, inArray, lt, lte, ne, or, sql } from "drizzle-orm";
import type { Database } from "../db";
import {
  appPermissions,
  apps,
  emailCampaigns,
  emailSends,
  emailSubscriptionEvents,
  emailUnsubscribes,
  organizations,
  users,
} from "../db/schema";
import type { Env } from "../types";
import {
  RESEND_BATCH_LIMIT,
  fromAddress,
  sendEmailBatch,
  signUnsubscribeToken,
  unsubscribeHeaders,
  type EmailMessage,
} from "./email";
import { isRecurring, nextRun, parseSchedule } from "./email-schedule";

export const DAILY_ORG_LIMIT = 2000;
export const ANNOUNCEMENTS = "announcements";
// A "sending" campaign untouched this long lost its worker; the cron resumes it.
const STALE_MS = 10 * 60 * 1000;

export type Audience =
  | { type: "all" | "admins" | "members" }
  | { type: "project"; projectId: string }
  | { type: "users"; userIds: string[] };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseAudience(raw: unknown): Audience | null {
  const a = raw as { type?: string; projectId?: unknown; userIds?: unknown } | null;
  if (!a || typeof a !== "object") return null;
  if (a.type === "all" || a.type === "admins" || a.type === "members") return { type: a.type };
  if (a.type === "project" && typeof a.projectId === "string" && UUID.test(a.projectId)) {
    return { type: "project", projectId: a.projectId };
  }
  if (
    a.type === "users" &&
    Array.isArray(a.userIds) &&
    a.userIds.length > 0 &&
    a.userIds.every((id) => typeof id === "string" && UUID.test(id))
  ) {
    return { type: "users", userIds: [...new Set(a.userIds as string[])] };
  }
  return null;
}

export interface Recipient {
  userId: string;
  email: string;
  name: string;
  unsubscribed: boolean;
}

/** Active users of the org matching the audience, one per address. */
export async function resolveRecipients(
  db: Database,
  orgId: string,
  audience: Audience,
  category: string
): Promise<Recipient[]> {
  const conds = [eq(users.orgId, orgId), eq(users.isActive, true)];
  if (audience.type === "admins") conds.push(eq(users.role, "org_admin"));
  if (audience.type === "members") conds.push(eq(users.role, "member"));
  if (audience.type === "users") conds.push(inArray(users.id, audience.userIds));
  if (audience.type === "project") {
    // Same rule as /my/apps: admins see every app; members see granted apps and default apps.
    const pid = audience.projectId;
    conds.push(
      or(
        eq(users.role, "org_admin"),
        sql`exists (select 1 from ${appPermissions} ap join ${apps} a on a.id = ap.app_id
                    where ap.user_id = ${users.id} and a.project_id = ${pid} and a.is_active)`,
        sql`exists (select 1 from ${apps} a where a.project_id = ${pid} and a.is_active and a.is_default)`,
        sql`exists (select 1 from ${organizations} o join ${apps} a on a.id = o.default_app_id
                    where o.id = ${orgId} and a.project_id = ${pid} and a.is_active)`
      )!
    );
  }

  const rows = await db
    .select({
      userId: users.id,
      email: users.email,
      name: users.name,
      unsubscribed: sql<boolean>`${emailUnsubscribes.userId} is not null`,
    })
    .from(users)
    .leftJoin(
      emailUnsubscribes,
      and(eq(emailUnsubscribes.userId, users.id), eq(emailUnsubscribes.category, category))
    )
    .where(and(...conds));

  const seen = new Set<string>();
  return rows.filter((r) => {
    const key = r.email.trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Sets one person's subscription and logs the change; one atomic batch. */
export async function setSubscription(
  db: Database,
  p: { userId: string; category: string; subscribed: boolean; source: "self" | "admin"; changedBy?: string | null }
): Promise<void> {
  const changedBy = p.changedBy ?? null;
  const change = p.subscribed
    ? db
        .delete(emailUnsubscribes)
        .where(and(eq(emailUnsubscribes.userId, p.userId), eq(emailUnsubscribes.category, p.category)))
    : db
        .insert(emailUnsubscribes)
        .values({ userId: p.userId, category: p.category, source: p.source, changedBy })
        .onConflictDoUpdate({
          target: [emailUnsubscribes.userId, emailUnsubscribes.category],
          set: { source: p.source, changedBy, createdAt: new Date() },
        });
  await db.batch([
    change,
    db.insert(emailSubscriptionEvents).values({
      userId: p.userId,
      category: p.category,
      subscribed: p.subscribed,
      source: p.source,
      changedBy,
    }),
  ]);
}

/** Emails sent (or queued) for the org in the last 24h, excluding one campaign. */
export async function dailyUsage(db: Database, orgId: string, excludeCampaignId?: string): Promise<number> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const conds = [
    eq(emailCampaigns.orgId, orgId),
    inArray(emailSends.status, ["pending", "sent"]),
    gte(emailSends.createdAt, since),
  ];
  if (excludeCampaignId) conds.push(ne(emailCampaigns.id, excludeCampaignId));
  const [row] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(emailSends)
    .innerJoin(emailCampaigns, eq(emailCampaigns.id, emailSends.campaignId))
    .where(and(...conds));
  return row?.n ?? 0;
}

// ─── Rendering ───────────────────────────────────────────

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function inline(html: string): string {
  return html
    .replace(
      /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
      '<a href="$2" style="color: #2563eb; text-decoration: underline;">$1</a>'
    )
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__(.+?)__/g, "<strong>$1</strong>")
    .replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>")
    .replace(/`(.+?)`/g, '<code style="background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 13px;">$1</code>');
}

/** Same subset as sa-platform-ui's emailMarkdown.ts (plus links), so the preview matches. */
export function renderMarkdown(md: string): string {
  const out: string[] = [];
  let list: "ul" | "ol" | null = null;
  const closeList = () => {
    if (list) out.push(`</${list}>`);
    list = null;
  };
  const li = (text: string) =>
    `<li style="margin: 4px 0; font-size: 14px; color: #374151; line-height: 1.6;">${inline(escapeHtml(text))}</li>`;

  for (const line of md.split("\n")) {
    const heading = line.match(/^(#{1,3})\s+(.*)/);
    const bullet = line.match(/^\s*[-*]\s+(.*)/);
    const numbered = line.match(/^\s*\d+\.\s+(.*)/);
    if (heading) {
      closeList();
      const size = { 1: "18px", 2: "16px", 3: "14px" }[heading[1].length as 1 | 2 | 3];
      out.push(`<p style="margin: 16px 0 8px 0; font-size: ${size}; font-weight: 700; color: #111827;">${inline(escapeHtml(heading[2]))}</p>`);
    } else if (bullet || numbered) {
      const tag = bullet ? "ul" : "ol";
      if (list !== tag) {
        closeList();
        out.push(`<${tag} style="margin: 8px 0; padding-left: 20px;">`);
        list = tag;
      }
      out.push(li((bullet ?? numbered)![1]));
    } else {
      closeList();
      if (line.trim()) {
        out.push(`<p style="margin: 6px 0; font-size: 14px; color: #374151; line-height: 1.6;">${inline(escapeHtml(line))}</p>`);
      }
    }
  }
  closeList();
  return out.join("\n");
}

/** Solid colours only: Gmail strips gradient backgrounds. */
export function buildEmailHtml(p: { orgName: string; bodyMarkdown: string; unsubscribeUrl?: string }): string {
  const org = escapeHtml(p.orgName);
  const footer = p.unsubscribeUrl
    ? `You're receiving this because you're a member of ${org} on Superatom.<br><a href="${escapeHtml(p.unsubscribeUrl)}" style="color: #6b7280;">Unsubscribe from announcements</a>`
    : `You're receiving this because you're a member of ${org} on Superatom.`;
  return `<!doctype html>
<html><body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 24px 0;"><tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 8px;">
<tr><td style="padding: 20px 28px; border-bottom: 1px solid #e5e7eb; font-size: 15px; font-weight: 700; color: #111827;">${org}</td></tr>
<tr><td style="padding: 20px 28px;">${renderMarkdown(p.bodyMarkdown)}</td></tr>
<tr><td style="padding: 16px 28px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; line-height: 1.5;">${footer}</td></tr>
</table></td></tr></table></body></html>`;
}

/** Public base for unsubscribe links: this worker's own URL. */
export function unsubscribeUrl(env: Env, token: string): string {
  return `${env.INSTALL_SA_API_URL.replace(/\/+$/, "")}/email/unsubscribe?token=${encodeURIComponent(token)}`;
}

// ─── Sending ─────────────────────────────────────────────

/** Cron entry: due scheduled campaigns plus "sending" ones whose worker died. */
export async function processDueCampaigns(env: Env, db: Database): Promise<void> {
  const now = new Date();
  const due = await db
    .select({ id: emailCampaigns.id })
    .from(emailCampaigns)
    .where(
      or(
        and(eq(emailCampaigns.status, "scheduled"), lte(emailCampaigns.scheduledAt, now)),
        and(eq(emailCampaigns.status, "sending"), lt(emailCampaigns.updatedAt, new Date(now.getTime() - STALE_MS)))
      )
    )
    .limit(10);
  for (const { id } of due) {
    try {
      await processCampaign(env, db, id);
    } catch (err) {
      console.error(`[email] campaign ${id} failed:`, err);
    }
  }
}

/** Sends one campaign to completion. The claim UPDATE makes concurrent runs a no-op. */
export async function processCampaign(env: Env, db: Database, campaignId: string): Promise<void> {
  const [head] = await db
    .select({ schedule: emailCampaigns.schedule })
    .from(emailCampaigns)
    .where(eq(emailCampaigns.id, campaignId));
  if (head && isRecurring(parseSchedule(head.schedule))) return runRecurring(env, db, campaignId);

  const now = new Date();
  const [campaign] = await db
    .update(emailCampaigns)
    .set({ status: "sending", updatedAt: now })
    .where(
      and(
        eq(emailCampaigns.id, campaignId),
        or(
          and(eq(emailCampaigns.status, "scheduled"), lte(emailCampaigns.scheduledAt, now)),
          and(eq(emailCampaigns.status, "sending"), lt(emailCampaigns.updatedAt, new Date(now.getTime() - STALE_MS)))
        )
      )
    )
    .returning();
  if (!campaign || !campaign.orgId) return;
  const orgId = campaign.orgId;

  const fail = (error: string) =>
    db.update(emailCampaigns).set({ status: "failed", error, updatedAt: new Date() }).where(eq(emailCampaigns.id, campaignId));
  if (!env.RESEND_API_KEY || !env.EMAIL_UNSUBSCRIBE_SECRET) {
    return void (await fail("Email sending is not configured (RESEND_API_KEY / EMAIL_UNSUBSCRIBE_SECRET)"));
  }

  // First run materialises the recipient list; a resumed run just drains what's pending.
  const [{ n: existing }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(emailSends)
    .where(eq(emailSends.campaignId, campaignId));
  if (existing === 0) {
    const audience = parseAudience(campaign.audience);
    if (!audience) return void (await fail("Invalid audience"));
    const recipients = await resolveRecipients(db, orgId, audience, campaign.category);
    const toSend = recipients.filter((r) => !r.unsubscribed).length;
    if (toSend === 0) return void (await fail("No recipients"));
    const used = await dailyUsage(db, orgId, campaignId);
    if (used + toSend > DAILY_ORG_LIMIT) {
      return void (await fail(`Daily limit reached: ${used} of ${DAILY_ORG_LIMIT} sent in the last 24 hours, this needs ${toSend}`));
    }
    for (let i = 0; i < recipients.length; i += 500) {
      await db
        .insert(emailSends)
        .values(
          recipients.slice(i, i + 500).map((r) => ({
            campaignId,
            userId: r.userId,
            email: r.email,
            status: r.unsubscribed ? "skipped" : "pending",
            error: r.unsubscribed ? "Unsubscribed" : null,
          }))
        )
        .onConflictDoNothing();
    }
    await db
      .update(emailCampaigns)
      .set({ recipientCount: toSend, updatedAt: new Date() })
      .where(eq(emailCampaigns.id, campaignId));
  }

  const [org] = await db.select({ name: organizations.name }).from(organizations).where(eq(organizations.id, orgId));
  const [author] = campaign.createdBy
    ? await db.select({ email: users.email }).from(users).where(eq(users.id, campaign.createdBy))
    : [];
  const orgName = org?.name ?? "Your organization";
  const from = fromAddress(env, orgName);

  for (;;) {
    const batch = await db
      .select({ id: emailSends.id, email: emailSends.email, userId: emailSends.userId })
      .from(emailSends)
      .where(and(eq(emailSends.campaignId, campaignId), eq(emailSends.status, "pending")))
      .orderBy(emailSends.id)
      .limit(RESEND_BATCH_LIMIT);
    if (batch.length === 0) break;

    const messages: EmailMessage[] = await Promise.all(
      batch.map(async (r) => {
        const url = r.userId ? unsubscribeUrl(env, await signUnsubscribeToken(env, r.userId, campaign.category)) : undefined;
        return {
          from,
          to: [r.email],
          subject: campaign.subject,
          html: buildEmailHtml({ orgName, bodyMarkdown: campaign.bodyMarkdown, unsubscribeUrl: url }),
          replyTo: author?.email,
          headers: url ? unsubscribeHeaders(url) : undefined,
          tags: [{ name: "campaign", value: campaignId }],
        };
      })
    );

    const result = await sendEmailBatch(env, messages, `campaign-${campaignId}-${await digest(batch.map((r) => r.id).join(","))}`);
    if (result.notConfigured) return void (await fail(result.error!));

    if (result.success) {
      const ids = result.ids ?? [];
      const values = sql.join(
        batch.map((r, i) => sql`(${r.id}::uuid, ${ids[i] ?? null})`),
        sql`, `
      );
      await db.execute(sql`
        update ${emailSends} set status = 'sent', resend_id = v.rid, sent_at = now()
        from (values ${values}) as v(id, rid) where ${emailSends.id} = v.id`);
    } else {
      await db
        .update(emailSends)
        .set({ status: "failed", error: result.error ?? "Send failed" })
        .where(inArray(emailSends.id, batch.map((r) => r.id)));
    }
    // Heartbeat, so the cron doesn't treat a long send as stalled.
    await db.update(emailCampaigns).set({ updatedAt: new Date() }).where(eq(emailCampaigns.id, campaignId));
  }

  const [counts] = await db
    .select({
      sent: sql<number>`count(*) filter (where ${emailSends.status} = 'sent')::int`,
      failed: sql<number>`count(*) filter (where ${emailSends.status} = 'failed')::int`,
    })
    .from(emailSends)
    .where(eq(emailSends.campaignId, campaignId));
  await db
    .update(emailCampaigns)
    .set({
      status: counts.sent === 0 && counts.failed > 0 ? "failed" : "sent",
      sentCount: counts.sent,
      failedCount: counts.failed,
      sentAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(emailCampaigns.id, campaignId));
}

/**
 * A due recurring email: move it on to its next run, then send this occurrence as a child
 * campaign. Moving scheduledAt is the claim, so a concurrent cron/send can't spawn it twice.
 */
async function runRecurring(env: Env, db: Database, campaignId: string): Promise<void> {
  const now = new Date();
  const [parent] = await db
    .select()
    .from(emailCampaigns)
    .where(and(eq(emailCampaigns.id, campaignId), eq(emailCampaigns.status, "scheduled"), lte(emailCampaigns.scheduledAt, now)));
  if (!parent?.orgId || !parent.scheduledAt) return;

  // Next run counts from now, so a missed run (cron down) is skipped rather than replayed.
  const next = nextRun(parseSchedule(parent.schedule)!, now);
  const [claimed] = await db
    .update(emailCampaigns)
    .set({ scheduledAt: next, status: next ? "scheduled" : "sent", updatedAt: now })
    .where(
      and(
        eq(emailCampaigns.id, campaignId),
        eq(emailCampaigns.status, "scheduled"),
        eq(emailCampaigns.scheduledAt, parent.scheduledAt)
      )
    )
    .returning({ id: emailCampaigns.id });
  if (!claimed) return;

  const [run] = await db
    .insert(emailCampaigns)
    .values({
      orgId: parent.orgId,
      parentId: parent.id,
      audience: parent.audience,
      category: parent.category,
      subject: parent.subject,
      bodyMarkdown: parent.bodyMarkdown,
      status: "scheduled",
      scheduledAt: now,
      createdBy: parent.createdBy,
    })
    .returning({ id: emailCampaigns.id });
  await processCampaign(env, db, run.id);
}

async function digest(value: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(buf).slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}
