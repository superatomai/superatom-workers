import { Hono } from "hono";
import { and, asc, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import { emailCampaigns, emailSends, emailUnsubscribes, organizations, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, orgScopeGuard } from "../middleware/auth";
import type { AppContext } from "../lib/project-access";
import { fromAddress, isEmailConfigured, sendEmail } from "../lib/email";
import {
  ANNOUNCEMENTS,
  DAILY_ORG_LIMIT,
  buildEmailHtml,
  dailyUsage,
  parseAudience,
  processCampaign,
  resolveRecipients,
  setSubscription,
  type Audience,
} from "../lib/email-campaigns";
import { isRecurring, nextRun, parseSchedule, type EmailSchedule } from "../lib/email-schedule";

/**
 * Org announcements: an org admin writes an email and sends it, now or later,
 * to users of their own org. Mounted at /orgs/:orgId/emails.
 */
const emails = new Hono<{ Bindings: Env; Variables: AppVariables }>();

emails.use("*", authMiddleware, adminOnly, orgScopeGuard);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_SCHEDULE_AHEAD_MS = 365 * 24 * 60 * 60 * 1000;

type Body = { subject?: unknown; bodyMarkdown?: unknown; audience?: unknown };

/** Validates a create/edit body; a project audience must be a project of this org. */
async function readCampaign(
  c: AppContext,
  orgId: string,
  body: Body,
  partial: boolean
): Promise<{ ok: true; value: { subject?: string; bodyMarkdown?: string; audience?: Audience } } | { ok: false; error: string }> {
  const value: { subject?: string; bodyMarkdown?: string; audience?: Audience } = {};
  if (body.subject !== undefined || !partial) {
    if (typeof body.subject !== "string" || !body.subject.trim()) return { ok: false, error: "subject is required" };
    if (body.subject.length > 255) return { ok: false, error: "subject is too long (max 255)" };
    value.subject = body.subject.trim();
  }
  if (body.bodyMarkdown !== undefined || !partial) {
    if (typeof body.bodyMarkdown !== "string" || !body.bodyMarkdown.trim()) return { ok: false, error: "bodyMarkdown is required" };
    if (body.bodyMarkdown.length > 50_000) return { ok: false, error: "bodyMarkdown is too long" };
    value.bodyMarkdown = body.bodyMarkdown;
  }
  if (body.audience !== undefined || !partial) {
    const audience = parseAudience(body.audience);
    if (!audience) return { ok: false, error: "audience is invalid" };
    if (audience.type === "project") {
      const [p] = await c
        .get("db")
        .select({ id: projects.id })
        .from(projects)
        .where(and(eq(projects.id, audience.projectId), eq(projects.orgId, orgId)));
      if (!p) return { ok: false, error: "Project not found in this organization" };
    }
    value.audience = audience;
  }
  return { ok: true, value };
}

async function loadCampaign(c: AppContext, orgId: string, id: string) {
  if (!UUID.test(id)) return undefined;
  const [row] = await c
    .get("db")
    .select()
    .from(emailCampaigns)
    .where(and(eq(emailCampaigns.id, id), eq(emailCampaigns.orgId, orgId)));
  return row;
}

/** Recipients that will actually get it, against what's left of today's limit. */
/** A recurring email is checked per run, so only against the whole daily limit here. */
async function checkLimit(
  c: AppContext,
  orgId: string,
  campaign: { id: string; audience: unknown; category: string },
  recurring = false
) {
  const db = c.get("db");
  const recipients = await resolveRecipients(db, orgId, parseAudience(campaign.audience)!, campaign.category);
  const count = recipients.filter((r) => !r.unsubscribed).length;
  const used = recurring ? 0 : await dailyUsage(db, orgId, campaign.id);
  if (count === 0) return { ok: false as const, error: "No recipients match this audience" };
  if (used + count > DAILY_ORG_LIMIT) {
    return { ok: false as const, error: `This needs ${count} emails, but only ${Math.max(0, DAILY_ORG_LIMIT - used)} of the ${DAILY_ORG_LIMIT} daily limit are left` };
  }
  return { ok: true as const, count };
}

/** GET /orgs/:orgId/emails — campaigns, newest first; a recurring email's runs are nested under it. */
emails.get("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const rows = await c
    .get("db")
    .select({
      campaign: emailCampaigns,
      createdByName: users.name,
      runCount: sql<number>`(select count(*)::int from email_campaigns r where r.parent_id = ${emailCampaigns.id})`,
      lastRunAt: sql<string | null>`(select max(r.sent_at) from email_campaigns r where r.parent_id = ${emailCampaigns.id})`,
    })
    .from(emailCampaigns)
    .leftJoin(users, eq(users.id, emailCampaigns.createdBy))
    .where(and(eq(emailCampaigns.orgId, orgId), isNull(emailCampaigns.parentId)))
    .orderBy(desc(emailCampaigns.createdAt))
    .limit(200);
  return c.json(
    rows.map((r) => ({ ...r.campaign, createdByName: r.createdByName, runCount: r.runCount, lastRunAt: r.lastRunAt }))
  );
});

/** GET /orgs/:orgId/emails/usage — today's quota, and whether sending is set up at all. */
emails.get("/usage", async (c) => {
  const orgId = c.req.param("orgId")!;
  return c.json({
    used: await dailyUsage(c.get("db"), orgId),
    limit: DAILY_ORG_LIMIT,
    configured: isEmailConfigured(c.env),
  });
});

/** GET /orgs/:orgId/emails/subscribers — every active user and their announcement subscription. */
emails.get("/subscribers", async (c) => {
  const orgId = c.req.param("orgId")!;
  const changer = alias(users, "changer");
  const rows = await c
    .get("db")
    .select({
      userId: users.id,
      name: users.name,
      email: users.email,
      role: users.role,
      unsubscribedAt: emailUnsubscribes.createdAt,
      source: emailUnsubscribes.source,
      changedByName: changer.name,
    })
    .from(users)
    .leftJoin(
      emailUnsubscribes,
      and(eq(emailUnsubscribes.userId, users.id), eq(emailUnsubscribes.category, ANNOUNCEMENTS))
    )
    .leftJoin(changer, eq(changer.id, emailUnsubscribes.changedBy))
    .where(and(eq(users.orgId, orgId), eq(users.isActive, true)))
    .orderBy(asc(users.name));
  return c.json(
    rows.map(({ unsubscribedAt, source, changedByName, ...u }) => ({
      ...u,
      subscribed: unsubscribedAt === null,
      unsubscribedAt,
      unsubscribedBy: unsubscribedAt === null ? null : source === "admin" ? (changedByName ?? "an admin") : "self",
    }))
  );
});

/** PUT /orgs/:orgId/emails/subscribers/:userId { subscribed } — admin override, logged with who did it. */
emails.put("/subscribers/:userId", async (c) => {
  const orgId = c.req.param("orgId")!;
  const userId = c.req.param("userId");
  const { subscribed } = await c.req.json<{ subscribed?: unknown }>().catch(() => ({}) as { subscribed?: unknown });
  if (typeof subscribed !== "boolean") return c.json({ error: "subscribed must be true or false" }, 400);
  if (!UUID.test(userId)) return c.json({ error: "User not found" }, 404);
  const db = c.get("db");
  const [user] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.id, userId), eq(users.orgId, orgId)));
  if (!user) return c.json({ error: "User not found" }, 404);
  await setSubscription(db, { userId, category: ANNOUNCEMENTS, subscribed, source: "admin", changedBy: c.get("userId") });
  return c.json({ userId, subscribed });
});

/** POST /orgs/:orgId/emails/recipients — preview who an audience reaches, before saving. */
emails.post("/recipients", async (c) => {
  const orgId = c.req.param("orgId")!;
  const body = await c.req.json<Body>().catch(() => ({}) as Body);
  const parsed = await readCampaign(c, orgId, { audience: body.audience }, true);
  if (!parsed.ok) return c.json({ error: parsed.error }, 400);
  if (!parsed.value.audience) return c.json({ error: "audience is required" }, 400);
  const recipients = await resolveRecipients(c.get("db"), orgId, parsed.value.audience, ANNOUNCEMENTS);
  return c.json({
    count: recipients.filter((r) => !r.unsubscribed).length,
    unsubscribed: recipients.filter((r) => r.unsubscribed).length,
    recipients: recipients.slice(0, 500).map(({ userId, email, name, unsubscribed }) => ({ userId, email, name, unsubscribed })),
  });
});

/** POST /orgs/:orgId/emails — create a draft. */
emails.post("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const parsed = await readCampaign(c, orgId, await c.req.json<Body>().catch(() => ({}) as Body), false);
  if (!parsed.ok) return c.json({ error: parsed.error }, 400);
  const [row] = await c
    .get("db")
    .insert(emailCampaigns)
    .values({
      orgId,
      category: ANNOUNCEMENTS,
      subject: parsed.value.subject!,
      bodyMarkdown: parsed.value.bodyMarkdown!,
      audience: parsed.value.audience!,
      createdBy: c.get("userId"),
    })
    .returning();
  return c.json(row, 201);
});

/** GET /orgs/:orgId/emails/:id */
emails.get("/:id", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  return campaign ? c.json(campaign) : c.json({ error: "Email not found" }, 404);
});

/** PATCH /orgs/:orgId/emails/:id — edit a draft or a not-yet-sent scheduled email. */
emails.patch("/:id", async (c) => {
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.status !== "draft" && campaign.status !== "scheduled") {
    return c.json({ error: `A ${campaign.status} email can't be edited` }, 409);
  }
  const parsed = await readCampaign(c, orgId, await c.req.json<Body>().catch(() => ({}) as Body), true);
  if (!parsed.ok) return c.json({ error: parsed.error }, 400);
  const [row] = await c
    .get("db")
    .update(emailCampaigns)
    .set({ ...parsed.value, updatedAt: new Date() })
    .where(and(eq(emailCampaigns.id, campaign.id), inArray(emailCampaigns.status, ["draft", "scheduled"])))
    .returning();
  return row ? c.json(row) : c.json({ error: "Email is already sending" }, 409);
});

/** DELETE /orgs/:orgId/emails/:id — drafts and cancelled emails only; sent ones stay as a record. */
emails.delete("/:id", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.status !== "draft" && campaign.status !== "cancelled") {
    return c.json({ error: `A ${campaign.status} email can't be deleted` }, 409);
  }
  await c.get("db").delete(emailCampaigns).where(eq(emailCampaigns.id, campaign.id));
  return c.json({ message: "Deleted" });
});

/** POST /orgs/:orgId/emails/:id/test — send it to the caller only. Not counted, no unsubscribe link. */
emails.post("/:id/test", async (c) => {
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const db = c.get("db");
  const [me] = await db.select({ email: users.email }).from(users).where(eq(users.id, c.get("userId")));
  if (!me) return c.json({ error: "Your account has no email address" }, 400);
  const [org] = await db.select({ name: organizations.name }).from(organizations).where(eq(organizations.id, orgId));
  const orgName = org?.name ?? "Your organization";
  const result = await sendEmail(c.env, {
    from: fromAddress(c.env, orgName),
    to: [me.email],
    subject: `[Test] ${campaign.subject}`,
    html: buildEmailHtml({ orgName, bodyMarkdown: campaign.bodyMarkdown }),
  });
  if (!result.success) return c.json({ error: result.error }, result.notConfigured ? 503 : 502);
  return c.json({ message: `Test sent to ${me.email}` });
});

/** POST /orgs/:orgId/emails/:id/send — send now; the work continues after the response. */
emails.post("/:id/send", async (c) => {
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.status !== "draft" && campaign.status !== "scheduled") {
    return c.json({ error: `A ${campaign.status} email can't be sent` }, 409);
  }
  if (!isEmailConfigured(c.env)) return c.json({ error: "Email sending is not configured" }, 503);
  const limit = await checkLimit(c, orgId, campaign);
  if (!limit.ok) return c.json({ error: limit.error }, 400);

  const now = new Date();
  const [row] = await c
    .get("db")
    .update(emailCampaigns)
    .set({ status: "scheduled", schedule: null, scheduledAt: now, error: null, updatedAt: now })
    .where(and(eq(emailCampaigns.id, campaign.id), inArray(emailCampaigns.status, ["draft", "scheduled"])))
    .returning();
  if (!row) return c.json({ error: "Email is already sending" }, 409);
  // If the worker is cut off, the cron resumes it.
  c.executionCtx.waitUntil(processCampaign(c.env, c.get("db"), row.id).catch((err) => console.error("[email] send now failed:", err)));
  return c.json({ ...row, status: "sending", recipientCount: limit.count }, 202);
});

/**
 * POST /orgs/:orgId/emails/:id/schedule { schedule } — an EmailSchedule (once or recurring),
 * or the older { scheduledAt } ISO time for a one-off.
 */
emails.post("/:id/schedule", async (c) => {
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.parentId) return c.json({ error: "A run of a recurring email can't be scheduled" }, 409);
  if (campaign.status !== "draft" && campaign.status !== "scheduled") {
    return c.json({ error: `A ${campaign.status} email can't be scheduled` }, 409);
  }
  const body = await c.req
    .json<{ scheduledAt?: string; schedule?: unknown }>()
    .catch(() => ({}) as { scheduledAt?: string; schedule?: unknown });

  let schedule: EmailSchedule | null = null;
  let at: Date | null;
  if (body.schedule !== undefined) {
    schedule = parseSchedule(body.schedule);
    if (!schedule) return c.json({ error: "schedule is invalid" }, 400);
    at = nextRun(schedule, new Date());
    if (!at) return c.json({ error: "That time has already passed" }, 400);
  } else {
    at = body.scheduledAt ? new Date(body.scheduledAt) : null;
    if (!at || Number.isNaN(at.getTime())) return c.json({ error: "scheduledAt must be an ISO date-time" }, 400);
    if (at.getTime() <= Date.now()) return c.json({ error: "scheduledAt must be in the future" }, 400);
  }
  if (at.getTime() - Date.now() > MAX_SCHEDULE_AHEAD_MS) return c.json({ error: "The first send must be within a year" }, 400);
  // Checked now; re-checked when each send actually goes out.
  const limit = await checkLimit(c, orgId, campaign, isRecurring(schedule));
  if (!limit.ok) return c.json({ error: limit.error }, 400);

  const [row] = await c
    .get("db")
    .update(emailCampaigns)
    .set({ status: "scheduled", schedule, scheduledAt: at, error: null, updatedAt: new Date() })
    .where(and(eq(emailCampaigns.id, campaign.id), inArray(emailCampaigns.status, ["draft", "scheduled"])))
    .returning();
  return row ? c.json(row) : c.json({ error: "Email is already sending" }, 409);
});

/** POST /orgs/:orgId/emails/:id/cancel — unschedule. A sending email can't be stopped. */
emails.post("/:id/cancel", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const [row] = await c
    .get("db")
    .update(emailCampaigns)
    .set({ status: "cancelled", updatedAt: new Date() })
    .where(and(eq(emailCampaigns.id, campaign.id), eq(emailCampaigns.status, "scheduled")))
    .returning();
  return row ? c.json(row) : c.json({ error: `A ${campaign.status} email can't be cancelled` }, 409);
});

/** GET /orgs/:orgId/emails/:id/runs — each send of a recurring email, newest first. */
emails.get("/:id/runs", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const rows = await c
    .get("db")
    .select()
    .from(emailCampaigns)
    .where(eq(emailCampaigns.parentId, campaign.id))
    .orderBy(desc(emailCampaigns.createdAt))
    .limit(200);
  return c.json(rows);
});

/** GET /orgs/:orgId/emails/:id/sends — per-recipient delivery log. */
emails.get("/:id/sends", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const rows = await c
    .get("db")
    .select({
      email: emailSends.email,
      name: users.name,
      status: emailSends.status,
      error: emailSends.error,
      sentAt: emailSends.sentAt,
    })
    .from(emailSends)
    .leftJoin(users, eq(users.id, emailSends.userId))
    .where(eq(emailSends.campaignId, campaign.id))
    .orderBy(emailSends.email)
    .limit(5000);
  return c.json(rows);
});

export default emails;
