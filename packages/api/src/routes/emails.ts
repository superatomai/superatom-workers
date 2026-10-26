import { Hono } from "hono";
import { and, asc, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import { emailApiKeys, emailAttachments, emailCampaigns, emailSends, emailUnsubscribes, organizations, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, orgScopeGuard } from "../middleware/auth";
import type { AppContext } from "../lib/project-access";
import { checkObject, deleteObject, signObjectUrl } from "../lib/r2-objects";
import { fromAddress, isEmailConfigured, sendEmail } from "../lib/email";
import {
  ANNOUNCEMENTS,
  DAILY_ORG_LIMIT,
  REQUEST_BUDGET_MS,
  attachmentLinks,
  readyAttachments,
  buildEmailHtml,
  dailyUsage,
  parseAudience,
  processCampaign,
  resolveRecipients,
  setSubscription,
  type Audience,
} from "../lib/email-campaigns";
import { isRecurring, nextRun, parseSchedule, type EmailSchedule } from "../lib/email-schedule";
import { generateEmailApiKey, hashEmailApiKey } from "../lib/email-api-keys";

/**
 * Org announcements: an org admin writes an email and sends it, now or later,
 * to users of their own org. Mounted at /orgs/:orgId/emails.
 */
const emails = new Hono<{ Bindings: Env; Variables: AppVariables }>();

emails.use("*", authMiddleware, adminOnly, orgScopeGuard);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_SCHEDULE_AHEAD_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_ATTACHMENTS = 10;
// Total per email: bigger mails get bounced or spam-filtered (Resend's own cap is 40 MB).
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
const UPLOAD_URL_TTL_SECONDS = 15 * 60;
const MAX_API_KEYS = 20;
// Documents, spreadsheets, slides, images and archives; never executables or scripts.
const ATTACHMENT_EXTENSIONS = [
  "pdf", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx", "txt", "rtf", "odt", "ods", "odp",
  "png", "jpg", "jpeg", "gif", "webp", "zip",
];

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
      attachmentCount: sql<number>`(select count(*)::int from email_attachments f where f.campaign_id = ${emailCampaigns.id} and f.status = 'ready')`,
    })
    .from(emailCampaigns)
    .leftJoin(users, eq(users.id, emailCampaigns.createdBy))
    .where(and(eq(emailCampaigns.orgId, orgId), isNull(emailCampaigns.parentId)))
    .orderBy(desc(emailCampaigns.createdAt))
    .limit(200);
  return c.json(
    rows.map((r) => ({
      ...r.campaign,
      createdByName: r.createdByName,
      runCount: r.runCount,
      lastRunAt: r.lastRunAt,
      attachmentCount: r.attachmentCount,
    }))
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

// ─── API keys ────────────────────────────────────────────
// Before "/:id" so these paths aren't read as email ids.

/** GET /orgs/:orgId/emails/api-keys — keys for POST /emails/messages, newest first (never the key itself). */
emails.get("/api-keys", async (c) => {
  const orgId = c.req.param("orgId")!;
  const rows = await c
    .get("db")
    .select({
      id: emailApiKeys.id,
      name: emailApiKeys.name,
      keyPrefix: emailApiKeys.keyPrefix,
      createdByName: users.name,
      createdAt: emailApiKeys.createdAt,
      lastUsedAt: emailApiKeys.lastUsedAt,
      revokedAt: emailApiKeys.revokedAt,
    })
    .from(emailApiKeys)
    .leftJoin(users, eq(users.id, emailApiKeys.createdBy))
    .where(eq(emailApiKeys.orgId, orgId))
    .orderBy(desc(emailApiKeys.createdAt));
  return c.json(rows);
});

/** POST /orgs/:orgId/emails/api-keys { name } — the full key is in this response only. */
emails.post("/api-keys", async (c) => {
  const orgId = c.req.param("orgId")!;
  const { name } = await c.req.json<{ name?: unknown }>().catch(() => ({}) as { name?: unknown });
  if (typeof name !== "string" || !name.trim()) return c.json({ error: "name is required" }, 400);
  if (name.length > 100) return c.json({ error: "name is too long (max 100)" }, 400);
  // The key acts for its creator, so only an admin of this org (not a super admin passing through) can make one.
  if (c.get("orgId") !== orgId || c.get("userRole") !== "org_admin") {
    return c.json({ error: "Only an admin of this organization can create its keys" }, 403);
  }
  const db = c.get("db");
  const [{ n }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(emailApiKeys)
    .where(and(eq(emailApiKeys.orgId, orgId), isNull(emailApiKeys.revokedAt)));
  if (n >= MAX_API_KEYS) return c.json({ error: `At most ${MAX_API_KEYS} active keys; revoke one first` }, 400);
  const { key, keyPrefix } = generateEmailApiKey();
  const [row] = await db
    .insert(emailApiKeys)
    .values({ orgId, name: name.trim(), keyPrefix, keyHash: await hashEmailApiKey(key), createdBy: c.get("userId") })
    .returning({ id: emailApiKeys.id, name: emailApiKeys.name, keyPrefix: emailApiKeys.keyPrefix, createdAt: emailApiKeys.createdAt });
  return c.json({ ...row, key }, 201);
});

/** DELETE /orgs/:orgId/emails/api-keys/:keyId — revoke; works immediately. */
emails.delete("/api-keys/:keyId", async (c) => {
  const keyId = c.req.param("keyId");
  if (!UUID.test(keyId)) return c.json({ error: "Key not found" }, 404);
  const [row] = await c
    .get("db")
    .update(emailApiKeys)
    .set({ revokedAt: new Date() })
    .where(and(eq(emailApiKeys.id, keyId), eq(emailApiKeys.orgId, c.req.param("orgId")!), isNull(emailApiKeys.revokedAt)))
    .returning({ id: emailApiKeys.id });
  return row ? c.json({ message: "Revoked" }) : c.json({ error: "Key not found" }, 404);
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
  const db = c.get("db");
  const files = await db.select({ r2Key: emailAttachments.r2Key }).from(emailAttachments).where(eq(emailAttachments.campaignId, campaign.id));
  await Promise.all(files.map((f) => deleteObject(c.env, f.r2Key, c.env.EMAIL_ATTACHMENTS_BUCKET_NAME)));
  await db.delete(emailCampaigns).where(eq(emailCampaigns.id, campaign.id));
  return c.json({ message: "Deleted" });
});

/** POST /orgs/:orgId/emails/:id/test — send it to the caller only. Not counted, no unsubscribe link. */
emails.post("/:id/test", async (c) => {
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.source === "api") return c.json({ error: "An API send keeps no content to test" }, 409);
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
    attachments: await attachmentLinks(c.env, await readyAttachments(db, campaign.parentId ?? campaign.id)),
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
  c.executionCtx.waitUntil(processCampaign(c.env, c.get("db"), row.id, REQUEST_BUDGET_MS).catch((err) => console.error("[email] send now failed:", err)));
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

// ─── Attachments ─────────────────────────────────────────
// Browser uploads straight to R2: POST (record + upload URL) → PUT to R2 → POST complete.

const editable = (status: string) => status === "draft" || status === "scheduled";

/** GET /orgs/:orgId/emails/:id/attachments — files that finished uploading. */
emails.get("/:id/attachments", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const rows = await readyAttachments(c.get("db"), campaign.parentId ?? campaign.id);
  return c.json(rows.map(({ id, fileName, contentType, sizeBytes }) => ({ id, fileName, contentType, sizeBytes })));
});

/** POST /orgs/:orgId/emails/:id/attachments { fileName, contentType?, size } → { attachment, uploadUrl } */
emails.post("/:id/attachments", async (c) => {
  if (!c.env.EMAIL_ATTACHMENTS_BUCKET_NAME) return c.json({ error: "Attachments are not configured" }, 503);
  const orgId = c.req.param("orgId")!;
  const campaign = await loadCampaign(c, orgId, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (campaign.parentId || !editable(campaign.status)) {
    return c.json({ error: `Files can't be added to a ${campaign.status} email` }, 409);
  }
  const body = await c.req
    .json<{ fileName?: unknown; contentType?: unknown; size?: unknown }>()
    .catch(() => ({}) as { fileName?: unknown; contentType?: unknown; size?: unknown });
  const fileName = typeof body.fileName === "string" ? body.fileName.replace(/[\\/\x00-\x1f]/g, "_").trim().slice(0, 200) : "";
  const size = Number(body.size);
  if (!fileName) return c.json({ error: "fileName is required" }, 400);
  const ext = fileName.split(".").pop()?.toLowerCase() ?? "";
  if (!fileName.includes(".") || !ATTACHMENT_EXTENSIONS.includes(ext)) {
    return c.json({ error: `This file type can't be attached. Allowed: ${ATTACHMENT_EXTENSIONS.join(", ")}` }, 400);
  }
  if (!Number.isInteger(size) || size <= 0) return c.json({ error: "size must be a positive number of bytes" }, 400);

  const db = c.get("db");
  // Uploads abandoned for over an hour don't count.
  const existing = await db
    .select({ sizeBytes: emailAttachments.sizeBytes })
    .from(emailAttachments)
    .where(
      and(
        eq(emailAttachments.campaignId, campaign.id),
        sql`(${emailAttachments.status} = 'ready' or ${emailAttachments.createdAt} > now() - interval '1 hour')`
      )
    );
  if (existing.length >= MAX_ATTACHMENTS) return c.json({ error: `At most ${MAX_ATTACHMENTS} files per email` }, 400);
  const total = existing.reduce((n, f) => n + f.sizeBytes, 0);
  if (total + size > MAX_ATTACHMENT_BYTES) {
    return c.json({ error: `Files can total at most ${MAX_ATTACHMENT_BYTES / 1024 / 1024} MB per email` }, 400);
  }

  const id = crypto.randomUUID();
  // The key gets a URL-safe name; recipients see the original one.
  const r2Key = `email-attachments/${orgId}/${campaign.id}/${id}/${fileName.replace(/[^A-Za-z0-9._-]/g, "_")}`;
  const [row] = await db
    .insert(emailAttachments)
    .values({
      id,
      campaignId: campaign.id,
      fileName,
      contentType: typeof body.contentType === "string" ? body.contentType.slice(0, 255) : null,
      sizeBytes: size,
      r2Key,
    })
    .returning();
  const uploadUrl = await signObjectUrl(c.env, r2Key, "PUT", UPLOAD_URL_TTL_SECONDS, {}, c.env.EMAIL_ATTACHMENTS_BUCKET_NAME);
  return c.json(
    { attachment: { id: row.id, fileName, contentType: row.contentType, sizeBytes: size }, uploadUrl, expiresIn: UPLOAD_URL_TTL_SECONDS },
    201
  );
});

/** POST /orgs/:orgId/emails/:id/attachments/:attId/complete — confirm the PUT landed, at a size within limits. */
emails.post("/:id/attachments/:attId/complete", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  const attId = c.req.param("attId");
  if (!UUID.test(attId)) return c.json({ error: "File not found" }, 404);
  const db = c.get("db");
  const [att] = await db
    .select()
    .from(emailAttachments)
    .where(and(eq(emailAttachments.id, attId), eq(emailAttachments.campaignId, campaign.id)));
  if (!att) return c.json({ error: "File not found" }, 404);

  const bucket = c.env.EMAIL_ATTACHMENTS_BUCKET_NAME;
  const probe = await checkObject(c.env, att.r2Key, bucket);
  if (probe.state !== "ok") return c.json({ error: "The upload didn't finish; try again" }, 409);
  // The size declared up front isn't binding on the PUT, so re-check the real one.
  const others = await db
    .select({ n: sql<number>`coalesce(sum(${emailAttachments.sizeBytes}), 0)::int` })
    .from(emailAttachments)
    .where(and(eq(emailAttachments.campaignId, campaign.id), eq(emailAttachments.status, "ready")));
  if ((others[0]?.n ?? 0) + probe.size > MAX_ATTACHMENT_BYTES) {
    await deleteObject(c.env, att.r2Key, bucket);
    await db.delete(emailAttachments).where(eq(emailAttachments.id, att.id));
    return c.json({ error: `Files can total at most ${MAX_ATTACHMENT_BYTES / 1024 / 1024} MB per email` }, 400);
  }
  const [row] = await db
    .update(emailAttachments)
    .set({ status: "ready", sizeBytes: probe.size, contentType: att.contentType ?? probe.contentType })
    .where(eq(emailAttachments.id, att.id))
    .returning();
  return c.json({ id: row.id, fileName: row.fileName, contentType: row.contentType, sizeBytes: row.sizeBytes });
});

/** DELETE /orgs/:orgId/emails/:id/attachments/:attId */
emails.delete("/:id/attachments/:attId", async (c) => {
  const campaign = await loadCampaign(c, c.req.param("orgId")!, c.req.param("id"));
  if (!campaign) return c.json({ error: "Email not found" }, 404);
  if (!editable(campaign.status)) return c.json({ error: `Files can't be removed from a ${campaign.status} email` }, 409);
  const attId = c.req.param("attId");
  if (!UUID.test(attId)) return c.json({ error: "File not found" }, 404);
  const db = c.get("db");
  const [att] = await db
    .delete(emailAttachments)
    .where(and(eq(emailAttachments.id, attId), eq(emailAttachments.campaignId, campaign.id)))
    .returning();
  if (!att) return c.json({ error: "File not found" }, 404);
  await deleteObject(c.env, att.r2Key, c.env.EMAIL_ATTACHMENTS_BUCKET_NAME);
  return c.json({ message: "Removed" });
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
      subject: emailSends.subject,
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
