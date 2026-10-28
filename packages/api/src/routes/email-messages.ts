import { Hono } from "hono";
import { and, eq, inArray, sql } from "drizzle-orm";
import { emailApiKeys, emailCampaigns, emailSends, emailUnsubscribes, organizations, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authenticateEmailKey } from "../lib/email-api-keys";
import {
  RESEND_BATCH_LIMIT,
  fromAddress,
  isEmailConfigured,
  sendEmailBatch,
  signUnsubscribeToken,
  unsubscribeHeaders,
  type EmailMessage,
} from "../lib/email";
import { ANNOUNCEMENTS, DAILY_ORG_LIMIT, buildEmailHtml, dailyUsage, unsubscribeUrl } from "../lib/email-campaigns";

/**
 * Script/agent sending: each message has its own recipient and content. Authenticated by an
 * org email API key (not a login). Mounted at /orgs/:orgId/emails/messages, before the
 * emails router so its login middleware doesn't apply.
 */
const emailMessages = new Hono<{ Bindings: Env; Variables: AppVariables }>();

const EMAIL = /^[^\s@<>",]+@[^\s@<>",]+\.[^\s@<>",]+$/;
const MAX_HTML = 500_000;
const MAX_MARKDOWN = 50_000;

type Input = { to?: unknown; subject?: unknown; html?: unknown; markdown?: unknown; text?: unknown; replyTo?: unknown };
type Message = { to: string; subject: string; html?: string; markdown?: string; text?: string; replyTo?: string };
type Result = { index: number; to: string; status: "sent" | "skipped" | "rejected" | "failed"; id?: string; error?: string };

function readMessage(m: Input): Message | string {
  if (!m || typeof m !== "object") return "must be an object";
  if (typeof m.to !== "string" || !EMAIL.test(m.to.trim())) return "to must be an email address";
  if (typeof m.subject !== "string" || !m.subject.trim()) return "subject is required";
  if (m.subject.length > 255) return "subject is too long (max 255)";
  const hasHtml = typeof m.html === "string" && m.html.trim() !== "";
  const hasMd = typeof m.markdown === "string" && m.markdown.trim() !== "";
  if (hasHtml === hasMd) return "give exactly one of html or markdown";
  if (hasHtml && (m.html as string).length > MAX_HTML) return `html is too long (max ${MAX_HTML} characters)`;
  if (hasMd && (m.markdown as string).length > MAX_MARKDOWN) return `markdown is too long (max ${MAX_MARKDOWN} characters)`;
  if (m.text !== undefined && typeof m.text !== "string") return "text must be a string";
  if (m.replyTo !== undefined && (typeof m.replyTo !== "string" || !EMAIL.test(m.replyTo))) return "replyTo must be an email address";
  return {
    to: m.to.trim(),
    subject: m.subject.trim(),
    ...(hasHtml ? { html: m.html as string } : { markdown: m.markdown as string }),
    ...(m.text ? { text: m.text as string } : {}),
    ...(m.replyTo ? { replyTo: m.replyTo as string } : {}),
  };
}

/** POST /orgs/:orgId/emails/messages { messages: [...], tag? } — see the API guide. */
emailMessages.post("/", async (c) => {
  const orgId = c.req.param("orgId")!;
  const db = c.get("db");
  const auth = await authenticateEmailKey(db, c.req.header("Authorization"), orgId);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  c.executionCtx.waitUntil(db.update(emailApiKeys).set({ lastUsedAt: new Date() }).where(eq(emailApiKeys.id, auth.keyId)).then(() => undefined));

  const idempotencyKey = c.req.header("Idempotency-Key")?.trim() || null;
  if (idempotencyKey && idempotencyKey.length > 255) return c.json({ error: "Idempotency-Key is too long (max 255)" }, 400);
  if (idempotencyKey) {
    const [prior] = await db
      .select({ id: emailCampaigns.id })
      .from(emailCampaigns)
      .where(and(eq(emailCampaigns.apiKeyId, auth.keyId), eq(emailCampaigns.idempotencyKey, idempotencyKey)));
    if (prior) return c.json({ ...(await priorResults(c, prior.id)), replayed: true });
  }

  const body = await c.req.json<{ messages?: unknown; tag?: unknown }>().catch(() => null);
  if (!body || !Array.isArray(body.messages) || body.messages.length === 0) {
    return c.json({ error: "messages must be a non-empty array" }, 400);
  }
  if (body.messages.length > RESEND_BATCH_LIMIT) {
    return c.json({ error: `At most ${RESEND_BATCH_LIMIT} messages per request` }, 400);
  }
  if (body.tag !== undefined && (typeof body.tag !== "string" || !body.tag.trim() || body.tag.length > 100)) {
    return c.json({ error: "tag must be a short string (max 100)" }, 400);
  }
  const errors: Array<{ index: number; error: string }> = [];
  const messages: Message[] = [];
  const seen = new Set<string>();
  body.messages.forEach((raw, index) => {
    const m = readMessage(raw as Input);
    if (typeof m === "string") return errors.push({ index, error: m });
    const key = m.to.toLowerCase();
    if (seen.has(key)) return errors.push({ index, error: "the same address appears twice in this request" });
    seen.add(key);
    messages.push(m);
  });
  if (errors.length) return c.json({ error: "Some messages are invalid; nothing was sent", errors }, 400);
  if (!isEmailConfigured(c.env) || !c.env.EMAIL_UNSUBSCRIBE_SECRET) {
    return c.json({ error: "Email sending is not configured" }, 503);
  }

  // Only active users of this org can receive; their unsubscribe choice is honoured.
  const people = await db
    .select({
      userId: users.id,
      email: users.email,
      unsubscribed: sql<boolean>`${emailUnsubscribes.userId} is not null`,
    })
    .from(users)
    .leftJoin(emailUnsubscribes, and(eq(emailUnsubscribes.userId, users.id), eq(emailUnsubscribes.category, ANNOUNCEMENTS)))
    .where(and(eq(users.orgId, orgId), eq(users.isActive, true), inArray(sql`lower(${users.email})`, [...seen])));
  const byEmail = new Map(people.map((p) => [p.email.toLowerCase(), p]));

  const deliverable = messages.filter((m) => byEmail.get(m.to.toLowerCase())?.unsubscribed === false).length;
  const used = await dailyUsage(db, orgId);
  if (used + deliverable > DAILY_ORG_LIMIT) {
    return c.json(
      {
        error: `This needs ${deliverable} emails, but only ${Math.max(0, DAILY_ORG_LIMIT - used)} of the ${DAILY_ORG_LIMIT} daily limit are left; nothing was sent`,
        usage: { used, limit: DAILY_ORG_LIMIT },
      },
      429
    );
  }

  const now = new Date();
  const tag = typeof body.tag === "string" ? body.tag.trim() : null;
  let campaign: { id: string };
  try {
    [campaign] = await db
      .insert(emailCampaigns)
      .values({
        orgId,
        source: "api",
        apiKeyId: auth.keyId,
        idempotencyKey,
        category: ANNOUNCEMENTS,
        subject: (tag ?? messages[0].subject).slice(0, 255),
        bodyMarkdown: "",
        audience: { type: "users", userIds: people.map((p) => p.userId) },
        status: "sending",
        recipientCount: deliverable,
        createdBy: auth.createdBy,
        createdAt: now,
        updatedAt: now,
      })
      .returning({ id: emailCampaigns.id });
  } catch (err) {
    // Same Idempotency-Key sent twice at once: the other request is handling it.
    if (idempotencyKey && String(err).includes("email_campaigns_api_idempotency_idx")) {
      return c.json({ error: "A request with this Idempotency-Key is already in progress" }, 409);
    }
    throw err;
  }

  const results: Result[] = [];
  const outgoing: Array<{ index: number; message: Message; userId: string }> = [];
  messages.forEach((m, index) => {
    const person = byEmail.get(m.to.toLowerCase());
    if (!person) results.push({ index, to: m.to, status: "rejected", error: "Not an active user of this organization" });
    else if (person.unsubscribed) results.push({ index, to: m.to, status: "skipped", error: "Unsubscribed" });
    else outgoing.push({ index, message: m, userId: person.userId });
  });
  const skipped = results.filter((r) => r.status === "skipped");
  const rows = [
    ...outgoing.map((o) => ({ campaignId: campaign.id, userId: o.userId, email: o.message.to, subject: o.message.subject, status: "pending" })),
    ...skipped.map((r) => ({
      campaignId: campaign.id,
      userId: byEmail.get(r.to.toLowerCase())!.userId,
      email: r.to,
      subject: messages[r.index].subject,
      status: "skipped",
      error: "Unsubscribed",
    })),
  ];
  if (rows.length) await db.insert(emailSends).values(rows);

  if (outgoing.length) {
    const [org] = await db.select({ name: organizations.name }).from(organizations).where(eq(organizations.id, orgId));
    const orgName = org?.name ?? "Your organization";
    const from = fromAddress(c.env, orgName);
    const batch: EmailMessage[] = await Promise.all(
      outgoing.map(async ({ message: m, userId }) => {
        const url = unsubscribeUrl(c.env, await signUnsubscribeToken(c.env, userId, ANNOUNCEMENTS));
        return {
          from,
          to: [m.to],
          subject: m.subject,
          html: buildEmailHtml(m.html !== undefined ? { orgName, bodyHtml: m.html, unsubscribeUrl: url } : { orgName, bodyMarkdown: m.markdown, unsubscribeUrl: url }),
          ...(m.text ? { text: m.text } : {}),
          replyTo: m.replyTo ?? auth.creatorEmail,
          headers: unsubscribeHeaders(url),
          tags: [{ name: "campaign", value: campaign.id }],
        };
      })
    );
    const sent = await sendEmailBatch(c.env, batch, `api-${campaign.id}`);
    outgoing.forEach((o, i) =>
      results.push(
        sent.success
          ? { index: o.index, to: o.message.to, status: "sent", id: sent.ids?.[i] }
          : { index: o.index, to: o.message.to, status: "failed", error: sent.error ?? "Send failed" }
      )
    );
    await db
      .update(emailSends)
      .set(sent.success ? { status: "sent", sentAt: new Date() } : { status: "failed", error: sent.error ?? "Send failed" })
      .where(and(eq(emailSends.campaignId, campaign.id), eq(emailSends.status, "pending")));
    if (sent.success && sent.ids?.length) {
      const values = sql.join(
        outgoing.map((o, i) => sql`(${o.message.to}, ${sent.ids![i] ?? null})`),
        sql`, `
      );
      await db.execute(sql`
        update ${emailSends} set resend_id = v.rid from (values ${values}) as v(email, rid)
        where ${emailSends.campaignId} = ${campaign.id} and ${emailSends.email} = v.email`);
    }
  }

  const sentCount = results.filter((r) => r.status === "sent").length;
  const failedCount = results.filter((r) => r.status === "failed").length;
  await db
    .update(emailCampaigns)
    .set({
      status: sentCount === 0 && failedCount > 0 ? "failed" : "sent",
      sentCount,
      failedCount,
      sentAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(emailCampaigns.id, campaign.id));

  results.sort((a, b) => a.index - b.index);
  return c.json({ requestId: campaign.id, results, usage: { used: used + sentCount, limit: DAILY_ORG_LIMIT } });
});

/** A repeated Idempotency-Key gets what was recorded the first time (rejected addresses aren't recorded; pending = still sending). */
async function priorResults(c: { get: (k: "db") => AppVariables["db"] }, campaignId: string) {
  const db = c.get("db");
  const rows = await db
    .select({ email: emailSends.email, status: emailSends.status, resendId: emailSends.resendId, error: emailSends.error })
    .from(emailSends)
    .where(eq(emailSends.campaignId, campaignId));
  return {
    requestId: campaignId,
    results: rows.map((r) => ({
      to: r.email,
      status: r.status,
      ...(r.resendId ? { id: r.resendId } : {}),
      ...(r.error ? { error: r.error } : {}),
    })),
  };
}

export default emailMessages;
