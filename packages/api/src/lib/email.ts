/**
 * Sends email through Resend: one at a time, or in batches of up to 100.
 * Also signs the one-click unsubscribe links every announcement carries.
 */
import type { Env } from "../types";
import { senderAllowed } from "./email-layout";

const RESEND_URL = "https://api.resend.com/emails";
const RESEND_BATCH_URL = "https://api.resend.com/emails/batch";
export const RESEND_BATCH_LIMIT = 100;
const MAX_ATTEMPTS = 3;

export interface EmailMessage {
  from: string;
  to: string[];
  subject: string;
  html: string;
  text?: string;
  replyTo?: string;
  headers?: Record<string, string>;
  tags?: Array<{ name: string; value: string }>;
  /** Resend downloads each `path` (a URL) itself. Not allowed in batch sends. */
  attachments?: Array<{ filename: string; path: string }>;
}

export interface SendResult {
  success: boolean;
  /** Resend ids, one per message, in input order. */
  ids?: string[];
  error?: string;
  /** No RESEND_API_KEY on this worker; nothing was sent. */
  notConfigured?: boolean;
  /** Resend refused the request as invalid (400/422), e.g. a bad address. */
  validation?: boolean;
}

export function isEmailConfigured(env: Env): boolean {
  return Boolean(env.RESEND_API_KEY);
}

/**
 * The From header. Default: "<org> via Superatom AI <EMAIL_FROM>". An org's own sender name and
 * address are used as given, the address only while it's still in the allowed list.
 */
export function fromAddress(
  env: Env,
  displayName?: string,
  sender?: { senderName: string | null; senderEmail: string | null; resendKeyEnc?: string | null; senderDomains?: unknown } | null
): string {
  const fallback = env.EMAIL_FROM || "updates@superatom.ai";
  const own = sender?.senderEmail?.trim().toLowerCase();
  const address = own && senderAllowed(env, own, sender) ? own : fallback;
  const name = (
    sender?.senderName?.trim() || (displayName ? `${displayName} via Superatom AI` : "Superatom AI")
  ).replace(/["<>\r\n]/g, "");
  return `"${name}" <${address}>`;
}

/** `apiKey` = an org's own Resend key; default the platform's. */
export async function sendEmail(env: Env, message: EmailMessage, idempotencyKey?: string, apiKey?: string): Promise<SendResult> {
  if (!message.to.length) return { success: false, error: "No recipients specified" };
  return post(env, RESEND_URL, toResend(message), idempotencyKey, apiKey);
}

/** One Resend call for up to 100 messages; all-or-nothing on Resend's side. */
export async function sendEmailBatch(env: Env, messages: EmailMessage[], idempotencyKey?: string, apiKey?: string): Promise<SendResult> {
  if (!messages.length) return { success: true, ids: [] };
  if (messages.some((m) => m.attachments?.length)) {
    return { success: false, error: "Resend batch sends don't support attachments" };
  }
  if (messages.length > RESEND_BATCH_LIMIT) {
    return { success: false, error: `Batch exceeds ${RESEND_BATCH_LIMIT} messages` };
  }
  return post(env, RESEND_BATCH_URL, messages.map(toResend), idempotencyKey, apiKey);
}

/** One outcome per message: a Resend id, or why it failed. */
export type MessageResult = { id?: string; error?: string };

// Reserved for docs/tests (RFC 2606/6761); Resend rejects them, and with them the whole batch.
const PLACEHOLDER_DOMAIN = /@(example\.(com|net|org)|[^@]*\.(test|example|invalid|localhost))$/i;

export function isPlaceholderAddress(email: string): boolean {
  return PLACEHOLDER_DOMAIN.test(email.trim());
}

/**
 * Batch send with per-message results. Placeholder addresses fail without a call. If Resend
 * rejects the batch as invalid (one bad address fails all), each message is sent on its own.
 */
export async function sendEmailsEach(
  env: Env,
  messages: EmailMessage[],
  idempotencyKey: string,
  apiKey?: string,
  intervalMs = 250
): Promise<MessageResult[]> {
  const results: MessageResult[] = messages.map((m) =>
    m.to.some(isPlaceholderAddress) ? { error: "Placeholder address (e.g. example.com): not deliverable" } : {}
  );
  const live = messages.flatMap((_, i) => (results[i].error ? [] : [i]));
  if (!live.length) return results;

  const batch = await sendEmailBatch(env, live.map((i) => messages[i]), idempotencyKey, apiKey);
  if (batch.success) {
    live.forEach((i, k) => (results[i] = { id: batch.ids?.[k] }));
    return results;
  }
  if (live.length === 1 || !batch.validation) {
    for (const i of live) results[i] = { error: batch.error ?? "Send failed" };
    return results;
  }
  for (const [k, i] of live.entries()) {
    if (k) await sleep(intervalMs);
    const one = await sendEmail(env, messages[i], `${idempotencyKey}-${i}`, apiKey);
    results[i] = one.success ? { id: one.ids?.[0] } : { error: one.error ?? "Send failed" };
  }
  return results;
}

function toResend(m: EmailMessage) {
  return {
    from: m.from,
    to: m.to,
    subject: m.subject,
    html: m.html,
    ...(m.text ? { text: m.text } : {}),
    ...(m.replyTo ? { reply_to: m.replyTo } : {}),
    ...(m.headers ? { headers: m.headers } : {}),
    ...(m.tags?.length ? { tags: m.tags } : {}),
    ...(m.attachments?.length ? { attachments: m.attachments } : {}),
  };
}

/** POST to Resend, retrying 429 and 5xx with backoff. Idempotency-Key makes the retries safe. */
async function post(env: Env, url: string, payload: unknown, idempotencyKey?: string, apiKey?: string): Promise<SendResult> {
  const key = apiKey ?? env.RESEND_API_KEY;
  if (!key) {
    return { success: false, notConfigured: true, error: "RESEND_API_KEY not configured" };
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
  };
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const body = JSON.stringify(payload);

  let lastError = "";
  let validation = false;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(url, { method: "POST", headers, body });
      if (res.ok) {
        const data = (await res.json().catch(() => ({}))) as { id?: string; data?: Array<{ id: string }> };
        const ids = data.data ? data.data.map((d) => d.id) : data.id ? [data.id] : [];
        return { success: true, ids };
      }
      const text = await res.text().catch(() => "");
      lastError = `Resend API error: ${res.status}${text ? ` - ${text.slice(0, 300)}` : ""}`;
      validation = res.status === 400 || res.status === 422;
      if (!(res.status === 429 || res.status >= 500) || attempt === MAX_ATTEMPTS) break;
      const retryAfter = Number(res.headers.get("retry-after"));
      await sleep(retryAfter > 0 ? retryAfter * 1000 : 500 * 2 ** (attempt - 1));
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(500 * 2 ** (attempt - 1));
    }
  }
  console.error("[email] send failed:", lastError);
  return { success: false, error: lastError, ...(validation ? { validation } : {}) };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Unsubscribe links ───────────────────────────────────
// Token = base64url(userId.category).base64url(HMAC); no expiry, so old emails keep working.

export async function signUnsubscribeToken(env: Env, userId: string, category: string): Promise<string> {
  const payload = b64url(new TextEncoder().encode(`${userId}.${category}`));
  return `${payload}.${await hmac(env, payload)}`;
}

export async function verifyUnsubscribeToken(
  env: Env,
  token: string
): Promise<{ userId: string; category: string } | null> {
  const [payload, sig] = token.split(".");
  if (!payload || !sig || !env.EMAIL_UNSUBSCRIBE_SECRET) return null;
  if (!timingSafeEqual(sig, await hmac(env, payload))) return null;
  const [userId, category] = new TextDecoder().decode(fromB64url(payload)).split(".");
  return userId && category ? { userId, category } : null;
}

/** RFC 8058 one-click headers; Gmail and Yahoo require them for bulk senders. */
export function unsubscribeHeaders(url: string): Record<string, string> {
  return { "List-Unsubscribe": `<${url}>`, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" };
}

async function hmac(env: Env, data: string): Promise<string> {
  if (!env.EMAIL_UNSUBSCRIBE_SECRET) throw new Error("EMAIL_UNSUBSCRIBE_SECRET not configured");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.EMAIL_UNSUBSCRIBE_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data))));
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
