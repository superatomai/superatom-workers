/**
 * Sends email through Resend: one at a time, or in batches of up to 100.
 * Also signs the one-click unsubscribe links every announcement carries.
 */
import type { Env } from "../types";

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
}

export interface SendResult {
  success: boolean;
  /** Resend ids, one per message, in input order. */
  ids?: string[];
  error?: string;
  /** No RESEND_API_KEY on this worker; nothing was sent. */
  notConfigured?: boolean;
}

export function isEmailConfigured(env: Env): boolean {
  return Boolean(env.RESEND_API_KEY);
}

/** The From header: "<name> via Superatom <EMAIL_FROM>". */
export function fromAddress(env: Env, displayName?: string): string {
  const address = env.EMAIL_FROM || "updates@superatom.ai";
  const name = (displayName ? `${displayName} via Superatom` : "Superatom").replace(/["<>]/g, "");
  return `"${name}" <${address}>`;
}

export async function sendEmail(env: Env, message: EmailMessage, idempotencyKey?: string): Promise<SendResult> {
  if (!message.to.length) return { success: false, error: "No recipients specified" };
  return post(env, RESEND_URL, toResend(message), idempotencyKey);
}

/** One Resend call for up to 100 messages; all-or-nothing on Resend's side. */
export async function sendEmailBatch(env: Env, messages: EmailMessage[], idempotencyKey?: string): Promise<SendResult> {
  if (!messages.length) return { success: true, ids: [] };
  if (messages.length > RESEND_BATCH_LIMIT) {
    return { success: false, error: `Batch exceeds ${RESEND_BATCH_LIMIT} messages` };
  }
  return post(env, RESEND_BATCH_URL, messages.map(toResend), idempotencyKey);
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
  };
}

/** POST to Resend, retrying 429 and 5xx with backoff. Idempotency-Key makes the retries safe. */
async function post(env: Env, url: string, payload: unknown, idempotencyKey?: string): Promise<SendResult> {
  if (!env.RESEND_API_KEY) {
    return { success: false, notConfigured: true, error: "RESEND_API_KEY not configured" };
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${env.RESEND_API_KEY}`,
    "Content-Type": "application/json",
  };
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const body = JSON.stringify(payload);

  let lastError = "";
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
  return { success: false, error: lastError };
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
