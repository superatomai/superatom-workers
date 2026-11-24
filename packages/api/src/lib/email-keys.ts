/**
 * An org's own Resend API key: its emails are sent (and billed) through its own Resend account.
 * Stored AES-GCM encrypted with EMAIL_KEYS_SECRET; only the last 4 characters are ever shown.
 */
import type { Env } from "../types";

const RESEND_DOMAINS_URL = "https://api.resend.com/domains";
export const RESEND_KEY_FORMAT = /^re_[A-Za-z0-9_]{10,200}$/;

async function aesKey(env: Pick<Env, "EMAIL_KEYS_SECRET">): Promise<CryptoKey> {
  if (!env.EMAIL_KEYS_SECRET) throw new Error("EMAIL_KEYS_SECRET is not configured");
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env.EMAIL_KEYS_SECRET));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** "v1:<iv>:<ciphertext>", base64. */
export async function encryptKey(env: Pick<Env, "EMAIL_KEYS_SECRET">, plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), new TextEncoder().encode(plain));
  return `v1:${b64(iv)}:${b64(new Uint8Array(ct))}`;
}

export async function decryptKey(env: Pick<Env, "EMAIL_KEYS_SECRET">, stored: string): Promise<string> {
  const [v, iv, ct] = stored.split(":");
  if (v !== "v1" || !iv || !ct) throw new Error("Unknown key format");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return new TextDecoder().decode(pt);
}

/**
 * Asks Resend which domains the key's account has verified. A sending-only key can't list
 * domains: it's accepted with domains = null (unknown), and Resend itself rejects a bad sender.
 */
export async function checkResendKey(
  apiKey: string,
  fetcher: typeof fetch = fetch
): Promise<{ ok: true; domains: string[] | null } | { ok: false; error: string }> {
  let res: Response;
  try {
    res = await fetcher(RESEND_DOMAINS_URL, { headers: { Authorization: `Bearer ${apiKey}` } });
  } catch {
    return { ok: false, error: "Couldn't reach Resend to check the key; try again" };
  }
  const body = (await res.json().catch(() => ({}))) as { name?: string; message?: string; data?: Array<{ name: string; status: string }> };
  if (res.ok) {
    const domains = (body.data ?? []).filter((d) => d.status === "verified").map((d) => d.name.toLowerCase());
    return { ok: true, domains };
  }
  if (body.name === "restricted_api_key") return { ok: true, domains: null };
  return { ok: false, error: `Resend rejected the key${body.message ? `: ${body.message}` : ""}` };
}

export interface OrgKeyFields {
  resendKeyEnc: string | null;
}

/** The key an org's emails go out with: its own, or the platform's. A broken own key is an error, never a fallback. */
export async function orgResendKey(
  env: Env,
  branding: OrgKeyFields | null
): Promise<{ ok: true; apiKey: string | undefined; own: boolean } | { ok: false; error: string }> {
  if (!branding?.resendKeyEnc) return { ok: true, apiKey: env.RESEND_API_KEY, own: false };
  try {
    return { ok: true, apiKey: await decryptKey(env, branding.resendKeyEnc), own: true };
  } catch {
    return { ok: false, error: "This organization's Resend key can't be read; enter it again under Emails → Branding" };
  }
}
