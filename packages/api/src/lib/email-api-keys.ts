/**
 * Org-scoped keys that let a script send email through POST /orgs/:orgId/emails/messages.
 * The full key is shown once at creation; only its SHA-256 is stored.
 */
import { and, eq, isNull } from "drizzle-orm";
import type { Database } from "../db";
import { emailApiKeys, users } from "../db/schema";

const PREFIX = "sa_email_";

export function generateEmailApiKey(): { key: string; keyPrefix: string } {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  const key = PREFIX + btoa(s).replace(/\+/g, "-").replace(/\//g, "_");
  return { key, keyPrefix: key.slice(0, PREFIX.length + 4) };
}

export async function hashEmailApiKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export type EmailKeyAuth =
  | { ok: true; keyId: string; orgId: string; createdBy: string; creatorEmail: string }
  | { ok: false; status: 401 | 403; error: string };

/** A live key of this org, whose creator is still an active admin of it. */
export async function authenticateEmailKey(db: Database, header: string | undefined, orgId: string): Promise<EmailKeyAuth> {
  const key = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!key.startsWith(PREFIX)) return { ok: false, status: 401, error: "Missing or invalid email API key" };
  const [row] = await db
    .select({
      id: emailApiKeys.id,
      orgId: emailApiKeys.orgId,
      createdBy: emailApiKeys.createdBy,
      creatorEmail: users.email,
      creatorOrg: users.orgId,
      creatorRole: users.role,
      creatorActive: users.isActive,
    })
    .from(emailApiKeys)
    .leftJoin(users, eq(users.id, emailApiKeys.createdBy))
    .where(and(eq(emailApiKeys.keyHash, await hashEmailApiKey(key)), isNull(emailApiKeys.revokedAt)));
  if (!row) return { ok: false, status: 401, error: "Missing or invalid email API key" };
  if (row.orgId !== orgId) return { ok: false, status: 403, error: "This key belongs to another organization" };
  if (!row.createdBy || !row.creatorActive || row.creatorOrg !== orgId || row.creatorRole !== "org_admin") {
    return { ok: false, status: 403, error: "The admin who created this key no longer has access; create a new key" };
  }
  return { ok: true, keyId: row.id, orgId, createdBy: row.createdBy, creatorEmail: row.creatorEmail! };
}
