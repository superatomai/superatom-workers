/**
 * Orgs can require single sign-on for their own email domains (sso_configs.sso_required_domains):
 * those users can't log in with a password, and no password is stored for them. Empty = off.
 */
import { and, eq, inArray } from "drizzle-orm";
import type { Database } from "../db";
import { ssoConfigs } from "../db/schema";

export const SSO_REQUIRED_MESSAGE = "Your organization requires single sign-on. Use “Sign in with SSO”.";

export function emailDomain(email: string): string {
  return email.trim().toLowerCase().split("@").pop() ?? "";
}

/** Whether `email` is in one of the required domains (exact domain match, case-insensitive). */
export function ssoRequiredFor(domains: unknown, email: string): boolean {
  if (!Array.isArray(domains) || !domains.length) return false;
  const domain = emailDomain(email);
  return domains.some((d) => typeof d === "string" && d.trim().toLowerCase() === domain);
}

/** Org ids (of those given) whose active SSO config requires SSO for this email. */
export async function ssoRequiredOrgs(db: Database, orgIds: string[], email: string): Promise<Set<string>> {
  if (!orgIds.length) return new Set();
  const rows = await db
    .select({ orgId: ssoConfigs.orgId, domains: ssoConfigs.ssoRequiredDomains })
    .from(ssoConfigs)
    .where(and(inArray(ssoConfigs.orgId, orgIds), eq(ssoConfigs.isActive, true)));
  return new Set(rows.filter((r) => ssoRequiredFor(r.domains, email)).map((r) => r.orgId));
}

/**
 * Login: drop the matches whose org requires SSO for this email. `ssoRequired` = every match
 * was dropped, so the caller should point the user to SSO rather than say "wrong password".
 */
export function passwordLoginUsers<T extends { orgId: string | null }>(
  matched: T[],
  ssoOrgs: Set<string>
): { users: T[]; ssoRequired: boolean } {
  const users = matched.filter((u) => !(u.orgId && ssoOrgs.has(u.orgId)));
  return { users, ssoRequired: matched.length > 0 && users.length === 0 };
}

export async function orgRequiresSso(db: Database, orgId: string, email: string): Promise<boolean> {
  return (await ssoRequiredOrgs(db, [orgId], email)).has(orgId);
}
