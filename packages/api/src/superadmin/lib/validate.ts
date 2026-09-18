// Org slugs become subdomains (<slug>.superatom.ai, <slug>.platform.superatom.ai).
const SLUG = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const RESERVED_ORG_SLUGS = new Set([
  "www", "app", "dashboard", "dev", "live", "platform", "superadmin",
  "admin", "api", "sa-api", "ws", "analytics",
]);
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string | undefined): value is string {
  return typeof value === "string" && UUID.test(value);
}

/** Trimmed non-empty string up to `max` chars, or null. */
export function cleanName(value: unknown, max = 255): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= max ? trimmed : null;
}

export function cleanEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return EMAIL.test(email) && email.length <= 255 ? email : null;
}

export function orgSlugError(slug: unknown): string | null {
  if (typeof slug !== "string" || !SLUG.test(slug) || slug.length > 63) {
    return "Slug must be 1–63 lowercase letters, digits or hyphens, not starting or ending with a hyphen.";
  }
  if (RESERVED_ORG_SLUGS.has(slug)) return `"${slug}" is reserved.`;
  return null;
}

export function projectSlugError(slug: unknown): string | null {
  if (typeof slug !== "string" || !SLUG.test(slug) || slug.length > 100) {
    return "Slug must be 1–100 lowercase letters, digits or hyphens, not starting or ending with a hyphen.";
  }
  return null;
}

/** Postgres unique-constraint violation, however the driver wraps it. */
export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string } } | null;
  return e?.code === "23505" || e?.cause?.code === "23505";
}

/**
 * Org-user password hash. MUST match what sa-api's /auth/login compares against
 * (unsalted SHA-256 hex) or the org admin can't sign in to the Platform UI.
 */
export async function orgUserPasswordHash(password: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
