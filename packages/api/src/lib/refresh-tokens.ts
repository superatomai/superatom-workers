/**
 * Rotating refresh tokens with reuse detection.
 *
 * Access tokens are short-lived and stateless. Refreshing them needs server
 * state because a stateless token cannot be revoked, so each refresh token is a
 * row: presenting one consumes it and issues a replacement in the same family.
 *
 * The token is opaque, not a JWT: `<rowId>.<secret>`. The id makes lookup a
 * primary-key hit rather than a table scan, and only the SHA-256 of the secret
 * is stored, so a database leak yields no usable tokens.
 */

import { eq, and, isNull, gt, ne } from "drizzle-orm";
import { refreshTokens } from "../db/schema";

/** 30 days. Long-lived by design — the ACCESS token is the short one. */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Grace period after rotation during which the old token is still accepted.
 *
 * Without this, two browser tabs refreshing at the same moment would have the
 * second one look like a stolen token, trip reuse detection, and sign the user
 * out everywhere. That is the classic way refresh rotation ships broken. A short
 * window costs little — the token is already single-use past 60 seconds — and it
 * needs no cross-tab coordination in the client.
 */
const ROTATION_GRACE_MS = 60 * 1000;

export type RotateResult =
  | { ok: true; userId: string; token: string; familyId: string }
  | { ok: false; reason: "invalid" | "expired" | "revoked" | "reuse_detected" };

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Length-independent comparison, so a mismatch position is not observable. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Mint a refresh token. Omit `familyId` to start a new family (a fresh login);
 * pass one to continue an existing chain (a rotation).
 */
export async function issueRefreshToken(
  db: any,
  userId: string,
  options: { familyId?: string; userAgent?: string | null } = {}
): Promise<{ token: string; id: string; familyId: string }> {
  const secret = randomSecret();
  const familyId = options.familyId ?? crypto.randomUUID();

  const [row] = await db
    .insert(refreshTokens)
    .values({
      userId,
      familyId,
      tokenHash: await sha256Hex(secret),
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
      userAgent: options.userAgent?.slice(0, 500) ?? null,
    })
    .returning({ id: refreshTokens.id });

  return { token: `${row.id}.${secret}`, id: row.id, familyId };
}

/**
 * Revoke every unrevoked token in a family — one session. Used on reuse
 * detection and on logout. Access tokens carrying that family as `sid` stop
 * verifying at once (see middleware/auth.ts and the relay's session check).
 */
export async function revokeFamily(db: any, familyId: string): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.familyId, familyId), isNull(refreshTokens.revokedAt)));
}

/** Revoke every session for a user — used on logout. */
export async function revokeAllForUser(db: any, userId: string): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)));
}

/**
 * Decide what an already-rotated token presented past the grace window means.
 *
 * Two very different events look identical at first: the browser never got the
 * replacement (a refresh response lost to sleep, a closed lid, a network drop)
 * and replays the old token; or a second party holds a copy. Treating every
 * replay as theft signed users out of every app whenever a refresh response
 * went missing — the most common cause of "logged out after my laptop slept".
 *
 * It is a lost response only when BOTH hold:
 *  - nothing in the family has been used since this token was rotated — so no
 *    one has moved on with the replacement or anything after it; and
 *  - it comes from the browser the token was issued to (same User-Agent).
 *
 * The User-Agent check keeps detection for the case "unused replacement" alone
 * would miss: a stolen token replayed from another browser before the real user
 * refreshes again. A thief on an identical browser in that window gets through;
 * that is the price of not logging real users out.
 */
async function isLostResponse(
  db: any,
  row: { id: string; familyId: string; rotatedAt: Date | string; userAgent: string | null },
  userAgent: string | null | undefined
): Promise<boolean> {
  const presentedUa = userAgent?.slice(0, 500) ?? null;
  if (!row.userAgent || row.userAgent !== presentedUa) return false;

  const [usedSince] = await db
    .select({ id: refreshTokens.id })
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.familyId, row.familyId),
        gt(refreshTokens.rotatedAt, new Date(row.rotatedAt)),
        ne(refreshTokens.id, row.id)
      )
    )
    .limit(1);

  return !usedSince;
}

/**
 * Validate a refresh token and exchange it for a new one.
 *
 * An already-rotated token presented again is accepted within the grace window
 * (concurrent tabs) or when it is a lost response (see isLostResponse);
 * otherwise it returns `reuse_detected`: two parties hold it, so the entire
 * family is revoked and everyone re-authenticates. This does not prevent theft —
 * it makes theft self-limiting and detectable, which a long-lived bearer token
 * never is.
 */
export async function rotateRefreshToken(
  db: any,
  rawToken: string,
  userAgent?: string | null
): Promise<RotateResult> {
  const separator = rawToken.indexOf(".");
  if (separator <= 0) return { ok: false, reason: "invalid" };

  const id = rawToken.slice(0, separator);
  const secret = rawToken.slice(separator + 1);
  if (!id || !secret) return { ok: false, reason: "invalid" };

  let row: any;
  try {
    [row] = await db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.id, id))
      .limit(1);
  } catch {
    // A malformed id is not a valid UUID and Postgres rejects the comparison.
    return { ok: false, reason: "invalid" };
  }

  if (!row) return { ok: false, reason: "invalid" };

  // Compare before any other check so a wrong secret cannot probe token state.
  if (!timingSafeEqual(await sha256Hex(secret), row.tokenHash)) {
    return { ok: false, reason: "invalid" };
  }

  if (row.revokedAt) return { ok: false, reason: "revoked" };
  if (new Date(row.expiresAt).getTime() <= Date.now()) {
    return { ok: false, reason: "expired" };
  }

  if (row.rotatedAt) {
    const since = Date.now() - new Date(row.rotatedAt).getTime();
    if (since > ROTATION_GRACE_MS) {
      if (!(await isLostResponse(db, row, userAgent))) {
        await revokeFamily(db, row.familyId);
        console.warn(
          `[auth] refresh token reuse detected: user=${row.userId} family=${row.familyId} — family revoked`
        );
        return { ok: false, reason: "reuse_detected" };
      }
      // The browser never received the replacement. Issue another token in the
      // same family, exactly as for a concurrent tab.
      console.warn(
        `[auth] refresh token replayed after a lost response: user=${row.userId} family=${row.familyId} ` +
          `rotated ${Math.round(since / 1000)}s ago — reissued`
      );
    }
    // Inside the grace window: a concurrent tab, not an attacker. Fall through
    // and issue another token in the same family rather than revoking.
  }

  const next = await issueRefreshToken(db, row.userId, {
    familyId: row.familyId,
    userAgent,
  });

  // rotated_at records the FIRST rotation only. Overwriting it on every replay
  // would restart the grace window each time and move the point that
  // isLostResponse measures "used since" from.
  await db
    .update(refreshTokens)
    .set({ rotatedAt: row.rotatedAt ?? new Date(), replacedById: next.id })
    .where(eq(refreshTokens.id, row.id));

  return { ok: true, userId: row.userId, token: next.token, familyId: row.familyId };
}
