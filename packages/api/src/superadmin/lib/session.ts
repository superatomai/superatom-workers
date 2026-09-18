import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { SignJWT, jwtVerify } from "jose";

// Sent as `__Host-sa_superadmin`: Secure, Path=/, no Domain — only the super-admin host sees it.
const COOKIE_NAME = "sa_superadmin";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const ISSUER = "sa-superadmin";
const AUDIENCE = "sa-superadmin";

function signingKey(secret: string | undefined): Uint8Array {
  // Fail closed: an unset or short secret must never produce accepted tokens.
  if (!secret || secret.length < 32) {
    throw new Error("SUPERADMIN_JWT_SECRET is not configured (min 32 chars)");
  }
  return new TextEncoder().encode(secret);
}

export async function signSession(adminId: string, secret: string | undefined): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(adminId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(signingKey(secret));
}

/** Returns the admin id and issue time (seconds), or null if the token is invalid or expired. */
export async function verifySession(
  token: string,
  secret: string | undefined
): Promise<{ adminId: string; issuedAt: number } | null> {
  const key = signingKey(secret);
  try {
    const { payload } = await jwtVerify(token, key, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["HS256"],
    });
    if (typeof payload.sub !== "string" || typeof payload.iat !== "number") return null;
    return { adminId: payload.sub, issuedAt: payload.iat };
  } catch {
    return null;
  }
}

export function readSessionCookie(c: Context): string | undefined {
  return getCookie(c, COOKIE_NAME, "host");
}

export function setSessionCookie(c: Context, token: string): void {
  setCookie(c, COOKIE_NAME, token, {
    prefix: "host",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export function clearSessionCookie(c: Context): void {
  deleteCookie(c, COOKIE_NAME, { prefix: "host", secure: true, path: "/" });
}

/**
 * Value for `tokens_valid_after` that revokes every session issued so far.
 * Floored to the second because JWT `iat` is; a session issued afterwards stays valid.
 */
export function revocationCutoff(): Date {
  return new Date(Math.floor(Date.now() / 1000) * 1000);
}
