/**
 * Access token minting — one definition, used by all three login paths
 * (password, OIDC, SAML).
 *
 * Previously each path had its own `SignJWT(...).setExpirationTime(...)` chain,
 * which is how they all ended up at 180 days and had to be changed in three
 * places. Centralising means the lifetime cannot drift between them.
 */

import { SignJWT } from "jose";
import { getOrgSecret, MissingOrgSecretError } from "./org-secrets";

/**
 * 15 minutes. Short because the token is a bearer credential that travels in
 * URLs — the WebSocket handshake query string and the SSO callback — and can
 * therefore reach access logs and browser history. The refresh cookie carries
 * the long-lived session instead, out of reach of JavaScript.
 */
export const ACCESS_TOKEN_TTL = "15m";

/**
 * Signed with the user's org secret from the JWT_SECRETS KV namespace
 * (super_admin: the __global secret) — see lib/org-secrets.ts. Throws
 * MissingOrgSecretError if the org has none; callers must report that as a
 * server fault (503), not as bad credentials.
 *
 * `sessionId` is the refresh-token family the token belongs to, carried as the
 * `sid` claim. It lets logout end one session: verifiers reject a token whose
 * family has been revoked (see sessionAliveSql). Every login and refresh passes
 * one; the parameter is optional only for type-compatibility.
 *
 * `src: "sdk"` marks a token issued by the SDK exchange (routes/sdk-auth.ts).
 * Verifiers treat such a session as a `member` whatever the user's role in the
 * database, so a customer-signed sign-in can never reach admin actions. The claim
 * is ours: it is signed with `org:<orgId>`, which the customer does not hold.
 *
 * `access` rides along as a claim of the same name for SDK sign-ins. The customer
 * states the user's data access on every sign-in, so the session should use what
 * they sent rather than what we happen to have stored; the relay prefers this
 * claim and falls back to `users.config` when it is absent. It is trustworthy for the
 * same reason `src` is — signed with our key, not theirs — and for the same
 * reason it must never be read from anything travelling beside the token.
 *
 * Callers cap its size before passing it: the token goes in the WebSocket
 * handshake URL, and a large claim would push that past what proxies accept.
 */
export async function mintAccessToken(
  user: { id: string; orgId: string | null; role: string },
  jwtSecrets: KVNamespace,
  sessionId?: string,
  src?: "sdk",
  access?: unknown
): Promise<string> {
  const secret = await getOrgSecret(jwtSecrets, user.orgId);
  if (!secret) throw new MissingOrgSecretError(user.orgId);

  return new SignJWT({
    userId: user.id,
    orgId: user.orgId,
    role: user.role,
    ...(sessionId ? { sid: sessionId } : {}),
    ...(src ? { src } : {}),
    ...(access != null ? { access } : {}),
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .sign(secret);
}
