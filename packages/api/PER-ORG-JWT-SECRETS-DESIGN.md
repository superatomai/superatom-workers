# Per-Org JWT Signing Secrets — Design

Status: **implemented on `feat/per-org-jwt-secrets`, dev tomls only** (2026-09-18). Author: platform. Reviewers: TBD.

Replaces the single `JWT_SECRET` that signs every access token with **one secret per
organization**, stored in Workers KV and shared by both workers that verify tokens
(`sa-api` and `sa-websocket`).

## 1. Why

Today every access token, for every org, is signed and verified with one `JWT_SECRET`
worker secret. Anyone who obtains it can mint a valid token for **any user in any org**,
including super_admin, and the only remedy is changing it, which invalidates every session
on the platform at once.

With a secret per org:

- a leaked org secret can only forge tokens for **that org's** users (enforced by §3.4);
- an org's secret can be changed without affecting any other org;
- super_admin tokens get their own secret, shared with no org.

## 2. Scope

**In scope:** the 15-minute access token (the JWT the SDK/runtime sends as `?token=` and
`Authorization: Bearer`) — where it is signed and everywhere it is verified.

**Out of scope, unchanged:**

- **Refresh tokens** — opaque `<rowId>.<secret>` values in `refresh_tokens`, not signed.
- **SSO/SAML state tokens** (`createStateToken`, `createSamlStateToken`, SAML RelayState) —
  short-lived tokens the API signs for itself across the IdP redirect. They stay on `JWT_SECRET`.
- **Clients** (runtime-react, sa-platform-ui, application SDK) and fusion-5 — they only decode
  the payload or trust the relay's stamped identity; none verify signatures.

## 3. Design

### 3.1 Storage — one KV entry per org

```
KV namespace JWT_SECRETS
  org:<orgId>      → <secret>     one per organization
  org:__global     → <secret>     super_admin (orgId = null)
```

- **Existing orgs:** seeded by hand with today's `JWT_SECRET` value (§5 step 2), so tokens in
  flight at deploy time keep verifying.
- **New orgs:** a freshly generated secret (32 random bytes, hex → 64 chars).
- **super_admin:** `org:__global`, seeded like the existing orgs with today's `JWT_SECRET`, so
  super_admin sessions are unaffected by the rollout. Follow-up: give it a distinct secret —
  super_admin tokens reach every org and project, so they should not be forgeable with any
  org's secret. Changing it later only costs super_admins one silent token refresh.
- **Secrets are plain strings**, used exactly as `JWT_SECRET` is today:
  `new TextEncoder().encode(secret)`. An existing org's entry must therefore be byte-identical
  to the current `JWT_SECRET`.
- **Prod and dev use separate namespaces** — they already have separate databases and
  separate `JWT_SECRET` values. Each namespace is bound to that environment's `sa-api` and
  `sa-websocket` workers (same namespace id in both tomls).

There is no current/previous key and no `kid` header: the key is chosen by the token's
`orgId` claim.

### 3.2 Key lookup — `lib/org-secrets.ts`

One small module, present in both workers (`packages/api/src/lib/org-secrets.ts` and
`packages/websocket/src/auth/org-secrets.ts`, the verification half only — same pattern as
`session.ts` mirroring `middleware/auth.ts`). Sketch below; the code is authoritative.

```ts
export const GLOBAL_SECRET_ID = "__global";

/** The KV key for a token's / user's org. null orgId = super_admin. */
export function secretKeyFor(orgId: string | null | undefined): string {
  return `org:${orgId ?? GLOBAL_SECRET_ID}`;
}

// Per-isolate cache so a busy isolate does not hit KV on every request.
const cache = new Map<string, { secret: Uint8Array; until: number }>();
const CACHE_MS = 60_000;

/** Returns the org's signing secret, or null if the org has none. Throws on a KV fault. */
export async function getOrgSecret(kv: KVNamespace, orgId: string | null | undefined) {
  const key = secretKeyFor(orgId);
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.secret;

  const value = await kv.get(key);           // throws on KV fault → caller returns 503
  if (!value) return null;                   // not cached: a missing key must not stick

  const secret = new TextEncoder().encode(value);
  cache.set(key, { secret, until: Date.now() + CACHE_MS });
  return secret;
}

/** Generate and store a secret for a new org. Returns nothing; the secret never leaves KV. */
export async function createOrgSecret(kv: KVNamespace, orgId: string): Promise<void> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  await kv.put(secretKeyFor(orgId), hex);
}
```

### 3.3 Signing — `lib/access-token.ts`

`mintAccessToken` takes the KV binding instead of a secret string and signs with the
user's org secret. Payload is unchanged (`userId`, `orgId`, `role`, `iat`, `exp`).

```ts
export async function mintAccessToken(
  user: { id: string; orgId: string | null; role: string },
  kv: KVNamespace
): Promise<string> {
  const secret = await getOrgSecret(kv, user.orgId);
  if (!secret) throw new MissingOrgSecretError(user.orgId);   // → 503 at the route

  return new SignJWT({ userId: user.id, orgId: user.orgId, role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .sign(secret);
}
```

Call sites:

| Where | Change |
|---|---|
| `routes/auth.ts` — `/login`, `/refresh` | pass `c.env.JWT_SECRETS` |
| `routes/sso.ts:428` | replace the inline `SignJWT` block with `mintAccessToken(user, c.env.JWT_SECRETS)` |
| `routes/saml.ts:349` | same |

A missing secret at login is a configuration error, not a bad password: log
`[auth] no signing secret for org=<id>` and return **503**, never 401.

### 3.4 Verification — the shared rule

Every verifier follows the same four steps:

```ts
// 1. Pick the key from the (not yet trusted) orgId claim.
const claimedOrgId = (decodeJwt(token).orgId as string | null | undefined) ?? null;
const secret = await getOrgSecret(env.JWT_SECRETS, claimedOrgId);   // KV fault → 503
if (!secret) return 401;                                          // unknown org

// 2. Verify signature + expiry. Pin the algorithm.
const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });

// 3. Existing authoritative user lookup (is_active, role, tokens_valid_after, org_id, config).

// 4. Bind the key to the user. THIS IS WHAT MAKES PER-ORG SECRETS WORTH ANYTHING.
if (secretKeyFor(user.orgId) !== secretKeyFor(claimedOrgId)) return 401;
```

Step 4 is required. Without it, a holder of org A's secret could sign
`{ userId: <org B user>, orgId: "<org A>" }`: step 1 picks org A's key, step 2 passes, and the
token would act as the org B user. Comparing the verified claim against the user's **database**
org closes that. The same comparison, with `__global`, confines the super_admin secret to
users whose `org_id` is null.

Where it goes:

| Verifier | Change |
|---|---|
| `api/src/middleware/auth.ts` | steps 1–2 replace the `JWT_SECRET` verify; step 4 added after the existing user lookup. Extract the body into an exported `authenticateRequest(c)` so it can be reused. |
| `api/src/routes/source-upload.ts:294, :336` | the two inline `jwtVerify(JWT_SECRET)` checks call `authenticateRequest(c)` instead. They currently skip the user lookup entirely; they gain it. |
| `websocket/src/auth/session.ts` | steps 1–2 replace the `JWT_SECRET` verify; step 4 added after the `users` query. `verifyBrowserSession` takes `jwtSecrets: KVNamespace` instead of `jwtSecret`. |
| `websocket/src/index.ts` | pass `env.JWT_SECRETS`. |

Error mapping stays as today: bad/expired/forged token → 401; KV or DB fault → 503 (API) /
500 (relay). A KV outage must not look like an expired session, or every client signs out.

### 3.5 Types and bindings

- `api/src/types.ts` — add `JWT_SECRETS: KVNamespace`. Keep `JWT_SECRET` (SSO/SAML state tokens).
- `websocket/src/index.ts` `Env` — `JWT_SECRET` replaced by `JWT_SECRETS: KVNamespace`; this
  worker no longer reads `JWT_SECRET` at all.
- All four tomls (`api/wrangler.toml`, `api/wrangler.dev.toml`, `websocket/wrangler.toml`,
  `websocket/wrangler.dev.toml`):

```toml
[[kv_namespaces]]
binding = "JWT_SECRETS"
id = "<prod or dev namespace id>"
```

## 4. Behaviour and edge cases

- **KV propagation.** A KV write can take up to ~60 s to be visible in every Cloudflare
  location, plus up to 60 s of the per-isolate cache in §3.2. Effects:
  - *New org:* its first logins happen well after the secret is written; no impact.
    `getOrgSecret` does not cache misses, so a lookup before the write cannot stick.
  - *Changing an org's secret:* for up to ~2 min, locations may disagree. A token minted with
    the new secret can be rejected where the old one is still cached; the client refreshes and
    retries. After the window, all locations agree.
- **Changing an org's secret** (`wrangler kv key put org:<id> <new>`) invalidates that org's
  current access tokens. Clients recover on their own: 401 → `/auth/refresh` (refresh tokens
  are not signed, so they still work) → new token signed with the new secret.
- **Deleting an org** should also delete `org:<id>`.
- **super_admin at deploy time.** `org:__global` holds the old shared secret, so existing
  super_admin tokens keep verifying.

## 5. Rollout

Seed KV **before** deploying the code — a missing entry rejects every token for that org.

1. **Create the namespace** — one per environment, from `packages/api`:
   ```sh
   npx wrangler kv namespace create JWT_SECRETS --config wrangler.dev.toml   # title sa-api-dev-JWT_SECRETS
   npx wrangler kv namespace create JWT_SECRETS                             # title sa-api-JWT_SECRETS (prod)
   ```
   Namespace titles must be unique per Cloudflare account; wrangler 3 prefixes the title with
   the worker name from the config, which keeps the two apart. Each creates a separate store
   with its own id: put the dev id into both dev tomls and the prod id into both prod tomls
   (§3.5). The binding name `JWT_SECRETS` is the same everywhere, so the code does not change
   between environments. `npx wrangler kv namespace list` shows titles and ids.

2. **Seed** each namespace:
   - one `org:<id>` per row of `SELECT id FROM organizations`, value = **that environment's**
     current `JWT_SECRET` (dev and prod differ);
   - `org:__global` = the same current `JWT_SECRET`.

   Build a JSON file `[{ "key": "org:<id>", "value": "<secret>" }, …]` **outside the repo**
   and load it with:
   ```sh
   npx wrangler kv bulk put seed.json --namespace-id=<id>
   ```
   Delete the file afterwards. Confirm the number of `org:` keys (excluding `__global`) equals
   the org count: `npx wrangler kv key list --namespace-id=<id>`.

3. **Deploy `sa-websocket` first, then `sa-api`** — dev, then prod. With every seeded entry
   equal to the old `JWT_SECRET`, either order works for existing orgs and super_admin; relay
   first is still the safe habit, since the verifier must understand a secret before anything
   is signed with it (matters once an org gets its own secret).

4. **Test on dev** (below), then repeat 1–3 on prod.

5. **Afterwards:** delete the now-unused `JWT_SECRET` from `sa-websocket`
   (`wrangler secret delete JWT_SECRET`). Keep it on `sa-api` for SSO/SAML state tokens.

### Test matrix (dev)

| Case | Expected |
|---|---|
| Login, existing org | token works on API + WebSocket, no re-login for already-open tabs |
| Login, org with a new secret (`wrangler kv key put`) | works on API + WebSocket |
| Token from org A's secret with `userId` of an org B user | 401 on API and relay (step 4) |
| super_admin login | signed with `__global`; can reach any project |
| Change an org's secret while a tab is open | tab recovers via refresh within ~2 min; other orgs unaffected |
| Org with no KV entry | login 503, verify 401, `no signing secret` in logs |
| SSO (OIDC) and SAML login | redirect token verifies on API + WebSocket |
| `/upload/source-file/signed-get` with a user token | works; deactivated user now rejected |

## 6. Follow-ups

- ~~**Org creation hook**~~ — done: `POST /orgs` generates the org id in code
  (`crypto.randomUUID()`), calls `createOrgSecret` **before** the DB insert, then inserts with that
  id. A failed KV write returns 503 with no org created; a failed insert leaves only an unused
  KV entry.
- **Secret changes without the CLI:** a super_admin-only endpoint that regenerates
  `org:<id>`.
- **Encryption at rest:** secrets are stored in plain text, readable by anyone with access to
  the KV namespace (Cloudflare dashboard, API tokens with KV read). If that is too broad,
  encrypt values with AES-GCM under a `JWT_KEK` worker secret; seeding then goes through a
  small script instead of `wrangler kv bulk put`.

## 7. Files touched

| Package | File | Change |
|---|---|---|
| api | `src/lib/org-secrets.ts` | **new** — lookup, cache, `createOrgSecret` |
| api | `src/lib/access-token.ts` | sign with the org secret |
| api | `src/middleware/auth.ts` | verify with the org secret + step 4; export `authenticateRequest` |
| api | `src/routes/auth.ts` | pass `JWT_SECRETS` to `mintAccessToken` |
| api | `src/routes/orgs.ts` | `POST /orgs` creates the new org's secret before inserting it |
| api | `src/routes/sso.ts`, `src/routes/saml.ts` | use `mintAccessToken` |
| api | `src/routes/source-upload.ts` | use `authenticateRequest` |
| api | `src/types.ts`, `wrangler.toml`, `wrangler.dev.toml` | `JWT_SECRETS` binding |
| websocket | `src/auth/org-secrets.ts` | **new** — copy of the api module |
| websocket | `src/auth/session.ts` | verify with the org secret + step 4 |
| websocket | `src/index.ts`, `wrangler.toml`, `wrangler.dev.toml` | `JWT_SECRETS` binding |
