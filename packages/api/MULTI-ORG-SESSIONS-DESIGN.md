# Multi-Org Concurrent Sessions — Design

Status: **deployed to dev + prod** (2026-08-04). Author: platform. Reviewers: TBD.
Rollout done UIs-first per §6: dev UIs → `sa-api-dev` (`42c9bced`), then prod UIs (all three
confirmed serving the new bundle) → prod `sa-api` (`c202a8cb`). Endpoint smoke tests green on both.
Still to do: run the §6 manual matrix on prod; the WS `WS_AUTH_ENFORCE` stale-tab incident (§7) is
independent and still open.

Lets one browser hold **several org sessions at once** — a Superatom staffer who is
`org_admin` in multiple orgs can have `bluelinx.superatom.ai` and another org open in
separate tabs, or two orgs open on the generic `live.superatom.ai`, without the sessions
overwriting each other.

## 1. Why it breaks today

Two shared pieces of state, one per browser:

1. **Refresh cookie is domain-wide and single-valued.** `lib/refresh-cookie.ts` sets one
   cookie `sa_refresh` (prod) / `sa_refresh_dev` (dev) with `Domain=.superatom.ai`,
   `Path=/auth`, `HttpOnly`, `SameSite=Lax`. The comment is explicit: *"Scope to the
   registrable domain so every subdomain front-end shares one session."* Logging into org B
   **overwrites** org A's cookie. Every tab's `ensureFreshToken()` then refreshes off that
   one cookie and converges on whichever org logged in last.

2. **Access token key is not org/tab scoped.** Runtime UIs store the JWT at
   `localStorage['sa_auth_token']`. Different **subdomains** already isolate this (per-origin
   `localStorage`), but two orgs opened on the **same** origin (`live.superatom.ai/<projectId>`
   in two tabs) share it and collide.

Observed symptom (2026-08-04): with `WS_AUTH_ENFORCE=true`, a `live.superatom.ai` tab opened
to a Superatom-org project while a Bluelinx tab was open refreshed into the **Bluelinx**
identity, showed Bluelinx UI, and the relay correctly returned **403 cross-org** on the
Superatom project. Enforcement did not cause this — it surfaced a pre-existing session
collision that used to pass silently because the relay ignored org.

## 2. Goals / non-goals

- **Goal:** N concurrent org sessions per browser, covering *both* access patterns —
  per-org subdomains **and** the generic `live.superatom.ai`.
- **Goal:** keep every security property of the current design — refresh token stays
  `HttpOnly`, rotation + reuse-detection unchanged, 15-min access tokens, `SameSite=Lax` CSRF
  control on `/auth/refresh`.
- **Non-goal:** cross-*device* session sync. Non-goal: changing the token TTLs or the
  rotation algorithm.

## 3. Design

### 3.1 Session discriminator = the URL always carries it

Every runtime URL is `/<projectId>/...`; every project maps to exactly one org. So the tab
**always** knows its `projectId` from the URL, even cold (no token yet). We key client state
by `projectId` and let the server resolve `projectId → orgId`. Admin UIs
(`platform.superatom.ai`) key by the selected `orgId` instead (their URL carries org, not
project).

### 3.2 Per-org refresh cookie (server)

Name the cookie per org so multiple coexist under `.superatom.ai`:

```
sa_refresh_<orgId>        (prod)
sa_refresh_dev_<orgId>    (non-prod)
```

Same attributes as today (`HttpOnly; Secure; Domain=.superatom.ai; Path=/auth;
SameSite=Lax; Max-Age=30d`). `refresh-cookie.ts` becomes org-parameterized:

```ts
// setRefreshCookie(c, token, orgId)   clearRefreshCookie(c, orgId)   readRefreshCookie(c, orgId)
function refreshCookieName(requestUrl: string, orgId: string): string {
  const host = new URL(requestUrl).hostname;
  const base = host === "sa-api.superatom.ai" ? "sa_refresh" : "sa_refresh_dev";
  return `${base}_${orgId}`;
}
```

Login and org-select set `sa_refresh_<orgId>` for the org just authenticated. Logout clears
only that org's cookie; a separate "log out everywhere" clears all `sa_refresh*` and revokes
the user's families (existing `revokeAllForUser`).

### 3.3 `/auth/refresh` selects the cookie by project/org (server)

The tab sends its `projectId` (runtime) or `orgId` (admin). The server resolves the org,
reads `sa_refresh_<orgId>`, then validates + rotates exactly as today:

```ts
// POST /auth/refresh  { projectId?  orgId? }
const orgId = body.orgId ?? (await orgIdForProject(body.projectId)); // one indexed SELECT
if (!orgId) return c.json({ error: "unknown_session" }, 401);
const cookie = readRefreshCookie(c, orgId);
if (!cookie) return c.json({ error: "no_session_for_org" }, 401);
const rotated = await rotateRefreshToken(db, cookie);   // unchanged
setRefreshCookie(c, rotated.token, orgId);
return c.json({ token: rotated.accessToken });
```

The hint only **selects** which cookie to read; the refresh token in that cookie is still the
credential and is fully server-validated, so a forged hint cannot escalate — worst case it
names an org whose cookie you don't hold and you get `401`.

### 3.4 Per-tab access token (client) — **implemented with `sessionStorage`**

The access token moves from `localStorage` to **`sessionStorage`**, which is inherently per-tab.
This is simpler and more robust than a `localStorage` key suffixed by `projectId`: it needs no
project context at login/SSO time (when no project is chosen yet), and two orgs on the same
`live.superatom.ai` origin can never collide because each tab has its own `sessionStorage`.

- Storage key stays `sa_auth_token` (runtime) / `sa_api_token` (admin, analytics), just in
  `sessionStorage`. Same for `sa_user` / `sa_org` in runtime-react — the whole session unit is
  per-tab.
- **One-time, non-destructive migration:** on load, if `sessionStorage` has no token, seed it from
  the legacy `localStorage` key so an existing login survives the upgrade. The `localStorage` copy
  is left in place for still-open old-build tabs and is dropped on the next logout.
- `ensureFreshToken()` now also refreshes when there is **no** token (a freshly opened tab
  re-mints from the refresh cookie), not only when one is expiring.
- On refresh, each UI sends a **hint** so the server knows which org cookie to rotate:
  - runtime-react: `{ orgId }` from the stored org → else `{ projectId }` parsed from the
    `/apps/<projectId>/…` URL → else `{ orgSlug }` from the subdomain.
  - sa-platform-ui / sa-analytics: `{ orgId }` decoded from the (possibly expired) token → else
    `{ orgSlug }` from the subdomain (admin) → else none (super_admin uses the base cookie).
- The refreshed token is pushed into the live SDK client via the existing `getClient()?.setToken()`
  plumbing.

Trade-off vs a `localStorage` scheme: opening the app in a **brand-new** tab does not inherit the
access token (sessionStorage is per-tab) — but it silently re-mints from the refresh cookie on load,
so the session (anchored by the 30-day per-org cookie) is preserved; only the 15-minute access token
is re-fetched.

### 3.5 Back-compat

Read the legacy `sa_refresh` / `sa_refresh_dev` (unsuffixed) for one release if no
`sa_refresh_<orgId>` is present, and re-issue the suffixed cookie on the next refresh/login.
Legacy `localStorage['sa_auth_token']` is read once and migrated to the project-scoped key.
Drop both fallbacks the release after.

## 4. Changes by repo

| Repo / file | Change |
|---|---|
| `do-websocket/packages/api/lib/refresh-cookie.ts` | Cookie name/set/read/clear take `orgId` |
| `do-websocket/packages/api/routes/auth.ts` | login + org-select set per-org cookie; `/auth/refresh` takes `projectId`/`orgId` hint + `orgIdForProject()` resolve; logout scopes to org (+ "everywhere") |
| `runtime-react` (`main.ts`, `services/saApi.ts`, `components/auth/utils.ts`, `SSOCallbackPage.tsx`) | project-scoped token key; send `projectId` on refresh |
| `sa-platform-ui` (`superatom.ts`, `services/saApi.ts`, `OrgSelectPage.tsx`) | org-scoped token key; send `orgId` on refresh |
| `sa-analytics` (`services/*`) | same treatment if multi-org is wanted there |

## 5. Security review

- **HttpOnly refresh preserved** — refresh tokens never touch JS; only the 15-min access token
  is in `localStorage`, exactly as today.
- **Rotation / reuse detection unchanged** — `rotateRefreshToken` and family revocation are
  untouched; we only pick which family's cookie to rotate.
- **CSRF** — `/auth/refresh` stays `SameSite=Lax` + same-site; the added body hint changes
  nothing about that.
- **Hint cannot escalate** — selecting a cookie you don't possess yields `401`.
- **`orgIdForProject`** is one indexed `SELECT org_id FROM projects WHERE id=$1` (already used
  by the relay's authz). It is behind `/auth/refresh` and reveals only project→org, which the
  relay already treats as non-secret; no new tenant-enumeration surface beyond what exists.

## 6. Rollout & test plan

> **Deploy the UIs FIRST, then `sa-api`. The reverse order breaks existing sessions.**
>
> If `sa-api` ships first: its login sets only the per-org cookie, but an *old* UI still reads the
> base cookie — so a fresh login on an old UI has no base cookie and 401s every 15 min. Worse, an
> existing session's old-UI refresh reads the base cookie, the new server migrates it to a per-org
> name without updating the base, and the *next* old-UI refresh replays the now-consumed base token —
> tripping reuse detection and **revoking the whole family** (a hard sign-out, including the migrated
> session). UIs-first avoids this: while `sa-api` is still old, new UIs refresh fine against the base
> cookie (the old server ignores the hint body); once `sa-api` upgrades, each session migrates
> base → per-org on its first refresh and never reads the base again.

1. Ship the **UIs** (per-tab `sessionStorage` token + refresh hint). Against the still-old `sa-api`
   they behave exactly as today (single base cookie); no regression, multi-org simply not active yet.
2. Ship **`sa-api`** (per-org cookies + legacy base fallback). Existing base cookies migrate to
   per-org on first refresh; multi-org becomes active.
3. Manual matrix: (a) two orgs on two subdomains; (b) two orgs on `live.superatom.ai` in two
   tabs; (c) same org two tabs; (d) 15-min access-token expiry → silent refresh per tab with no
   cross-wiring; (e) logout one org leaves the other logged in; (f) existing single-org session
   survives the deploy without a re-login.
4. Remove the legacy base-cookie fallback one release later.

**Known transient (self-healing):** a tab left open on the *old* build across the `sa-api` deploy,
if the user logs out and back in before reloading, can 401-loop until the tab is reloaded onto the
new build. It does not affect already-authenticated sessions and clears on any reload.

## 7. Interaction with `WS_AUTH_ENFORCE`

This also removes the cross-org 403 confusion: each tab carries **its own project's** org
token, so the relay's `projects.org_id == session.orgId` check passes for the right project and
denies only genuine cross-org attempts. Land this (and the client stale-tab turnover) **before**
re-enabling enforcement, per the staged-rollout ordering.
