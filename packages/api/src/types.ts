import type { Database } from "./db";

export type Env = {
  DATABASE_URL: string;
  // Signs only the SSO/SAML state tokens now. Access tokens use JWT_SECRETS.
  JWT_SECRET: string;
  // Per-org access-token signing secrets (org:<orgId>, org:__global), shared
  // with sa-websocket. See lib/org-secrets.ts.
  JWT_SECRETS: KVNamespace;
  PLATFORM_UI_URL: string;
  /**
   * Optional comma-separated extra CORS origins, for front-ends not served from
   * a *.superatom.ai subdomain (e.g. a white-labelled client domain). Lets ops
   * add an origin without a code change. Exact matches only.
   */
  ALLOWED_ORIGINS?: string;
  R2_BUCKET: R2Bucket;
  R2_PUBLIC_URL: string; // e.g. "https://sa-assets.superatom.ai" or "https://pub-xxx.r2.dev"
  // Private bucket for client-uploaded source files (Excel/CSV).
  R2_SOURCE_FILES: R2Bucket;
  // Must match R2_SOURCE_FILES's actual bucket_name — the R2 binding API has no
  // getSignedUrl(), so presigned URLs are built by hand against the S3-compatible
  // endpoint and need the bucket name as a plain string.
  R2_SOURCE_FILES_BUCKET_NAME: string;
  // R2 S3-compatible API credentials — used by aws4fetch to presign URLs
  // that the worker binding API can't generate natively.
  R2_ACCOUNT_ID: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  // Shared secret for backend → worker service calls (e.g. /upload/source-file/signed-get).
  SA_INTERNAL_SERVICE_TOKEN: string;
  /**
   * Cloudflare Turnstile secret for login captcha verification (VAPT 2e513875).
   * Optional: login captcha is skipped until this is set, so the backend can
   * ship before the front-ends send a token. Set it to switch enforcement on.
   */
  TURNSTILE_SECRET_KEY?: string;
  // Voice input (speech-to-text) — see docs/SPEECH-TO-TEXT-DESIGN.md.
  OPENROUTER_API_KEY: string;
  SPEECH_RATE_LIMITER: RateLimit;
  // "true" → run the optional vocabulary-correction pass (§4.3 of the design
  // doc). Leave unset until live testing shows the recognizer-side biasing
  // (provider.options.google.prompt) is not honored.
  SPEECH_CORRECT_TERMS?: string;
  // Built front-end apps, served by hostname: <app>/releases/<buildId>/… + <app>/current.json.
  FRONTEND_BUILDS: R2Bucket;
  // Hostname that serves the super-admin console (UI + /api/*) instead of sa-api.
  SUPERADMIN_HOST: string;
  // Signs super-admin console sessions. Must differ from JWT_SECRET (min 32 chars).
  SUPERADMIN_JWT_SECRET: string;
  SUPERADMIN_LOGIN_LIMITER: RateLimit;
  // ─── Installer host (src/install) ───
  INSTALL_HOST: string;
  INSTALL_RATE_LIMITER: RateLimit;
  // Code source: fine-grained GitHub token, one repo, contents read-only.
  GITHUB_CODE_TOKEN?: string;
  INSTALL_CODE_REPO: string;
  INSTALL_CODE_REF: string;
  INSTALL_GITHUB_API?: string;
  // Signs the short-lived code download links (min 32 chars).
  INSTALL_DOWNLOAD_SECRET?: string;
  // Values handed to new installs.
  INSTALL_SA_API_URL: string;
  // Client UI links for the install summary; "{slug}" is replaced with the org slug.
  INSTALL_PLATFORM_UI_URL: string;
  INSTALL_USER_UI_URL: string;
  INSTALL_WS_URL?: string;
  RESEND_API_KEY?: string;
  // Per-project LLM proxy keys via the llm-proxy worker's admin API; "dummy" skips it (dev).
  LLM_PROXY?: Fetcher;
  LLM_PROXY_ADMIN_SECRET?: string;
  INSTALL_LLM_PROXY_MODE?: string;
};

export type AppVariables = {
  db: Database;
  userId: string;
  orgId: string | null;
  userRole: "super_admin" | "org_admin" | "member";
  /** The caller's login session (refresh-token family), from the token's `sid`; null for older tokens. */
  sessionId: string | null;
};
