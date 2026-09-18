/**
 * Serves a built front-end app (Vite output) from R2.
 *
 * Layout per app:
 *   <app>/current.json               {"release": "<buildId>"}  — the live build
 *   <app>/releases/<buildId>/…       the build's files (index.html, assets/…)
 * A deploy uploads a new release first and flips current.json last, so a
 * half-finished upload is never served and rollback is a pointer change.
 */

const POINTER_TTL_MS = 30_000;
const RELEASE_ID = /^[A-Za-z0-9._-]{1,100}$/;

const DEFAULT_CSP = [
  "default-src 'self'",
  "script-src 'self' https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "connect-src 'self'",
  "img-src 'self' data: https:",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const CONTENT_TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json; charset=utf-8",
  map: "application/json; charset=utf-8",
  webmanifest: "application/manifest+json",
  txt: "text/plain; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  ico: "image/x-icon",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
};

// Per-isolate cache of each app's live release, so every request isn't an extra R2 read.
const pointerCache = new Map<string, { release: string | null; at: number }>();

async function currentRelease(bucket: R2Bucket, app: string): Promise<string | null> {
  const cached = pointerCache.get(app);
  if (cached && Date.now() - cached.at < POINTER_TTL_MS) return cached.release;

  let release: string | null = null;
  const obj = await bucket.get(`${app}/current.json`);
  if (obj) {
    try {
      const parsed = await obj.json<{ release?: unknown }>();
      if (typeof parsed.release === "string" && RELEASE_ID.test(parsed.release)) {
        release = parsed.release;
      }
    } catch {
      // Malformed pointer — treat as not deployed rather than guessing.
    }
  }
  pointerCache.set(app, { release, at: Date.now() });
  return release;
}

function notDeployed(): Response {
  return new Response(
    "<!doctype html><title>Not deployed</title><p>This app has not been deployed yet.</p>",
    {
      status: 503,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    }
  );
}

export async function serveUi(
  bucket: R2Bucket,
  app: string,
  request: Request,
  options: { csp?: string } = {}
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
  }

  let path: string;
  try {
    path = decodeURIComponent(new URL(request.url).pathname);
  } catch {
    return new Response("Bad request", { status: 400 });
  }
  if (path.includes("..") || path.includes("\0") || path.includes("\\")) {
    return new Response("Not found", { status: 404 });
  }

  const release = await currentRelease(bucket, app);
  if (!release) return notDeployed();

  // Paths without a file extension are client-side routes → the SPA shell.
  const lastSegment = path.slice(path.lastIndexOf("/") + 1);
  const file = /\.[A-Za-z0-9]+$/.test(lastSegment) ? path.replace(/^\/+/, "") : "index.html";
  const isShell = file === "index.html";

  const obj = await bucket.get(`${app}/releases/${release}/${file}`, { onlyIf: request.headers });
  if (!obj) {
    return isShell ? notDeployed() : new Response("Not found", { status: 404 });
  }

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("ETag", obj.httpEtag);
  if (!headers.has("Content-Type")) {
    const ext = file.slice(file.lastIndexOf(".") + 1).toLowerCase();
    headers.set("Content-Type", CONTENT_TYPES[ext] ?? "application/octet-stream");
  }
  // Hashed build assets never change; the shell must always be revalidated.
  headers.set(
    "Cache-Control",
    isShell
      ? "no-cache"
      : file.startsWith("assets/")
        ? "public, max-age=31536000, immutable"
        : "public, max-age=300"
  );
  headers.set("X-Content-Type-Options", "nosniff");
  if (isShell) {
    headers.set("Content-Security-Policy", options.csp ?? DEFAULT_CSP);
    headers.set("X-Frame-Options", "DENY");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  }

  // With onlyIf, a matching If-None-Match returns metadata without a body.
  if (!("body" in obj)) return new Response(null, { status: 304, headers });
  return new Response(request.method === "HEAD" ? null : obj.body, { headers });
}
