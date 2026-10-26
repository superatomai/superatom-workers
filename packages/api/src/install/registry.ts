import { Hono } from "hono";
import { and, eq } from "drizzle-orm";
import type { Database } from "../db";
import { apiKeys } from "../db/schema";
import type { Env } from "../types";
import { hashApiKey } from "../../../websocket/src/api-keys/service";

/**
 * An OCI registry read path, so a client VM can `docker pull` its own image from
 * *.superatom.ai. Pulls are authenticated with the project's API key and scoped
 * to that project's repository, which a bucket on a public domain cannot do.
 *
 * Repository name IS the project id, except for `base`: the third-party images the
 * stack runs (postgres, chroma), mirrored once and readable by any active key.
 * Only reads exist: releases are published by writing objects into the bucket,
 * never by `docker push`.
 */
type RegistryApp = Hono<{ Bindings: Env; Variables: { db: Database } }>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
const IMMUTABLE = "public, max-age=31536000, immutable";
// Shared, not client code: mirrored public images, so any active key may read it.
const SHARED_REPO = "base";

function key(repo: string, kind: "blobs" | "manifests", ref: string): string {
  return `registry/${repo}/${kind}/${ref}`;
}

/** OCI error body, so the docker client prints something readable. */
function ociError(code: string, message: string) {
  return { errors: [{ code, message, detail: null }] };
}

function challenge(c: any) {
  return c.json(ociError("UNAUTHORIZED", "authentication required"), 401, {
    "WWW-Authenticate": 'Basic realm="superatom-install"',
    "Docker-Distribution-API-Version": "registry/2.0",
  });
}

/** The API key from a Basic credential; the username is ignored. */
function basicKey(c: any): string | null {
  const header = c.req.header("Authorization") ?? "";
  if (!header.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6).trim());
    const key = decoded.slice(decoded.indexOf(":") + 1);
    return key.startsWith("sa_live_") ? key : null;
  } catch {
    return null;
  }
}

/** True when this key is active for any project. */
async function anyActiveKey(db: Database, apiKey: string): Promise<boolean> {
  const [row] = await db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.keyHash, await hashApiKey(apiKey)), eq(apiKeys.isActive, true)))
    .limit(1);
  return !!row;
}

/** True when this key is active for `repo` (the project id). */
async function mayPull(db: Database, repo: string, apiKey: string): Promise<boolean> {
  const [row] = await db
    .select({ id: apiKeys.id })
    .from(apiKeys)
    .where(and(eq(apiKeys.projectId, repo), eq(apiKeys.keyHash, await hashApiKey(apiKey)), eq(apiKeys.isActive, true)))
    .limit(1);
  return !!row;
}

function bucket(c: any) {
  return c.env.INSTALL_ARTIFACTS as R2Bucket;
}

/** GET /v2/ — the client's first call; the 401 here is what makes it send credentials. */
const ping = async (c: any) => {
  const apiKey = basicKey(c);
  if (!apiKey) return challenge(c);
  if (!(await anyActiveKey(c.var.db, apiKey))) return challenge(c);
  return c.json({}, 200, { "Docker-Distribution-API-Version": "registry/2.0" });
};

/** Shared gate: valid repo name, a credential, and that credential scoped to this repo. */
async function gate(c: any, repo: string): Promise<Response | null> {
  if (repo !== SHARED_REPO && !UUID.test(repo)) {
    return c.json(ociError("NAME_UNKNOWN", "repository name not known"), 404);
  }
  const apiKey = basicKey(c);
  if (!apiKey) return challenge(c);
  if (repo === SHARED_REPO) {
    // Any active key: these are public upstream images, mirrored for offline VMs.
    return (await anyActiveKey(c.var.db, apiKey))
      ? null
      : c.json(ociError("DENIED", "not authorised for this repository"), 403);
  }
  if (!(await mayPull(c.var.db, repo, apiKey))) {
    // Deny rather than 404, so a wrong key never maps the existence of other repos.
    return c.json(ociError("DENIED", "not authorised for this repository"), 403);
  }
  return null;
}

/** Streams an object, honouring Range so a dropped layer download can resume. */
async function serveObject(c: any, objectKey: string, contentType: string, cache: string, digest?: string) {
  const rangeHeader = c.req.header("Range");
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader ?? "");
  const head = c.req.method === "HEAD";

  if (match && !head) {
    const size = (await bucket(c).head(objectKey))?.size;
    if (size === undefined) return c.json(ociError("BLOB_UNKNOWN", "blob unknown"), 404);
    const start = match[1] ? Number(match[1]) : 0;
    const end = match[2] ? Number(match[2]) : size - 1;
    if (start >= size || end < start) {
      return c.body(null, 416, { "Content-Range": `bytes */${size}` });
    }
    const part = await bucket(c).get(objectKey, { range: { offset: start, length: end - start + 1 } });
    if (!part) return c.json(ociError("BLOB_UNKNOWN", "blob unknown"), 404);
    return new Response(part.body, {
      status: 206,
      headers: {
        "Content-Type": contentType,
        "Content-Length": String(end - start + 1),
        "Content-Range": `bytes ${start}-${end}/${size}`,
        "Cache-Control": cache,
        ...(digest ? { "Docker-Content-Digest": digest } : {}),
      },
    });
  }

  const obj = head ? await bucket(c).head(objectKey) : await bucket(c).get(objectKey);
  if (!obj) return c.json(ociError("BLOB_UNKNOWN", "not found"), 404);
  const headers: Record<string, string> = {
    "Content-Type": contentType,
    "Content-Length": String(obj.size),
    "Cache-Control": cache,
    "Accept-Ranges": "bytes",
    ETag: obj.httpEtag,
    ...(digest ? { "Docker-Content-Digest": digest } : {}),
  };
  return head ? new Response(null, { status: 200, headers }) : new Response((obj as R2ObjectBody).body, { headers });
}

/** GET|HEAD /v2/:repo/manifests/:ref — by tag or by digest. */
const manifests = async (c: any) => {
  const { repo, ref } = c.req.param();
  const denied = await gate(c, repo);
  if (denied) return denied;
  if (!DIGEST.test(ref) && !TAG.test(ref)) {
    return c.json(ociError("MANIFEST_UNKNOWN", "manifest unknown"), 404);
  }

  const obj = await bucket(c).get(key(repo, "manifests", ref));
  if (!obj) return c.json(ociError("MANIFEST_UNKNOWN", "manifest unknown"), 404);
  // Manifests are small; read them to serve the digest the client verifies against.
  const body = await obj.arrayBuffer();
  const digest = DIGEST.test(ref)
    ? ref
    : "sha256:" + Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)),
        (b) => b.toString(16).padStart(2, "0")).join("");
  const headers: Record<string, string> = {
    "Content-Type": obj.httpMetadata?.contentType ?? "application/vnd.oci.image.manifest.v1+json",
    "Content-Length": String(body.byteLength),
    "Docker-Content-Digest": digest,
    // A tag moves between releases; a digest never does.
    "Cache-Control": DIGEST.test(ref) ? IMMUTABLE : "no-cache",
  };
  return c.req.method === "HEAD" ? new Response(null, { status: 200, headers }) : new Response(body, { headers });
};

/** GET|HEAD /v2/:repo/blobs/:digest — layers and configs, content-addressed. */
const blobs = async (c: any) => {
  const { repo, digest } = c.req.param();
  const denied = await gate(c, repo);
  if (denied) return denied;
  if (!DIGEST.test(digest)) return c.json(ociError("DIGEST_INVALID", "digest invalid"), 400);
  return serveObject(c, key(repo, "blobs", digest), "application/octet-stream", IMMUTABLE, digest);
};

/**
 * Registered as absolute paths on the install app: Hono's route() prefix mount
 * never matches "/v2/" (with the trailing slash docker actually sends).
 */
export function mountRegistry(app: RegistryApp): void {
  app.on("GET", ["/v2", "/v2/"], ping);
  app.on(["GET", "HEAD"], "/v2/:repo/manifests/:ref", manifests);
  app.on(["GET", "HEAD"], "/v2/:repo/blobs/:digest", blobs);
  app.all("/v2/*", (c) => c.json(ociError("UNSUPPORTED", "this registry is read-only"), 405));
}
