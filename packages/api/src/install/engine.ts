import { Hono } from "hono";
import type { Env } from "../types";
import { InstallError, envLines } from "./lib";

/**
 * Docker Engine and compose binaries, mirrored into R2 so a VM whose only
 * allowed egress is *.superatom.ai can still install Docker — which cannot come
 * from the registry, since Docker is what pulls from it.
 *
 * Unauthenticated on purpose: these are public upstream binaries, and the
 * installer verifies the published sha256 before using them.
 */
const engine = new Hono<{ Bindings: Env }>();

const KIND = new Set(["docker", "compose"]);
const ARCH = new Set(["x86_64", "aarch64"]);
const VERSION = /^\d+\.\d+\.\d+$/;
// Version-keyed and immutable, so the edge may keep them for a year.
const IMMUTABLE = "public, max-age=31536000, immutable";
const POINTER_TTL_MS = 60_000;

let pointer: { body: { docker: string; compose: string }; at: number } | null = null;

function bucket(env: Env): R2Bucket {
  if (!env.INSTALL_ARTIFACTS) throw new InstallError(503, "Installer is not configured (artifacts).");
  return env.INSTALL_ARTIFACTS;
}

/** engine/current.json — which versions a fresh install should use. */
async function current(env: Env) {
  if (pointer && Date.now() - pointer.at < POINTER_TTL_MS) return pointer.body;
  const obj = await bucket(env).get("engine/current.json");
  if (!obj) throw new InstallError(503, "No Docker Engine version is published yet.");
  const parsed = await obj.json<{ docker?: unknown; compose?: unknown }>();
  if (typeof parsed.docker !== "string" || typeof parsed.compose !== "string") {
    throw new InstallError(503, "The published Docker Engine version is unreadable.");
  }
  pointer = { body: { docker: parsed.docker, compose: parsed.compose }, at: Date.now() };
  return pointer.body;
}

/** GET /api/engine — the versions to install. */
engine.get("/", async (c) => {
  const { docker, compose } = await current(c.env);
  return c.text(envLines({ DOCKER_VERSION: docker, COMPOSE_VERSION: compose }), 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=60",
  });
});

/** The object for one kind/version/arch, or null when the path is not one we serve. */
function keyFor(kind: string, ver: string, arch: string): string | null {
  if (!KIND.has(kind) || !ARCH.has(arch) || !VERSION.test(ver)) return null;
  return kind === "docker" ? `engine/docker/${ver}/${arch}.tgz` : `engine/compose/${ver}/${arch}`;
}

async function serve(c: any, key: string, contentType: string) {
  const obj = await bucket(c.env).get(key);
  if (!obj) return c.text("Not found", 404);
  return new Response(obj.body, {
    headers: {
      "Content-Type": contentType,
      "Content-Length": String(obj.size),
      "Cache-Control": IMMUTABLE,
      ETag: obj.httpEtag,
    },
  });
}

/** GET /api/engine/:kind/:ver/:arch — the binary. */
engine.get("/:kind/:ver/:arch", async (c) => {
  const { kind, ver, arch } = c.req.param();
  const key = keyFor(kind, ver, arch);
  if (!key) return c.text("Not found", 404);
  return serve(c, key, kind === "docker" ? "application/gzip" : "application/octet-stream");
});

/** GET /api/engine/:kind/:ver/:arch/sha256 — its checksum, for the installer to verify. */
engine.get("/:kind/:ver/:arch/sha256", async (c) => {
  const { kind, ver, arch } = c.req.param();
  const key = keyFor(kind, ver, arch);
  if (!key) return c.text("Not found", 404);
  return serve(c, `${key}.sha256`, "text/plain; charset=utf-8");
});

export default engine;
