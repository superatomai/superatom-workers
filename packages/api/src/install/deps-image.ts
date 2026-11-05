import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The dependency image (Dockerfile stage `deps`: OS packages, codex, node_modules) is built once per
 * Dockerfile + lockfile set and reused by every release, so a release adds only its code layers.
 * Before this every publish rebuilt ~2 GB of identical content under new layer ids.
 */

/** Every file the install stage reads: a change to any of them is a new dependency set. */
export const DEPS_INPUTS = [
  "Dockerfile",
  ...["frontend", "backend", "database/postgres", "database/chromadb"].flatMap((d) =>
    ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"].map((f) => `${d}/${f}`)),
  "backend/.npmrc",
];

/** Repos not yet split into a `deps` stage publish the old way. */
export function hasDepsStage(dockerfile: string): boolean {
  return /^FROM\s+\S+\s+AS\s+deps\s*$/im.test(dockerfile);
}

/** Content hash of the dependency inputs in a source tree; a missing file counts as its absence. */
export function depsKey(tree: string): string {
  const h = createHash("sha256");
  for (const rel of DEPS_INPUTS) {
    const file = join(tree, rel);
    h.update(`${rel}\0`);
    h.update(existsSync(file) ? readFileSync(file) : "\0missing\0");
  }
  return h.digest("hex").slice(0, 32);
}

/** R2 keys: the pointer that names a deps image, and where its manifest lives. */
export const depsPointerKey = (repo: string, key: string) => `registry/${repo}/deps/${key}.json`;
