import { projectReleases } from "../db/schema";
import type { Database } from "../db";
import type { Env } from "../types";

/** Shared repo every active project key may pull; must match src/install/registry.ts. */
const BASE_REPO = "base";

export interface Baseline {
  version: string;
  branch: string;
  commit: string;
  image: string;
  imageDigest: string;
  bundleSha256: string;
  engineVersion?: string | null;
  composeVersion?: string | null;
  migrations?: number | null;
  publishedBy?: string | null;
  notes?: string | null;
}

/**
 * The platform release new clients start on, written by `publish-release --baseline`.
 * One image in the shared "base" repo, so onboarding needs no per-client build.
 */
export async function readBaseline(env: Env): Promise<Baseline | null> {
  if (!env.INSTALL_ARTIFACTS) return null;
  const obj = await env.INSTALL_ARTIFACTS.get(`registry/${BASE_REPO}/current-release.json`);
  if (!obj) return null;
  const j = await obj.json<Partial<Baseline>>();
  return j.version && j.branch && j.commit && j.image && j.imageDigest && j.bundleSha256
    ? (j as Baseline)
    : null;
}

/**
 * Points a project at the current baseline so it is installable straight away.
 * Returns the version, or null when no baseline is published — not an error: a
 * project with no release falls back to the source-tarball install.
 */
export async function assignBaseline(
  db: Database, env: Env, projectId: string,
): Promise<string | null> {
  const b = await readBaseline(env);
  if (!b) return null;
  await db
    .insert(projectReleases)
    .values({
      projectId,
      version: b.version,
      branch: b.branch,
      commit: b.commit,
      image: b.image,
      imageDigest: b.imageDigest,
      bundleSha256: b.bundleSha256,
      engineVersion: b.engineVersion ?? null,
      composeVersion: b.composeVersion ?? null,
      migrations: b.migrations ?? null,
      publishedBy: b.publishedBy ?? null,
      notes: b.notes ?? null,
    })
    // Re-assigning the same baseline is a no-op, not a 500.
    .onConflictDoNothing();
  return b.version;
}
