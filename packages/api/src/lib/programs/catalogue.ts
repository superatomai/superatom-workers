/**
 * The program catalogue's rules, free of HTTP and the database so they can be
 * tested on their own: archive keys, what a registration must say, and which
 * version of each program is live.
 */
export const NAME_RE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
export const SEMVER_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
export const SHA256_RE = /^[0-9a-f]{64}$/;
export const MAX_ARCHIVE_BYTES = 200 * 1024 * 1024;

export function builtKey(projectId: string, name: string, version: string, hash: string): string {
  return `${projectId}/${name}/${version}/${hash}.tar.gz`;
}
export function sourceKey(projectId: string, name: string, version: string, hash: string): string {
  return `${projectId}/${name}/${version}/${hash}.src.tar.gz`;
}

export interface Registration {
  name: string;
  version: string;
  hash: string;
  bytes: number;
  manifest: Record<string, unknown>;
  commit?: string;
  builtBy?: string;
  notes?: string;
  sourceHash?: string;
  sourceBytes?: number;
  /** Honoured only for service-token callers (the publish CLI); a signed-in caller is the creator. */
  creatorId?: string;
}

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

/** Validates a register body. The manifest's own rules are the engine's; here only identity and sizes. */
export function parseRegistration(body: unknown): Parsed<Registration> {
  if (!body || typeof body !== "object") return { ok: false, error: "A JSON body is required" };
  const b = body as Record<string, unknown>;
  const name = typeof b.name === "string" ? b.name : "";
  const version = typeof b.version === "string" ? b.version : "";
  const hash = typeof b.hash === "string" ? b.hash.toLowerCase() : "";
  if (!NAME_RE.test(name)) return { ok: false, error: "name must be kebab-case" };
  if (!SEMVER_RE.test(version)) return { ok: false, error: "version must be semver (x.y.z)" };
  if (!SHA256_RE.test(hash)) return { ok: false, error: "hash must be the archive's sha256 (64 hex chars)" };
  if (typeof b.bytes !== "number" || !Number.isInteger(b.bytes) || b.bytes <= 0) return { ok: false, error: "bytes must be a positive integer" };
  if (b.bytes > MAX_ARCHIVE_BYTES) return { ok: false, error: `the archive is larger than ${MAX_ARCHIVE_BYTES / 1024 / 1024} MB` };
  if (!b.manifest || typeof b.manifest !== "object" || Array.isArray(b.manifest)) return { ok: false, error: "manifest (program.json) is required" };
  const m = b.manifest as Record<string, unknown>;
  if (m.name !== name || m.version !== version) return { ok: false, error: "manifest name/version must match the registration" };
  if (!m.server && !m.web) return { ok: false, error: "manifest needs a server part, a web part, or both" };
  const out: Registration = { name, version, hash, bytes: b.bytes, manifest: m };
  if (b.commit !== undefined) {
    if (typeof b.commit !== "string" || !/^[0-9a-f]{7,40}$/i.test(b.commit)) return { ok: false, error: "commit must be a git sha" };
    out.commit = b.commit.toLowerCase();
  }
  if (b.builtBy !== undefined) { if (typeof b.builtBy !== "string") return { ok: false, error: "builtBy must be a string" }; out.builtBy = b.builtBy.slice(0, 255); }
  if (b.notes !== undefined) { if (typeof b.notes !== "string") return { ok: false, error: "notes must be a string" }; out.notes = b.notes.slice(0, 4000); }
  if (b.creatorId !== undefined) {
    if (typeof b.creatorId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(b.creatorId)) return { ok: false, error: "creatorId must be a user id" };
    out.creatorId = b.creatorId.toLowerCase();
  }
  if (b.sourceHash !== undefined || b.sourceBytes !== undefined) {
    if (typeof b.sourceHash !== "string" || !SHA256_RE.test(b.sourceHash.toLowerCase())) return { ok: false, error: "sourceHash must be a sha256" };
    if (typeof b.sourceBytes !== "number" || !Number.isInteger(b.sourceBytes) || b.sourceBytes <= 0 || b.sourceBytes > MAX_ARCHIVE_BYTES) return { ok: false, error: "sourceBytes must be a positive integer within the size limit" };
    out.sourceHash = b.sourceHash.toLowerCase(); out.sourceBytes = b.sourceBytes;
  }
  return { ok: true, value: out };
}

export interface CatalogueRow {
  id: string;
  name: string;
  version: string;
  hash: string;
  bytes: number;
  status: string;
  publishedAt: Date | string | null;
  uploadedAt: Date | string;
  creatorId: string | null;
  manifest: Record<string, unknown> | null;
  /** The build the project's engines run; one per name. */
  current?: boolean;
  /** `current` is frozen: a newer publish does not move it. */
  pinned?: boolean;
}

const publishedReady = (r: CatalogueRow) => r.status === "ready" && Boolean(r.publishedAt);
const newestFirst = <T extends CatalogueRow>(a: T, b: T) => +new Date(b.publishedAt!) - +new Date(a.publishedAt!);

/**
 * The build each program's engines run: the row marked `current`. A name with
 * published rows but no mark (registered before the mark existed) falls back to
 * the newest published one, so an un-backfilled project keeps working.
 */
export function currentRows<T extends CatalogueRow>(rows: T[]): T[] {
  const byName = new Map<string, T[]>();
  for (const r of rows) {
    if (!publishedReady(r)) continue;
    const list = byName.get(r.name) ?? [];
    list.push(r);
    byName.set(r.name, list);
  }
  const out: T[] = [];
  for (const list of byName.values()) out.push(list.find((r) => r.current) ?? list.sort(newestFirst)[0]);
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Row ids whose `current` / `pinned` flags change, as `{ id: { current, pinned } }`. */
export type FlagChanges = Record<string, { current: boolean; pinned?: boolean }>;

/**
 * Publishing a build makes it current, unless the name's current build is pinned:
 * then the new build is published but the pointer stays until someone unpins or pins it.
 */
export function publishPlan<T extends CatalogueRow>(rows: T[], id: string): { changes: FlagChanges; becameCurrent: boolean } {
  const target = rows.find((r) => r.id === id);
  if (!target) return { changes: {}, becameCurrent: false };
  const siblings = rows.filter((r) => r.name === target.name && r.id !== id);
  const held = siblings.find((r) => r.current && r.pinned);
  if (held) return { changes: {}, becameCurrent: false };
  const changes: FlagChanges = { [id]: { current: true } };
  for (const r of siblings) if (r.current) changes[r.id] = { current: false, pinned: false };
  return { changes, becameCurrent: true };
}

/** Unpublishing clears the pointer (and any pin); the newest other published build takes it. */
export function unpublishPlan<T extends CatalogueRow>(rows: T[], id: string): { changes: FlagChanges; nextId: string | null } {
  const target = rows.find((r) => r.id === id);
  if (!target) return { changes: {}, nextId: null };
  const changes: FlagChanges = { [id]: { current: false, pinned: false } };
  if (!target.current) return { changes, nextId: null };
  const next = rows.filter((r) => r.name === target.name && r.id !== id && publishedReady(r)).sort(newestFirst)[0];
  if (next) changes[next.id] = { current: true };
  return { changes, nextId: next?.id ?? null };
}

/**
 * Pin: the published build with this hash becomes current and frozen. Unpin
 * (hash null): the current build stays current, no longer frozen.
 */
export function pinPlan<T extends CatalogueRow>(rows: T[], name: string, hash: string | null): { ok: true; changes: FlagChanges } | { ok: false; error: string } {
  const mine = rows.filter((r) => r.name === name);
  if (hash === null) {
    const cur = currentRows(mine)[0];
    return { ok: true, changes: cur ? { [cur.id]: { current: true, pinned: false } } : {} };
  }
  const target = mine.find((r) => r.hash === hash);
  if (!target || !publishedReady(target)) return { ok: false, error: `${name}@${hash.slice(0, 12)} is not a published build` };
  const changes: FlagChanges = { [target.id]: { current: true, pinned: true } };
  for (const r of mine) if (r.id !== target.id && (r.current || r.pinned)) changes[r.id] = { current: false, pinned: false };
  return { ok: true, changes };
}

/** `name → version` of the pinned current builds, for callers that still read the old pins map. */
export function pinsOf<T extends CatalogueRow>(rows: T[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of currentRows(rows)) if (r.pinned) out[r.name] = r.version;
  return out;
}

/**
 * The version of each program an engine should run: the newest published one,
 * unless `pins[name]` names a published version. A pin to a version that is
 * not published is ignored, so a bad pin can never take a program away.
 */
export function liveVersions<T extends CatalogueRow>(rows: T[], pins: Record<string, string> = {}): T[] {
  const byName = new Map<string, T[]>();
  for (const r of rows) {
    if (r.status !== "ready" || !r.publishedAt) continue;
    const list = byName.get(r.name) ?? [];
    list.push(r);
    byName.set(r.name, list);
  }
  const out: T[] = [];
  for (const [name, list] of byName) {
    const pinned = pins[name] ? list.find((r) => r.version === pins[name]) : undefined;
    out.push(pinned ?? list.sort((a, b) => +new Date(b.publishedAt!) - +new Date(a.publishedAt!))[0]);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Drafts an engine may see: ready, unpublished, and registered by this creator. */
export function draftsFor<T extends CatalogueRow>(rows: T[], creatorId: string | undefined): T[] {
  if (!creatorId) return [];
  const newest = new Map<string, T>();
  for (const r of rows) {
    if (r.status !== "ready" || r.publishedAt || r.creatorId !== creatorId) continue;
    const prev = newest.get(r.name);
    if (!prev || +new Date(r.uploadedAt) > +new Date(prev.uploadedAt)) newest.set(r.name, r);
  }
  return [...newest.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** What an engine needs per program, nothing it should not have. */
export function engineView<T extends CatalogueRow>(r: T, draft = false) {
  return { name: r.name, version: r.version, hash: r.hash, bytes: r.bytes, manifest: r.manifest, publishedAt: r.publishedAt, draft, pinned: Boolean(r.pinned) };
}
