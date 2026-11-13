import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { builtKey, draftsFor, engineView, liveVersions, parseRegistration, sourceKey, currentRows, pinPlan, pinsOf, publishPlan, unpublishPlan } from "./catalogue";

const H = "a".repeat(64);
const base = { name: "orders-kpi", version: "1.2.0", hash: H, bytes: 1234, manifest: { name: "orders-kpi", version: "1.2.0", server: true } };

describe("keys", () => {
  it("are per project, program, version and hash", () => {
    assert.equal(builtKey("p", "a", "1.0.0", H), `p/a/1.0.0/${H}.tar.gz`);
    assert.equal(sourceKey("p", "a", "1.0.0", H), `p/a/1.0.0/${H}.src.tar.gz`);
  });
});

describe("parseRegistration", () => {
  it("accepts a minimal valid body and lowercases the hash", () => {
    const r = parseRegistration({ ...base, hash: H.toUpperCase() });
    assert.ok(r.ok);
    assert.equal(r.value.hash, H);
    assert.equal(r.value.commit, undefined);
  });
  const bad = (patch: Record<string, unknown>, re: RegExp) => {
    const r = parseRegistration({ ...base, ...patch });
    assert.ok(!r.ok, "expected a refusal");
    assert.match(r.error, re);
  };
  it("refuses bad identity and sizes", () => {
    bad({ name: "Orders" }, /kebab-case/);
    bad({ version: "1.2" }, /semver/);
    bad({ hash: "abc" }, /sha256/);
    bad({ bytes: 0 }, /positive integer/);
    bad({ bytes: 500 * 1024 * 1024 }, /larger than/);
  });
  it("refuses a manifest that disagrees or has no parts", () => {
    bad({ manifest: { name: "other", version: "1.2.0", server: true } }, /must match/);
    bad({ manifest: { name: "orders-kpi", version: "1.2.0" } }, /server part, a web part/);
    bad({ manifest: null }, /manifest/);
  });
  it("validates the optional fields", () => {
    bad({ commit: "zz" }, /commit/);
    bad({ creatorId: "me" }, /creatorId/);
    assert.equal((parseRegistration({ ...base, creatorId: "90C88B30-5914-4EFE-8109-2D0E1DE91FF3" }) as any).value.creatorId, "90c88b30-5914-4efe-8109-2d0e1de91ff3");
    bad({ sourceHash: "x" }, /sourceHash/);
    bad({ sourceHash: H }, /sourceBytes/);
    const r = parseRegistration({ ...base, commit: "ABCDEF1", sourceHash: H, sourceBytes: 9, builtBy: "me", notes: "n" });
    assert.ok(r.ok);
    assert.equal(r.value.commit, "abcdef1");
    assert.equal(r.value.sourceBytes, 9);
  });
});

const row = (name: string, version: string, patch: Record<string, unknown> = {}) => ({
  id: `${name}-${version}`, name, version, hash: H, bytes: 1, status: "ready", publishedAt: null as any, uploadedAt: "2026-10-01T00:00:00Z", creatorId: "u1", manifest: null, ...patch,
});

describe("liveVersions", () => {
  const rows = [
    row("a", "1.0.0", { publishedAt: "2026-10-01T00:00:00Z" }),
    row("a", "1.1.0", { publishedAt: "2026-10-05T00:00:00Z" }),
    row("a", "2.0.0", { publishedAt: null }),
    row("b", "0.1.0", { publishedAt: "2026-10-02T00:00:00Z", status: "pending" }),
    row("c", "3.0.0", { publishedAt: "2026-10-03T00:00:00Z" }),
  ];
  it("picks the newest published, ready version per program", () => {
    assert.deepEqual(liveVersions(rows).map((r) => `${r.name}@${r.version}`), ["a@1.1.0", "c@3.0.0"]);
  });
  it("honours a pin to a published version and ignores a pin to anything else", () => {
    assert.deepEqual(liveVersions(rows, { a: "1.0.0" }).map((r) => `${r.name}@${r.version}`), ["a@1.0.0", "c@3.0.0"]);
    assert.deepEqual(liveVersions(rows, { a: "2.0.0", c: "9.9.9" }).map((r) => `${r.name}@${r.version}`), ["a@1.1.0", "c@3.0.0"]);
  });
});

describe("draftsFor", () => {
  it("returns the creator's newest unpublished ready build per program", () => {
    const rows = [
      row("a", "2.0.0", { uploadedAt: "2026-10-06T00:00:00Z" }),
      row("a", "2.1.0", { uploadedAt: "2026-10-07T00:00:00Z" }),
      row("a", "2.2.0", { uploadedAt: "2026-10-08T00:00:00Z", status: "pending" }),
      row("b", "1.0.0", { creatorId: "u2" }),
    ];
    assert.deepEqual(draftsFor(rows, "u1").map((r) => `${r.name}@${r.version}`), ["a@2.1.0"]);
    assert.deepEqual(draftsFor(rows, undefined), []);
  });
  it("engineView carries only what an engine needs", () => {
    assert.deepEqual(Object.keys(engineView(row("a", "1.0.0"), true)), ["name", "version", "hash", "bytes", "manifest", "publishedAt", "draft", "pinned"]);
  });
});

describe("the current pointer", () => {
  // Distinct hashes: a pin is by hash, and the shared fixture hash would make every row match.
  const rows = [
    row("a", "1.0.0", { publishedAt: "2026-10-01T00:00:00Z", hash: "1".repeat(64) }),
    row("a", "1.1.0", { publishedAt: "2026-10-05T00:00:00Z", current: true, hash: "2".repeat(64) }),
    row("a", "2.0.0", { publishedAt: null, hash: "3".repeat(64) }),
    row("c", "3.0.0", { publishedAt: "2026-10-03T00:00:00Z", hash: "4".repeat(64) }),
  ];
  const ids = (r: any[]) => r.map((x) => `${x.name}@${x.version}`);
  it("currentRows: the marked build per name; a name without a mark falls back to the newest published", () => {
    assert.deepEqual(ids(currentRows(rows)), ["a@1.1.0", "c@3.0.0"]);
    assert.deepEqual(ids(currentRows(rows.map((r) => ({ ...r, current: false })))), ["a@1.1.0", "c@3.0.0"]);
  });
  it("publish moves the pointer to the new build unless the current one is pinned", () => {
    const a10 = rows[0], a11 = rows[1];
    const p = publishPlan(rows, a10.id);
    assert.deepEqual(p, { becameCurrent: true, changes: { [a10.id]: { current: true }, [a11.id]: { current: false, pinned: false } } });
    const held = publishPlan(rows.map((r) => (r.id === a11.id ? { ...r, pinned: true } : r)), a10.id);
    assert.deepEqual(held, { becameCurrent: false, changes: {} });
  });
  it("unpublish clears the pointer and the newest other published build takes it", () => {
    const a10 = rows[0], a11 = rows[1];
    assert.deepEqual(unpublishPlan(rows, a11.id), { nextId: a10.id, changes: { [a11.id]: { current: false, pinned: false }, [a10.id]: { current: true } } });
    assert.deepEqual(unpublishPlan(rows, a10.id), { nextId: null, changes: { [a10.id]: { current: false, pinned: false } } });
  });
  it("pin by hash makes a published build current and frozen; unpin keeps current and thaws; a draft cannot be pinned", () => {
    const a10 = rows[0], a11 = rows[1], a20 = rows[2];
    assert.deepEqual(pinPlan(rows, "a", a10.hash), { ok: true, changes: { [a10.id]: { current: true, pinned: true }, [a11.id]: { current: false, pinned: false } } });
    assert.deepEqual(pinPlan(rows, "a", null), { ok: true, changes: { [a11.id]: { current: true, pinned: false } } });
    assert.equal((pinPlan(rows, "a", a20.hash) as any).ok, false);
    assert.equal((pinPlan(rows, "a", "f".repeat(64)) as any).ok, false);
  });
  it("pinsOf derives the old name → version map from pinned current builds", () => {
    assert.deepEqual(pinsOf(rows), {});
    assert.deepEqual(pinsOf(rows.map((r) => (r.version === "1.1.0" ? { ...r, pinned: true } : r))), { a: "1.1.0" });
  });
});
