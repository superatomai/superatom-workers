import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { depsKey, hasDepsStage } from "./deps-image";

function tree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "deps-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

const base = {
  Dockerfile: "FROM node AS install\nFROM node AS deps\nFROM deps\n",
  "backend/package.json": "{}",
  "backend/pnpm-lock.yaml": "lock-1",
};

describe("deps image key", () => {
  it("is the same for a code-only change, so the release reuses the dependency image", () => {
    const a = tree({ ...base, "backend/src/app.ts": "v1" });
    const b = tree({ ...base, "backend/src/app.ts": "v2" });
    assert.equal(depsKey(a), depsKey(b));
  });

  it("changes with a lockfile, a manifest or the Dockerfile", () => {
    const k = depsKey(tree(base));
    assert.notEqual(depsKey(tree({ ...base, "backend/pnpm-lock.yaml": "lock-2" })), k);
    assert.notEqual(depsKey(tree({ ...base, "backend/package.json": '{"x":1}' })), k);
    assert.notEqual(depsKey(tree({ ...base, Dockerfile: base.Dockerfile + "RUN true\n" })), k);
  });

  it("tells a missing file from an empty one", () => {
    assert.notEqual(depsKey(tree({ ...base, "backend/.npmrc": "" })), depsKey(tree(base)));
  });
});

describe("deps stage detection", () => {
  it("finds the split Dockerfile and leaves an old one on the old path", () => {
    assert.equal(hasDepsStage("FROM node:24-bookworm-slim AS deps\n"), true);
    assert.equal(hasDepsStage("FROM node:24 AS build\nFROM node:24\n"), false);
  });
});
