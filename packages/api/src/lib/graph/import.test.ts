import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { newNodeOwner } from "./import";

const ME = "user-1";

describe("newNodeOwner", () => {
  it("leaves the shared instructions without an owner", () => {
    assert.equal(newNodeOwner({ kind: "domain", name: "shared", meta: { shared: true } }, ME), null);
  });

  it("leaves the default (fallback) domain without an owner", () => {
    assert.equal(newNodeOwner({ kind: "domain", name: "generic", meta: { fallback: true } }, ME), null);
  });

  it("recognises the built-ins by name when meta is missing", () => {
    assert.equal(newNodeOwner({ kind: "domain", name: "Shared", meta: null }, ME), null);
    assert.equal(newNodeOwner({ kind: "domain", name: "generic", meta: {} }, ME), null);
  });

  it("gives an ordinary domain to the importer", () => {
    assert.equal(newNodeOwner({ kind: "domain", name: "sales", meta: { threshold: 0.5 } }, ME), ME);
  });

  it("gives each instruction (part) to the importer, even one named like a built-in", () => {
    assert.equal(newNodeOwner({ kind: "part", name: "date-ranges", meta: {} }, ME), ME);
    assert.equal(newNodeOwner({ kind: "part", name: "shared", meta: { shared: true } }, ME), ME);
  });
});
