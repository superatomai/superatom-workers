import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RESERVED_KEYS, checkedPermissions, keyFrom } from "./roles";

describe("a custom role's permissions", () => {
  it("accepts known permissions and drops repeats", () => {
    const got = checkedPermissions(["analytics.view", "dashboards.create", "analytics.view"]);
    assert.ok(got.ok);
    assert.deepEqual(got.ok && got.permissions, ["analytics.view", "dashboards.create"]);
  });

  it("accepts none: a role can start empty", () => {
    const got = checkedPermissions([]);
    assert.ok(got.ok);
  });

  it("refuses a permission that does not exist, and names it", () => {
    const got = checkedPermissions(["analytics.view", "made.up"]);
    assert.ok(!got.ok);
    assert.match(!got.ok ? got.error : "", /made\.up/);
  });

  it("refuses every Owner-only permission", () => {
    for (const p of ["admins.manage", "roles.manage", "org.settings"]) {
      const got = checkedPermissions(["analytics.view", p]);
      assert.ok(!got.ok, `${p} was accepted`);
    }
  });

  it("refuses anything that is not a list", () => {
    for (const v of ["analytics.view", null, undefined, { a: 1 }]) assert.ok(!checkedPermissions(v).ok);
  });
});

describe("a custom role's key", () => {
  it("is made from its name", () => {
    assert.equal(keyFrom("Data Lead"), "data_lead");
    assert.equal(keyFrom("  Sales / North  "), "sales_north");
    assert.equal(keyFrom("Analyst 2"), "analyst_2");
  });

  it("is at most 64 characters", () => {
    assert.equal(keyFrom("x".repeat(100)).length, 64);
  });

  it("cannot be a built-in role's", () => {
    for (const name of ["Owner", "admin", "Member", "org admin", "Super Admin"]) {
      assert.ok(RESERVED_KEYS.includes(keyFrom(name)), `${name} → ${keyFrom(name)} is not reserved`);
    }
  });
});
