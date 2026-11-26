import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RESERVED_KEYS, checkedPermissions, keyFrom } from "../../../src/routes/roles";

describe("a custom role's permissions", () => {
  it("accepts known permissions and drops repeats", () => {
    const got = checkedPermissions(["platform.access", "analytics.view", "dashboard.create", "analytics.view"]);
    assert.ok(got.ok);
    assert.deepEqual(got.ok && got.permissions, ["platform.access", "analytics.view", "dashboard.create"]);
  });

  it("refuses any permission without platform access, and names them", () => {
    const got = checkedPermissions(["dashboard.view", "analytics.export"]);
    assert.ok(!got.ok);
    assert.match(!got.ok ? got.error : "", /dashboard\.view, analytics\.export need platform\.access/);
  });

  it("accepts none: a role can start empty", () => {
    const got = checkedPermissions([]);
    assert.ok(got.ok);
  });

  it("refuses a permission that does not exist, and names it", () => {
    const got = checkedPermissions(["platform.access", "analytics.view", "made.up"]);
    assert.ok(!got.ok);
    assert.match(!got.ok ? got.error : "", /made\.up/);
  });

  it("refuses the powers fixed to the built-in roles: they are not permissions", () => {
    for (const p of ["members.manage", "admins.manage", "roles.manage", "access.manage", "org.edit", "org.settings"]) {
      const got = checkedPermissions(["platform.access", "analytics.view", p]);
      assert.ok(!got.ok, `${p} was accepted`);
    }
  });

  it("refuses a Members action without See members, and accepts it with", () => {
    const got = checkedPermissions(["platform.access", "members.edit"]);
    assert.ok(!got.ok);
    assert.match(!got.ok ? got.error : "", /members\.edit need members\.view/);
    assert.ok(checkedPermissions(["platform.access", "members.view", "members.edit"]).ok);
    assert.ok(checkedPermissions(["platform.access", "members.history"]).ok);
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
