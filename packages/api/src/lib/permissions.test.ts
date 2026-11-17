import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BUILT_IN_ROLES,
  OWNER_ONLY,
  PERMISSIONS,
  PERMISSION_CATALOGUE,
  mayGrantRole,
  orgRoleOf,
  parseOrgRole,
  permissionsOf,
  roleKindFor,
} from "./permissions";

describe("the permission catalogue", () => {
  it("names every permission once, as module.action", () => {
    assert.equal(new Set(PERMISSIONS).size, PERMISSIONS.length);
    for (const p of PERMISSIONS) assert.match(p, /^[a-z_]+\.[a-z_]+$/);
  });

  it("gives every permission a label, under a module with a label", () => {
    for (const m of PERMISSION_CATALOGUE) {
      assert.ok(m.label);
      for (const p of m.permissions) assert.ok(p.label, `${p.key} has no label`);
    }
  });

  it("keeps exactly the three Owner-only permissions", () => {
    assert.deepEqual([...OWNER_ONLY].sort(), ["admins.manage", "org.settings", "roles.manage"]);
  });
});

describe("built-in roles", () => {
  it("an Owner holds every permission", () => {
    assert.deepEqual([...BUILT_IN_ROLES.owner].sort(), [...PERMISSIONS].sort());
  });

  it("an Admin holds everything but the Owner-only permissions", () => {
    for (const p of OWNER_ONLY) assert.ok(!BUILT_IN_ROLES.admin.includes(p), `admin holds ${p}`);
    assert.equal(BUILT_IN_ROLES.admin.length, PERMISSIONS.length - OWNER_ONLY.length);
  });

  it("a Member holds none: they use the runtime only", () => {
    assert.deepEqual([...BUILT_IN_ROLES.member], []);
  });
});

describe("orgRoleOf", () => {
  it("reads the role row's key when there is one", () => {
    assert.equal(orgRoleOf({ role: "org_admin", roleKey: "owner" }), "owner");
    assert.equal(orgRoleOf({ role: "member", roleKey: "analyst" }), "analyst");
  });

  it("falls back to users.role when role_id is empty", () => {
    assert.equal(orgRoleOf({ role: "org_admin", roleKey: null }), "admin");
    assert.equal(orgRoleOf({ role: "member" }), "member");
  });

  it("reports the platform super admin as such, whatever the row says", () => {
    assert.equal(orgRoleOf({ role: "super_admin", roleKey: "member" }), "super_admin");
  });
});

describe("permissionsOf", () => {
  it("gives the platform super admin every permission", () => {
    assert.deepEqual(permissionsOf({ role: "super_admin" }).sort(), [...PERMISSIONS].sort());
  });

  it("gives a built-in role its list from code, ignoring role_permissions rows", () => {
    const owner = permissionsOf({ role: "org_admin", roleKey: "owner", roleIsSystem: true, customPermissions: ["junk"] });
    assert.ok(owner.includes("admins.manage"));
    assert.ok(!owner.includes("junk" as never));
    assert.ok(!permissionsOf({ role: "org_admin", roleKey: "admin", roleIsSystem: true }).includes("admins.manage"));
  });

  it("treats an empty role_id as the role users.role implies", () => {
    assert.ok(permissionsOf({ role: "org_admin", roleKey: null }).includes("members.manage"));
    assert.ok(!permissionsOf({ role: "org_admin", roleKey: null }).includes("admins.manage"));
    assert.deepEqual(permissionsOf({ role: "member", roleKey: null }), []);
  });

  it("gives a custom role its rows, dropping unknown and Owner-only permissions", () => {
    const got = permissionsOf({
      role: "member",
      roleKey: "analyst",
      roleIsSystem: false,
      customPermissions: ["analytics.view", "dashboards.create", "made.up", "admins.manage", "roles.manage"],
    });
    assert.deepEqual(got.sort(), ["analytics.view", "dashboards.create"]);
  });

  it("gives a custom role with no rows nothing", () => {
    assert.deepEqual(permissionsOf({ role: "member", roleKey: "empty", roleIsSystem: false, customPermissions: null }), []);
  });
});

describe("parseOrgRole and roleKindFor", () => {
  it("reads the built-in roles, and the old org_admin as admin", () => {
    assert.equal(parseOrgRole("owner"), "owner");
    assert.equal(parseOrgRole("admin"), "admin");
    assert.equal(parseOrgRole("member"), "member");
    assert.equal(parseOrgRole("org_admin"), "admin");
  });

  it("refuses anything else, super_admin included", () => {
    for (const v of ["super_admin", "Owner", "", null, undefined, 1, {}]) assert.equal(parseOrgRole(v), null);
  });

  it("stores Owner and Admin as org_admin, Member as member", () => {
    assert.equal(roleKindFor("owner"), "org_admin");
    assert.equal(roleKindFor("admin"), "org_admin");
    assert.equal(roleKindFor("member"), "member");
  });
});

describe("mayGrantRole", () => {
  it("allows a role whose every permission the giver holds", () => {
    assert.ok(mayGrantRole(["analytics.view", "dashboards.create", "members.manage"], { permissions: ["analytics.view"] }));
    assert.ok(mayGrantRole([], { permissions: [] }));
  });

  it("refuses a role carrying even one permission the giver lacks", () => {
    assert.ok(!mayGrantRole(["members.manage", "analytics.view"], { permissions: ["analytics.view", "sources.manage"] }));
  });

  it("lets an Admin give an Admin's permissions but not an Owner's", () => {
    assert.ok(mayGrantRole(BUILT_IN_ROLES.admin, { permissions: BUILT_IN_ROLES.admin }));
    assert.ok(!mayGrantRole(BUILT_IN_ROLES.admin, { permissions: BUILT_IN_ROLES.owner }));
  });
});
