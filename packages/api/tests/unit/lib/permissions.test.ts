import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ADMIN_WITHHELD,
  BUILT_IN_ROLES,
  FIXED,
  PEOPLE_PERMISSIONS,
  PERMISSIONS,
  PERMISSION_CATALOGUE,
  hasFixedPower,
  mayGrantRole,
  orgRoleOf,
  parseOrgRole,
  permissionsOf,
  roleKindFor,
} from "../../../src/lib/permissions";

describe("the permission catalogue", () => {
  it("names every permission once, as resource.action", () => {
    assert.equal(new Set(PERMISSIONS).size, PERMISSIONS.length);
    for (const p of PERMISSIONS) assert.match(p, /^[a-z_]+\.[a-z_]+$/);
  });

  it("gives every permission a label, under a module with a label", () => {
    for (const m of PERMISSION_CATALOGUE) {
      assert.ok(m.label);
      for (const p of m.permissions) assert.ok(p.label, `${p.key} has no label`);
    }
  });

  it("gives every kind of object view, create, edit and delete", () => {
    for (const r of ["project", "source", "dashboard", "report", "agent", "app"]) {
      for (const a of ["view", "create", "edit", "delete"]) {
        assert.ok((PERMISSIONS as readonly string[]).includes(`${r}.${a}`), `${r}.${a} missing`);
      }
    }
  });

  it("has no way to delete feedback", () => {
    assert.ok(!(PERMISSIONS as readonly string[]).some((p) => p.startsWith("feedback.") && p.endsWith(".delete")));
    assert.ok(!(PERMISSIONS as readonly string[]).includes("feedback.delete"));
  });

  it("carries none of the powers fixed to the built-in roles, so no role can hand out roles", () => {
    for (const p of ["members.manage", "admins.manage", "roles.manage", "access.manage", "org.edit", "org.settings"]) {
      assert.ok(!(PERMISSIONS as readonly string[]).includes(p), `${p} is grantable`);
    }
  });

  it("splits managing people into separate permissions", () => {
    assert.deepEqual(
      [...PEOPLE_PERMISSIONS].sort(),
      ["members.assign", "members.create", "members.data_rules", "members.edit", "members.history", "members.reset_password", "members.view"]
    );
  });
});

describe("per-person limits", () => {
  const admin = { role: "org_admin" as const, roleKey: "admin", roleIsSystem: true };

  it("take people powers away from one Admin, leaving everything else", () => {
    const got = permissionsOf({ ...admin, limits: [...PEOPLE_PERMISSIONS] });
    for (const p of PEOPLE_PERMISSIONS) assert.ok(!got.includes(p), p);
    assert.ok(got.includes("project.create") && got.includes("source.edit"));
  });

  it("can take away any permission, not just people powers", () => {
    assert.ok(!permissionsOf({ ...admin, limits: ["source.delete"] }).includes("source.delete"));
  });

  it("only ever narrow: a limit naming something the role lacks gives nothing", () => {
    const member = permissionsOf({ role: "member", roleKey: "member", roleIsSystem: true, limits: ["project.create"] });
    assert.deepEqual(member, []);
  });

  it("never touch an Owner, a custom role or the super admin", () => {
    assert.deepEqual(permissionsOf({ role: "org_admin", roleKey: "owner", roleIsSystem: true, limits: ["members.view"] }).sort(), [...PERMISSIONS].sort());
    assert.deepEqual(permissionsOf({ role: "member", roleKey: "analyst", roleIsSystem: false, customPermissions: ["members.view"], limits: ["members.view"] }), ["members.view"]);
    assert.ok(permissionsOf({ role: "super_admin", limits: ["members.view"] }).includes("members.view"));
  });

  it("an Admin with no limits keeps everything the Admin role carries", () => {
    assert.deepEqual(permissionsOf(admin).sort(), [...BUILT_IN_ROLES.admin].sort());
  });
});

describe("built-in roles", () => {
  it("an Owner holds the whole catalogue", () => {
    assert.deepEqual([...BUILT_IN_ROLES.owner].sort(), [...PERMISSIONS].sort());
  });

  it("every permission is deliberately given to Admins or withheld from them, never by accident", () => {
    for (const p of PERMISSIONS) {
      const given = BUILT_IN_ROLES.admin.includes(p);
      const withheld = ADMIN_WITHHELD.includes(p);
      assert.ok(given !== withheld, `${p}: add it to ADMIN_PERMISSIONS or ADMIN_WITHHELD in lib/permissions.ts`);
    }
  });

  it("an Admin holds only catalogue permissions", () => {
    for (const p of BUILT_IN_ROLES.admin) assert.ok((PERMISSIONS as readonly string[]).includes(p), p);
  });

  it("a Member holds none: they use the runtime only", () => {
    assert.deepEqual([...BUILT_IN_ROLES.member], []);
  });
});

describe("fixed powers", () => {
  it("the Owner has all of them", () => {
    for (const power of Object.keys(FIXED) as (keyof typeof FIXED)[]) assert.ok(hasFixedPower("owner", power), power);
  });

  it("an Admin edits the org, but does not manage admins, roles or SSO", () => {
    assert.ok(hasFixedPower("admin", "editOrg"));
    assert.ok(!hasFixedPower("admin", "manageAdmins"));
    assert.ok(!hasFixedPower("admin", "manageRoles"));
    assert.ok(!hasFixedPower("admin", "orgSettings"));
  });

  it("a Member or any custom role has none, whatever permissions it carries", () => {
    for (const role of ["member", "data_lead", "manager", "", null, undefined]) {
      for (const power of Object.keys(FIXED) as (keyof typeof FIXED)[]) assert.ok(!hasFixedPower(role, power), `${role} ${power}`);
    }
  });

  it("the platform super admin has all of them", () => {
    for (const power of Object.keys(FIXED) as (keyof typeof FIXED)[]) assert.ok(hasFixedPower("super_admin", power), power);
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
    assert.ok(owner.includes("project.delete"));
    assert.ok(!owner.includes("junk" as never));
  });

  it("treats an empty role_id as the role users.role implies", () => {
    assert.ok(permissionsOf({ role: "org_admin", roleKey: null }).includes("source.edit"));
    assert.deepEqual(permissionsOf({ role: "member", roleKey: null }), []);
  });

  it("gives a custom role its rows, dropping unknown, retired and fixed ones", () => {
    const got = permissionsOf({
      role: "member",
      roleKey: "analyst",
      roleIsSystem: false,
      customPermissions: ["analytics.view", "dashboard.create", "made.up", "members.manage", "sources.manage"],
    });
    assert.deepEqual(got.sort(), ["analytics.view", "dashboard.create"]);
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
    assert.ok(mayGrantRole(["analytics.view", "dashboard.create"], { permissions: ["analytics.view"] }));
    assert.ok(mayGrantRole([], { permissions: [] }));
  });

  it("refuses a role carrying even one permission the giver lacks", () => {
    assert.ok(!mayGrantRole(["analytics.view"], { permissions: ["analytics.view", "source.edit"] }));
  });

  it("lets an Admin give any custom role: they hold the whole catalogue", () => {
    assert.ok(mayGrantRole(BUILT_IN_ROLES.admin, { permissions: BUILT_IN_ROLES.admin }));
  });
});
