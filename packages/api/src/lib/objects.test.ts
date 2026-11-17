import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { atLeast, legacyPermission, levelOf, parseGrantLevel, type Caller, type Level } from "./objects";

describe("levels", () => {
  it("are ordered view < comment < edit < manage < owner", () => {
    assert.ok(atLeast("owner", "manage"));
    assert.ok(atLeast("manage", "edit"));
    assert.ok(atLeast("edit", "comment"));
    assert.ok(atLeast("comment", "view"));
    assert.ok(atLeast("edit", "edit"));
    assert.ok(!atLeast("view", "comment"));
    assert.ok(!atLeast("edit", "manage"));
  });

  it("no level reaches nothing", () => {
    assert.ok(!atLeast(null, "view"));
    assert.ok(!atLeast(undefined, "view"));
  });
});

describe("parseGrantLevel", () => {
  it("reads the four grant levels", () => {
    for (const l of ["view", "comment", "edit", "manage"]) assert.equal(parseGrantLevel(l), l);
  });

  it("reads the old app permission admin as manage", () => {
    assert.equal(parseGrantLevel("admin"), "manage");
  });

  it("refuses owner (owners are handed over, never granted) and anything else", () => {
    for (const v of ["owner", "Owner", "read", "", null, undefined, 3]) assert.equal(parseGrantLevel(v), null);
  });
});

describe("legacyPermission", () => {
  it("names each level the way the platform and runtime still read it", () => {
    assert.equal(legacyPermission("view"), "view");
    assert.equal(legacyPermission("comment"), "view");
    assert.equal(legacyPermission("edit"), "edit");
    assert.equal(legacyPermission("manage"), "admin");
    assert.equal(legacyPermission("owner"), "admin");
    assert.equal(legacyPermission(null), null);
  });
});

describe("levelOf: a caller's level on an app", () => {
  const ORG = "org-a";
  const member: Caller = { userId: "u-member", orgId: ORG, userRole: "member", roleId: "r-member" };
  const admin: Caller = { userId: "u-admin", orgId: ORG, userRole: "org_admin", roleId: "r-admin" };
  const superAdmin: Caller = { userId: "u-super", orgId: null, userRole: "super_admin", roleId: null };

  const app = (over: Partial<{ id: string; isDefault: boolean }> = {}) =>
    ({ id: "app-1", isDefault: false, ...over }) as Parameters<typeof levelOf>[1];
  const object = (over: Partial<{ ownerId: string | null; status: string }> = {}) =>
    ({ ownerId: "u-someone", status: "active", ...over }) as Parameters<typeof levelOf>[3];
  const level = (caller: Caller, opts: { grants?: Level[]; isDefault?: boolean; ownerId?: string | null; status?: string; orgDefault?: string | null; appOrg?: string; inScope?: boolean } = {}) =>
    levelOf(
      caller,
      app({ isDefault: opts.isDefault ?? false }),
      opts.appOrg ?? ORG,
      object({ ownerId: opts.ownerId ?? "u-someone", status: opts.status ?? "active" }),
      opts.grants ?? [],
      opts.orgDefault ?? null,
      opts.inScope ?? true
    );

  it("gives nothing on an app whose project is outside the caller's scope, whatever else applies", () => {
    assert.equal(level(member, { inScope: false, grants: ["manage"] }), null);
    assert.equal(level(member, { inScope: false, ownerId: "u-member" }), null);
    assert.equal(level(member, { inScope: false, isDefault: true }), null);
  });

  it("limits a scoped Admin too: outside their projects they have no level", () => {
    assert.equal(level(admin, { inScope: false }), null);
    assert.equal(level(admin, { inScope: true }), "owner");
  });

  it("gives an org Owner or Admin every level on every app in their org", () => {
    assert.equal(level(admin), "owner");
  });

  it("gives the platform super admin every level, in any org", () => {
    assert.equal(level(superAdmin, { appOrg: "org-b" }), "owner");
  });

  it("gives nothing on another organization's app, whatever is granted", () => {
    assert.equal(level(member, { appOrg: "org-b", grants: ["manage"], isDefault: true }), null);
    assert.equal(level(admin, { appOrg: "org-b" }), null);
  });

  it("gives a member nothing without an owner, a grant or a default", () => {
    assert.equal(level(member), null);
  });

  it("gives the owner owner", () => {
    assert.equal(level(member, { ownerId: "u-member" }), "owner");
  });

  it("takes the highest of the member's grants", () => {
    assert.equal(level(member, { grants: ["view", "edit", "comment"] }), "edit");
  });

  it("gives view on an app open to everyone, and on the org's landing app", () => {
    assert.equal(level(member, { isDefault: true }), "view");
    assert.equal(level(member, { orgDefault: "app-1" }), "view");
  });

  it("lets a grant raise an app that is open to everyone above view", () => {
    assert.equal(level(member, { isDefault: true, grants: ["manage"] }), "manage");
  });

  it("hides a disabled app from anyone below manage", () => {
    assert.equal(level(member, { status: "disabled", grants: ["edit"] }), null);
    assert.equal(level(member, { status: "disabled", isDefault: true }), null);
  });

  it("keeps a disabled app for those who manage or own it", () => {
    assert.equal(level(member, { status: "disabled", grants: ["manage"] }), "manage");
    assert.equal(level(member, { status: "disabled", ownerId: "u-member" }), "owner");
    assert.equal(level(admin, { status: "disabled" }), "owner");
  });
});
