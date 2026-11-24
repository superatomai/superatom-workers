import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { appActions, legacyPermission, objectActions, parseGrantLevel, projectPowers, type Caller } from "../../../src/lib/objects";
import { BUILTIN_ACTIONS, OBJECT_ACTIONS, type ObjectAction } from "../../../src/lib/object-policy";

describe("legacy sharing compatibility", () => {
  it("accepts the old grant names without changing their meaning", () => {
    assert.equal(parseGrantLevel("comment"), "view");
    assert.equal(parseGrantLevel("admin"), "manage");
    assert.equal(parseGrantLevel("edit"), "edit");
    assert.equal(parseGrantLevel("owner"), null);
  });

  it("refuses anything that is not a role, owner included (owners are handed over, never granted)", () => {
    for (const v of ["owner", "Owner", "read", "", null, undefined, 3]) assert.equal(parseGrantLevel(v), null);
  });

  it("returns the old permission names for built-in levels", () => {
    assert.equal(legacyPermission("view"), "view");
    assert.equal(legacyPermission("edit"), "edit");
    assert.equal(legacyPermission("manage"), "admin");
    assert.equal(legacyPermission(null), null);
  });
});

// ── The rules for one app ────────────────────────────────────────────────────
const ORG = "org-a";
const member: Caller = { userId: "u-member", orgId: ORG, userRole: "member", roleId: "r-member", permissions: [] };
const admin: Caller = { userId: "u-admin", orgId: ORG, userRole: "org_admin", roleId: "r-admin", permissions: [] };
const superAdmin: Caller = { userId: "u-super", orgId: null, userRole: "super_admin", roleId: null, permissions: [] };
const withPermissions = (permissions: string[]): Caller => ({ ...member, permissions });

const app = (over: Partial<{ id: string; type: string; isDefault: boolean }> = {}) =>
  ({ id: "app-1", type: "dashboard", isDefault: false, ...over }) as Parameters<typeof appActions>[1];
const object = (over: Partial<{ ownerId: string | null; status: string; orgId: string; type: string }> = {}) =>
  ({ ownerId: "u-someone", status: "active", orgId: ORG, type: "dashboard", ...over }) as Parameters<typeof appActions>[3];

/** The caller's actions on one dashboard, with the options a test cares about. */
const on = (
  caller: Caller,
  opts: { grants?: ObjectAction[]; denies?: ObjectAction[]; isDefault?: boolean; orgDefault?: string | null; ownerId?: string | null; status?: string; appOrg?: string; inScope?: boolean; type?: string } = {}
) =>
  appActions(
    caller,
    app({ isDefault: opts.isDefault ?? false, type: opts.type ?? "dashboard" }),
    opts.appOrg ?? ORG,
    object({ ownerId: opts.ownerId ?? "u-someone", status: opts.status ?? "active", type: opts.type ?? "dashboard" }),
    opts.grants ?? [],
    opts.denies ?? [],
    opts.orgDefault ?? null,
    opts.inScope ?? true
  );
const ALL = [...OBJECT_ACTIONS];

describe("appActions: who can do what on one app", () => {
  it("gives an org Owner or Admin every action on every app in their org", () => {
    assert.deepEqual(on(admin), ALL);
  });

  it("gives the platform super admin every action, in any org", () => {
    assert.deepEqual(on(superAdmin, { appOrg: "org-b" }), ALL);
  });

  it("gives nothing on another organization's app, whatever is granted", () => {
    assert.deepEqual(on(member, { appOrg: "org-b", grants: [...BUILTIN_ACTIONS.manage], isDefault: true }), []);
    assert.deepEqual(on(admin, { appOrg: "org-b" }), []);
  });

  it("gives nothing outside the caller's project scope, whatever else applies", () => {
    assert.deepEqual(on(member, { inScope: false, grants: [...BUILTIN_ACTIONS.manage] }), []);
    assert.deepEqual(on(member, { inScope: false, ownerId: "u-member" }), []);
    assert.deepEqual(on(member, { inScope: false, isDefault: true }), []);
  });

  it("limits a scoped Admin too: outside their projects they have nothing", () => {
    assert.deepEqual(on(admin, { inScope: false }), []);
    assert.deepEqual(on(admin, { inScope: true }), ALL);
  });

  it("gives a member nothing without an owner, a grant, a permission or a default", () => {
    assert.deepEqual(on(member), []);
  });

  it("gives the owner every action, handing it over included", () => {
    assert.deepEqual(on(member, { ownerId: "u-member" }), ALL);
  });

  it("gives exactly the actions of the roles granted, added together", () => {
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.view] }), ["view"]);
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.view, ...BUILTIN_ACTIONS.edit] }), [...BUILTIN_ACTIONS.edit]);
  });

  it("adds a project role and the app's own role, the higher one winning either way round", () => {
    // Viewer on the project, Editor on this app (the caller passes both lists in).
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.view, ...BUILTIN_ACTIONS.edit] }), [...BUILTIN_ACTIONS.edit]);
    // Editor on the project, Viewer on the app: still Editor; an app role never lowers it.
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.edit, ...BUILTIN_ACTIONS.view] }), [...BUILTIN_ACTIONS.edit]);
  });

  it("gives exactly a custom role's actions: edit without delete", () => {
    const actions = on(member, { grants: ["view", "edit"] });
    assert.deepEqual(actions, ["view", "edit"]);
    assert.equal(actions.includes("delete"), false);
  });

  it("gives view on an app open to everyone, and on the org's landing app", () => {
    assert.deepEqual(on(member, { isDefault: true }), ["view"]);
    assert.deepEqual(on(member, { orgDefault: "app-1" }), ["view"]);
  });

  it("lets a grant raise an app that is open to everyone above view", () => {
    assert.deepEqual(on(member, { isDefault: true, grants: [...BUILTIN_ACTIONS.manage] }), [...BUILTIN_ACTIONS.manage]);
  });

  it("hides a disabled app from anyone who cannot share or disable it", () => {
    assert.deepEqual(on(member, { status: "disabled", grants: [...BUILTIN_ACTIONS.edit] }), []);
    assert.deepEqual(on(member, { status: "disabled", isDefault: true }), []);
  });

  it("keeps a disabled app for its managers, its owner and admins", () => {
    assert.deepEqual(on(member, { status: "disabled", grants: [...BUILTIN_ACTIONS.manage] }), [...BUILTIN_ACTIONS.manage]);
    assert.deepEqual(on(member, { status: "disabled", ownerId: "u-member" }), ALL);
    assert.deepEqual(on(admin, { status: "disabled" }), ALL);
  });
});

describe("appActions: the org role's permissions", () => {
  it("gives exactly the actions the role's permissions name, on every app of that kind", () => {
    assert.deepEqual(on(withPermissions(["dashboard.view"])), ["view"]);
    assert.deepEqual(on(withPermissions(["dashboard.view", "dashboard.edit"])), ["view", "edit"]);
  });

  it("maps each kind of app to its own permissions, chat agents to agent.*", () => {
    assert.deepEqual(on(withPermissions(["agent.view"]), { type: "chat_agent" }), ["view"]);
    assert.deepEqual(on(withPermissions(["dashboard.view"]), { type: "report" }), []);
  });

  it("gives nothing without view: edit alone does not open an app", () => {
    assert.deepEqual(on(withPermissions(["dashboard.edit", "dashboard.delete"])), []);
  });

  it("never gives share, disable or handover: those come only from a share or ownership", () => {
    const actions = on(withPermissions(["dashboard.view", "dashboard.create", "dashboard.edit", "dashboard.delete"]));
    for (const a of ["share", "disable", "handover"] as const) assert.equal(actions.includes(a), false, a);
  });

  it("adds the role's permissions to a share", () => {
    assert.deepEqual(on(withPermissions(["dashboard.view", "dashboard.delete"]), { grants: ["view", "edit"] }), ["view", "edit", "delete"]);
  });
});

describe("appActions: deny rules", () => {
  it("a deny beats a share", () => {
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.edit], denies: ["delete"] }), ["view", "create", "edit"]);
  });

  it("a deny beats the role's permissions", () => {
    assert.deepEqual(on(withPermissions(["dashboard.view", "dashboard.edit"]), { denies: ["edit"] }), ["view"]);
  });

  it("a deny beats an Admin", () => {
    assert.equal(on(admin, { denies: ["delete"] }).includes("delete"), false);
  });

  it("no deny touches its own owner", () => {
    assert.deepEqual(on(member, { ownerId: "u-member", denies: ["share", "view"] }), ALL);
  });

  it("denying view takes everything away, even from an Admin", () => {
    assert.deepEqual(on(admin, { denies: ["view"] }), []);
    assert.deepEqual(on(member, { grants: [...BUILTIN_ACTIONS.manage], denies: ["view"] }), []);
  });

  it("a deny on an action someone never had changes nothing", () => {
    assert.deepEqual(on(member, { grants: ["view"], denies: ["delete"] }), ["view"]);
  });
});

// ── Projects and data sources ───────────────────────────────────────────────
const project = (over: Partial<{ ownerId: string | null; status: string; orgId: string }> = {}) =>
  ({ ownerId: "u-someone", status: "active", orgId: ORG, type: "project", ...over }) as Parameters<typeof objectActions>[1];
const source = (over: Partial<{ ownerId: string | null; status: string }> = {}) =>
  ({ ownerId: null, status: "active", orgId: ORG, type: "source", ...over }) as Parameters<typeof objectActions>[1];

describe("objectActions: projects and data sources", () => {
  it("gives an Admin, the super admin and the owner everything", () => {
    assert.deepEqual(objectActions(admin, project(), [], [], true), ALL);
    assert.deepEqual(objectActions(superAdmin, project({ orgId: "org-b" }), [], [], true), ALL);
    assert.deepEqual(objectActions(member, project({ ownerId: "u-member" }), [], [], true), ALL);
  });

  it("gives nothing outside the org or the caller's project scope", () => {
    assert.deepEqual(objectActions(member, project({ orgId: "org-b" }), [...BUILTIN_ACTIONS.manage], [], true), []);
    assert.deepEqual(objectActions(admin, project(), [], [], false), []);
  });

  it("gives exactly the granted role on a project", () => {
    assert.deepEqual(objectActions(member, project(), [...BUILTIN_ACTIONS.view], [], true), ["view"]);
    assert.deepEqual(objectActions(member, project(), [...BUILTIN_ACTIONS.manage], [], true), [...BUILTIN_ACTIONS.manage]);
  });

  it("project.create does not let someone create things inside an existing project", () => {
    const actions = objectActions(withPermissions(["project.view", "project.create"]), project(), [], [], true);
    assert.deepEqual(actions, ["view"]);
  });

  it("gives a data source the role's source permissions", () => {
    assert.deepEqual(objectActions(withPermissions(["source.view", "source.edit"]), source(), [], [], true), ["view", "edit"]);
  });

  it("a deny on a project or source beats everything, an Admin included", () => {
    assert.deepEqual(objectActions(admin, project(), [], ["view"], true), []);
    assert.equal(objectActions(admin, source(), [], ["delete"], true).includes("delete"), false);
  });

  it("no deny touches the project's own owner", () => {
    assert.deepEqual(objectActions(member, project({ ownerId: "u-member" }), [], ["view"], true), ALL);
  });

  it("hides a disabled source from those who cannot share or disable it", () => {
    assert.deepEqual(objectActions(member, source({ status: "disabled" }), [...BUILTIN_ACTIONS.edit], [], true), []);
    assert.deepEqual(objectActions(member, source({ status: "disabled" }), [...BUILTIN_ACTIONS.manage], [], true), [...BUILTIN_ACTIONS.manage]);
  });
});

describe("projectPowers: renaming or deleting a project itself", () => {
  const someone = { userId: "u1", permissions: [] as string[] };
  const holder = { userId: "u1", permissions: ["project.edit", "project.delete"] };
  const project = (actions: readonly ObjectAction[], ownerId: string | null = "u9") => ({ actions, ownerId });

  it("lets a shared Manager rename the project, but not delete it", () => {
    assert.deepEqual(projectPowers(project(BUILTIN_ACTIONS.manage), someone), { canRename: true, canDelete: false });
  });

  it("lets a shared Editor do neither", () => {
    assert.deepEqual(projectPowers(project(BUILTIN_ACTIONS.edit), someone), { canRename: false, canDelete: false });
  });

  it("lets the project's owner delete it", () => {
    assert.equal(projectPowers(project(OBJECT_ACTIONS, "u1"), someone).canDelete, true);
  });

  it("lets project.edit and project.delete rename and delete", () => {
    assert.deepEqual(projectPowers(project(["view", "edit", "delete"]), holder), { canRename: true, canDelete: true });
  });

  it("follows a deny rule over the permission", () => {
    assert.deepEqual(projectPowers(project(["view"]), holder), { canRename: false, canDelete: false });
  });

  it("gives nothing without access, and never treats a missing owner as the caller", () => {
    assert.deepEqual(projectPowers(null, someone), { canRename: false, canDelete: false });
    assert.equal(projectPowers(project(OBJECT_ACTIONS, null), someone).canDelete, false);
  });
});
