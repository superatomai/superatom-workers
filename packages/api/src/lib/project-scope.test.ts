import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PROJECT_SCOPES, reachesAllProjects } from "./project-scope";

describe("reachesAllProjects", () => {
  it("an Owner reaches every project, even if their row says selected", () => {
    assert.equal(reachesAllProjects({ userId: "u", userRole: "org_admin", orgRole: "owner", projectScope: "selected" }), true);
  });

  it("the platform super admin reaches every project", () => {
    assert.equal(reachesAllProjects({ userId: "u", userRole: "super_admin", projectScope: "selected" }), true);
  });

  it("anyone whose scope is all reaches every project", () => {
    assert.equal(reachesAllProjects({ userId: "u", userRole: "org_admin", orgRole: "admin", projectScope: "all" }), true);
    assert.equal(reachesAllProjects({ userId: "u", userRole: "member", orgRole: "analyst", projectScope: "all" }), true);
  });

  it("a missing scope (an older row) means all, as before scopes existed", () => {
    assert.equal(reachesAllProjects({ userId: "u", userRole: "member", orgRole: "member" }), true);
    assert.equal(reachesAllProjects({ userId: "u", userRole: "member", projectScope: null }), true);
  });

  it("an Admin, member or custom role limited to selected projects does not", () => {
    for (const orgRole of ["admin", "member", "analyst"]) {
      assert.equal(
        reachesAllProjects({ userId: "u", userRole: orgRole === "admin" ? "org_admin" : "member", orgRole, projectScope: "selected" }),
        false,
        orgRole
      );
    }
  });

  it("knows exactly the two scopes", () => {
    assert.deepEqual([...PROJECT_SCOPES], ["all", "selected"]);
  });
});
