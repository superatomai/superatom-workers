import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scopedOrgId } from "./auth";

// Analytics, export, speech usage and checklist reports read ?orgId=; only super admins may choose it.
const ctx = (role: string, own: string | undefined, query?: string) => ({
  req: { query: (n: string) => (n === "orgId" ? query : undefined) },
  get: (k: "userRole" | "orgId") => (k === "userRole" ? role : own),
});

describe("scopedOrgId", () => {
  it("an org admin passing another org's id still gets only their own org", () => {
    assert.equal(scopedOrgId(ctx("org_admin", "org-a", "org-b")), "org-a");
  });

  it("an org admin with no ?orgId= gets their own org", () => {
    assert.equal(scopedOrgId(ctx("org_admin", "org-a")), "org-a");
  });

  it("a super admin may pick any org, or see all with none", () => {
    assert.equal(scopedOrgId(ctx("super_admin", "org-a", "org-b")), "org-b");
    assert.equal(scopedOrgId(ctx("super_admin", undefined)), undefined);
  });
});
