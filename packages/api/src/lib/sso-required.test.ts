import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { passwordLoginUsers, ssoRequiredFor, ssoRequiredOrgs } from "./sso-required";
import type { Database } from "../db";

const BLUELINX = "org-bluelinx";
const TOTAL_GROUP = "org-total-group";

/** sso_configs rows as the query returns them; only active configs are returned by the real WHERE. */
function fakeDb(rows: Array<{ orgId: string; domains: unknown }>) {
  return {
    select: () => ({
      from: () => ({
        where: async () => rows,
      }),
    }),
  } as unknown as Database;
}

describe("which emails must use SSO", () => {
  it("only the listed domain, matched exactly and case-insensitively", () => {
    assert.equal(ssoRequiredFor(["bluelinxco.com"], "Danielle.Rhea@BlueLinxCo.com"), true);
    assert.equal(ssoRequiredFor(["bluelinxco.com"], "gopinadh@superatom.ai"), false);
    assert.equal(ssoRequiredFor(["bluelinxco.com"], "x@notbluelinxco.com"), false);
    assert.equal(ssoRequiredFor(["bluelinxco.com"], "x@mail.bluelinxco.com"), false);
  });

  it("no setting (every other client today) never requires SSO", () => {
    for (const d of [null, undefined, [], "bluelinxco.com", {}]) assert.equal(ssoRequiredFor(d, "a@bluelinxco.com"), false, JSON.stringify(d));
  });

  it("only orgs whose own config lists the domain are returned", async () => {
    const db = fakeDb([
      { orgId: BLUELINX, domains: ["bluelinxco.com"] },
      { orgId: TOTAL_GROUP, domains: null },
    ]);
    assert.deepEqual([...(await ssoRequiredOrgs(db, [BLUELINX, TOTAL_GROUP], "kate.riel@bluelinxco.com"))], [BLUELINX]);
    assert.deepEqual([...(await ssoRequiredOrgs(db, [BLUELINX, TOTAL_GROUP], "chetan@superatom.ai"))], []);
    assert.deepEqual([...(await ssoRequiredOrgs(db, [], "kate.riel@bluelinxco.com"))], []);
  });
});

describe("password login", () => {
  const u = (orgId: string | null) => ({ orgId });

  it("a BlueLinx user is sent to SSO instead of 'wrong password'", () => {
    const r = passwordLoginUsers([u(BLUELINX)], new Set([BLUELINX]));
    assert.equal(r.ssoRequired, true);
    assert.deepEqual(r.users, []);
  });

  it("other clients' users log in with a password exactly as before", () => {
    const r = passwordLoginUsers([u(TOTAL_GROUP)], new Set());
    assert.equal(r.ssoRequired, false);
    assert.deepEqual(r.users, [u(TOTAL_GROUP)]);
  });

  it("someone in a SSO-only org and another org keeps password login to the other one", () => {
    const r = passwordLoginUsers([u(BLUELINX), u(TOTAL_GROUP)], new Set([BLUELINX]));
    assert.equal(r.ssoRequired, false);
    assert.deepEqual(r.users, [u(TOTAL_GROUP)]);
  });

  it("an unknown email stays a plain 'invalid email or password'", () => {
    assert.equal(passwordLoginUsers([], new Set([BLUELINX])).ssoRequired, false);
  });
});
