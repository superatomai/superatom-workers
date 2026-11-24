import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { approvedVersion, envLines } from "./lib";

describe("approvedVersion", () => {
  it("a super-admin pin wins over the admin's target", () => {
    assert.equal(approvedVersion("v1", "v2"), "v1");
  });
  it("the admin's target when nothing is pinned", () => {
    assert.equal(approvedVersion(null, "v2"), "v2");
  });
  it("null when nobody chose a version: publishing alone must not deploy", () => {
    assert.equal(approvedVersion(null, null), null);
    assert.equal(approvedVersion(undefined, ""), null);
  });
});

describe("TARGET_VERSION in the /api/update reply", () => {
  it("is present when chosen and absent otherwise, which old agents ignore", () => {
    assert.match(envLines({ RELEASE_VERSION: "v2", TARGET_VERSION: approvedVersion(null, "v2") }), /^TARGET_VERSION=v2$/m);
    assert.doesNotMatch(envLines({ RELEASE_VERSION: "v2", TARGET_VERSION: approvedVersion(null, null) }), /TARGET_VERSION/);
  });
});
