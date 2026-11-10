import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { branchToRecord, layerSummary } from "./publish-summary";

const MB = 1024 * 1024;

// 2026-11-10, first publish of install-test: ~640 MB of deps went up first, then the summary said
// "layers: new 3.9 MB, reused 638.4 MB", and the project kept code_branch "main" for a dev build.
describe("publish summary", () => {
  it("a new dependency set is reported as uploaded, not as reused", () => {
    assert.equal(
      layerSummary({ newBytes: 3.9 * MB, reusedBytes: 638.4 * MB, depsUploadedBytes: 638.4 * MB }),
      "layers: deps 638.4 MB uploaded (new dependency set), code 3.9 MB new",
    );
  });
  it("a code-only release reads as before", () => {
    assert.equal(layerSummary({ newBytes: 4.4 * MB, reusedBytes: 638.5 * MB, depsUploadedBytes: 0 }), "layers: new 4.4 MB, reused 638.5 MB");
  });
});

describe("branchToRecord", () => {
  it("records the branch a release was built from when it differs", () => {
    assert.equal(branchToRecord("main", "dev", false), "dev");
  });
  it("leaves it when it already matches, for a --local test build, and for the baseline", () => {
    assert.equal(branchToRecord("dev", "dev", false), null);
    assert.equal(branchToRecord("main", "dev", true), null);
    assert.equal(branchToRecord(undefined, "dev", false), null);
  });
});
