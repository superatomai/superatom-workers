import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { removalBlockedReason, REMOVE_AFTER_SILENT_MS } from "./releases";

describe("removing an install", () => {
  const now = Date.parse("2026-11-05T10:00:00Z");
  it("is refused while it still checks in: its next check-in would re-create it", () => {
    assert.match(removalBlockedReason(new Date(now - 30_000), now)!, /still running/);
    assert.match(removalBlockedReason(new Date(now - REMOVE_AFTER_SILENT_MS + 1000).toISOString(), now)!, /still running/);
  });
  it("is allowed once it has been silent for 10 minutes, or never reported", () => {
    assert.equal(removalBlockedReason(new Date(now - REMOVE_AFTER_SILENT_MS - 1000), now), null);
    assert.equal(removalBlockedReason(new Date(now - 18 * 3600_000), now), null);
    assert.equal(removalBlockedReason(null, now), null);
  });
});
