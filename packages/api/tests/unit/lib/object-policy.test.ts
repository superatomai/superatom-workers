import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BUILTIN_ACTIONS, effectiveActions, levelForActions } from "../../../src/lib/object-policy";

describe("object action decisions", () => {
  it("does not turn an edit-only custom role into delete access", () => {
    const actions = effectiveActions(["view", "edit"], []);
    assert.deepEqual(actions, ["view", "edit"]);
    assert.equal(actions.includes("delete"), false);
    assert.equal(levelForActions(actions), "view");
  });

  it("lets a deny override an admin or owner allowance", () => {
    const actions = effectiveActions(BUILTIN_ACTIONS.owner, ["delete"]);
    assert.equal(actions.includes("edit"), true);
    assert.equal(actions.includes("delete"), false);
  });

  it("hides the object when view is denied", () => {
    assert.deepEqual(effectiveActions(BUILTIN_ACTIONS.owner, ["view"]), []);
  });

  it("unions independent grants before applying denies", () => {
    const actions = effectiveActions(["view", "edit", "delete"], ["delete"]);
    assert.deepEqual(actions, ["view", "edit"]);
  });
});
