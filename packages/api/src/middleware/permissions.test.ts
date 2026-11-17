import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hasPermission, requirePermission } from "./auth";

/** Just enough of a Hono context for the permission middleware. */
function ctx(permissions: string[], opts: { method?: string; tokenSource?: "app" | "sdk" } = {}) {
  const vars: Record<string, unknown> = { permissions, tokenSource: opts.tokenSource ?? "app" };
  let sent: { body: any; status: number } | null = null;
  return {
    c: {
      get: (k: string) => vars[k],
      set: (k: string, v: unknown) => { vars[k] = v; },
      req: { method: opts.method ?? "GET" },
      json: (body: any, status: number) => { sent = { body, status }; return sent; },
    },
    sent: () => sent,
  };
}

async function run(mw: ReturnType<typeof requirePermission>, c: any) {
  let nextCalled = false;
  await (mw as any)(c, async () => { nextCalled = true; });
  return nextCalled;
}

describe("requirePermission", () => {
  it("lets a caller holding the permission through", async () => {
    const { c, sent } = ctx(["analytics.view"]);
    assert.equal(await run(requirePermission("analytics.view"), c), true);
    assert.equal(sent(), null);
  });

  it("refuses with 403, naming what is missing", async () => {
    const { c, sent } = ctx(["dashboards.create"]);
    assert.equal(await run(requirePermission("analytics.view"), c), false);
    assert.equal(sent()!.status, 403);
    assert.match(sent()!.body.error, /analytics\.view/);
  });

  it("needs every permission listed, not just one", async () => {
    const { c } = ctx(["projects.edit"]);
    assert.equal(await run(requirePermission("projects.edit", "design.edit"), c), false);
  });

  it("refuses a caller with no permissions at all", async () => {
    const { c } = ctx([]);
    assert.equal(await run(requirePermission("platform.access"), c), false);
  });

  it("refuses a change from an SDK session even with the permission", async () => {
    const { c, sent } = ctx(["members.manage"], { method: "PUT", tokenSource: "sdk" });
    assert.equal(await run(requirePermission("members.manage"), c), false);
    assert.equal(sent()!.status, 403);
  });

  it("lets an SDK session read what its permissions allow", async () => {
    const { c } = ctx(["platform.access"], { method: "GET", tokenSource: "sdk" });
    assert.equal(await run(requirePermission("platform.access"), c), true);
  });
});

describe("hasPermission", () => {
  it("answers from the caller's permissions", () => {
    const { c } = ctx(["access.manage"]);
    assert.equal(hasPermission(c as any, "access.manage"), true);
    assert.equal(hasPermission(c as any, "members.manage"), false);
  });

  it("treats missing permissions as none", () => {
    assert.equal(hasPermission({ get: () => undefined } as any, "platform.access"), false);
  });
});
