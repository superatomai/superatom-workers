import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hasPermission, requireFixed, requirePermission, requireReadWrite } from "../../../src/middleware/auth";

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
    const { c, sent } = ctx(["dashboard.create"]);
    assert.equal(await run(requirePermission("analytics.view"), c), false);
    assert.equal(sent()!.status, 403);
    assert.match(sent()!.body.error, /analytics\.view/);
  });

  it("needs every permission listed, not just one", async () => {
    const { c } = ctx(["project.edit"]);
    assert.equal(await run(requirePermission("project.edit", "design.edit"), c), false);
  });

  it("refuses a caller with no permissions at all", async () => {
    const { c } = ctx([]);
    assert.equal(await run(requirePermission("platform.access"), c), false);
  });

  it("refuses a change from an SDK session even with the permission", async () => {
    const { c, sent } = ctx(["project.edit"], { method: "PUT", tokenSource: "sdk" });
    assert.equal(await run(requirePermission("project.edit"), c), false);
    assert.equal(sent()!.status, 403);
  });

  it("lets an SDK session read what its permissions allow", async () => {
    const { c } = ctx(["platform.access"], { method: "GET", tokenSource: "sdk" });
    assert.equal(await run(requirePermission("platform.access"), c), true);
  });
});

describe("requireReadWrite", () => {
  it("needs the read permission for GET and the write one for changes", async () => {
    const reader = ctx(["email.view"]);
    assert.equal(await run(requireReadWrite("email.view", "email.send"), reader.c), true);
    const writer = ctx(["email.view"], { method: "POST" });
    assert.equal(await run(requireReadWrite("email.view", "email.send"), writer.c), false);
    assert.match(writer.sent()!.body.error, /email\.send/);
  });
});

describe("requireFixed", () => {
  const withRole = (orgRole: string, method = "POST") => {
    const t = ctx(["platform.access"], { method });
    t.c.set("orgRole", orgRole);
    return t;
  };

  it("lets the Owner and Admins edit the org, nobody else, whatever they hold", async () => {
    assert.equal(await run(requireFixed("editOrg"), withRole("owner").c), true);
    assert.equal(await run(requireFixed("editOrg"), withRole("admin").c), true);
    assert.equal(await run(requireFixed("editOrg"), withRole("data_lead").c), false);
    assert.equal(await run(requireFixed("editOrg"), withRole("member").c), false);
  });

  it("keeps managing Admins (and setting their limits) to the Owner", async () => {
    assert.equal(await run(requireFixed("manageAdmins"), withRole("owner").c), true);
    assert.equal(await run(requireFixed("manageAdmins"), withRole("admin").c), false);
  });

  it("keeps managing roles to the Owner", async () => {
    assert.equal(await run(requireFixed("manageRoles"), withRole("owner").c), true);
    const admin = withRole("admin");
    assert.equal(await run(requireFixed("manageRoles"), admin.c), false);
    assert.match(admin.sent()!.body.error, /only the Owner/);
  });
});

describe("hasPermission", () => {
  it("answers from the caller's permissions", () => {
    const { c } = ctx(["source.edit"]);
    assert.equal(hasPermission(c as any, "source.edit"), true);
    assert.equal(hasPermission(c as any, "source.delete"), false);
  });

  it("treats missing permissions as none", () => {
    assert.equal(hasPermission({ get: () => undefined } as any, "platform.access"), false);
  });
});
