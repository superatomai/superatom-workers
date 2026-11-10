import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deleteProject, type ProjectDeleteSteps } from "./project-delete";
import { disableProxyClient } from "../install/lib";
import type { Env } from "../types";

function fakeSteps(opts: { exists?: boolean; clients?: string[]; failOn?: string } = {}) {
  const calls: string[] = [];
  const steps: ProjectDeleteSteps = {
    exists: async () => opts.exists ?? true,
    proxyClientIds: async () => opts.clients ?? [],
    disableProxyClient: async (id) => { calls.push(`disable:${id}`); return id !== opts.failOn; },
    deleteWithKeys: async () => { calls.push("deleteWithKeys"); },
  };
  return { steps, calls };
}

describe("deleting a project", () => {
  it("disables every proxy client before revoking keys and deleting the row", async () => {
    const { steps, calls } = fakeSteps({ clients: ["acme-prod", "acme-dev"] });
    assert.deepEqual(await deleteProject(steps), { status: "deleted" });
    assert.deepEqual(calls, ["disable:acme-prod", "disable:acme-dev", "deleteWithKeys"]);
  });

  it("revokes keys and deletes even when the project never had an install token", async () => {
    const { steps, calls } = fakeSteps();
    assert.deepEqual(await deleteProject(steps), { status: "deleted" });
    assert.deepEqual(calls, ["deleteWithKeys"]);
  });

  it("keeps the project when a proxy client cannot be disabled (its link would be lost)", async () => {
    const { steps, calls } = fakeSteps({ clients: ["a", "b"], failOn: "a" });
    assert.deepEqual(await deleteProject(steps), { status: "proxy_failed", clientId: "a" });
    assert.deepEqual(calls, ["disable:a"]);
  });

  it("touches nothing for a project outside the org", async () => {
    const { steps, calls } = fakeSteps({ exists: false, clients: ["other-org-client"] });
    assert.deepEqual(await deleteProject(steps), { status: "not_found" });
    assert.deepEqual(calls, []);
  });
});

describe("disableProxyClient", () => {
  const proxy = (status: number, seen: string[] = []) =>
    ({
      LLM_PROXY: { fetch: async (url: string) => { seen.push(url); return new Response("{}", { status }); } },
      LLM_PROXY_ADMIN_SECRET: "s",
    }) as unknown as Env;

  it("calls the admin disable route for the client", async () => {
    const seen: string[] = [];
    assert.equal(await disableProxyClient(proxy(200, seen), "acme prod"), true);
    assert.deepEqual(seen, ["https://llm-proxy/admin/clients/acme%20prod/disable"]);
  });
  it("treats a client that no longer exists as done", async () => {
    assert.equal(await disableProxyClient(proxy(404), "gone"), true);
  });
  it("reports a proxy error, and a missing proxy binding, as failure", async () => {
    assert.equal(await disableProxyClient(proxy(500), "x"), false);
    assert.equal(await disableProxyClient({} as Env, "x"), false);
  });
  it("skips the proxy in dummy mode (dev)", async () => {
    assert.equal(await disableProxyClient({ INSTALL_LLM_PROXY_MODE: "dummy" } as Env, "x"), true);
  });
});
