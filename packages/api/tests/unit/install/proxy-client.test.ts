import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { issueProxyKey, proxyClientId } from "../../../src/install/lib";
import type { Env } from "../../../src/types";

// 2026-11-26: dev installs got a made-up "dummy" proxy key, so every dev project's coding agent got 401.
// Dev now gets real clients from the shared llm-proxy, named with a "dev-" prefix so they never take a prod name.
const ROOT = join(__dirname, "../../..");

/** An llm-proxy admin API that records each call and answers from `reply`. */
function fakeProxy(reply: (path: string) => Response) {
  const calls: { path: string; body: any }[] = [];
  const env = {
    LLM_PROXY_ADMIN_SECRET: "s",
    LLM_PROXY: {
      fetch: async (url: string, init: RequestInit) => {
        const path = new URL(url).pathname;
        calls.push({ path, body: JSON.parse(String(init.body)) });
        return reply(path);
      },
    },
  } as unknown as Env;
  return { env, calls };
}

describe("proxyClientId", () => {
  it("is the install name on prod (no prefix), so existing prod clients keep their names", () => {
    assert.equal(proxyClientId({}, "acme-prod"), "acme-prod");
  });
  it("carries the environment's prefix on dev", () => {
    assert.equal(proxyClientId({ INSTALL_LLM_CLIENT_PREFIX: "dev-" }, "acme-prod"), "dev-acme-prod");
  });
});

describe("issueProxyKey with a real llm-proxy", () => {
  it("creates the client under the id it is given and returns its key", async () => {
    const { env, calls } = fakeProxy(() => Response.json({ proxyKey: "sk-prox-dev-acme-abc" }, { status: 201 }));
    const r = await issueProxyKey(env, proxyClientId({ INSTALL_LLM_CLIENT_PREFIX: "dev-" }, "acme"), 0, false);
    assert.deepEqual(r, { proxyKey: "sk-prox-dev-acme-abc", created: true });
    assert.equal(calls[0].path, "/admin/clients");
    assert.equal(calls[0].body.clientId, "dev-acme");
  });

  it("rotates only the prefixed client when this project created it earlier", async () => {
    const { env, calls } = fakeProxy((p) =>
      p === "/admin/clients" ? new Response("{}", { status: 409 }) : Response.json({ proxyKey: "sk-prox-dev-acme-new" })
    );
    const r = await issueProxyKey(env, "dev-acme", 0, true);
    assert.equal(r.proxyKey, "sk-prox-dev-acme-new");
    assert.deepEqual(calls.map((c) => c.path), ["/admin/clients", "/admin/clients/dev-acme/rotate", "/admin/clients/dev-acme/budget"]);
  });

  it("a name taken by someone else is refused, never rotated", async () => {
    const { env, calls } = fakeProxy(() => new Response("{}", { status: 409 }));
    await assert.rejects(issueProxyKey(env, "dev-acme", 0, false), /'dev-acme' already exists/);
    assert.equal(calls.length, 1);
  });
});

describe("worker config", () => {
  const dev = readFileSync(join(ROOT, "wrangler.dev.toml"), "utf8");
  const prod = readFileSync(join(ROOT, "wrangler.toml"), "utf8");
  const binding = /\[\[services\]\]\s*\nbinding = "LLM_PROXY"\s*\nservice = "llm-proxy"/;

  it("dev issues real keys: llm-proxy bound, no dummy mode, dev- prefix", () => {
    assert.doesNotMatch(dev, /^INSTALL_LLM_PROXY_MODE/m);
    assert.match(dev, binding);
    assert.match(dev, /^INSTALL_LLM_CLIENT_PREFIX = "dev-"$/m);
  });

  it("prod is unchanged: llm-proxy bound, no prefix, no dummy mode", () => {
    assert.match(prod, binding);
    assert.doesNotMatch(prod, /^INSTALL_LLM_CLIENT_PREFIX/m);
    assert.doesNotMatch(prod, /^INSTALL_LLM_PROXY_MODE/m);
  });
});

describe("redeem", () => {
  it("names, reuses and records the proxy client by the prefixed id, never the bare install name", () => {
    const src = readFileSync(join(ROOT, "src/install/app.ts"), "utf8");
    const redeem = src.slice(src.indexOf('install.post("/api/redeem"'), src.indexOf("apiKeys).values"));
    assert.match(redeem, /const clientId = proxyClientId\(c\.env, row\.installName\)/);
    assert.match(redeem, /eq\(installTokens\.llmClientId, clientId\)/);
    assert.match(redeem, /issueProxyKey\(c\.env, clientId,/);
    assert.match(redeem, /set\(\{ llmClientId: clientId \}\)/);
    assert.doesNotMatch(redeem, /llmClientId(: |, )row\.installName|issueProxyKey\(c\.env, row\.installName/);
  });
});
