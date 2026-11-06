import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkResendKey, decryptKey, encryptKey, orgResendKey } from "./email-keys";
import { senderAllowed } from "./email-layout";
import { fromAddress } from "./email";
import { readBranding } from "../routes/emails";
import type { Env } from "../types";

const env = { EMAIL_KEYS_SECRET: "test-secret", RESEND_API_KEY: "re_platform_key_123", EMAIL_FROM: "alerts@superatom.ai", EMAIL_SENDERS: "agents@superatom.ai" } as Env;
const reply = (status: number, body: unknown) => (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

describe("org Resend key storage", () => {
  it("round-trips, and the stored form never contains the key", async () => {
    const stored = await encryptKey(env, "re_bluelinx_paid_key_9876");
    assert.doesNotMatch(stored, /bluelinx|9876/);
    assert.equal(await decryptKey(env, stored), "re_bluelinx_paid_key_9876");
  });

  it("can't be read with another server secret", async () => {
    const stored = await encryptKey(env, "re_bluelinx_paid_key_9876");
    await assert.rejects(decryptKey({ EMAIL_KEYS_SECRET: "other" } as Env, stored));
  });

  it("an org with a key sends with it; without one, the platform key", async () => {
    const own = await orgResendKey(env, { resendKeyEnc: await encryptKey(env, "re_bluelinx_paid_key_9876") });
    assert.deepEqual(own, { ok: true, apiKey: "re_bluelinx_paid_key_9876", own: true });
    assert.deepEqual(await orgResendKey(env, null), { ok: true, apiKey: "re_platform_key_123", own: false });
  });

  it("an unreadable key is an error, never a silent fallback to the platform account", async () => {
    const r = await orgResendKey(env, { resendKeyEnc: "v1:AAAA:BBBB" });
    assert.equal(r.ok, false);
  });
});

describe("checking a key with Resend", () => {
  it("full-access key: the verified domains only", async () => {
    const r = await checkResendKey("re_x", reply(200, { data: [
      { name: "notifications.bluelinxco.com", status: "verified" },
      { name: "mail.superatom.ai", status: "pending" },
    ] }));
    assert.deepEqual(r, { ok: true, domains: ["notifications.bluelinxco.com"] });
  });

  it("sending-only key: accepted, domains unknown", async () => {
    assert.deepEqual(await checkResendKey("re_x", reply(401, { name: "restricted_api_key", message: "This API key is restricted to only send emails" })), { ok: true, domains: null });
  });

  it("invalid key: refused with Resend's reason", async () => {
    const r = await checkResendKey("re_x", reply(400, { name: "validation_error", message: "API key is invalid" }));
    assert.deepEqual(r, { ok: false, error: "Resend rejected the key: API key is invalid" });
  });
});

describe("sender addresses with an org's own account", () => {
  const key = { resendKeyEnc: "v1:x:y", senderDomains: ["notifications.bluelinxco.com"] };

  it("any address on its verified domains; not the platform's addresses", () => {
    assert.equal(senderAllowed(env, "inventory@notifications.bluelinxco.com", key), true);
    assert.equal(senderAllowed(env, "agents@superatom.ai", key), false);
    assert.equal(senderAllowed(env, "agents@superatom.ai", null), true);
  });

  it("domains unknown (sending-only key): any address; Resend has the final say", () => {
    assert.equal(senderAllowed(env, "x@anything.com", { resendKeyEnc: "v1:x:y", senderDomains: null }), true);
  });

  it("branding validation and the From header follow the same rule", () => {
    assert.ok(readBranding(env, { senderEmail: "inventory@notifications.bluelinxco.com" }, key).ok);
    const bad = readBranding(env, { senderEmail: "agents@superatom.ai" }, key);
    assert.ok(!bad.ok);
    assert.match(bad.error, /@notifications\.bluelinxco\.com/);
    assert.equal(
      fromAddress(env, "Bluelinx", { senderName: "Inventory Intelligence", senderEmail: "inventory@notifications.bluelinxco.com", ...key }),
      '"Inventory Intelligence" <inventory@notifications.bluelinxco.com>'
    );
  });
});
