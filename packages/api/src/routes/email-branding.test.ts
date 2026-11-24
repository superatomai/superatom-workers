import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readBranding } from "./emails";
import type { Env } from "../types";

const env = { EMAIL_FROM: "alerts@superatom.ai", EMAIL_SENDERS: "agent@superatom.ai,agents@superatom.ai" } as Env;

describe("email branding validation", () => {
  it("accepts the BlueLinx setting and normalises case", () => {
    const r = readBranding(env, { buttonColor: "#15243A", senderName: "Inventory Intelligence", senderEmail: "Agent@Superatom.ai", footerNote: "This is a system-generated email. Please do not reply." });
    assert.ok(r.ok);
    assert.equal(r.value.buttonColor, "#15243a");
    assert.equal(r.value.senderEmail, "agent@superatom.ai");
    assert.equal(r.value.footerMode, "default");
  });

  it("a sender address outside the allowed list is refused, naming the allowed ones", () => {
    const r = readBranding(env, { senderEmail: "ceo@bluelinxco.com" });
    assert.ok(!r.ok);
    assert.match(r.error, /alerts@superatom\.ai, agent@superatom\.ai, agents@superatom\.ai/);
  });

  it("refuses a bad colour and a header-breaking sender name", () => {
    for (const b of [{ buttonColor: "navy" }, { senderName: 'A" <x@y.z>' }]) assert.ok(!readBranding(env, b).ok, JSON.stringify(b));
  });

  it("a custom footer must carry {{unsubscribeUrl}}, so people can always opt out", () => {
    const missing = readBranding(env, { footerMode: "custom", footerHtml: "<p>Thanks for reading</p>" });
    assert.ok(!missing.ok);
    assert.match(missing.error, /\{\{unsubscribeUrl\}\}/);
    assert.ok(!readBranding(env, { footerMode: "custom" }).ok, "custom needs HTML");
    const ok = readBranding(env, { footerMode: "custom", footerHtml: '<a href="{{ unsubscribeUrl }}">Opt out</a>' });
    assert.ok(ok.ok);
    assert.equal(ok.value.footerMode, "custom");
  });

  it("an unknown footer mode is refused; empty strings clear fields", () => {
    assert.ok(!readBranding(env, { footerMode: "none" }).ok);
    const r = readBranding(env, { buttonColor: "", whyText: "" });
    assert.ok(r.ok);
    assert.equal(r.value.buttonColor, null);
    assert.equal(r.value.whyText, null);
  });
});
