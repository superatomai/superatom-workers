import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readBranding } from "./emails";
import type { Env } from "../types";

const env = { EMAIL_FROM: "alerts@superatom.ai", EMAIL_SENDERS: "agents@superatom.ai" } as Env;

describe("email branding validation", () => {
  it("accepts the BlueLinx setting and normalises case", () => {
    const r = readBranding(env, { headerColor: "#15243A", senderName: "Inventory Intelligence", senderEmail: "Agents@Superatom.ai", footerNote: "This is a system-generated email. Please do not reply." });
    assert.ok(r.ok);
    assert.equal(r.value.headerColor, "#15243a");
    assert.equal(r.value.senderEmail, "agents@superatom.ai");
    assert.equal(r.value.showSuperatomLogo, true);
    assert.equal(r.value.logoUrl, null);
  });

  it("a sender address outside the allowed list is refused, naming the allowed ones", () => {
    const r = readBranding(env, { senderEmail: "ceo@bluelinxco.com" });
    assert.ok(!r.ok);
    assert.match(r.error, /alerts@superatom\.ai, agents@superatom\.ai/);
  });

  it("refuses a bad colour, a non-https logo, and a header-breaking sender name", () => {
    for (const b of [{ headerColor: "navy" }, { logoUrl: "http://x.example/a.png" }, { logoUrl: "javascript:alert(1)" }, { senderName: 'A" <x@y.z>' }]) {
      assert.ok(!readBranding(env, b).ok, JSON.stringify(b));
    }
  });

  it("empty strings clear fields; showSuperatomLogo false is kept", () => {
    const r = readBranding(env, { headerColor: "", whyText: "", showSuperatomLogo: false });
    assert.ok(r.ok);
    assert.equal(r.value.headerColor, null);
    assert.equal(r.value.showSuperatomLogo, false);
  });
});
