import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { allowedSenders, buildEmailHtml, htmlFragment, isDark, personalize, renderBody, renderMarkdown } from "./email-layout";
import { fromAddress } from "./email";
import type { Env } from "../types";

const env = { R2_PUBLIC_URL: "https://assets.example", EMAIL_FROM: "alerts@superatom.ai", EMAIL_SENDERS: "agents@superatom.ai" } as Env;
const BLUELINX = {
  headerColor: "#152435",
  logoUrl: "https://assets.example/email-branding/org/logo-ab.png",
  showSuperatomLogo: true,
  senderName: "Inventory Intelligence",
  senderEmail: "agents@superatom.ai",
  whyText: "You're a user of Inventory Intelligence at BlueLinx.",
  footerNote: "This is a system-generated email. Please do not reply.",
};

describe("email layout", () => {
  const html = buildEmailHtml(env, { orgName: "Bluelinx", title: "Inventory Intelligence has been updated", bodyHtml: "<p>x</p>", branding: BLUELINX, unsubscribeUrl: "https://u.example/x" });

  it("header: org colour, org logo left, light Superatom logo right on a dark band, title in white", () => {
    assert.match(html, /bgcolor="#152435" style="padding: 28px 32px; background-color: #152435;/);
    assert.match(html, /<img src="https:\/\/assets\.example\/email-branding\/org\/logo-ab\.png" alt="Bluelinx"/);
    assert.match(html, /<td valign="middle" align="right"><img src="https:\/\/assets\.example\/email\/superatom-logo-on-dark\.png"/);
    assert.match(html, /<h1[^>]*color: #ffffff;">Inventory Intelligence has been updated<\/h1>/);
  });

  it("footer: why text, unsubscribe button, and the note under the card", () => {
    assert.match(html, /You&#39;re a user|You're a user of Inventory Intelligence at BlueLinx\./);
    assert.match(html, /href="https:\/\/u\.example\/x"[^>]*>Unsubscribe<\/a>/);
    assert.match(html, /This is a system-generated email\. Please do not reply\./);
  });

  it("no branding: default dark header with the org name as text, original-colour logo only on light headers", () => {
    const plain = buildEmailHtml(env, { orgName: "Acme", title: "Hello", bodyHtml: "" });
    assert.match(plain, /background-color: #111827;/);
    assert.match(plain, /font-weight: 700; color: #ffffff;">Acme<\/p>/);
    assert.doesNotMatch(plain, /system-generated/);
    const light = buildEmailHtml(env, { orgName: "Acme", title: "Hello", bodyHtml: "", branding: { ...BLUELINX, headerColor: "#f5f5f5" } });
    assert.match(light, /email\/superatom-logo\.png/);
    assert.match(light, /<h1[^>]*color: #111827;">Hello<\/h1>/);
  });

  it("isDark splits the BlueLinx navy from light colours", () => {
    assert.equal(isDark("#152435"), true);
    assert.equal(isDark("#ffffff"), false);
    assert.equal(isDark("#f5f5f5"), false);
  });
});

describe("markdown body", () => {
  it("a [button: …](url) line becomes a centred button in the header colour", () => {
    const out = renderMarkdown("Intro\n\n[button: Open Transfer Recommendations](https://bluelinx.superatom.ai)", "#152435");
    assert.match(out, /<table role="presentation" cellpadding="0" cellspacing="0" align="center"[^>]*><tr><td align="center" bgcolor="#152435"/);
    assert.match(out, /<a href="https:\/\/bluelinx\.superatom\.ai" target="_blank" style="[^"]*color: #ffffff;[^"]*">Open Transfer Recommendations<\/a>/);
  });

  it("a button inside a sentence stays an ordinary link", () => {
    const out = renderMarkdown("See [button: here](https://x.example) now");
    assert.doesNotMatch(out, /align="center"/);
  });

  it("HTML typed into markdown is escaped", () => {
    assert.match(renderMarkdown("<b>hi</b>"), /&lt;b&gt;hi&lt;\/b&gt;/);
  });
});

describe("placeholders", () => {
  it("{{firstName}} and {{name}} fill per recipient, with a fallback", () => {
    assert.equal(personalize("Hi {{firstName}}, {{ name }}", "Danielle Rhea", "markdown"), "Hi Danielle, Danielle Rhea");
    assert.equal(personalize("Hi {{firstName}},", null, "markdown"), "Hi there,");
  });

  it("names are escaped in HTML bodies", () => {
    assert.equal(personalize("{{name}}", "<x>", "html"), "&lt;x&gt;");
  });
});

describe("HTML body", () => {
  it("keeps layout, images and styles; drops scripts, frames, forms, handlers, javascript: links", () => {
    const out = htmlFragment(`<html><head><style>.a{color:red}</style><script>bad()</script></head><body>
      <img src="https://x.example/banner.png" onerror="steal()"><a href="javascript:alert(1)">x</a>
      <iframe src="https://evil"></iframe><form action="https://evil"><input name=p></form><table><tr><td class="a">ok</td></tr></table></body></html>`);
    assert.match(out, /<style>\.a\{color:red\}<\/style>/);
    assert.match(out, /<img src="https:\/\/x\.example\/banner\.png">/);
    assert.match(out, /<td class="a">ok<\/td>/);
    for (const bad of [/script/i, /onerror/i, /javascript:/i, /iframe/i, /<form/i, /<input/i]) assert.doesNotMatch(out, bad);
  });

  it("renderBody passes html through the cleaner and markdown through the renderer", () => {
    assert.equal(renderBody("<p onclick=\"x()\">a</p>", "html"), "<p>a</p>");
    assert.match(renderBody("**a**", "markdown"), /<strong>a<\/strong>/);
  });
});

describe("sender", () => {
  it("allowed senders = EMAIL_FROM plus EMAIL_SENDERS", () => {
    assert.deepEqual(allowedSenders(env), ["alerts@superatom.ai", "agents@superatom.ai"]);
  });

  it("an org sender is used as given", () => {
    assert.equal(fromAddress(env, "Bluelinx", BLUELINX), '"Inventory Intelligence" <agents@superatom.ai>');
  });

  it("an address no longer allowed falls back to EMAIL_FROM; no org sender keeps the old default", () => {
    assert.equal(fromAddress(env, "Bluelinx", { senderName: "X", senderEmail: "ceo@other.com" }), '"X" <alerts@superatom.ai>');
    assert.equal(fromAddress(env, "Bluelinx", null), '"Bluelinx via Superatom AI" <alerts@superatom.ai>');
  });
});
