import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { allowedSenders, buildEmailHtml, htmlFragment, isDark, personalize, renderMarkdown } from "./email-layout";
import { fromAddress } from "./email";
import type { Env } from "../types";

const env = { R2_PUBLIC_URL: "https://assets.example", EMAIL_FROM: "alerts@superatom.ai", EMAIL_SENDERS: "agents@superatom.ai" } as Env;
const BLUELINX = {
  senderName: "Inventory Intelligence",
  senderEmail: "agents@superatom.ai",
  buttonColor: "#152435",
  footerMode: "default",
  footerHtml: null,
  whyText: "You're a user of Inventory Intelligence at BlueLinx.",
  footerNote: "This is a system-generated email. Please do not reply.",
};
const URL = "https://sa-api.example/email/unsubscribe?token=abc";

describe("layout: no header band; the body is the email", () => {
  // 2026-11-09: Total Group's API email (its own teal "Superatom AI" banner) went out under a
  // platform "Total Group" header band too: two headers.
  const own = '<table><tr><td style="background:#3e8e8e"><h1>Superatom AI</h1></td></tr></table><p>Hello, {{firstName}}</p>';
  const html = buildEmailHtml({ orgName: "Total Group", body: own, format: "html", recipientName: "Chetan Sai", unsubscribeUrl: URL });

  it("an HTML body is placed as written, with no header of ours", () => {
    assert.match(html, /<h1>Superatom AI<\/h1>/);
    assert.equal((html.match(/<h1/g) ?? []).length, 1);
    assert.doesNotMatch(html, /superatom-logo|>Total Group<\/p>/);
    assert.match(html, /<p>Hello, Chetan<\/p>/);
  });

  it("the default footer adds why-you-got-this and a working unsubscribe link", () => {
    assert.match(html, /member of Total Group on Superatom/);
    assert.ok(html.includes(`href="${URL.replace(/&/g, "&amp;")}"`));
    assert.match(html, />Unsubscribe<\/a>/);
  });

  it("a markdown body sits in the padded card, buttons in the org's button colour", () => {
    const md = buildEmailHtml({ orgName: "Bluelinx", body: "Hi {{firstName}},\n\n[button: Open Transfer Recommendations](https://bluelinx.superatom.ai)", format: "markdown", branding: BLUELINX, recipientName: "Danielle Rhea" });
    assert.match(md, /padding: 24px 32px 8px;[^"]*">\s*<p[^>]*>Hi Danielle,<\/p>/);
    assert.match(md, /bgcolor="#152435"[^>]*><a href="https:\/\/bluelinx\.superatom\.ai"[^>]*color: #ffffff;/);
    assert.match(md, /You're a user of Inventory Intelligence at BlueLinx\./);
    assert.match(md, /This is a system-generated email\. Please do not reply\./);
  });
});

describe("footer", () => {
  it("a body that places {{unsubscribeUrl}} itself gets no footer, and its link works", () => {
    const html = buildEmailHtml({ orgName: "Bluelinx", body: '<p>Hi</p><a href="{{unsubscribeUrl}}">Stop these</a>', format: "html", branding: BLUELINX, unsubscribeUrl: URL });
    assert.doesNotMatch(html, /Why you got this/i);
    assert.ok(html.includes(`<a href="${URL.replace(/&/g, "&amp;")}">Stop these</a>`));
    assert.match(html, /system-generated/, "the org's note still shows");
  });

  it("the same works in markdown: [Unsubscribe]({{unsubscribeUrl}}) becomes the link", () => {
    const html = buildEmailHtml({ orgName: "Acme", body: "Bye. [Unsubscribe]({{unsubscribeUrl}})", format: "markdown", unsubscribeUrl: URL });
    assert.match(html, /<a href="https:\/\/sa-api\.example\/email\/unsubscribe\?token=abc"[^>]*>Unsubscribe<\/a>/);
    assert.doesNotMatch(html, /Why you got this/i);
  });

  it("a custom footer replaces the default, with placeholders filled and active content removed", () => {
    const html = buildEmailHtml({
      orgName: "Bluelinx",
      body: "Hi",
      format: "markdown",
      recipientName: "Danielle Rhea",
      unsubscribeUrl: URL,
      branding: { ...BLUELINX, footerMode: "custom", footerHtml: '<p onclick="x()">Sent to {{name}} at {{orgName}}. <a href="{{unsubscribeUrl}}">Opt out</a></p><script>bad()</script>' },
    });
    assert.doesNotMatch(html, /Why you got this/i);
    assert.match(html, /<p>Sent to Danielle Rhea at Bluelinx\. <a href="https:\/\/sa-api\.example\/email\/unsubscribe\?token=abc">Opt out<\/a><\/p>/);
    assert.doesNotMatch(html, /script|onclick/);
  });

  it("previews and test sends (no URL) link to # and still render the markdown link", () => {
    const html = buildEmailHtml({ orgName: "Acme", body: "[Unsubscribe]({{unsubscribeUrl}})", format: "markdown" });
    assert.match(html, /<a href="#"[^>]*>Unsubscribe<\/a>/);
  });
});

describe("markdown body", () => {
  it("a button inside a sentence stays an ordinary link", () => {
    assert.doesNotMatch(renderMarkdown("See [button: here](https://x.example) now"), /align="center"/);
  });

  it("HTML typed into markdown is escaped", () => {
    assert.match(renderMarkdown("<b>hi</b>"), /&lt;b&gt;hi&lt;\/b&gt;/);
  });

  it("a light button colour gets dark text", () => {
    assert.match(renderMarkdown("[button: Go](https://x.example)", "#f5f5f5"), /color: #111827;/);
    assert.equal(isDark("#152435"), true);
  });
});

describe("placeholders", () => {
  it("{{firstName}}, {{name}}, {{orgName}} fill per recipient, with a fallback", () => {
    assert.equal(personalize("Hi {{firstName}}, {{ name }} of {{orgName}}", { recipientName: "Danielle Rhea", orgName: "Bluelinx" }, "markdown"), "Hi Danielle, Danielle Rhea of Bluelinx");
    assert.equal(personalize("Hi {{firstName}},", {}, "markdown"), "Hi there,");
  });

  it("values are escaped in HTML", () => {
    assert.equal(personalize("{{name}}", { recipientName: "<x>" }, "html"), "&lt;x&gt;");
  });
});

describe("HTML cleaning", () => {
  it("keeps layout, images and styles; drops scripts, frames, forms, handlers, javascript: links", () => {
    const out = htmlFragment(`<html><head><style>.a{color:red}</style><script>bad()</script></head><body>
      <img src="https://x.example/banner.png" onerror="steal()"><a href="javascript:alert(1)">x</a>
      <iframe src="https://evil"></iframe><form action="https://evil"><input name=p></form><table><tr><td class="a">ok</td></tr></table></body></html>`);
    assert.match(out, /<style>\.a\{color:red\}<\/style>/);
    assert.match(out, /<img src="https:\/\/x\.example\/banner\.png">/);
    assert.match(out, /<td class="a">ok<\/td>/);
    for (const bad of [/script/i, /onerror/i, /javascript:/i, /iframe/i, /<form/i, /<input/i]) assert.doesNotMatch(out, bad);
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
