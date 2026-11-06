/**
 * The one layout every org email uses: a header band (org logo left, Superatom logo right,
 * title), the body, a two-column footer (why you got this / unsubscribe) and an optional note.
 * Tables and solid colours only: Outlook drops div backgrounds, Gmail drops gradients.
 */
import type { Env } from "../types";

export interface Branding {
  headerColor: string | null;
  logoUrl: string | null;
  showSuperatomLogo: boolean;
  senderName: string | null;
  senderEmail: string | null;
  whyText: string | null;
  footerNote: string | null;
}

export const DEFAULT_BRANDING: Branding = {
  headerColor: null,
  logoUrl: null,
  showSuperatomLogo: true,
  senderName: null,
  senderEmail: null,
  whyText: null,
  footerNote: null,
};

export const DEFAULT_HEADER_COLOR = "#111827";
export const HEX_COLOR = /^#[0-9a-f]{6}$/i;

export type BodyFormat = "markdown" | "html";

export function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Hosted in the public assets bucket: email apps don't show data: or private images. */
export function superatomLogoUrl(env: Pick<Env, "R2_PUBLIC_URL">, onDark: boolean): string {
  const base = (env.R2_PUBLIC_URL || "https://sa-assets.superatom.ai").replace(/\/+$/, "");
  return `${base}/email/superatom-logo${onDark ? "-on-dark" : ""}.png`;
}

/** Relative luminance below the midpoint → white text and the light Superatom logo. */
export function isDark(hex: string): boolean {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.4;
}

/** {{name}} and {{firstName}}; values are escaped by the renderer (markdown) or here (html). */
export function personalize(body: string, recipientName: string | null | undefined, format: BodyFormat): string {
  const full = (recipientName ?? "").trim();
  const first = full.split(/\s+/)[0] ?? "";
  const esc = (v: string) => (format === "html" ? escapeHtml(v) : v);
  return body
    .replace(/\{\{\s*firstName\s*\}\}/g, esc(first || "there"))
    .replace(/\{\{\s*name\s*\}\}/g, esc(full || "there"));
}

function inline(html: string): string {
  return html
    .replace(
      /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
      '<a href="$2" style="color: #2563eb; text-decoration: underline;">$1</a>'
    )
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__(.+?)__/g, "<strong>$1</strong>")
    .replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>")
    .replace(/`(.+?)`/g, '<code style="background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 13px;">$1</code>');
}

const BUTTON_LINE = /^\s*\[button:\s*([^\]]+)\]\((https?:\/\/[^\s)]+)\)\s*$/i;

/** A centred, solid button; the table cell carries the colour so Outlook keeps it. */
export function buttonHtml(label: string, url: string, color: string): string {
  const text = isDark(color) ? "#ffffff" : "#111827";
  return `<table role="presentation" cellpadding="0" cellspacing="0" align="center" style="margin: 16px auto;"><tr><td align="center" bgcolor="${color}" style="background-color: ${color}; border-radius: 6px;"><a href="${escapeHtml(url)}" target="_blank" style="display: inline-block; padding: 12px 24px; color: ${text}; font-size: 15px; font-weight: 700; text-decoration: none;">${escapeHtml(label.trim())}</a></td></tr></table>`;
}

/** Headings, lists, bold/italic/code, links, and a line `[button: Label](https://…)`. HTML is escaped. */
export function renderMarkdown(md: string, buttonColor = DEFAULT_HEADER_COLOR): string {
  const out: string[] = [];
  let list: "ul" | "ol" | null = null;
  const closeList = () => {
    if (list) out.push(`</${list}>`);
    list = null;
  };
  const li = (text: string) =>
    `<li style="margin: 6px 0; font-size: 15px; color: #374151; line-height: 1.6;">${inline(escapeHtml(text))}</li>`;
  for (const line of md.split("\n")) {
    const button = line.match(BUTTON_LINE);
    const heading = line.match(/^(#{1,3})\s+(.*)/);
    const bullet = line.match(/^\s*[-*]\s+(.*)/);
    const numbered = line.match(/^\s*\d+\.\s+(.*)/);
    if (button) {
      closeList();
      out.push(buttonHtml(button[1], button[2], buttonColor));
    } else if (heading) {
      closeList();
      const size = { 1: "20px", 2: "17px", 3: "15px" }[heading[1].length as 1 | 2 | 3];
      out.push(`<p style="margin: 16px 0 8px 0; font-size: ${size}; font-weight: 700; color: #111827;">${inline(escapeHtml(heading[2]))}</p>`);
    } else if (bullet || numbered) {
      const tag = bullet ? "ul" : "ol";
      if (list !== tag) {
        closeList();
        out.push(`<${tag} style="margin: 8px 0 12px; padding-left: 20px;">`);
        list = tag;
      }
      out.push(li((bullet ?? numbered)![1]));
    } else {
      closeList();
      if (line.trim()) {
        out.push(`<p style="margin: 0 0 12px; font-size: 15px; color: #374151; line-height: 1.6;">${inline(escapeHtml(line))}</p>`);
      }
    }
  }
  closeList();
  return out.join("\n");
}

/**
 * The part of caller HTML that goes inside our layout: the <body> contents plus <style> blocks,
 * without active content (scripts, frames, forms, on* handlers, javascript: links).
 */
export function htmlFragment(html: string): string {
  const body = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  let out = body
    ? (html.slice(0, body.index).match(/<style[^>]*>[\s\S]*?<\/style>/gi) ?? []).join("\n") + body[1]
    : html.replace(/<!doctype[^>]*>|<\/?html[^>]*>|<head[^>]*>[\s\S]*?<\/head>/gi, "");
  out = out
    .replace(/<(script|iframe|object|embed|form|textarea|select|noscript)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<\/?(script|iframe|object|embed|form|input|button|textarea|select|option|meta|link|base|noscript)\b[^>]*>/gi, "")
    .replace(/\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(href|src|action)\s*=\s*(["']?)\s*(javascript|vbscript|data):[^"'\s>]*\2/gi, '$1="#"');
  return out;
}

export function renderBody(body: string, format: BodyFormat, buttonColor?: string): string {
  return format === "html" ? htmlFragment(body) : renderMarkdown(body, buttonColor);
}

export interface LayoutInput {
  orgName: string;
  title: string;
  /** Rendered body HTML (renderBody). */
  bodyHtml: string;
  branding?: Branding | null;
  unsubscribeUrl?: string;
}

export function buildEmailHtml(env: Pick<Env, "R2_PUBLIC_URL">, p: LayoutInput): string {
  const b = p.branding ?? DEFAULT_BRANDING;
  const color = b.headerColor && HEX_COLOR.test(b.headerColor) ? b.headerColor : DEFAULT_HEADER_COLOR;
  const dark = isDark(color);
  const ink = dark ? "#ffffff" : "#111827";
  const org = escapeHtml(p.orgName);

  // color on the <img> is for the alt text when images are blocked.
  const orgMark = b.logoUrl
    ? `<img src="${escapeHtml(b.logoUrl)}" alt="${org}" width="160" style="display: block; width: 160px; max-width: 160px; height: auto; border: 0; outline: none; color: ${ink}; font-size: 15px; font-weight: 700;" />`
    : `<p style="margin: 0; font-size: 15px; font-weight: 700; color: ${ink};">${org}</p>`;
  const saMark = b.showSuperatomLogo
    ? `<td valign="middle" align="right"><img src="${superatomLogoUrl(env, dark)}" alt="Superatom AI" width="110" style="display: block; width: 110px; max-width: 110px; height: auto; border: 0; outline: none; color: ${ink}; font-size: 12px;" /></td>`
    : "";

  const column = (heading: string, content: string, style: string, width: string) =>
    `<td width="${width}" valign="top" style="font-size: 12px; line-height: 1.6; color: #9ca3af; ${style}"><p style="margin: 0 0 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: #6b7280;">${heading}</p>${content}</td>`;
  const why = `<p style="margin: 0;">${escapeHtml(b.whyText?.trim() || `You're receiving this because you're a member of ${p.orgName} on Superatom.`)}</p>`;
  const footer = p.unsubscribeUrl
    ? column("Why you got this", why, "padding-right: 16px;", "50%") +
      column(
        "Email preferences",
        `<p style="margin: 0 0 12px;">Don't want these updates? You can unsubscribe at any time.</p><a href="${escapeHtml(p.unsubscribeUrl)}" target="_blank" style="display: inline-block; padding: 8px 20px; border: 1px solid #d1d5db; border-radius: 6px; color: #6b7280; font-size: 12px; font-weight: 600; text-decoration: none;">Unsubscribe</a>`,
        "padding-left: 16px; border-left: 1px solid #e5e7eb;",
        "50%"
      )
    : column("Why you got this", why, "", "100%");
  const note = b.footerNote?.trim()
    ? `<tr><td align="center" style="padding: 16px 12px 0; font-size: 11px; color: #9ca3af;">${escapeHtml(b.footerNote.trim())}</td></tr>`
    : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 32px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background-color: #ffffff; border-radius: 8px;">
<tr><td bgcolor="${color}" style="padding: 28px 32px; background-color: ${color}; border-radius: 8px 8px 0 0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td valign="middle">${orgMark}</td>${saMark}</tr></table>
<h1 style="margin: 14px 0 0; font-size: 22px; line-height: 1.3; color: ${ink};">${escapeHtml(p.title)}</h1>
</td></tr>
<tr><td style="padding: 24px 32px 8px; font-size: 15px; color: #374151; line-height: 1.6;">${p.bodyHtml}</td></tr>
<tr><td style="padding: 20px 32px 24px; border-top: 1px solid #e5e7eb;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>${footer}</tr></table></td></tr>
</table></td></tr>
${note}
</table></body></html>`;
}

/**
 * Whether an org may send from `email`. With its own Resend key: any address on a domain verified
 * in that account (any address while the domains are unknown). Otherwise the platform list.
 */
export function senderAllowed(
  env: Pick<Env, "EMAIL_FROM" | "EMAIL_SENDERS">,
  email: string,
  key?: { resendKeyEnc?: string | null; senderDomains?: unknown } | null
): boolean {
  const address = email.trim().toLowerCase();
  if (key?.resendKeyEnc) {
    const domains = Array.isArray(key.senderDomains) ? (key.senderDomains as string[]) : null;
    return domains === null || domains.includes(address.split("@")[1] ?? "");
  }
  return allowedSenders(env).includes(address);
}

/** Addresses this worker may send from: EMAIL_FROM plus the comma-separated EMAIL_SENDERS. */
export function allowedSenders(env: Pick<Env, "EMAIL_FROM" | "EMAIL_SENDERS">): string[] {
  const list = [env.EMAIL_FROM || "updates@superatom.ai", ...(env.EMAIL_SENDERS ?? "").split(",")];
  return [...new Set(list.map((s) => s.trim().toLowerCase()).filter(Boolean))];
}
