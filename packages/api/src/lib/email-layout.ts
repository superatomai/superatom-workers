/**
 * How every org email is put together: the body (markdown, or the sender's own HTML, which can carry
 * any header) in a card, then a footer that always offers an unsubscribe link, and an optional note.
 * The footer is the org's own HTML when it has one; a body that places {{unsubscribeUrl}} itself gets none.
 * Tables and solid colours only: Outlook drops div backgrounds, Gmail drops gradients.
 */
import type { Env } from "../types";

export interface Branding {
  senderName: string | null;
  senderEmail: string | null;
  /** Markdown [button: …] colour; null = DEFAULT_BUTTON_COLOR. */
  buttonColor: string | null;
  /** "default" = why-you-got-this + unsubscribe button; "custom" = footerHtml (must hold {{unsubscribeUrl}}). */
  footerMode: string;
  footerHtml: string | null;
  whyText: string | null;
  footerNote: string | null;
}

export const DEFAULT_BRANDING: Branding = {
  senderName: null,
  senderEmail: null,
  buttonColor: null,
  footerMode: "default",
  footerHtml: null,
  whyText: null,
  footerNote: null,
};

export const DEFAULT_BUTTON_COLOR = "#111827";
export const HEX_COLOR = /^#[0-9a-f]{6}$/i;
export const UNSUBSCRIBE_PLACEHOLDER = /\{\{\s*unsubscribeUrl\s*\}\}/;

export type BodyFormat = "markdown" | "html";

export function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Relative luminance below the midpoint → white button text. */
export function isDark(hex: string): boolean {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.4;
}

/**
 * {{name}}, {{firstName}}, {{orgName}}, {{unsubscribeUrl}}. In HTML the values are escaped here;
 * in markdown the renderer escapes them (a URL stays a plain https link it can turn into a link).
 */
export function personalize(
  text: string,
  v: { recipientName?: string | null; orgName?: string; unsubscribeUrl?: string },
  format: BodyFormat
): string {
  const full = (v.recipientName ?? "").trim();
  const first = full.split(/\s+/)[0] ?? "";
  const esc = (s: string) => (format === "html" ? escapeHtml(s) : s);
  return text
    .replace(/\{\{\s*firstName\s*\}\}/g, esc(first || "there"))
    .replace(/\{\{\s*name\s*\}\}/g, esc(full || "there"))
    .replace(/\{\{\s*orgName\s*\}\}/g, esc(v.orgName ?? ""))
    .replace(new RegExp(UNSUBSCRIBE_PLACEHOLDER.source, "g"), esc(v.unsubscribeUrl || "#"));
}

function inline(html: string): string {
  return html
    .replace(
      // "#" = an unsubscribe link in a preview or test send.
      /\[([^\]]+)\]\((https?:\/\/[^\s)]+|#)\)/g,
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
export function renderMarkdown(md: string, buttonColor = DEFAULT_BUTTON_COLOR): string {
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

export interface LayoutInput {
  orgName: string;
  /** The body as written (placeholders not yet filled). */
  body: string;
  format: BodyFormat;
  branding?: Branding | null;
  recipientName?: string | null;
  /** Absent for test sends and previews: links read "#". */
  unsubscribeUrl?: string;
}

/** The footer cell, or "" when the body places its own unsubscribe link. */
function footerHtml(p: LayoutInput, b: Branding): string {
  if (UNSUBSCRIBE_PLACEHOLDER.test(p.body)) return "";
  const fill = { recipientName: p.recipientName, orgName: p.orgName, unsubscribeUrl: p.unsubscribeUrl };
  if (b.footerMode === "custom" && b.footerHtml) {
    return `<tr><td style="padding: 20px 32px 24px; border-top: 1px solid #e5e7eb; font-size: 12px; line-height: 1.6; color: #6b7280;">${htmlFragment(personalize(b.footerHtml, fill, "html"))}</td></tr>`;
  }
  const column = (heading: string, content: string, style: string, width: string) =>
    `<td width="${width}" valign="top" style="font-size: 12px; line-height: 1.6; color: #9ca3af; ${style}"><p style="margin: 0 0 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: #6b7280;">${heading}</p>${content}</td>`;
  const why = `<p style="margin: 0;">${escapeHtml(b.whyText?.trim() || `You're receiving this because you're a member of ${p.orgName} on Superatom.`)}</p>`;
  const unsubscribe = `<p style="margin: 0 0 12px;">Don't want these updates? You can unsubscribe at any time.</p><a href="${escapeHtml(p.unsubscribeUrl || "#")}" target="_blank" style="display: inline-block; padding: 8px 20px; border: 1px solid #d1d5db; border-radius: 6px; color: #6b7280; font-size: 12px; font-weight: 600; text-decoration: none;">Unsubscribe</a>`;
  const cols =
    column("Why you got this", why, "padding-right: 16px;", "50%") +
    column("Email preferences", unsubscribe, "padding-left: 16px; border-left: 1px solid #e5e7eb;", "50%");
  return `<tr><td style="padding: 20px 32px 24px; border-top: 1px solid #e5e7eb;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>${cols}</tr></table></td></tr>`;
}

export function buildEmailHtml(p: LayoutInput): string {
  const b = p.branding ?? DEFAULT_BRANDING;
  const color = b.buttonColor && HEX_COLOR.test(b.buttonColor) ? b.buttonColor : DEFAULT_BUTTON_COLOR;
  const filled = personalize(p.body, { recipientName: p.recipientName, orgName: p.orgName, unsubscribeUrl: p.unsubscribeUrl }, p.format);
  // The sender's own HTML sets its own spacing (and any header); markdown gets the card's padding.
  const body =
    p.format === "html"
      ? `<tr><td style="padding: 0;">${htmlFragment(filled)}</td></tr>`
      : `<tr><td style="padding: 24px 32px 8px; font-size: 15px; color: #374151; line-height: 1.6;">${renderMarkdown(filled, color)}</td></tr>`;
  const note = b.footerNote?.trim()
    ? `<tr><td align="center" style="padding: 16px 12px 0; font-size: 11px; color: #9ca3af;">${escapeHtml(b.footerNote.trim())}</td></tr>`
    : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 32px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; overflow: hidden;">
${body}
${footerHtml(p, b)}
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
