import { Hono } from "hono";
import type { Env, AppVariables } from "../types";
import { eq } from "drizzle-orm";
import { emailUnsubscribes, users } from "../db/schema";
import { verifyUnsubscribeToken } from "../lib/email";

/**
 * Public unsubscribe, mounted at /email. The signed token is the only credential.
 * GET only shows a confirm button: link scanners prefetch GETs and must not unsubscribe anyone.
 * POST unsubscribes, from that button or from a mail client's one-click (RFC 8058).
 */
const unsubscribe = new Hono<{ Bindings: Env; Variables: AppVariables }>();

function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title></head>
<body style="margin: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<div style="max-width: 440px; margin: 64px auto; padding: 32px; background-color: #ffffff; border-radius: 8px; color: #111827;">${body}</div>
</body></html>`;
}

unsubscribe.get("/unsubscribe", async (c) => {
  const token = c.req.query("token") ?? "";
  if (!(await verifyUnsubscribeToken(c.env, token))) {
    return c.html(page("Invalid link", `<h2 style="margin-top: 0;">This link is invalid</h2><p>It may have been copied incompletely.</p>`), 400);
  }
  return c.html(
    page(
      "Unsubscribe",
      `<h2 style="margin-top: 0;">Unsubscribe from announcements?</h2>
<p style="color: #4b5563;">You'll stop receiving announcement emails from your organization on Superatom. Report and alert emails are not affected.</p>
<form method="post" action="?token=${encodeURIComponent(token)}">
<button type="submit" style="padding: 10px 18px; border: 0; border-radius: 6px; background-color: #111827; color: #ffffff; font-size: 14px; cursor: pointer;">Unsubscribe</button>
</form>`
    )
  );
});

unsubscribe.post("/unsubscribe", async (c) => {
  const parsed = await verifyUnsubscribeToken(c.env, c.req.query("token") ?? "");
  if (!parsed) return c.html(page("Invalid link", `<h2 style="margin-top: 0;">This link is invalid</h2>`), 400);
  const db = c.get("db");
  // A deleted user has no row to reference, and no one left to email.
  const [user] = await db.select({ id: users.id }).from(users).where(eq(users.id, parsed.userId));
  if (user) {
    await db.insert(emailUnsubscribes).values({ userId: parsed.userId, category: parsed.category }).onConflictDoNothing();
  }
  return c.html(page("Unsubscribed", `<h2 style="margin-top: 0;">You're unsubscribed</h2><p style="color: #4b5563;">You won't receive any more announcement emails.</p>`));
});

export default unsubscribe;
