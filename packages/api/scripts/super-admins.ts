/**
 * Manage super-admin console accounts (the `super_admins` table).
 *
 *   DATABASE_URL=… pnpm superadmin list
 *   DATABASE_URL=… pnpm superadmin add "<Name>" <email>     # prompts for the password
 *   DATABASE_URL=… pnpm superadmin reset <email>            # prompts for a new password
 *   DATABASE_URL=… pnpm superadmin deactivate <email>
 *   DATABASE_URL=… pnpm superadmin activate <email>
 *
 * reset/deactivate also end that admin's open sessions.
 */
import { createInterface } from "node:readline";
import { asc, eq, sql } from "drizzle-orm";
import { createDb } from "../src/db";
import { superAdmins } from "../src/db/schema";
import { validatePassword } from "../src/lib/password-policy";
import { hashPassword } from "../src/superadmin/lib/password";
import { revocationCutoff } from "../src/superadmin/lib/session";

const USAGE = `Usage:
  pnpm superadmin list
  pnpm superadmin add "<Name>" <email>
  pnpm superadmin reset <email>
  pnpm superadmin deactivate <email>
  pnpm superadmin activate <email>`;

const CTRL_C = String.fromCharCode(3);
const BACKSPACE = String.fromCharCode(127);
const BS = String.fromCharCode(8);

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

// One reader for all piped lines: a per-prompt reader would swallow the lines after its own.
let pipedLines: AsyncIterator<string> | null = null;

async function nextPipedLine(): Promise<string> {
  pipedLines ??= createInterface({ input: process.stdin })[Symbol.asyncIterator]();
  const { value, done } = await pipedLines.next();
  if (done) fail("Expected a password on stdin.");
  return value;
}

/** Reads a line without echoing it (TTY), or the next stdin line when piped. */
function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) return nextPipedLine();
  process.stdout.write(question);
  return new Promise((resolve) => {
    let value = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (ch === CTRL_C) {
          process.stdout.write("\n");
          process.exit(130);
        }
        if (ch === BACKSPACE || ch === BS) value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function askNewPassword(): Promise<string> {
  const password = await promptHidden("Password: ");
  const policyError = validatePassword(password);
  if (policyError) fail(policyError);
  const confirm = await promptHidden("Confirm password: ");
  if (confirm !== password) fail("Passwords do not match.");
  return password;
}

function normalizeEmail(raw: string | undefined): string {
  const email = (raw ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255) fail(`Invalid email: ${raw ?? ""}`);
  return email;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command) fail(USAGE);

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) fail("DATABASE_URL is not set.");
  // Show which database is being changed, so dev vs prod is never a guess.
  const target = new URL(databaseUrl);
  console.log(`Database: ${target.hostname}${target.pathname}\n`);

  const db = createDb(databaseUrl);
  const byEmail = (email: string) => sql`lower(${superAdmins.email}) = ${email}`;

  switch (command) {
    case "list": {
      const rows = await db
        .select({
          email: superAdmins.email,
          name: superAdmins.name,
          active: superAdmins.isActive,
          created: superAdmins.createdAt,
        })
        .from(superAdmins)
        .orderBy(asc(superAdmins.createdAt));
      if (rows.length === 0) console.log("No super admins.");
      else console.table(rows.map((r) => ({ ...r, created: r.created.toISOString().slice(0, 10) })));
      return;
    }

    case "add": {
      const name = (args[0] ?? "").trim();
      const email = normalizeEmail(args[1]);
      if (!name || name.length > 255) fail(USAGE);
      const [existing] = await db.select({ id: superAdmins.id }).from(superAdmins).where(byEmail(email)).limit(1);
      if (existing) fail(`${email} already exists — use "reset" to change the password.`);
      const passwordHash = await hashPassword(await askNewPassword());
      await db.insert(superAdmins).values({ name, email, passwordHash });
      console.log(`Added ${name} <${email}>.`);
      return;
    }

    case "reset": {
      const email = normalizeEmail(args[0]);
      const [existing] = await db.select({ id: superAdmins.id }).from(superAdmins).where(byEmail(email)).limit(1);
      if (!existing) fail(`No super admin with email ${email}.`);
      const passwordHash = await hashPassword(await askNewPassword());
      await db
        .update(superAdmins)
        .set({ passwordHash, tokensValidAfter: revocationCutoff(), updatedAt: new Date() })
        .where(eq(superAdmins.id, existing.id));
      console.log(`Password reset for ${email}; existing sessions ended.`);
      return;
    }

    case "deactivate":
    case "activate": {
      const email = normalizeEmail(args[0]);
      const isActive = command === "activate";
      const updated = await db
        .update(superAdmins)
        .set({
          isActive,
          updatedAt: new Date(),
          ...(isActive ? {} : { tokensValidAfter: revocationCutoff() }),
        })
        .where(byEmail(email))
        .returning({ id: superAdmins.id });
      if (updated.length === 0) fail(`No super admin with email ${email}.`);
      console.log(`${email} ${isActive ? "activated" : "deactivated; existing sessions ended"}.`);
      return;
    }

    default:
      fail(USAGE);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
