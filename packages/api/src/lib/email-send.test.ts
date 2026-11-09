import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { isPlaceholderAddress, sendEmailsEach, type EmailMessage } from "./email";
import type { Env } from "../types";

const env = { RESEND_API_KEY: "re_test" } as Env;
const msg = (to: string): EmailMessage => ({ from: "a@superatom.ai", to: [to], subject: "Hi", html: "<p>Hi</p>" });
const realFetch = globalThis.fetch;
afterEach(() => (globalThis.fetch = realFetch));

/** A fake Resend: rejects any request naming a bad address, like the real batch endpoint. */
function fakeResend(bad: (to: string) => boolean, status = 422) {
  const calls: Array<{ url: string; to: string[] }> = [];
  let n = 0;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    const items: Array<{ to: string[] }> = Array.isArray(body) ? body : [body];
    const to = items.flatMap((m) => m.to);
    calls.push({ url, to });
    if (to.some(bad)) return new Response(JSON.stringify({ message: "Invalid `to` field" }), { status });
    const ids = items.map(() => `id-${++n}`);
    return Response.json(Array.isArray(body) ? { data: ids.map((id) => ({ id })) } : { id: ids[0] });
  }) as typeof fetch;
  return calls;
}

describe("sending to many people", () => {
  // 2026-11-09: one laura.bennett@example.com in a 20-person BlueLinx send failed all 20.
  it("a placeholder address fails alone and is never sent to Resend", async () => {
    const calls = fakeResend((to) => to.endsWith("@example.com"));
    const r = await sendEmailsEach(env, [msg("kate@bluelinxco.com"), msg("laura.bennett@example.com"), msg("mark@bluelinxco.com")], "k", undefined, 0);
    assert.deepEqual(r.map((x) => x.id ?? "failed"), ["id-1", "failed", "id-2"]);
    assert.match(r[1].error!, /Placeholder/);
    assert.equal(calls.length, 1, "one batch call");
    assert.deepEqual(calls[0].to, ["kate@bluelinxco.com", "mark@bluelinxco.com"]);
  });

  it("when Resend rejects the batch as invalid, each person is sent on their own so only the bad one fails", async () => {
    const calls = fakeResend((to) => to === "broken@bluelinxco.com");
    const r = await sendEmailsEach(env, [msg("kate@bluelinxco.com"), msg("broken@bluelinxco.com"), msg("mark@bluelinxco.com")], "k", undefined, 0);
    assert.ok(r[0].id && r[2].id);
    assert.match(r[1].error!, /422/);
    assert.equal(calls.length, 4, "1 batch + 3 single");
  });

  it("other failures (auth, quota) fail everyone without retrying each", async () => {
    const calls = fakeResend(() => true, 403);
    const r = await sendEmailsEach(env, [msg("kate@bluelinxco.com"), msg("mark@bluelinxco.com")], "k", undefined, 0);
    assert.ok(r.every((x) => /403/.test(x.error!)));
    assert.equal(calls.length, 1);
  });

  it("recognises reserved domains only", () => {
    for (const e of ["a@example.com", "a@EXAMPLE.org", "a@foo.test", "a@x.invalid", "a@mail.example"]) assert.ok(isPlaceholderAddress(e), e);
    for (const e of ["a@bluelinxco.com", "a@example.co", "a@myexample.com", "a@test.com"]) assert.ok(!isPlaceholderAddress(e), e);
  });
});
