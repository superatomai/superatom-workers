/**
 * Test: the feedback triage rule.
 *
 * Three things are being protected, and the first is the one that would do real
 * damage. The mirror's write is an UPSERT whose `set` spreads these fields, so
 * a payload that says nothing about triage must produce NOTHING. If it produced
 * `{ resolution: 'open' }` instead, every edit of a feedback's text would quietly
 * reopen a row somebody had closed, and nobody would see it happen.
 *
 * The second is that the four judgement-call outcomes are refused without a
 * reason — the point of recording them at all is being able to say why.
 *
 * The third is that this list matches the engine's. The engine refuses first; if
 * the two ever disagree, the forward is 400ed here, the warning is swallowed,
 * and the mirror drifts from the authoritative table.
 *
 * Run: npx tsx tests/unit/lib/feedback-resolution.test.ts
 */

import {
  FEEDBACK_RESOLUTIONS,
  RESOLUTIONS_NEEDING_NOTE,
  resolutionUpdate,
} from "../../../src/lib/feedback-resolution";

let failures = 0;
let checks = 0;

function check(name: string, got: unknown, want: unknown): void {
  checks++;
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g === w) return;
  failures++;
  console.error(`FAIL ${name}\n  want ${w}\n  got  ${g}`);
}

/** Asserts the payload is accepted, and returns the fields it produced. */
function accepted(name: string, payload: any): Record<string, unknown> | undefined {
  checks++;
  const result = resolutionUpdate(payload);
  if (!result.ok) {
    failures++;
    console.error(`FAIL ${name}\n  expected acceptance, got: ${result.error}`);
    return undefined;
  }
  return result.fields;
}

/** Asserts the payload is refused, and that the message names the problem. */
function refused(name: string, payload: any, expect: string): void {
  checks++;
  const result = resolutionUpdate(payload);
  if (result.ok) {
    failures++;
    console.error(`FAIL ${name}\n  expected a refusal, got fields ${JSON.stringify(result.fields)}`);
    return;
  }
  if (!result.error.includes(expect)) {
    failures++;
    console.error(`FAIL ${name}\n  message should mention "${expect}"\n  got: ${result.error}`);
  }
}

// ─── absent means absent ─────────────────────────────────
// The regression this file exists for: a feedback write carries no resolution,
// and must not be read as one.

check("no resolution produces no fields", resolutionUpdate({}), { ok: true, fields: {} });
check(
  "a feedback edit with text but no resolution produces no fields",
  resolutionUpdate({ resolutionNote: "a stray note" } as any),
  { ok: true, fields: {} },
);

// ─── the enum ────────────────────────────────────────────

for (const value of FEEDBACK_RESOLUTIONS) {
  const needsNote = RESOLUTIONS_NEEDING_NOTE.includes(value);
  const fields = accepted(`${value} is accepted`, {
    resolution: value,
    resolutionNote: needsNote ? "because" : undefined,
  });
  check(`${value} survives into the fields`, fields?.resolution, value);
}

refused("an unknown resolution is refused", { resolution: "wont_fix" }, "must be one of");
refused("an empty string is refused", { resolution: "" }, "must be one of");
refused("a cased value is refused", { resolution: "Resolved" }, "must be one of");

// ─── the note rule ───────────────────────────────────────
// `open` and `resolved` say what happened on their own. The other four are a
// judgement, and a judgement with no reason cannot be reviewed.

check("open takes no note", accepted("open", { resolution: "open" })?.resolutionNote, null);
check(
  "resolved takes no note",
  accepted("resolved", { resolution: "resolved" })?.resolutionNote,
  null,
);

for (const value of RESOLUTIONS_NEEDING_NOTE) {
  refused(`${value} without a note`, { resolution: value }, "resolutionNote is required");
  refused(
    `${value} with a blank note`,
    { resolution: value, resolutionNote: "   " },
    "resolutionNote is required",
  );
  refused(
    `${value} with a null note`,
    { resolution: value, resolutionNote: null },
    "resolutionNote is required",
  );
}

check(
  "a note is trimmed before it is stored",
  accepted("duplicate with padding", {
    resolution: "duplicate",
    resolutionNote: "  same as #12  ",
  })?.resolutionNote,
  "same as #12",
);

// ─── the other three columns ─────────────────────────────

check(
  "resolvedBy and resolvedAt are null when not sent",
  (() => {
    const f = accepted("resolved, bare", { resolution: "resolved" });
    return [f?.resolvedBy, f?.resolvedAt];
  })(),
  [null, null],
);

check(
  "resolvedBy is carried through",
  accepted("resolved by someone", { resolution: "resolved", resolvedBy: "user-1" })?.resolvedBy,
  "user-1",
);

check(
  "resolvedAt becomes a Date",
  accepted("resolved at a time", {
    resolution: "resolved",
    resolvedAt: "2026-11-16T10:00:00.000Z",
  })?.resolvedAt instanceof Date,
  true,
);

// ─── the two repos agree ─────────────────────────────────
// Spelled out rather than imported, because the engine is a separate repo and
// there is no shared module. If someone edits one list, this fails and names it.

check("the enum is exactly these six", [...FEEDBACK_RESOLUTIONS], [
  "open",
  "resolved",
  "later_scope",
  "not_an_issue",
  "duplicate",
  "needs_info",
]);

check("exactly these four need a note", [...RESOLUTIONS_NEEDING_NOTE], [
  "later_scope",
  "not_an_issue",
  "duplicate",
  "needs_info",
]);

console.log(failures ? `\n${failures} of ${checks} checks FAILED` : `\nall ${checks} checks passed`);
process.exit(failures ? 1 : 0);
