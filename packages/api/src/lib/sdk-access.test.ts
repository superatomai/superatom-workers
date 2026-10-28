/**
 * Test: the `access` claim validator.
 *
 * Two things are being protected here. The first is that the ARRAY form behaves
 * exactly as it did before source scoping existed — every customer in the wild
 * is on it, so a difference there is a regression in production.
 *
 * The second is the direction of failure. This module exists because the
 * backend drops a malformed filter silently and runs the query UNRESTRICTED, so
 * a typo must refuse the sign-in here instead. Every "refuses" case below is a
 * case that would otherwise have widened someone's access without a trace.
 *
 * Run: npx tsx src/lib/sdk-access.test.ts
 */

import { buildFiltersConfig, sendsFilters } from "./sdk-access";

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

/** Asserts the claim is accepted, and returns the config it produced. */
function accepted(name: string, access: unknown): unknown {
  checks++;
  const result = buildFiltersConfig(access);
  if (!result.ok) {
    failures++;
    console.error(`FAIL ${name}\n  expected acceptance, got: ${result.error}`);
    return undefined;
  }
  return result.config;
}

/** Asserts the claim is refused — the important direction. */
function refused(name: string, access: unknown): void {
  checks++;
  const result = buildFiltersConfig(access);
  if (result.ok) {
    failures++;
    console.error(`FAIL ${name}\n  expected refusal, got config: ${JSON.stringify(result.config)}`);
  }
}

const filter = { table: "orders", column: "customer_id", op: "in", values: [12] };
const builtFilter = { table: "orders", column: "customer_id", op: "in", values: [12], label: "customer_id 12" };

// ─── The array form, unchanged ───────────────────────────
// If any of these move, existing customers break.

check("empty list means no restriction", accepted("empty", []), null);

check(
  "a loose filter collects into one policy with no source id",
  accepted("loose filter", [filter]),
  [{ rowFilters: [builtFilter] }],
);

check(
  "a policy keeps its source id and label",
  accepted("policy", [{ sourceId: "mssql-1a2b", label: "Assigned", rowFilters: [filter] }]),
  [{ sourceId: "mssql-1a2b", label: "Assigned", rowFilters: [{ ...builtFilter, label: "Assigned" }] }],
);

refused("a sourceId alone is not a policy", [{ sourceId: "mssql-1a2b" }]);
refused("an empty values list", [{ ...filter, values: [] }]);
refused("an empty rowFilters list", [{ sourceId: "mssql-1a2b", rowFilters: [] }]);
refused("an unsupported op", [{ ...filter, op: "equals" }]);
refused("eq with several values", [{ ...filter, op: "eq", values: [1, 2] }]);

// ─── readableTables ──────────────────────────────────────

check(
  "readableTables survives into the config",
  accepted("tables", [{ sourceId: "mssql-1a2b", readableTables: ["dbo.customer"], rowFilters: [filter] }]),
  [{ sourceId: "mssql-1a2b", rowFilters: [builtFilter], readableTables: ["dbo.customer"] }],
);

check(
  "a policy may restrict tables without restricting rows",
  accepted("tables only", [{ sourceId: "mssql-1a2b", readableTables: ["dbo.customer"] }]),
  [{ sourceId: "mssql-1a2b", readableTables: ["dbo.customer"] }],
);

check(
  "table names are trimmed and deduped",
  accepted("dedupe", [{ sourceId: "s", readableTables: [" dbo.customer ", "dbo.customer"] }]),
  [{ sourceId: "s", readableTables: ["dbo.customer"] }],
);

// Empty is refused rather than read as "no restriction": a policy naming no
// tables is a mistake, and the permissive reading is the dangerous one.
refused("an empty readableTables list", [{ sourceId: "s", readableTables: [] }]);
refused("a blank table name", [{ sourceId: "s", readableTables: [""] }]);
refused("readableTables that is not a list", [{ sourceId: "s", readableTables: "dbo.customer" }]);

// ─── The object form ─────────────────────────────────────

check(
  "allowedSources and policies travel together",
  accepted("object", {
    allowedSources: ["mssql-1a2b"],
    policies: [{ sourceId: "mssql-1a2b", readableTables: ["dbo.customer"], rowFilters: [filter] }],
  }),
  {
    allowedSources: ["mssql-1a2b"],
    policies: [{ sourceId: "mssql-1a2b", rowFilters: [builtFilter], readableTables: ["dbo.customer"] }],
  },
);

check(
  "allowedSources alone is enough",
  accepted("sources only", { allowedSources: ["mssql-1a2b"] }),
  { allowedSources: ["mssql-1a2b"], policies: [] },
);

// THE CASE THIS WHOLE SHAPE EXISTS FOR. An empty array is what
// `user.sources.map(s => s.id)` returns for a user with nothing assigned.
// Reading it as "no restriction" would hand the least privileged user the most
// access, silently.
check(
  "an empty allowedSources denies everything and is NOT collapsed to null",
  accepted("deny all", { allowedSources: [] }),
  { allowedSources: [], policies: [] },
);

check("an object saying nothing means no restriction", accepted("empty object", {}), null);

refused("an unknown field, rather than ignoring a misspelling", { allowedSource: ["s"], policies: [] });
refused("allowedSources that is not a list", { allowedSources: "mssql-1a2b" });
refused("a blank source id", { allowedSources: [""] });
refused("policies that is not a list", { policies: {} });
refused("a malformed filter inside the object form", { policies: [{ ...filter, values: [] }] });

// ─── sendsFilters ────────────────────────────────────────
// Its absence is what makes the relay fall back to users.config, so an empty
// object must still count as "the customer said something".

check("an array counts", sendsFilters([]), true);
check("an object counts", sendsFilters({}), true);
check("a string does not", sendsFilters("all"), false);
check("null does not", sendsFilters(null), false);

console.log(failures ? `\n${failures} of ${checks} checks FAILED` : `\nall ${checks} checks passed`);
process.exit(failures ? 1 : 0);
