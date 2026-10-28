/**
 * SDK data access — turns the `access` claim of a customer's sign-in token into
 * the user's `users.config`, which the relay stamps onto every message and the
 * backend enforces by rewriting SQL.
 *
 * The customer writes it, in whichever of two shapes fits their project. With
 * ONE data source there is nothing to disambiguate, so they send filters:
 *
 *   "access": [
 *     { "table": "fact_sales", "column": "cust_id", "op": "in", "values": [5, 117] },
 *     { "table": "fact_sales", "column": "status", "op": "not_in", "values": ["Cancelled"] }
 *   ]
 *
 * With SEVERAL data sources a filter has to say which one it belongs to, so they
 * send whole policies — the same shape we store:
 *
 *   "access": [
 *     { "label": "Assigned customers", "sourceId": "mssql-722b9497",
 *       "rowFilters": [ { "table": "customer", "column": "customerId", "op": "in", "values": [5, 117] } ] },
 *     { "label": "Assigned customers", "sourceId": "postgres-4f2c1a9b",
 *       "rowFilters": [ { "table": "shipment_summary", "column": "customer_ref", "op": "in", "values": [41306] } ] }
 *   ]
 *
 * A policy may also name `readableTables` — the tables the user may read AT ALL
 * in that source. Row filters alone are fail-open: a filter on `customer` does
 * nothing when the agent reads `customer_bak`, a view, or a synonym holding the
 * same rows (sqlrewrite/worker.py:281). Empty or absent means no table
 * restriction; naming any table makes it a strict allowlist.
 *
 * To scope whole SOURCES rather than rows or tables, send the OBJECT form:
 *
 *   "access": {
 *     "allowedSources": ["mssql-722b9497"],
 *     "policies": [
 *       { "sourceId": "mssql-722b9497", "readableTables": ["dbo.customer"],
 *         "rowFilters": [ { "table": "customer", "column": "id", "op": "in", "values": [5] } ] }
 *     ]
 *   }
 *
 * This is the only control that reaches a source the SQL rewriter does not
 * touch — dynamodb, redis, rest_api and graphql have no dialect, so they take
 * neither row filters nor a table allowlist.
 *
 * Either way we only check and store: nothing is inferred from the project, and
 * no source id is guessed. The result is the config interface the backend reads
 * (sdk-nodejs `policiesFromConfig`): the array form, or
 * `{ allowedSources?, policies: [...] }`.
 *
 * Rules:
 *  - No `access`, or an empty list, means no restriction (config null).
 *  - The two filter shapes may be mixed in one list; loose filters collect into
 *    a single policy with no source id.
 *  - `allowedSources` ABSENT means every source. `allowedSources: []` means
 *    NONE. The difference is deliberate and must survive: an empty array is
 *    what a computed-but-unprivileged lookup produces, so reading it as "all"
 *    would hand the least privileged user the most access.
 *  - Anything malformed refuses the sign-in rather than being dropped. The
 *    backend silently ignores a filter with no column or no values, which would
 *    leave the user UNRESTRICTED — so a typo must fail loudly here instead. An
 *    empty `values` list is refused for the same reason: "no customers" must not
 *    end up meaning "all customers".
 */

/**
 * Every operator the SQL rewriter supports. `eq`/`ne` compare against a single
 * value — the rewriter uses `values[0]` — so more than one value with them is
 * refused rather than silently trimmed.
 */
const OPS = ["in", "not_in", "eq", "ne"] as const;
type Op = (typeof OPS)[number];
const SINGLE_VALUE_OPS: readonly Op[] = ["eq", "ne"];

/** Mirrors sdk-nodejs `RowFilter` / `SourcePolicy`. */
interface RowFilter {
  table: string;
  column: string;
  op: Op;
  values: (string | number)[];
  label: string;
}
interface SourcePolicy {
  sourceId?: string;
  label?: string;
  /** Omitted entirely when the policy only restricts tables. */
  rowFilters?: RowFilter[];
  /** Gate 3. Absent or empty means no table restriction. */
  readableTables?: string[];
}

/**
 * What the backend receives. The array form is what every existing customer
 * sends and is stored unchanged; the object form adds source scoping.
 */
export type AccessConfig = SourcePolicy[] | { allowedSources?: string[]; policies: SourcePolicy[] };

/** Bounds, so a bad token cannot fill the database or the SQL. */
const MAX_VALUES = 1000;
const MAX_VALUE_LENGTH = 200;
const MAX_NAME_LENGTH = 100;
/** Entries one token may carry, whether filters or policies. */
const MAX_FILTERS = 50;
/** Row filters one policy may carry. */
const MAX_FILTERS_PER_POLICY = 50;
/** Tables one policy may allow, and sources one token may allow. */
const MAX_TABLES_PER_POLICY = 200;
const MAX_ALLOWED_SOURCES = 50;

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/** How a value reads in a message: quoted if text, bare if a number. */
function describe(item: unknown): string {
  if (item === null) return "null";
  if (typeof item === "string") return `"${item.slice(0, 30)}"`;
  if (typeof item === "number") return String(item);
  if (Array.isArray(item)) return "a list";
  return typeof item;
}

/**
 * One value or a list, as a clean list. On failure it says what is wrong in
 * words, since this message reaches whoever wrote the integration.
 */
function parseValues(value: unknown): { ok: true; values: (string | number)[] } | { ok: false; why: string } {
  if (value === undefined || value === null) return { ok: false, why: "is missing" };

  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0) return { ok: false, why: "is empty — an empty list restricts nothing" };
  if (list.length > MAX_VALUES) return { ok: false, why: `has ${list.length} values, more than the ${MAX_VALUES} allowed` };

  const out: (string | number)[] = [];
  for (const [i, item] of list.entries()) {
    const at = Array.isArray(value) ? ` at ${i}` : "";
    let v: string | number;
    if (typeof item === "number") {
      if (!Number.isFinite(item)) return { ok: false, why: `has a value${at} that is not a real number` };
      v = item;
    } else if (typeof item === "string") {
      if (!item.trim()) return { ok: false, why: `has an empty text value${at}` };
      if (item.trim().length > MAX_VALUE_LENGTH) {
        return { ok: false, why: `has a text value${at} over ${MAX_VALUE_LENGTH} characters` };
      }
      v = item.trim();
    } else {
      return { ok: false, why: `must hold text or numbers, found ${describe(item)}${at}` };
    }
    if (!out.includes(v)) out.push(v);
  }
  return { ok: true, values: out };
}

export type AccessResult =
  | { ok: true; config: AccessConfig | null }
  | { ok: false; reason: string; error: string };

/**
 * True when the token carries an access claim at all — either shape.
 *
 * Its absence is what makes the relay fall back to `users.config`, so an object
 * that is merely EMPTY (`{}`) still counts: the customer said something, and
 * silently using stored config instead would be a different answer than they
 * gave.
 */
export function sendsFilters(access: unknown): boolean {
  if (Array.isArray(access)) return true;
  return !!access && typeof access === "object";
}

/**
 * A list of names — table names or source ids — trimmed, deduped and bounded.
 *
 * Shared by `readableTables` and `allowedSources` because both are allowlists
 * of identifiers and both must fail loudly rather than drop an entry: a name
 * quietly discarded here widens access without anyone seeing it.
 */
function parseNames(
  value: unknown,
  where: string,
  max: number,
): { ok: true; names: string[] } | { ok: false; reason: string; error: string } {
  if (!Array.isArray(value)) return bad(`${where} must be a list`);
  if (value.length > max) return bad(`${where} must hold at most ${max} entries`);

  const out: string[] = [];
  for (const [i, item] of value.entries()) {
    if (!nonEmpty(item)) return bad(`${where}[${i}] must be a non-empty name, found ${describe(item)}`);
    const name = item.trim();
    if (name.length > MAX_NAME_LENGTH) return bad(`${where}[${i}] is over ${MAX_NAME_LENGTH} characters`);
    if (!out.includes(name)) out.push(name);
  }
  return { ok: true, names: out };
}

/** A failure carrying where it happened, so the customer can find the entry. */
function bad(error: string): { ok: false; reason: string; error: string } {
  return { ok: false, reason: "bad_access_filters", error };
}

/**
 * One row filter, checked. `fallbackLabel` is the policy's label, used when the
 * filter has none — without any label the assistant describes the restriction to
 * the user as a raw SQL predicate.
 */
function readFilter(entry: unknown, where: string, fallbackLabel?: string): RowFilter | { ok: false; reason: string; error: string } {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return bad(`${where} must be an object`);
  const { table, column, op, values, label } = entry as Record<string, unknown>;

  if (!nonEmpty(table)) return bad(`${where}.table is missing`);
  if (table.trim().length > MAX_NAME_LENGTH) return bad(`${where}.table is over ${MAX_NAME_LENGTH} characters`);
  if (!nonEmpty(column)) return bad(`${where}.column is missing`);
  if (column.trim().length > MAX_NAME_LENGTH) return bad(`${where}.column is over ${MAX_NAME_LENGTH} characters`);
  if (op !== undefined && !OPS.includes(op as Op)) {
    return bad(`${where}.op ${describe(op)} is not supported — use ${OPS.join(", ")}`);
  }

  const parsed = parseValues(values);
  if (!parsed.ok) return bad(`${where}.values ${parsed.why}`);

  if (label !== undefined && (!nonEmpty(label) || label.trim().length > MAX_VALUE_LENGTH)) {
    return bad(`${where}.label must be short text`);
  }
  if (SINGLE_VALUE_OPS.includes((op as Op) ?? "in") && parsed.values.length !== 1) {
    return bad(`${where}.op "${op}" takes one value, got ${parsed.values.length} — use "in" or "not_in" for several`);
  }

  return {
    table: table.trim(),
    column: column.trim(),
    op: (op as Op | undefined) ?? "in",
    values: parsed.values,
    label: (label as string | undefined)?.trim() || fallbackLabel || `${column.trim()} ${parsed.values.join(", ")}`,
  };
}

const isFailure = (v: unknown): v is { ok: false; reason: string; error: string } =>
  !!v && typeof v === "object" && (v as { ok?: unknown }).ok === false;

/**
 * The user's config from the `access` claim. Accepts a list of row filters, a
 * list of source policies, or a mix, and stores what it is given — the project
 * is not consulted and no source id is inferred.
 */
export function buildFiltersConfig(access: unknown): AccessResult {
  if (!Array.isArray(access)) return buildScopedConfig(access);

  const built = buildPolicies(access, "access");
  if (isFailure(built)) return built;
  return { ok: true, config: built.policies.length ? built.policies : null };
}

/**
 * The object form: `{ allowedSources?, policies? }`.
 *
 * Kept separate from the array form so the array path stays exactly as it was —
 * every existing customer is on it, and this change must not alter a single
 * outcome there.
 *
 * `allowedSources` is preserved as sent, INCLUDING an empty list. Collapsing
 * `[]` to "no restriction" is the one transformation that must never happen
 * here: an empty array is what `user.sources.map(s => s.id)` returns for a user
 * with nothing assigned.
 */
function buildScopedConfig(access: unknown): AccessResult {
  if (!access || typeof access !== "object") {
    return bad(`access must be a list of filters or an object with allowedSources and policies`);
  }

  const { allowedSources, policies: rawPolicies, ...rest } = access as Record<string, unknown>;
  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length) {
    // Refused rather than ignored: a misspelt key would otherwise mean the
    // restriction the customer wrote simply does not exist.
    return bad(`access has unknown field(s): ${unknownKeys.join(", ")} — expected allowedSources, policies`);
  }

  let sources: string[] | undefined;
  if (allowedSources !== undefined) {
    const parsed = parseNames(allowedSources, "access.allowedSources", MAX_ALLOWED_SOURCES);
    if (isFailure(parsed)) return parsed;
    sources = parsed.names;
  }

  let policies: SourcePolicy[] = [];
  if (rawPolicies !== undefined) {
    if (!Array.isArray(rawPolicies)) return bad(`access.policies must be a list`);
    const built = buildPolicies(rawPolicies, "access.policies");
    if (isFailure(built)) return built;
    policies = built.policies;
  }

  // Nothing said at all. Treated as the array form's empty list: no restriction.
  if (sources === undefined && policies.length === 0) return { ok: true, config: null };

  return {
    ok: true,
    config: { ...(sources !== undefined ? { allowedSources: sources } : {}), policies },
  };
}

/** The shared policy/filter parser, used by both shapes. */
function buildPolicies(
  raw: unknown[],
  path: string,
): { ok: true; policies: SourcePolicy[] } | { ok: false; reason: string; error: string } {
  if (raw.length === 0) return { ok: true, policies: [] };
  if (raw.length > MAX_FILTERS) {
    return bad(`${path} must hold at most ${MAX_FILTERS} entries`);
  }

  const policies: SourcePolicy[] = [];
  /** Loose filters, collected into one policy with no source id. */
  const loose: RowFilter[] = [];

  for (const [i, entry] of raw.entries()) {
    const where = `${path}[${i}]`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return bad(`${where} must be an object`);
    const { sourceId, label, rowFilters, readableTables } = entry as Record<string, unknown>;

    // A policy is anything carrying `rowFilters` or `readableTables`. Deciding
    // on those keys rather than on `sourceId` matters: a policy whose source id
    // was left out is still a policy, and must not be read as a filter missing
    // its table.
    if (rowFilters === undefined && readableTables === undefined) {
      if (sourceId !== undefined) {
        return bad(
          `${where} has a sourceId but no rowFilters or readableTables — a filter cannot name a source on its own`,
        );
      }
      const filter = readFilter(entry, where);
      if (isFailure(filter)) return filter;
      loose.push(filter);
      continue;
    }

    if (rowFilters !== undefined) {
      if (!Array.isArray(rowFilters)) return bad(`${where}.rowFilters must be a list`);
      if (rowFilters.length === 0) return bad(`${where}.rowFilters is empty`);
      if (rowFilters.length > MAX_FILTERS_PER_POLICY) {
        return bad(`${where}.rowFilters must hold at most ${MAX_FILTERS_PER_POLICY} filters`);
      }
    }
    if (sourceId !== undefined && (!nonEmpty(sourceId) || sourceId.trim().length > MAX_NAME_LENGTH)) {
      return bad(`${where}.sourceId must be a string`);
    }
    if (label !== undefined && (!nonEmpty(label) || label.trim().length > MAX_VALUE_LENGTH)) {
      return bad(`${where}.label must be a short string`);
    }

    // Refused when present but empty, for the reason an empty `values` is: a
    // policy saying "these tables" and naming none reads as a mistake, and
    // treating it as "no restriction" would silently widen access.
    let tables: string[] | undefined;
    if (readableTables !== undefined) {
      const parsed = parseNames(readableTables, `${where}.readableTables`, MAX_TABLES_PER_POLICY);
      if (isFailure(parsed)) return parsed;
      if (parsed.names.length === 0) {
        return bad(`${where}.readableTables is empty — omit it to allow every table`);
      }
      tables = parsed.names;
    }

    const policyLabel = (label as string | undefined)?.trim();
    const filters: RowFilter[] = [];
    for (const [j, f] of (rowFilters as unknown[] | undefined)?.entries() ?? []) {
      const filter = readFilter(f, `${where}.rowFilters[${j}]`, policyLabel);
      if (isFailure(filter)) return filter;
      filters.push(filter);
    }

    policies.push({
      ...(sourceId ? { sourceId: (sourceId as string).trim() } : {}),
      ...(policyLabel ? { label: policyLabel } : {}),
      // Omitted rather than empty when the policy only restricts tables: the
      // backend reads an empty list the same way, but storing one would claim a
      // row restriction exists where none was asked for.
      ...(filters.length ? { rowFilters: filters } : {}),
      ...(tables ? { readableTables: tables } : {}),
    });
  }

  if (loose.length) policies.push({ rowFilters: loose });
  return { ok: true, policies };
}
