/**
 * SDK data access — turns the `access` claim of a customer's sign-in token into
 * the user's `users.config`, which the relay stamps onto every message and the
 * backend enforces by rewriting SQL.
 *
 * The customer writes the filters — they know their own schema:
 *
 *   "access": [
 *     { "table": "com_trn_documentstamp", "column": "LocationId", "op": "in",
 *       "values": [5, 117, 127], "label": "Bhubaneshwar region" }
 *   ]
 *
 * We add what is ours to know and meaningless to them: which data source each
 * table belongs to. A project lists its sources and the tables exposed for
 * filtering in `projects.config.sdkAccess`:
 *
 *   "sdkAccess": {
 *     "sources": [
 *       { "sourceId": "mssql-722b9497", "label": "Warehouse DB",
 *         "tables": ["com_trn_documentstamp", "com_mst_location"] },
 *       { "sourceId": "athena-4f2c1a9b", "label": "Lany Summary",
 *         "tables": ["shipment_summary"] }
 *     ]
 *   }
 *
 * Each filter is routed by its table, so a project with two databases gets one
 * policy per source — the shape the backend reads (sdk-nodejs
 * `policiesFromConfig`): `[{ sourceId, rowFilters: [...] }]`. Without that, one
 * source id would have to cover every filter, and a query against any other
 * source would match no policy at all and run unrestricted.
 *
 * Rules:
 *  - No `access`, or an empty list, means no restriction (config null).
 *  - A table listed under several sources is filtered in all of them: over-
 *    restricting is safe, guessing one and leaving the other open is not.
 *  - A table listed under none is kept without a source id, which the backend
 *    offers to every source. It still only fires where that table exists.
 *  - Anything malformed refuses the sign-in rather than being dropped: the
 *    backend silently ignores a filter with no column or no values, which would
 *    leave the user unrestricted. An empty `values` list is refused for the same
 *    reason — "no customers" must not end up meaning "all customers".
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
  rowFilters: RowFilter[];
}

/** Bounds, so a bad token cannot fill the database or the SQL. */
const MAX_VALUES = 1000;
const MAX_VALUE_LENGTH = 200;
const MAX_NAME_LENGTH = 100;
/** Filters one token may carry when the customer sends them itself. */
const MAX_FILTERS = 50;

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/** One data source of a project, and the tables it exposes for filtering. */
interface AccessSource {
  sourceId: string;
  /** Human name for whoever reads the config, e.g. "Warehouse DB". Not shown to users. */
  label?: string;
  /** Table names, lower-cased for matching. */
  tables: string[];
}

/** What the project knows and the customer does not: where each table lives. */
export interface AccessDefaults {
  sources: AccessSource[];
}

/** Bounds on the project's own config, so one bad edit cannot blow up a sign-in. */
const MAX_SOURCES = 20;
const MAX_TABLES_PER_SOURCE = 500;

/**
 * `projects.config.sdkAccess`. Throws when it is malformed — that is a fault in
 * our configuration, not in the customer's token, and the caller answers 503
 * rather than blaming them.
 *
 * A project with no `sdkAccess` is not an error: its filters simply carry no
 * source id, which the backend offers to every source.
 */
export function readAccessDefaults(projectConfig: unknown): AccessDefaults {
  const raw = (projectConfig as Record<string, unknown> | null)?.sdkAccess;
  if (raw === undefined || raw === null) return { sources: [] };
  if (typeof raw !== "object" || Array.isArray(raw)) throw new Error("sdkAccess must be an object");

  const { sources } = raw as Record<string, unknown>;
  if (sources === undefined || sources === null) return { sources: [] };
  if (!Array.isArray(sources)) throw new Error("sdkAccess.sources must be a list");
  if (sources.length > MAX_SOURCES) throw new Error(`sdkAccess.sources must hold at most ${MAX_SOURCES} sources`);

  return {
    sources: sources.map((entry, i) => {
      const where = `sdkAccess.sources[${i}]`;
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${where} must be an object`);
      const { sourceId, label, tables } = entry as Record<string, unknown>;

      if (!nonEmpty(sourceId)) throw new Error(`${where}.sourceId is required`);
      if (label !== undefined && !nonEmpty(label)) throw new Error(`${where}.label must be a string`);
      if (!Array.isArray(tables)) throw new Error(`${where}.tables must be a list`);
      if (tables.length > MAX_TABLES_PER_SOURCE) {
        throw new Error(`${where}.tables must hold at most ${MAX_TABLES_PER_SOURCE} tables`);
      }
      for (const t of tables) {
        if (!nonEmpty(t)) throw new Error(`${where}.tables must hold table names`);
      }

      return {
        sourceId: sourceId.trim(),
        ...(label ? { label: (label as string).trim() } : {}),
        // Matching is case-insensitive: a customer writing "Orders" must hit a
        // table we recorded as "orders".
        tables: (tables as string[]).map((t) => t.trim().toLowerCase()),
      };
    }),
  };
}

/** The sources a table belongs to; empty when the project lists it nowhere. */
function sourcesForTable(table: string, defaults: AccessDefaults): AccessSource[] {
  const want = table.toLowerCase();
  return defaults.sources.filter((s) => s.tables.includes(want));
}


/** One value or a list, as a clean list; null if malformed. */
function parseValues(value: unknown): (string | number)[] | null {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0 || list.length > MAX_VALUES) return null;

  const out: (string | number)[] = [];
  for (const item of list) {
    let v: string | number;
    if (typeof item === "number" && Number.isFinite(item)) v = item;
    else if (typeof item === "string" && item.trim() && item.trim().length <= MAX_VALUE_LENGTH) v = item.trim();
    else return null;
    if (!out.includes(v)) out.push(v);
  }
  return out;
}

export type AccessResult =
  | { ok: true; config: SourcePolicy[] | null; warnings: string[] }
  | { ok: false; reason: string; error: string };

/** True when the token sends filters rather than values for us to map. */
export function sendsFilters(access: unknown): boolean {
  return Array.isArray(access);
}

/**
 * The user's config from filters the CUSTOMER wrote. They know their schema, so
 * table, column, op and values come from the token; which data source each table
 * belongs to is ours, and a filter without a label gets one so the assistant
 * does not read SQL aloud.
 *
 * Filters are grouped into one policy per source, keyed by "" for the ones the
 * project never placed.
 *
 * Everything is checked: a filter the backend would silently drop — no column, no
 * values — must refuse the sign-in instead, or the user ends up unrestricted.
 */
export function buildFiltersConfig(access: unknown, defaults: AccessDefaults): AccessResult {
  const raw = access as unknown[];
  if (raw.length === 0) return { ok: true, config: null, warnings: [] };
  if (raw.length > MAX_FILTERS) {
    return { ok: false, reason: "bad_access_filters", error: `access must hold at most ${MAX_FILTERS} filters` };
  }

  const bySource = new Map<string, SourcePolicy>();
  for (const [i, entry] of raw.entries()) {
    const where = `access[${i}]`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return { ok: false, reason: "bad_access_filters", error: `${where} must be an object` };
    }
    const { table, column, op, values, label } = entry as Record<string, unknown>;

    if (!nonEmpty(table) || table.trim().length > MAX_NAME_LENGTH) {
      return { ok: false, reason: "bad_access_filters", error: `${where}.table is required` };
    }
    if (!nonEmpty(column) || column.trim().length > MAX_NAME_LENGTH) {
      return { ok: false, reason: "bad_access_filters", error: `${where}.column is required` };
    }
    if (op !== undefined && !OPS.includes(op as Op)) {
      return { ok: false, reason: "bad_access_filters", error: `${where}.op must be one of ${OPS.join(", ")}` };
    }
    const parsed = parseValues(values);
    if (!parsed) {
      return {
        ok: false,
        reason: "bad_access_filters",
        error: `${where}.values must be a value or a list of 1–${MAX_VALUES} values (strings or numbers)`,
      };
    }
    if (label !== undefined && (!nonEmpty(label) || label.trim().length > MAX_VALUE_LENGTH)) {
      return { ok: false, reason: "bad_access_filters", error: `${where}.label must be a short string` };
    }
    if (SINGLE_VALUE_OPS.includes((op as Op) ?? "in") && parsed.length !== 1) {
      return {
        ok: false,
        reason: "bad_access_filters",
        error: `${where}.op "${op}" takes exactly one value — use "in" or "not_in" for several`,
      };
    }

    // Where this table lives. Several sources means the same name in more than
    // one database, and the filter goes into each: restricting a table we were
    // not asked about is recoverable, leaving one open is not. No source means
    // the project never listed it — keep it under "" so the backend offers it
    // everywhere, which is what the single-source projects already do.
    const matched = sourcesForTable(table.trim(), defaults);
    const targets = matched.length ? matched : [null];

    for (const source of targets) {
      const key = source?.sourceId ?? "";
      if (!bySource.has(key)) {
        bySource.set(key, { ...(source ? { sourceId: source.sourceId } : {}), rowFilters: [] });
      }
      bySource.get(key)!.rowFilters.push({
        table: table.trim(),
        column: column.trim(),
        op: (op as Op | undefined) ?? "in",
        values: parsed,
        // Without a label the assistant describes the restriction to the user as
        // a raw SQL predicate. The source's own label is deliberately not used
        // here: "Warehouse DB" names where the data lives, not what the user is
        // limited to, and reads as nonsense in "showing you Warehouse DB only".
        label: (label as string | undefined)?.trim() || `${column.trim()} ${parsed.join(", ")}`,
      });
    }
  }

  return { ok: true, config: [...bySource.values()], warnings: [] };
}
