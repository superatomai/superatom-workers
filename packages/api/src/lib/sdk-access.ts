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
 * We add only what is ours to know: the source id, and a fallback label, from
 * `projects.config.sdkAccess`. The result follows the config interface the
 * backend reads (sdk-nodejs `policiesFromConfig`):
 * `[{ sourceId, rowFilters: [{ table, column, op, values, label }] }]`.
 *
 * Rules:
 *  - No `access`, or an empty list, means no restriction (config null).
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

/** What the project adds to filters the customer sent: ours to know, not theirs. */
export interface AccessDefaults {
  /** Source the filters apply to; absent means every source. */
  sourceId?: string;
  /** Fallback label for a filter that came without one. */
  label?: string;
}

/**
 * `projects.config.sdkAccess` — used with the `filters` shape. Throws when it is
 * malformed, a configuration fault on our side.
 */
export function readAccessDefaults(projectConfig: unknown): AccessDefaults {
  const raw = (projectConfig as Record<string, unknown> | null)?.sdkAccess;
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== "object" || Array.isArray(raw)) throw new Error("sdkAccess must be an object");
  const { sourceId, label } = raw as Record<string, unknown>;
  if (sourceId !== undefined && !nonEmpty(sourceId)) throw new Error("sdkAccess.sourceId must be a string");
  if (label !== undefined && !nonEmpty(label)) throw new Error("sdkAccess.label must be a string");
  return {
    ...(sourceId ? { sourceId: (sourceId as string).trim() } : {}),
    ...(label ? { label: (label as string).trim() } : {}),
  };
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
 * table, column, op and values come from the token; the source id is ours, and a
 * filter without a label gets one so the assistant does not read SQL aloud.
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

  const rowFilters: RowFilter[] = [];
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

    rowFilters.push({
      table: table.trim(),
      column: column.trim(),
      op: (op as Op | undefined) ?? "in",
      values: parsed,
      label: (label as string | undefined)?.trim() || defaults.label || `${column.trim()} ${parsed.join(", ")}`,
    });
  }

  return {
    ok: true,
    config: [{ ...(defaults.sourceId ? { sourceId: defaults.sourceId } : {}), rowFilters }],
    warnings: [],
  };
}
