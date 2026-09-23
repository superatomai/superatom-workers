/**
 * SDK data access — turns the `access` claim of a customer's sign-in token into
 * the user's `users.config`, which the relay stamps onto every message and the
 * backend enforces by rewriting SQL.
 *
 * The customer sends only VALUES, in their own terms:
 *
 *   "access": { "customerId": [12, 15], "locationId": 9 }
 *
 * Each name IS the column it filters, so a token reads the same as the data.
 * Which source and table it lives in is agreed at onboarding and stored on the
 * project, never taken from the token — schema details are not per-user, and a
 * bug on their side must not be able to point a filter at a different column:
 *
 *   projects.config.sdkAccessMapping = {
 *     "customerId": { "sourceId": "mssql-…", "table": "orders", "column": "customerId" },
 *     "locationId": [ { …documents… }, { …stock… } ]   // the same column in several tables
 *   }
 *
 * `column` must equal the field name — a mapping that points elsewhere is refused
 * as a configuration fault. A column that is named differently in another table
 * therefore needs its own field name.
 *
 * The result follows the config interface the backend reads
 * (sdk-nodejs `policiesFromConfig`): an array of
 * `{ sourceId, rowFilters: [{ table, column, op, values, label }] }`, one entry per source.
 *
 * Rules:
 *  - Only the names the token sends become filters; a name it leaves out is not
 *    restricted, and no `access` at all means no restriction (config null).
 *  - Anything malformed rejects the sign-in rather than being dropped: the
 *    backend silently drops a bad filter, which would leave the user unrestricted.
 *    That includes an empty list — "no customers" must not read as "all customers".
 *  - A name not in the project's mapping restricts nothing, and does not block
 *    the sign-in: mappings are set up at onboarding, often after the customer
 *    has started sending `access`. It is reported back as a warning instead.
 */

const OPS = ["in", "not_in"] as const;
type Op = (typeof OPS)[number];

/** Where one access name applies in the customer's data. */
export interface AccessTarget {
  /** Source the filter applies to; absent means every source. */
  sourceId?: string;
  table: string;
  column: string;
  /** Default "in". */
  op?: Op;
  /** How the restriction is described to the user, e.g. "Assigned customers". */
  label?: string;
}

export type AccessMapping = Record<string, AccessTarget[]>;

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

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/**
 * The project's mapping: null when the project has none (SDK access is not set
 * up), or throws when it is malformed — a configuration fault on our side.
 */
export function readAccessMapping(projectConfig: unknown): AccessMapping | null {
  const raw = (projectConfig as Record<string, unknown> | null)?.sdkAccessMapping;
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("sdkAccessMapping must be an object");
  }

  const mapping: AccessMapping = {};
  for (const [name, value] of Object.entries(raw)) {
    const list = Array.isArray(value) ? value : [value];
    if (list.length === 0) throw new Error(`sdkAccessMapping.${name} is empty`);
    mapping[name] = list.map((t, i) => {
      const where = `sdkAccessMapping.${name}${Array.isArray(value) ? `[${i}]` : ""}`;
      if (!t || typeof t !== "object") throw new Error(`${where} must be an object`);
      const { sourceId, table, column, op, label } = t as Record<string, unknown>;
      if (!nonEmpty(table) || !nonEmpty(column)) throw new Error(`${where} needs table and column`);
      // The field name IS the column name: what the customer sends reads the same
      // as the data it filters, and nobody has to remember a second vocabulary.
      if (column.trim() !== name) {
        throw new Error(`${where}.column must be "${name}" — the access field name is the column name`);
      }
      if (sourceId !== undefined && !nonEmpty(sourceId)) throw new Error(`${where}.sourceId must be a string`);
      if (op !== undefined && !OPS.includes(op as Op)) throw new Error(`${where}.op must be one of ${OPS.join(", ")}`);
      if (label !== undefined && !nonEmpty(label)) throw new Error(`${where}.label must be a string`);
      return {
        ...(sourceId ? { sourceId: sourceId.trim() } : {}),
        table: table.trim(),
        column: column.trim(),
        op: (op as Op | undefined) ?? "in",
        ...(label ? { label: label.trim() } : {}),
      };
    });
  }
  return mapping;
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

/** Warning for access names the project has no mapping for. */
export function unmappedWarning(names: string[]): string {
  const list = names.map((n) => `access.${n.slice(0, MAX_NAME_LENGTH)}`).join(", ");
  return `${list} ${names.length === 1 ? "is" : "are"} not set up for this project yet, so not applied`;
}

/**
 * The user's config from the `access` claim and the project's mapping (empty
 * when the project has none).
 */
export function buildAccessConfig(access: unknown, mapping: AccessMapping): AccessResult {
  if (access === undefined || access === null) return { ok: true, config: null, warnings: [] };
  if (typeof access !== "object" || Array.isArray(access)) {
    return { ok: false, reason: "bad_access", error: "access must be an object, e.g. { \"customerId\": [12] }" };
  }

  const bySource = new Map<string, SourcePolicy>();
  const unmapped: string[] = [];
  for (const [name, value] of Object.entries(access)) {
    const targets = mapping[name];
    if (!targets) {
      unmapped.push(name);
      continue;
    }
    const values = parseValues(value);
    if (!values) {
      return {
        ok: false,
        reason: "bad_access_values",
        error: `access.${name.slice(0, MAX_NAME_LENGTH)} must be a value or a list of 1–${MAX_VALUES} values (strings or numbers)`,
      };
    }
    for (const t of targets) {
      const key = t.sourceId ?? "";
      if (!bySource.has(key)) bySource.set(key, { ...(t.sourceId ? { sourceId: t.sourceId } : {}), rowFilters: [] });
      bySource.get(key)!.rowFilters.push({
        table: t.table,
        column: t.column,
        op: t.op ?? "in",
        values,
        // Without a label the agent describes the restriction as a raw SQL predicate.
        label: t.label ?? `${name} ${values.join(", ")}`,
      });
    }
  }

  const config = [...bySource.values()];
  return { ok: true, config: config.length ? config : null, warnings: unmapped.length ? [unmappedWarning(unmapped)] : [] };
}
