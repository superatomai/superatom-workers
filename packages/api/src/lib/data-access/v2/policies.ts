/**
 * The versioned claim shape (`version: 2`), read by the constraint engine
 * (`sqlrewrite/v2/engine.py`).
 *
 * Stricter than the original shapes throughout, and for one reason: every field
 * here can only narrow access, so a field dropped rather than refused WIDENS
 * it. Nothing is coerced and nothing is skipped — a policy that cannot be read
 * refuses the sign-in, so the customer fixes it now rather than discovering
 * later that a restriction was never applied.
 */

import {
  MAX_COLUMNS_PER_TABLE,
  MAX_FILTERS,
  MAX_FILTERS_PER_TABLE,
  MAX_NAME_LENGTH,
  MAX_TABLES_PER_POLICY,
  MAX_VALUE_LENGTH,
  MAX_ALLOWED_SOURCES,
  bad,
  describe,
  isFailure,
  nonEmpty,
  parseNames,
  parseValues,
} from "../primitives";
import {
  CONSTRAINT_OPS,
  NO_VALUE_CONSTRAINT_OPS,
  SINGLE_VALUE_CONSTRAINT_OPS,
  type AccessResult,
  type ConstraintFilter,
  type ConstraintOp,
  type ConstraintPolicy,
  type Failure,
} from "../types";

/** The whole claim: `{ version: 2, allowedSources?, policies }`. */
export function buildConstraintConfig(access: Record<string, unknown>): AccessResult {
  const { version, allowedSources, policies: rawPolicies, ...rest } = access;
  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length) {
    return bad(
      `access has unknown field(s): ${unknownKeys.join(", ")} — expected version, allowedSources, policies`,
    );
  }

  let sources: string[] | undefined;
  if (allowedSources !== undefined) {
    const parsed = parseNames(allowedSources, "access.allowedSources", MAX_ALLOWED_SOURCES);
    if (isFailure(parsed)) return parsed;
    sources = parsed.names;
  }

  if (!Array.isArray(rawPolicies)) return bad(`access.policies must be a list`);
  if (rawPolicies.length === 0) {
    // Unlike the other shapes, this is not "no restriction": sending a version
    // is a statement that restrictions apply, so an empty list is a mistake
    // worth naming rather than a licence to read everything.
    return bad(`access.policies is empty — omit "version" to send no restrictions`);
  }
  if (rawPolicies.length > MAX_FILTERS) {
    return bad(`access.policies must hold at most ${MAX_FILTERS} entries`);
  }

  const policies: ConstraintPolicy[] = [];
  for (const [i, entry] of rawPolicies.entries()) {
    const built = readConstraintPolicy(entry, `access.policies[${i}]`);
    if (isFailure(built)) return built;
    policies.push(built);
  }

  return {
    ok: true,
    config: { version: 2, ...(sources !== undefined ? { allowedSources: sources } : {}), policies },
  };
}

/**
 * One policy: its schema, its readable tables and columns, its filters and
 * limits.
 *
 * Every restriction is optional and independent. A policy that restricts
 * nothing at all is still refused, though — `version: 2` is a statement that
 * restrictions apply, so a policy saying none of them is a mistake worth
 * naming.
 */
function readConstraintPolicy(entry: unknown, where: string): ConstraintPolicy | Failure {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return bad(`${where} must be an object`);
  const { sourceId, label, schema, readableTables, rowFilters, limits, ...rest } =
    entry as Record<string, unknown>;

  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length) {
    return bad(
      `${where} has unknown field(s): ${unknownKeys.join(", ")} — expected sourceId, label, ` +
      `schema, readableTables, rowFilters, limits`,
    );
  }

  if (sourceId !== undefined && (!nonEmpty(sourceId) || sourceId.trim().length > MAX_NAME_LENGTH)) {
    return bad(`${where}.sourceId must be a string`);
  }
  if (label !== undefined && (!nonEmpty(label) || label.trim().length > MAX_VALUE_LENGTH)) {
    return bad(`${where}.label must be a short string`);
  }
  if (schema !== undefined && (!nonEmpty(schema) || schema.trim().length > MAX_NAME_LENGTH)) {
    return bad(`${where}.schema must be a schema name, e.g. "dbo"`);
  }

  const tables = readTables(readableTables, where);
  if (isFailure(tables)) return tables;

  const filters = readFilters(rowFilters, tables, where, (label as string | undefined)?.trim());
  if (isFailure(filters)) return filters;

  const bounds = readLimits(limits, where);
  if (isFailure(bounds)) return bounds;

  if (!nonEmpty(schema) && !tables && !filters && !bounds) {
    return bad(
      `${where} restricts nothing — give it a schema, readableTables, rowFilters or limits, ` +
      `or omit "version" to send no restrictions at all`,
    );
  }

  return {
    ...(nonEmpty(sourceId) ? { sourceId: sourceId.trim() } : {}),
    ...(nonEmpty(label) ? { label: label.trim() } : {}),
    ...(nonEmpty(schema) ? { schema: schema.trim() } : {}),
    ...(tables ? { readableTables: tables } : {}),
    ...(filters && Object.keys(filters).length ? { rowFilters: filters } : {}),
    ...(bounds ? { limits: bounds } : {}),
  };
}

/**
 * `{ table: [columns] | null }` — `null` meaning every column of that table.
 *
 * Optional: absent means no table restriction, the same as the original shape.
 * Requiring it would mean listing every table a broadly-scoped user may read,
 * which for a warehouse is unworkable. Present but EMPTY is still refused —
 * that reads as a mistake, and the permissive interpretation is the dangerous
 * one.
 */
function readTables(
  readableTables: unknown,
  where: string,
): Record<string, string[] | null> | undefined | Failure {
  if (readableTables === undefined || readableTables === null) return undefined;
  if (typeof readableTables !== "object" || Array.isArray(readableTables)) {
    return bad(`${where}.readableTables must be an object of table to columns`);
  }
  const entries = Object.entries(readableTables as Record<string, unknown>);
  if (entries.length === 0) {
    return bad(`${where}.readableTables names no tables — omit it to allow every table`);
  }
  if (entries.length > MAX_TABLES_PER_POLICY) {
    return bad(`${where}.readableTables must hold at most ${MAX_TABLES_PER_POLICY} tables`);
  }

  const tables: Record<string, string[] | null> = {};
  for (const [table, cols] of entries) {
    if (!table.trim() || table.trim().length > MAX_NAME_LENGTH) {
      return bad(`${where}.readableTables has a table name that is empty or too long`);
    }
    if (cols === null) {
      tables[table.trim()] = null;
      continue;
    }
    const parsed = parseNames(cols, `${where}.readableTables["${table}"]`, MAX_COLUMNS_PER_TABLE);
    if (isFailure(parsed)) return parsed;
    if (parsed.names.length === 0) {
      return bad(`${where}.readableTables["${table}"] is empty — send null for every column, or omit the table`);
    }
    tables[table.trim()] = parsed.names;
  }
  return tables;
}

/**
 * `{ table: [filters] }`, each table's filters checked against its own columns.
 *
 * A key only has to appear in `readableTables` when that allowlist EXISTS:
 * filtering a table is not the same as listing it, and a user with no table
 * restriction still needs their rows narrowed. When the allowlist is there, the
 * two must agree — a filter on a table the policy excludes could never apply.
 */
function readFilters(
  rowFilters: unknown,
  tables: Record<string, string[] | null> | undefined,
  where: string,
  policyLabel?: string,
): Record<string, ConstraintFilter[]> | undefined | Failure {
  if (rowFilters === undefined || rowFilters === null) return undefined;
  if (typeof rowFilters !== "object" || Array.isArray(rowFilters)) {
    return bad(`${where}.rowFilters must be an object keyed by table`);
  }

  const out: Record<string, ConstraintFilter[]> = {};
  for (const [table, items] of Object.entries(rowFilters as Record<string, unknown>)) {
    const key = table.trim();
    if (tables && !(key in tables)) {
      return bad(`${where}.rowFilters names "${table}", which readableTables does not allow`);
    }
    if (!Array.isArray(items) || items.length === 0) {
      return bad(`${where}.rowFilters["${table}"] must be a non-empty list`);
    }
    if (items.length > MAX_FILTERS_PER_TABLE) {
      return bad(`${where}.rowFilters["${table}"] must hold at most ${MAX_FILTERS_PER_TABLE} filters`);
    }
    const built: ConstraintFilter[] = [];
    for (const [j, item] of items.entries()) {
      const filter = readConstraintFilter(
        item, `${where}.rowFilters["${table}"][${j}]`, tables?.[key] ?? null, policyLabel,
      );
      if (isFailure(filter)) return filter;
      built.push(filter);
    }
    out[key] = built;
  }
  return out;
}

/** `{ maxRows?, maxExecutionSeconds? }`, both positive whole numbers. */
function readLimits(
  limits: unknown,
  where: string,
): ConstraintPolicy["limits"] | undefined | Failure {
  if (limits === undefined || limits === null) return undefined;
  if (typeof limits !== "object" || Array.isArray(limits)) return bad(`${where}.limits must be an object`);

  const { maxRows, maxExecutionSeconds, ...rest } = limits as Record<string, unknown>;
  if (Object.keys(rest).length) {
    return bad(`${where}.limits has unknown field(s): ${Object.keys(rest).join(", ")}`);
  }
  const positiveInt = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v > 0;
  if (maxRows !== undefined && !positiveInt(maxRows)) {
    return bad(`${where}.limits.maxRows must be a positive whole number`);
  }
  if (maxExecutionSeconds !== undefined && !positiveInt(maxExecutionSeconds)) {
    return bad(`${where}.limits.maxExecutionSeconds must be a positive whole number`);
  }
  const bounds = {
    ...(maxRows !== undefined ? { maxRows: maxRows as number } : {}),
    ...(maxExecutionSeconds !== undefined ? { maxExecutionSeconds: maxExecutionSeconds as number } : {}),
  };
  return Object.keys(bounds).length ? bounds : undefined;
}

/**
 * One filter, checked against its table's column allowlist.
 *
 * A filter on a column the policy does not expose is refused rather than
 * accepted: the engine would have to read that column to apply it, so the two
 * statements contradict each other and only the customer can say which they
 * meant.
 */
function readConstraintFilter(
  entry: unknown,
  where: string,
  allowedColumns: string[] | null,
  fallbackLabel?: string,
): ConstraintFilter | Failure {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return bad(`${where} must be an object`);
  const { column, op, values, label, table, ...rest } = entry as Record<string, unknown>;

  if (table !== undefined) {
    // Keyed by table already. A `table` here means the customer wrote the old
    // shape inside the new one, and the two could disagree.
    return bad(`${where} must not carry "table" — filters are keyed by table in this form`);
  }
  const unknownKeys = Object.keys(rest);
  if (unknownKeys.length) {
    return bad(`${where} has unknown field(s): ${unknownKeys.join(", ")} — expected column, op, values, label`);
  }

  if (!nonEmpty(column)) return bad(`${where}.column is missing`);
  if (column.trim().length > MAX_NAME_LENGTH) return bad(`${where}.column is over ${MAX_NAME_LENGTH} characters`);
  if (op !== undefined && !CONSTRAINT_OPS.includes(op as ConstraintOp)) {
    return bad(`${where}.op ${describe(op)} is not supported — use ${CONSTRAINT_OPS.join(", ")}`);
  }
  const operator = (op as ConstraintOp | undefined) ?? "in";

  if (allowedColumns && !allowedColumns.includes(column.trim())) {
    return bad(
      `${where}.column "${column.trim()}" is not in this table's readableTables — ` +
      `a filter cannot name a column the policy hides`,
    );
  }

  if (label !== undefined && (!nonEmpty(label) || label.trim().length > MAX_VALUE_LENGTH)) {
    return bad(`${where}.label must be short text`);
  }

  if (NO_VALUE_CONSTRAINT_OPS.includes(operator)) {
    if (values !== undefined) return bad(`${where}.op "${operator}" takes no values`);
    return {
      column: column.trim(),
      op: operator,
      label: (label as string | undefined)?.trim() || fallbackLabel || `${column.trim()} ${operator}`,
    };
  }

  const parsed = parseValues(values);
  if (!parsed.ok) return bad(`${where}.values ${parsed.why}`);
  if (SINGLE_VALUE_CONSTRAINT_OPS.includes(operator) && parsed.values.length !== 1) {
    return bad(
      `${where}.op "${operator}" takes one value, got ${parsed.values.length} — use "in" or "not_in" for several`,
    );
  }

  return {
    column: column.trim(),
    op: operator,
    values: parsed.values,
    label: (label as string | undefined)?.trim() || fallbackLabel || `${column.trim()} ${parsed.values.join(", ")}`,
  };
}
