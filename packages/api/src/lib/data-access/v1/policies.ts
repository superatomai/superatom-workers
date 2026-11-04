/**
 * The two original claim shapes: a flat list of row filters, and a list of
 * source policies. Every existing customer is on one of these.
 *
 * Unchanged behaviour is the whole requirement here. The constraint form lives
 * next door precisely so this file never has to move for it.
 */

import {
  MAX_FILTERS,
  MAX_FILTERS_PER_POLICY,
  MAX_NAME_LENGTH,
  MAX_TABLES_PER_POLICY,
  MAX_VALUE_LENGTH,
  bad,
  isFailure,
  nonEmpty,
  parseNames,
  parseValues,
  describe,
} from "../primitives";
import { OPS, SINGLE_VALUE_OPS, type Failure, type Op, type RowFilter, type SourcePolicy } from "../types";

/**
 * One row filter, checked. `fallbackLabel` is the policy's label, used when the
 * filter has none — without any label the assistant describes the restriction to
 * the user as a raw SQL predicate.
 */
export function readFilter(entry: unknown, where: string, fallbackLabel?: string): RowFilter | Failure {
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

/** The shared policy/filter parser, used by both of the original shapes. */
export function buildPolicies(
  raw: unknown[],
  path: string,
): { ok: true; policies: SourcePolicy[] } | Failure {
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
