/**
 * The access contract, as types and as the operator vocabulary.
 *
 * These mirror sdk-nodejs `src/utils/request-context.ts`, which the backend
 * reads, and — for the constraint form — `sqlrewrite/v2/engine.py`,
 * which enforces it. Three hand-kept copies of one schema; a field added here
 * does nothing until the other two know about it.
 */

/**
 * Every operator the original rewriter supports. `eq`/`ne` compare against a
 * single value — it uses `values[0]` — so more than one value with them is
 * refused rather than silently trimmed.
 */
export const OPS = ["in", "not_in", "eq", "ne"] as const;
export type Op = (typeof OPS)[number];
export const SINGLE_VALUE_OPS: readonly Op[] = ["eq", "ne"];

/**
 * Operators the constraint engine builds predicates from. A superset of
 * {@link OPS}: it builds them as syntax nodes, so it can express comparisons
 * the original cannot.
 */
export const CONSTRAINT_OPS = [
  "in", "not_in", "eq", "ne", "gt", "gte", "lt", "lte",
  "like", "not_like", "is_null", "is_not_null",
] as const;
export type ConstraintOp = (typeof CONSTRAINT_OPS)[number];
/** These compare against one value; the engine reads `values[0]`. */
export const SINGLE_VALUE_CONSTRAINT_OPS: readonly ConstraintOp[] =
  ["eq", "ne", "gt", "gte", "lt", "lte", "like", "not_like"];
/** These take no values at all. */
export const NO_VALUE_CONSTRAINT_OPS: readonly ConstraintOp[] = ["is_null", "is_not_null"];

/** Mirrors sdk-nodejs `RowFilter` / `SourcePolicy`. */
export interface RowFilter {
  table: string;
  column: string;
  op: Op;
  values: (string | number)[];
  label: string;
}
export interface SourcePolicy {
  sourceId?: string;
  label?: string;
  /** Omitted entirely when the policy only restricts tables. */
  rowFilters?: RowFilter[];
  /** Absent or empty means no table restriction. */
  readableTables?: string[];
}

/** Mirrors sdk-nodejs `ConstraintFilter` / `ConstraintPolicy`. */
export interface ConstraintFilter {
  column: string;
  op: ConstraintOp;
  /** Omitted for `is_null` / `is_not_null`. */
  values?: (string | number)[];
  label: string;
}
export interface ConstraintPolicy {
  sourceId?: string;
  label?: string;
  /**
   * Every table is read from this schema, whatever schema the query wrote —
   * which is what makes it a restriction: there is no other schema to reach.
   * Absent means schemas are left exactly as written.
   */
  schema?: string;
  /** table → readable columns, or `null` for every column. Absent: every table. */
  readableTables?: Record<string, string[] | null>;
  /** table → filters, ANDed. */
  rowFilters?: Record<string, ConstraintFilter[]>;
  limits?: { maxRows?: number; maxExecutionSeconds?: number };
}

/**
 * What the backend receives. The array form is what every existing customer
 * sends and is stored unchanged; the object form adds source scoping; the
 * versioned form adds schemas, columns and limits, and is read by the
 * constraint engine.
 */
export type AccessConfig =
  | SourcePolicy[]
  | { allowedSources?: string[]; policies: SourcePolicy[] }
  | { version: 2; allowedSources?: string[]; policies: ConstraintPolicy[] };

export type AccessResult =
  | { ok: true; config: AccessConfig | null }
  | { ok: false; reason: string; error: string };

/** A refusal, carrying where it happened so the customer can find the entry. */
export type Failure = { ok: false; reason: string; error: string };
