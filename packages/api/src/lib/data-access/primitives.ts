/**
 * The checks both claim shapes are built from, and the bounds they enforce.
 *
 * Shared on purpose: a value rule tightened for one shape and not the other is
 * how two validators of the same contract drift apart.
 */

import type { Failure } from "./types";

/** Bounds, so a bad token cannot fill the database or the SQL. */
export const MAX_VALUES = 1000;
export const MAX_VALUE_LENGTH = 200;
export const MAX_NAME_LENGTH = 100;
/** Entries one token may carry, whether filters or policies. */
export const MAX_FILTERS = 50;
/** Row filters one policy may carry. */
export const MAX_FILTERS_PER_POLICY = 50;
/** Tables one policy may allow, and sources one token may allow. */
export const MAX_TABLES_PER_POLICY = 200;
export const MAX_ALLOWED_SOURCES = 50;
/** Constraint form: columns one table may expose, and filters one table may carry. */
export const MAX_COLUMNS_PER_TABLE = 500;
export const MAX_FILTERS_PER_TABLE = 20;

export const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/** How a value reads in a message: quoted if text, bare if a number. */
export function describe(item: unknown): string {
  if (item === null) return "null";
  if (typeof item === "string") return `"${item.slice(0, 30)}"`;
  if (typeof item === "number") return String(item);
  if (Array.isArray(item)) return "a list";
  return typeof item;
}

/** A failure carrying where it happened, so the customer can find the entry. */
export function bad(error: string): Failure {
  return { ok: false, reason: "bad_access_filters", error };
}

export const isFailure = (v: unknown): v is Failure =>
  !!v && typeof v === "object" && (v as { ok?: unknown }).ok === false;

/**
 * One value or a list, as a clean list. On failure it says what is wrong in
 * words, since this message reaches whoever wrote the integration.
 */
export function parseValues(
  value: unknown,
): { ok: true; values: (string | number)[] } | { ok: false; why: string } {
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

/**
 * A list of names — table names, column names or source ids — trimmed, deduped
 * and bounded.
 *
 * Shared because all of them are allowlists of identifiers, and all must fail
 * loudly rather than drop an entry: a name quietly discarded here widens access
 * without anyone seeing it.
 */
export function parseNames(
  value: unknown,
  where: string,
  max: number,
): { ok: true; names: string[] } | Failure {
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
