/**
 * SDK data access — turns the `access` claim of a customer's sign-in token into
 * the user's `users.config`, which the relay stamps onto every message and the
 * backend enforces by rewriting SQL.
 *
 * This file is the entry point and the dispatch. The shapes themselves live in
 * `data-access/`, one folder per claim version — `v1/` for the two original
 * shapes, `v2/` for the constraint one — beside `primitives.ts` for the checks
 * they share and `types.ts` for the contract. Named by version because that is
 * what the claim itself says, so a `version` on the wire maps to a folder with
 * nothing to translate. Split because the two validators had grown into one
 * 700-line file where a rule tightened in one shape could silently not apply to
 * the other.
 *
 * THE ORIGINAL SHAPES. The customer writes whichever fits their project. With
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
 *       "rowFilters": [ { "table": "customer", "column": "customerId", "op": "in", "values": [5, 117] } ] }
 *   ]
 *
 * A policy may also name `readableTables` — the tables the user may read AT ALL
 * in that source. Row filters alone are fail-open: a filter on `customer` does
 * nothing when the agent reads `customer_bak`, a view, or a synonym holding the
 * same rows. To scope whole SOURCES, send the OBJECT form:
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
 * THE CONSTRAINT SHAPE adds a schema, per-table columns and limits, and is read
 * by a second engine. `version` selects it; absent means the original path, so
 * every existing customer is unaffected:
 *
 *   "access": {
 *     "version": 2,
 *     "allowedSources": ["mssql-722b9497"],
 *     "policies": [{
 *       "sourceId": "mssql-722b9497",
 *       "namespace": { "sourceSchema": "dbo" },
 *       "readableTables": { "customer": ["id", "name"] },
 *       "rowFilters": { "customer": [{ "column": "id", "op": "in", "values": [5] }] },
 *       "limits": { "maxRows": 1000, "maxExecutionSeconds": 30 }
 *     }]
 *   }
 *
 * Either way we only check and store: nothing is inferred from the project, and
 * no source id is guessed.
 *
 * Rules common to every shape:
 *  - No `access`, or an empty list, means no restriction (config null). The
 *    exception is the constraint shape, where sending a version is itself a
 *    statement that restrictions apply, so an empty policy list is refused.
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

import { buildConstraintConfig } from "./data-access/v2/policies";
import { buildPolicies } from "./data-access/v1/policies";
import { MAX_ALLOWED_SOURCES, bad, describe, isFailure, parseNames } from "./data-access/primitives";
import type { AccessResult, SourcePolicy } from "./data-access/types";

export type {
  AccessConfig,
  AccessResult,
  ConstraintFilter,
  ConstraintPolicy,
  RowFilter,
  SourcePolicy,
} from "./data-access/types";

/**
 * True when the token carries an access claim at all — any shape.
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
 * The user's config from the `access` claim. Accepts a list of row filters, a
 * list of source policies, a mix, or the versioned object — and stores what it
 * is given: the project is not consulted and no source id is inferred.
 */
export function buildFiltersConfig(access: unknown): AccessResult {
  if (!Array.isArray(access)) return buildScopedConfig(access);

  const built = buildPolicies(access, "access");
  if (isFailure(built)) return built;
  return { ok: true, config: built.policies.length ? built.policies : null };
}

/**
 * The object forms, and the choice between them.
 *
 * Kept separate from the array form so that path stays exactly as it was —
 * every existing customer is on it, and nothing here may alter a single outcome
 * there.
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

  // `version` selects the engine, so it is read before the unknown-key check
  // below — which would otherwise refuse it as a typo.
  const version = (access as Record<string, unknown>).version;
  if (version !== undefined) {
    if (version !== 2) {
      return bad(`access.version ${describe(version)} is not supported — omit it, or send 2`);
    }
    return buildConstraintConfig(access as Record<string, unknown>);
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
