import { HttpError } from "./errors";

/** Request validation for the graph routes; unknown fields are dropped. */

export const NODE_STATUSES = ["draft", "published", "retired"] as const;
export const CONCEPT_TYPES = ["global", "user", "group"] as const;

export type NodeStatus = (typeof NODE_STATUSES)[number];
export type ConceptType = (typeof CONCEPT_TYPES)[number];

export interface NodeFields {
  kind: string;
  name: string;
  title: string | null;
  body: string;
  meta: Record<string, unknown>;
  status: NodeStatus;
}

/** A link from a node: to another node or to a concept, at a role and position. */
export interface EdgeInput {
  role: string;
  position: number;
  nodeId: number | null;
  conceptId: number | null;
}

export interface TermInput {
  term: string;
  weight: number;
}

/** A node as written or proposed: its fields plus its links and terms. */
export interface NodeProposal {
  fields: NodeFields;
  edges: EdgeInput[];
  terms: TermInput[];
}

export interface ConceptFields {
  name: string;
  body: string;
  kind: string;
  type: ConceptType | null;
  requires: string[];
  returns: Record<string, unknown>;
  aliases: string[];
  description: string | null;
  sourceId: string | null;
  originRef: string | null;
}

const KIND = /^[a-z][a-z0-9_]{0,15}$/;
const ROLE = /^[a-z][a-z0-9_]{0,11}$/;
const DOMAIN_NAME = /^[a-z0-9_]+$/i;
const CONCEPT_KIND = /^[a-z_]{1,24}$/;
const MAX_EDGES = 500;
const MAX_TERMS = 200;

const bad = (message: string): never => {
  throw new HttpError(400, message);
};

const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);

function str(v: unknown, field: string, max: number, { required = false, allowEmpty = false } = {}): string | null {
  if (v === undefined || v === null) return required ? bad(`${field} is required`) : null;
  if (typeof v !== "string") return bad(`${field} must be text`);
  const s = v.trim();
  if (!s && !allowEmpty) return required ? bad(`${field} is required`) : null;
  if (s.length > max) return bad(`${field} is longer than ${max} characters`);
  return s;
}

function strList(v: unknown, field: string, max = 64): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return bad(`${field} must be a list of text`);
  const out: string[] = [];
  for (const x of v) {
    if (typeof x !== "string") return bad(`${field} must be a list of text`);
    const s = x.trim().replace(/\s+/g, " ");
    if (s.length > max) return bad(`${field}: "${s.slice(0, 20)}…" is longer than ${max} characters`);
    if (s && !out.some((o) => o.toLowerCase() === s.toLowerCase())) out.push(s);
  }
  return out;
}

function positiveInt(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v > 0 ? v : null;
}

/** Positions may start at 0: the engine numbers the shared / fallback instructions from 0. */
function position(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}

/** An id from a route parameter. */
export function parseId(v: string | undefined, what = "id"): number {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0 || n > 2147483647) throw new HttpError(404, `Unknown ${what}`);
  return n;
}

/** Node fields, edges and terms; on update, anything left out keeps its value from `base`. */
export function parseNodeInput(body: unknown, base?: NodeProposal): NodeProposal {
  if (!isObject(body)) return bad("Body must be a JSON object");

  const kind = body.kind === undefined && base ? base.fields.kind : str(body.kind, "kind", 16, { required: true })!;
  if (!KIND.test(kind)) bad("kind must be lower-case letters, numbers or underscores (up to 16)");
  if (base && kind !== base.fields.kind) bad("kind cannot be changed");

  const name = body.name === undefined && base ? base.fields.name : str(body.name, "name", 96, { required: true })!;
  if (kind === "domain" && !DOMAIN_NAME.test(name)) bad("A domain name may use only letters, numbers and underscores");

  const title = body.title === undefined && base ? base.fields.title : str(body.title, "title", 160);
  const text = body.body === undefined && base ? base.fields.body : str(body.body, "body", 200_000, { allowEmpty: true }) ?? "";

  let meta = base?.fields.meta ?? {};
  if (body.meta !== undefined) {
    if (!isObject(body.meta)) bad("meta must be an object");
    meta = body.meta as Record<string, unknown>;
  }

  let status: NodeStatus = base?.fields.status ?? "draft";
  if (body.status !== undefined) {
    if (!NODE_STATUSES.includes(body.status as NodeStatus)) bad(`status must be one of ${NODE_STATUSES.join(", ")}`);
    status = body.status as NodeStatus;
  }

  return {
    fields: { kind, name, title, body: text, meta, status },
    edges: body.edges === undefined && base ? base.edges : parseEdges(body.edges),
    terms: body.terms === undefined && base ? base.terms : parseTerms(body.terms),
  };
}

/** Edges as `[{ role, nodeId? , conceptId?, position? }]`; positions default to list order within each role. */
export function parseEdges(v: unknown): EdgeInput[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return bad("edges must be a list");
  if (v.length > MAX_EDGES) return bad(`A node can have at most ${MAX_EDGES} links`);

  const nextPosition = new Map<string, number>();
  const seen = new Set<string>();
  const out: EdgeInput[] = [];
  for (const [i, e] of v.entries()) {
    if (!isObject(e)) return bad(`edges[${i}] must be an object`);
    const role = typeof e.role === "string" ? e.role : "";
    if (!ROLE.test(role)) bad(`edges[${i}].role must be lower-case letters, numbers or underscores (up to 12)`);
    const nodeId = positiveInt(e.nodeId);
    const conceptId = positiveInt(e.conceptId);
    if ((nodeId === null) === (conceptId === null)) bad(`edges[${i}] needs exactly one of nodeId or conceptId`);
    const key = `${role}:${nodeId !== null ? `n${nodeId}` : `c${conceptId}`}`;
    if (seen.has(key)) bad(`edges[${i}] links the same item twice in role "${role}"`);
    seen.add(key);

    const pos = e.position === undefined ? (nextPosition.get(role) ?? 0) + 1 : position(e.position);
    if (pos === null) return bad(`edges[${i}].position must be a whole number, 0 or more`);
    nextPosition.set(role, Math.max(pos, nextPosition.get(role) ?? 0));
    out.push({ role, position: pos, nodeId, conceptId });
  }
  return out;
}

/** Terms as `[{ term, weight? }]`; stored lower-case, duplicates dropped. */
export function parseTerms(v: unknown): TermInput[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return bad("terms must be a list");
  if (v.length > MAX_TERMS) return bad(`A node can have at most ${MAX_TERMS} terms`);
  const out: TermInput[] = [];
  for (const [i, t] of v.entries()) {
    if (!isObject(t)) return bad(`terms[${i}] must be an object`);
    const term = str(t.term, `terms[${i}].term`, 64, { required: true })!.toLowerCase().replace(/\s+/g, " ");
    const weight = t.weight === undefined ? 1 : positiveInt(t.weight);
    if (weight === null || weight > 100) return bad(`terms[${i}].weight must be a whole number from 1 to 100`);
    if (!out.some((o) => o.term === term)) out.push({ term, weight });
  }
  return out;
}

/** Concept fields. On update, `base` supplies the fields left out. */
export function parseConceptInput(body: unknown, base?: ConceptFields): ConceptFields {
  if (!isObject(body)) return bad("Body must be a JSON object");
  const pick = <K extends keyof ConceptFields>(key: K, parse: () => ConceptFields[K], fallback: ConceptFields[K]): ConceptFields[K] =>
    body[key] === undefined ? (base ? base[key] : fallback) : parse();

  const fields: ConceptFields = {
    name: pick("name", () => str(body.name, "name", 64, { required: true })!, ""),
    body: pick("body", () => str(body.body, "body", 200_000, { required: true })!, ""),
    kind: pick("kind", () => str(body.kind, "kind", 24) ?? "definition", "definition"),
    // Optional: null (or "") means no type.
    type: pick(
      "type",
      () =>
        body.type === null || body.type === ""
          ? null
          : CONCEPT_TYPES.includes(body.type as ConceptType)
            ? (body.type as ConceptType)
            : bad(`type must be one of ${CONCEPT_TYPES.join(", ")}, or null`),
      null,
    ),
    requires: pick("requires", () => strList(body.requires, "requires"), []),
    returns: pick("returns", () => (isObject(body.returns) ? (body.returns as Record<string, unknown>) : bad("returns must be an object")), {}),
    aliases: pick("aliases", () => strList(body.aliases, "aliases"), []),
    description: pick("description", () => str(body.description, "description", 240), null),
    sourceId: pick("sourceId", () => str(body.sourceId, "sourceId", 100), null),
    originRef: pick("originRef", () => str(body.originRef, "originRef", 100), null),
  };
  if (!fields.name) bad("name is required");
  if (!fields.body) bad("body is required");
  if (!CONCEPT_KIND.test(fields.kind)) bad("kind must be lower-case letters or underscores");
  return fields;
}

/** Optimistic-concurrency token sent with every update and delete. */
export function parseEditVersion(v: unknown): number {
  const n = typeof v === "string" ? Number(v) : v;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1) {
    throw new HttpError(400, "editVersion is required (the version you last read)");
  }
  return n;
}
