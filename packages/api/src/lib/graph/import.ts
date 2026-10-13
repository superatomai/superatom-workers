import { inArray, sql } from "drizzle-orm";
import { concepts, graphChangeRequests, graphChanges, graphDomainTerms, graphEdges, graphNodes } from "../../db/schema";
import type { Q } from "../../db/tx";
import { analyseGraph, MAX_DEPTH } from "./dag";
import { HttpError, isUniqueViolation } from "./errors";
import { canonicalJson } from "./hash";
import { flattenProposal } from "./requests";
import {
  canEditDirectly,
  conceptFieldsOf,
  edgeOrder,
  loadWorkingCopy,
  lockProject,
  nodeContent,
  nodeHash,
  proposalOf,
  type ConceptRow,
  type NodeRow,
  type Scope,
} from "./store";
import { parseConceptInput, parseNodeInput, type ConceptFields, type NodeProposal } from "./validate";

/** Import an export file into the working copy, matching by name; other owners' items become change requests. */

export type ImportMode = "merge" | "replace";
type Tally = { created: number; updated: number; unchanged: number; removed: number; requested: number };

const tally = (): Tally => ({ created: 0, updated: 0, unchanged: 0, removed: 0, requested: 0 });
const lower = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");
/** A domain part's role → the kind of node it points at. */
const ROLE_KIND: Record<string, string> = { prompt: "part", file: "file", setting: "setting", program: "program" };

interface FileConcept {
  name: string;
  kind?: string;
  description?: string | null;
  body: string;
  aliases?: string[];
  requires?: string[];
  returns?: Record<string, unknown>;
  sourceId?: string | null;
}
interface FileDomain {
  name: string;
  title?: string | null;
  body: string;
  status?: string;
  meta?: Record<string, unknown>;
  terms?: { term: string; weight?: number }[];
  concepts?: string[];
  parts?: { role: string; name: string; position: number }[];
}
interface FilePart {
  kind: string;
  name: string;
  title?: string | null;
  body: string;
}
interface ImportFile {
  /** The project it was exported from. Optional; when given it must be this project. */
  projectId?: string;
  concepts: FileConcept[];
  domains: FileDomain[];
  parts?: FilePart[];
}

/** `version` (written by older exports) is ignored. */
function checkFile(raw: unknown, projectId: string): ImportFile {
  const f = raw as Partial<ImportFile> | null;
  if (!f || typeof f !== "object") throw new HttpError(400, "The file isn't a JSON object");
  if (f.projectId !== undefined && f.projectId !== projectId) {
    throw new HttpError(400, "This file was exported from another project; it can only be imported into that project", {
      fileProjectId: f.projectId,
    });
  }
  if (!Array.isArray(f.concepts) || !Array.isArray(f.domains)) {
    throw new HttpError(400, `"concepts" and "domains" must be lists`);
  }
  if (f.parts !== undefined && !Array.isArray(f.parts)) throw new HttpError(400, `"parts" must be a list`);
  return f as ImportFile;
}

const isBuiltIn = (n: NodeRow) => {
  const meta = (n.meta ?? {}) as { shared?: boolean; fallback?: boolean };
  return !!meta.shared || !!meta.fallback || ["shared", "generic"].includes(n.name.toLowerCase());
};

/** Proposal with edges and terms in a fixed order, so equal content compares equal. */
const normal = (p: NodeProposal) =>
  canonicalJson(flattenProposal({ ...p, edges: [...p.edges].sort(edgeOrder), terms: [...p.terms].sort((a, b) => a.term.localeCompare(b.term)) }));

// ─── Batched writes ─────────────────────────────────────
// The import is planned in memory, then written with a few bulk statements.

/** Rows per statement: well under Postgres' 65,535 bind parameters. */
const CHUNK = 300;

async function inChunks<T, R>(rows: T[], write: (chunk: T[]) => Promise<R[]>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < rows.length; i += CHUNK) out.push(...(await write(rows.slice(i, i + CHUNK))));
  return out;
}

type ChangeRow = typeof graphChanges.$inferInsert;
type RequestInsert = typeof graphChangeRequests.$inferInsert;

/** A node to create or update, with its final links and terms. */
interface NodeWrite {
  existing: NodeRow | null;
  p: NodeProposal;
  /** The node before (updates), for the history row. */
  before?: unknown;
}

/** Concept fields as written (`excluded.*` on update keeps them as given). */
const conceptSet = {
  name: sql`excluded.name`,
  body: sql`excluded.body`,
  kind: sql`excluded.kind`,
  type: sql`excluded.type`,
  requires: sql`excluded.requires`,
  returns: sql`excluded.returns`,
  aliases: sql`excluded.aliases`,
  description: sql`excluded.description`,
  sourceId: sql`excluded.source_id`,
  originRef: sql`excluded.origin_ref`,
  editVersion: sql`${concepts.editVersion} + 1`,
  updatedBy: sql`excluded.updated_by`,
  updatedAt: sql`now()`,
};

const nodeSet = {
  name: sql`excluded.name`,
  title: sql`excluded.title`,
  body: sql`excluded.body`,
  meta: sql`excluded.meta`,
  status: sql`excluded.status`,
  hash: sql`excluded.hash`,
  editVersion: sql`${graphNodes.editVersion} + 1`,
  updatedBy: sql`excluded.updated_by`,
  updatedAt: sql`now()`,
};

/** Create/update nodes in bulk and replace their links and terms; returns created ids by kind|name. */
async function writeNodes(q: Q, s: Scope, writes: NodeWrite[], changes: ChangeRow[], key: (kind: string, name: string) => string) {
  const ids = new Map<string, number>();
  if (!writes.length) return ids;
  const hashes = await Promise.all(writes.map((w) => nodeHash(w.p.fields)));
  const rowOf = (w: NodeWrite, i: number) => ({
    ...w.p.fields,
    orgId: s.orgId,
    projectId: s.projectId,
    hash: hashes[i],
    updatedBy: s.userId,
  });

  try {
    const fresh = writes.flatMap((w, i) => (w.existing ? [] : [rowOf(w, i)]));
    const inserted = await inChunks(fresh, (chunk) =>
      q
        .insert(graphNodes)
        .values(chunk.map((r) => ({ ...r, ownerId: s.userId, origin: "import", createdBy: s.userId })))
        .returning({ id: graphNodes.id, kind: graphNodes.kind, name: graphNodes.name }),
    );
    for (const r of inserted) ids.set(key(r.kind, r.name), r.id);

    const updated = writes.flatMap((w, i) => (w.existing ? [{ ...rowOf(w, i), id: w.existing.id }] : []));
    await inChunks(updated, (chunk) =>
      q.insert(graphNodes).values(chunk).onConflictDoUpdate({ target: graphNodes.id, set: nodeSet }).returning({ id: graphNodes.id }),
    );
  } catch (err) {
    if (isUniqueViolation(err)) throw new HttpError(409, "Two items in the file have the same name");
    throw err;
  }

  const idOf = (w: NodeWrite) => w.existing?.id ?? ids.get(key(w.p.fields.kind, w.p.fields.name))!;
  const nodeIds = writes.map(idOf);

  // Links and terms: replaced as a whole for every written node.
  await q.delete(graphEdges).where(inArray(graphEdges.parentId, nodeIds));
  await q.delete(graphDomainTerms).where(inArray(graphDomainTerms.nodeId, nodeIds));
  const edgeRows = writes.flatMap((w) =>
    w.p.edges.map((e) => ({
      orgId: s.orgId,
      projectId: s.projectId,
      parentId: idOf(w),
      childNodeId: e.nodeId,
      childConceptId: e.conceptId,
      role: e.role,
      position: e.position,
      createdBy: s.userId,
    })),
  );
  const termRows = writes.flatMap((w) =>
    w.p.terms.map((t) => ({ orgId: s.orgId, projectId: s.projectId, nodeId: idOf(w), term: t.term, weight: t.weight })),
  );
  await inChunks(edgeRows, (chunk) => q.insert(graphEdges).values(chunk).returning({ id: graphEdges.id }));
  await inChunks(termRows, (chunk) => q.insert(graphDomainTerms).values(chunk).returning({ id: graphDomainTerms.id }));

  for (const w of writes) {
    changes.push(historyRow(s, "node", idOf(w), w.existing ? "update" : "create", w.before ?? null, nodeContent(w.p)));
  }
  return ids;
}

const historyRow = (
  s: Scope,
  entity: "node" | "concept",
  entityId: number,
  action: "create" | "update" | "delete",
  before: unknown,
  after: unknown,
): ChangeRow => ({
  orgId: s.orgId,
  projectId: s.projectId,
  entity,
  entityId,
  action,
  via: "import",
  before: before ?? null,
  after: after ?? null,
  changedBy: s.userId,
});

const requestRow = (
  s: Scope,
  entity: "node" | "concept",
  entityId: number,
  action: "update" | "delete",
  baseEditVersion: number,
  proposed: Record<string, unknown>,
): RequestInsert => ({
  orgId: s.orgId,
  projectId: s.projectId,
  entity,
  entityId,
  action,
  baseEditVersion,
  proposed,
  authorId: s.userId,
  source: "import",
});

/** Run in a transaction (takes lockProject); plans every change in memory, then writes in bulk. */
export async function importGraph(q: Q, s: Scope, raw: unknown, mode: ImportMode) {
  const file = checkFile(raw, s.projectId);
  await lockProject(q, s.projectId);
  const wc = await loadWorkingCopy(q, s.projectId);
  const counts = { concepts: tally(), parts: tally(), domains: tally() };
  const changes: ChangeRow[] = [];
  const requests: RequestInsert[] = [];

  const edgesOf = (id: number) => wc.edges.filter((e) => e.parentId === id);
  const termsOf = (id: number) => wc.terms.filter((t) => t.nodeId === id);
  const nodeKey = (kind: string, name: string) => `${kind}|${lower(name)}`;
  const nodeByKey = new Map(wc.nodes.map((n) => [nodeKey(n.kind, n.name), n]));
  /** Final links per node id, for the replace check below (written nodes overwrite theirs). */
  const finalEdges = new Map<number, { nodeId: number | null; conceptId: number | null }[]>(
    wc.nodes.map((n) => [n.id, edgesOf(n.id).map((e) => ({ nodeId: e.childNodeId, conceptId: e.childConceptId }))]),
  );

  /** Sort a node into create / update / unchanged / request. */
  const planNode = (existing: NodeRow | undefined, p: NodeProposal, t: Tally, writes: NodeWrite[], removing = false) => {
    if (!existing) {
      // Named twice in the file: the later one wins, as an update of the first.
      const k = nodeKey(p.fields.kind, p.fields.name);
      const twice = writes.find((w) => !w.existing && nodeKey(w.p.fields.kind, w.p.fields.name) === k);
      if (twice) {
        twice.p = p;
        t.updated++;
      } else {
        writes.push({ existing: null, p });
        t.created++;
      }
      return;
    }
    const base = proposalOf(existing, edgesOf(existing.id), termsOf(existing.id));
    if (normal(base) === normal(p)) {
      t.unchanged++;
    } else if (canEditDirectly(existing, s)) {
      writes.push({ existing, p, before: nodeContent(base) });
      finalEdges.set(existing.id, p.edges);
      if (removing) t.removed++;
      else t.updated++;
    } else {
      requests.push(requestRow(s, "node", existing.id, "update", existing.editVersion, flattenProposal(p)));
      t.requested++;
    }
  };

  // ── Concepts
  const conceptByKey = new Map(wc.concepts.map((c) => [`${lower(c.name)}|${c.sourceId ?? ""}`, c]));
  const conceptIdByName = new Map<string, number>();
  for (const c of wc.concepts) if (!conceptIdByName.has(lower(c.name))) conceptIdByName.set(lower(c.name), c.id);
  const fileConceptKeys = new Set<string>();
  const conceptCreates: ConceptFields[] = [];
  const conceptUpdates: { existing: ConceptRow; fields: ConceptFields }[] = [];

  for (const fc of file.concepts) {
    const k = `${lower(String(fc.name ?? ""))}|${fc.sourceId ?? ""}`;
    fileConceptKeys.add(k);
    const existing = conceptByKey.get(k);
    const fields = parseConceptInput({
      name: fc.name,
      body: fc.body,
      kind: fc.kind ?? "definition",
      type: existing?.type ?? null,
      // Exports leave requires out: a file without it keeps the concept's own.
      requires: fc.requires ?? existing?.requires ?? [],
      returns: fc.returns ?? {},
      aliases: fc.aliases ?? [],
      description: fc.description ?? null,
      sourceId: fc.sourceId ?? null,
      originRef: existing?.originRef ?? null,
    });
    if (!existing) {
      conceptCreates.push(fields);
      counts.concepts.created++;
    } else {
      conceptIdByName.set(lower(fields.name), existing.id);
      if (canonicalJson(conceptFieldsOf(existing)) === canonicalJson(fields)) counts.concepts.unchanged++;
      else if (canEditDirectly(existing, s)) {
        conceptUpdates.push({ existing, fields });
        counts.concepts.updated++;
      } else {
        requests.push(requestRow(s, "concept", existing.id, "update", existing.editVersion, fields as unknown as Record<string, unknown>));
        counts.concepts.requested++;
      }
    }
  }

  try {
    const inserted = await inChunks(conceptCreates, (chunk) =>
      q
        .insert(concepts)
        .values(chunk.map((f) => ({ ...f, orgId: s.orgId, projectId: s.projectId, ownerId: s.userId, origin: "import", createdBy: s.userId, updatedBy: s.userId })))
        .returning(),
    );
    for (const row of inserted) {
      conceptIdByName.set(lower(row.name), row.id);
      changes.push(historyRow(s, "concept", row.id, "create", null, conceptFieldsOf(row)));
    }
    await inChunks(conceptUpdates, (chunk) =>
      q
        .insert(concepts)
        .values(chunk.map(({ existing, fields }) => ({ ...fields, id: existing.id, orgId: s.orgId, projectId: s.projectId, updatedBy: s.userId })))
        .onConflictDoUpdate({ target: concepts.id, set: conceptSet })
        .returning({ id: concepts.id }),
    );
  } catch (err) {
    if (isUniqueViolation(err)) throw new HttpError(409, "Two concepts in the file have the same name");
    throw err;
  }
  for (const { existing, fields } of conceptUpdates) {
    changes.push(historyRow(s, "concept", existing.id, "update", conceptFieldsOf(existing), fields));
  }

  // ── Parts (shared / fallback instructions): written before the domains that link to them.
  const partWrites: NodeWrite[] = [];
  for (const fp of file.parts ?? []) {
    const existing = nodeByKey.get(nodeKey(String(fp.kind), String(fp.name)));
    const base = existing ? proposalOf(existing, edgesOf(existing.id), termsOf(existing.id)) : undefined;
    const p = parseNodeInput(
      { kind: fp.kind, name: fp.name, title: fp.title ?? null, body: fp.body, ...(existing ? {} : { status: "published" }) },
      base,
    );
    planNode(existing, p, counts.parts, partWrites);
  }
  const partIds = await writeNodes(q, s, partWrites, changes, nodeKey);
  const nodeIdByKey = (k: string) => nodeByKey.get(k)?.id ?? partIds.get(k);

  // ── Domains
  const domainWrites: NodeWrite[] = [];
  const fileDomainNames = new Set<string>();
  for (const fd of file.domains) {
    fileDomainNames.add(lower(String(fd.name ?? "")));
    const missing: string[] = [];
    const edges: { role: string; position: number; nodeId?: number; conceptId?: number }[] = [];
    (fd.concepts ?? []).forEach((name, i) => {
      const id = conceptIdByName.get(lower(name));
      if (id === undefined) missing.push(`concept "${name}"`);
      else edges.push({ role: "concept", position: i + 1, conceptId: id });
    });
    for (const part of fd.parts ?? []) {
      const id = nodeIdByKey(nodeKey(ROLE_KIND[part.role] ?? "part", part.name));
      if (id === undefined) missing.push(`${part.role} "${part.name}"`);
      else edges.push({ role: part.role, position: part.position, nodeId: id });
    }
    if (missing.length) throw new HttpError(400, `Domain "${fd.name}" refers to items that aren't in the file or the project`, { missing });

    const existing = nodeByKey.get(nodeKey("domain", String(fd.name)));
    const base = existing ? proposalOf(existing, edgesOf(existing.id), termsOf(existing.id)) : undefined;
    const p = parseNodeInput(
      {
        kind: "domain",
        name: fd.name,
        title: fd.title ?? null,
        body: fd.body,
        status: fd.status ?? base?.fields.status ?? "draft",
        meta: fd.meta ?? base?.fields.meta ?? {},
        edges,
        terms: fd.terms ?? [],
      },
      base,
    );
    planNode(existing, p, counts.domains, domainWrites);
  }

  // ── Replace: domains the file leaves out are retired (written with the domains).
  if (mode === "replace") {
    for (const n of wc.nodes) {
      if (n.kind !== "domain" || isBuiltIn(n) || n.status === "retired" || fileDomainNames.has(lower(n.name))) continue;
      const base = proposalOf(n, edgesOf(n.id), termsOf(n.id));
      planNode(n, { ...base, fields: { ...base.fields, status: "retired" } }, counts.domains, domainWrites, true);
    }
  }
  const domainIds = await writeNodes(q, s, domainWrites, changes, nodeKey);
  for (const w of domainWrites) {
    if (!w.existing) finalEdges.set(domainIds.get(nodeKey(w.p.fields.kind, w.p.fields.name))!, w.p.edges);
  }

  // ── Replace: concepts the file leaves out and nothing links to any more.
  if (mode === "replace") {
    const used = new Set([...finalEdges.values()].flatMap((list) => list.flatMap((e) => (e.conceptId !== null ? [e.conceptId] : []))));
    const gone: ConceptRow[] = [];
    for (const c of wc.concepts) {
      if (fileConceptKeys.has(`${lower(c.name)}|${c.sourceId ?? ""}`) || used.has(c.id)) continue;
      if (canEditDirectly(c, s)) {
        gone.push(c);
        counts.concepts.removed++;
      } else {
        requests.push(requestRow(s, "concept", c.id, "delete", c.editVersion, {}));
        counts.concepts.requested++;
      }
    }
    if (gone.length) {
      await q
        .update(concepts)
        .set({ deletedAt: new Date(), editVersion: sql`${concepts.editVersion} + 1`, updatedBy: s.userId, updatedAt: new Date() })
        .where(inArray(concepts.id, gone.map((c) => c.id)));
      for (const c of gone) changes.push(historyRow(s, "concept", c.id, "delete", conceptFieldsOf(c), null));
    }
  }

  // ── The links must still form a DAG (checked once, over the final graph).
  const links = [...finalEdges.entries()].flatMap(([parentId, list]) =>
    list.flatMap((e) => (e.nodeId !== null ? [{ parentId, childId: e.nodeId }] : [])),
  );
  const dag = analyseGraph(finalEdges.keys(), links);
  if (!dag.ok) {
    const nameById = new Map<number, string>(wc.nodes.map((n) => [n.id, n.name]));
    for (const [k, id] of [...partIds, ...domainIds]) nameById.set(id, k.split("|")[1]);
    throw new HttpError(409, "The file's links would create a loop", { cycle: dag.cycle.map((id) => nameById.get(id) ?? `#${id}`) });
  }
  if ([...dag.depth.values()].some((d) => d > MAX_DEPTH)) throw new HttpError(409, `Links may be at most ${MAX_DEPTH} levels deep`);

  // ── Requests and history, one insert each.
  await inChunks(requests, (chunk) => q.insert(graphChangeRequests).values(chunk).returning({ id: graphChangeRequests.id }));
  await inChunks(changes, (chunk) => q.insert(graphChanges).values(chunk).returning({ id: graphChanges.id }));

  return { mode, counts };
}
