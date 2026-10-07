import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import { concepts, graphChanges, graphDomainTerms, graphEdges, graphNodes, users } from "../../db/schema";
import type { Q } from "../../db/tx";
import { HttpError, isUniqueViolation } from "./errors";
import { analyseGraph, MAX_DEPTH } from "./dag";
import { canonicalJson, sha256Hex } from "./hash";
import type { ConceptFields, EdgeInput, NodeProposal, TermInput } from "./validate";

/** Reads and writes on a project's working copy (nodes, edges, domain terms, concepts). */

export interface Scope {
  projectId: string;
  orgId: string;
  userId: string;
  role: "super_admin" | "org_admin" | "member";
}

export type NodeRow = typeof graphNodes.$inferSelect;
export type ConceptRow = typeof concepts.$inferSelect;
export type EdgeRow = typeof graphEdges.$inferSelect;
export type TermRow = typeof graphDomainTerms.$inferSelect;

// ─── Ownership ──────────────────────────────────────────

/** Owner (or a super admin, or anyone if the owner is gone) edits directly; others make a change request. */
export function canEditDirectly(item: { ownerId: string | null }, s: Scope): boolean {
  return item.ownerId === null || item.ownerId === s.userId || s.role === "super_admin";
}

// ─── Locking ────────────────────────────────────────────

/** Serialises a project's graph writes for the transaction, so two edits can't each add half a cycle. */
export async function lockProject(q: Q, projectId: string): Promise<void> {
  await q.execute(sql`select pg_advisory_xact_lock(hashtext(${`graph:${projectId}`}))`);
}

// ─── Reads ──────────────────────────────────────────────

export async function getNode(q: Q, projectId: string, id: number): Promise<NodeRow | null> {
  const [row] = await q
    .select()
    .from(graphNodes)
    .where(and(eq(graphNodes.id, id), eq(graphNodes.projectId, projectId), isNull(graphNodes.deletedAt)))
    .limit(1);
  return row ?? null;
}

export async function getConcept(q: Q, projectId: string, id: number): Promise<ConceptRow | null> {
  const [row] = await q
    .select()
    .from(concepts)
    .where(and(eq(concepts.id, id), eq(concepts.projectId, projectId), isNull(concepts.deletedAt)))
    .limit(1);
  return row ?? null;
}

export const edgeOrder = (a: { role: string; position: number }, b: { role: string; position: number }) =>
  a.role.localeCompare(b.role) || a.position - b.position;

const toEdgeInput = (e: EdgeRow): EdgeInput => ({
  role: e.role,
  position: e.position,
  nodeId: e.childNodeId,
  conceptId: e.childConceptId,
});

/** A node as fields + edges + terms: the shape updates and change requests use. */
export function proposalOf(node: NodeRow, edges: EdgeRow[], terms: TermRow[]): NodeProposal {
  return {
    fields: {
      kind: node.kind,
      name: node.name,
      title: node.title,
      body: node.body,
      meta: (node.meta ?? {}) as Record<string, unknown>,
      status: node.status as NodeProposal["fields"]["status"],
    },
    edges: edges.map(toEdgeInput).sort(edgeOrder),
    terms: terms.map((t) => ({ term: t.term, weight: t.weight })).sort((a, b) => a.term.localeCompare(b.term)),
  };
}

export async function loadNodeProposal(q: Q, node: NodeRow): Promise<NodeProposal> {
  const [edges, terms] = await Promise.all([
    q.select().from(graphEdges).where(eq(graphEdges.parentId, node.id)),
    q.select().from(graphDomainTerms).where(eq(graphDomainTerms.nodeId, node.id)),
  ]);
  return proposalOf(node, edges, terms);
}

export function conceptFieldsOf(c: ConceptRow): ConceptFields {
  return {
    name: c.name,
    body: c.body,
    kind: c.kind,
    type: c.type,
    requires: c.requires,
    returns: (c.returns ?? {}) as Record<string, unknown>,
    aliases: c.aliases,
    description: c.description,
    sourceId: c.sourceId,
    originRef: c.originRef,
  };
}

/** The whole working copy of a project (deleted rows left out; edges and terms only of live nodes). */
export async function loadWorkingCopy(q: Q, projectId: string) {
  const [nodes, conceptRows, edgeRows, termRows] = await Promise.all([
    q.select().from(graphNodes).where(and(eq(graphNodes.projectId, projectId), isNull(graphNodes.deletedAt))),
    q.select().from(concepts).where(and(eq(concepts.projectId, projectId), isNull(concepts.deletedAt))),
    q.select().from(graphEdges).where(eq(graphEdges.projectId, projectId)),
    q.select().from(graphDomainTerms).where(eq(graphDomainTerms.projectId, projectId)),
  ]);
  const live = new Set(nodes.map((n) => n.id));
  return {
    nodes,
    concepts: conceptRows,
    edges: edgeRows.filter((e) => live.has(e.parentId)),
    terms: termRows.filter((t) => live.has(t.nodeId)),
  };
}

/** Owner names for display, keyed by user id. */
export async function ownerNames(q: Q, ids: (string | null)[]): Promise<Map<string, { name: string; email: string }>> {
  const unique = [...new Set(ids.filter((x): x is string => !!x))];
  if (!unique.length) return new Map();
  const rows = await q.select({ id: users.id, name: users.name, email: users.email }).from(users).where(inArray(users.id, unique));
  return new Map(rows.map((r) => [r.id, { name: r.name, email: r.email }]));
}

// ─── Checks ─────────────────────────────────────────────

/** Every edge must point at a live node or concept of this project. */
async function checkEdgeTargets(q: Q, projectId: string, edges: EdgeInput[], selfId: number | null): Promise<void> {
  const nodeIds = [...new Set(edges.flatMap((e) => (e.nodeId !== null ? [e.nodeId] : [])))];
  const conceptIds = [...new Set(edges.flatMap((e) => (e.conceptId !== null ? [e.conceptId] : [])))];
  if (selfId !== null && nodeIds.includes(selfId)) throw new HttpError(400, "A node cannot link to itself");

  const [liveNodes, liveConcepts] = await Promise.all([
    nodeIds.length
      ? q.select({ id: graphNodes.id }).from(graphNodes).where(and(eq(graphNodes.projectId, projectId), isNull(graphNodes.deletedAt), inArray(graphNodes.id, nodeIds)))
      : Promise.resolve([] as { id: number }[]),
    conceptIds.length
      ? q.select({ id: concepts.id }).from(concepts).where(and(eq(concepts.projectId, projectId), isNull(concepts.deletedAt), inArray(concepts.id, conceptIds)))
      : Promise.resolve([] as { id: number }[]),
  ]);
  const okNodes = new Set(liveNodes.map((r) => r.id));
  const okConcepts = new Set(liveConcepts.map((r) => r.id));
  const missingNodes = nodeIds.filter((id) => !okNodes.has(id));
  const missingConcepts = conceptIds.filter((id) => !okConcepts.has(id));
  if (missingNodes.length || missingConcepts.length) {
    throw new HttpError(400, "Some links point at nodes or concepts that don't exist in this project", {
      missingNodeIds: missingNodes,
      missingConceptIds: missingConcepts,
    });
  }
}

/** Replacing `nodeId`'s node links must not create a loop or exceed the depth limit. */
async function checkNoCycle(q: Q, projectId: string, nodeId: number, edges: EdgeInput[]): Promise<void> {
  const own = edges.flatMap((e) => (e.nodeId !== null ? [{ parentId: nodeId, childId: e.nodeId }] : []));
  if (!own.length) return; // no outgoing node links: this node can't close a loop

  const rows = await q
    .select({ parentId: graphEdges.parentId, childId: graphEdges.childNodeId })
    .from(graphEdges)
    .innerJoin(graphNodes, eq(graphNodes.id, graphEdges.parentId))
    .where(and(eq(graphEdges.projectId, projectId), isNull(graphNodes.deletedAt)));
  const links = [
    ...rows.flatMap((r) => (r.childId !== null && r.parentId !== nodeId ? [{ parentId: r.parentId, childId: r.childId }] : [])),
    ...own,
  ];
  const check = analyseGraph([nodeId], links);
  if (!check.ok) {
    const names = await nodeNames(q, check.cycle);
    throw new HttpError(409, "This link would create a loop", { cycle: check.cycle.map((id) => names.get(id) ?? `#${id}`) });
  }
  if ((check.depth.get(nodeId) ?? 0) > MAX_DEPTH) {
    throw new HttpError(409, `Links may be at most ${MAX_DEPTH} levels deep`);
  }
}

export async function nodeNames(q: Q, ids: number[]): Promise<Map<number, string>> {
  if (!ids.length) return new Map();
  const rows = await q.select({ id: graphNodes.id, name: graphNodes.name }).from(graphNodes).where(inArray(graphNodes.id, [...new Set(ids)]));
  return new Map(rows.map((r) => [r.id, r.name]));
}

// ─── History ────────────────────────────────────────────

/** How a change reached the working copy, and the request it came from (merge). */
export interface ChangeVia {
  via?: "edit" | "merge" | "import" | "discard";
  changeRequestId?: number;
}

/** A node in the flat shape history stores: fields + edges + terms, in a stable order. */
export const nodeContent = (p: NodeProposal) => ({
  ...p.fields,
  edges: [...p.edges].sort(edgeOrder),
  terms: [...p.terms].sort((a, b) => a.term.localeCompare(b.term)),
});

/** Append one row to graph_changes. An update that changes nothing is not recorded. */
export async function logChange(
  q: Q,
  s: Scope,
  c: { entity: "node" | "concept"; entityId: number; action: "create" | "update" | "delete" | "restore" | "owner"; before: unknown; after: unknown },
  how: ChangeVia = {},
): Promise<void> {
  if (c.action === "update" && canonicalJson(c.before) === canonicalJson(c.after)) return;
  await q.insert(graphChanges).values({
    orgId: s.orgId,
    projectId: s.projectId,
    entity: c.entity,
    entityId: c.entityId,
    action: c.action,
    via: how.via ?? "edit",
    changeRequestId: how.changeRequestId ?? null,
    before: c.before ?? null,
    after: c.after ?? null,
    changedBy: s.userId,
  });
}

// ─── Writes ─────────────────────────────────────────────

export const nodeHash = (f: NodeProposal["fields"]) =>
  sha256Hex(canonicalJson({ kind: f.kind, name: f.name, body: f.body, meta: f.meta }));

async function replaceEdges(q: Q, s: Scope, nodeId: number, edges: EdgeInput[]): Promise<void> {
  await q.delete(graphEdges).where(eq(graphEdges.parentId, nodeId));
  if (!edges.length) return;
  await q.insert(graphEdges).values(
    edges.map((e) => ({
      orgId: s.orgId,
      projectId: s.projectId,
      parentId: nodeId,
      childNodeId: e.nodeId,
      childConceptId: e.conceptId,
      role: e.role,
      position: e.position,
      createdBy: s.userId,
    })),
  );
}

async function replaceTerms(q: Q, s: Scope, nodeId: number, terms: TermInput[]): Promise<void> {
  await q.delete(graphDomainTerms).where(eq(graphDomainTerms.nodeId, nodeId));
  if (!terms.length) return;
  await q.insert(graphDomainTerms).values(
    terms.map((t) => ({ orgId: s.orgId, projectId: s.projectId, nodeId, term: t.term, weight: t.weight })),
  );
}

/** Create or update a node (in a transaction, after lockProject); 409 if not at `expectedEditVersion`. */
export async function writeNode(
  q: Q,
  s: Scope,
  existing: NodeRow | null,
  p: NodeProposal,
  opts: { expectedEditVersion?: number; ownerId?: string | null; origin?: string } & ChangeVia = {},
): Promise<NodeRow> {
  await checkEdgeTargets(q, s.projectId, p.edges, existing?.id ?? null);
  if (existing) await checkNoCycle(q, s.projectId, existing.id, p.edges);
  const hash = await nodeHash(p.fields);
  const before = existing ? nodeContent(await loadNodeProposal(q, existing)) : null;

  let row: NodeRow | undefined;
  try {
    if (existing) {
      [row] = await q
        .update(graphNodes)
        .set({
          ...p.fields,
          hash,
          editVersion: sql`${graphNodes.editVersion} + 1`,
          updatedBy: s.userId,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(graphNodes.id, existing.id),
            isNull(graphNodes.deletedAt),
            eq(graphNodes.editVersion, opts.expectedEditVersion ?? existing.editVersion),
          ),
        )
        .returning();
      if (!row) throw conflict("node", existing.id);
    } else {
      [row] = await q
        .insert(graphNodes)
        .values({
          ...p.fields,
          orgId: s.orgId,
          projectId: s.projectId,
          ownerId: opts.ownerId === undefined ? s.userId : opts.ownerId,
          hash,
          origin: opts.origin ?? "platform",
          createdBy: s.userId,
          updatedBy: s.userId,
        })
        .returning();
    }
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new HttpError(409, `A ${p.fields.kind} named "${p.fields.name}" already exists in this project`);
    }
    throw err;
  }

  await replaceEdges(q, s, row!.id, p.edges);
  await replaceTerms(q, s, row!.id, p.terms);
  await logChange(q, s, { entity: "node", entityId: row!.id, action: existing ? "update" : "create", before, after: nodeContent(p) }, opts);
  return row!;
}

/** Soft-delete a node. Refused while another live node still links to it. */
export async function deleteNode(q: Q, s: Scope, node: NodeRow, expectedEditVersion: number, how: ChangeVia = {}): Promise<void> {
  const usedBy = await q
    .select({ id: graphNodes.id, name: graphNodes.name, kind: graphNodes.kind })
    .from(graphEdges)
    .innerJoin(graphNodes, eq(graphNodes.id, graphEdges.parentId))
    .where(and(eq(graphEdges.childNodeId, node.id), isNull(graphNodes.deletedAt)));
  if (usedBy.length) {
    throw new HttpError(409, `"${node.name}" is still used; remove those links first`, { usedBy });
  }
  const before = nodeContent(await loadNodeProposal(q, node));
  const [row] = await q
    .update(graphNodes)
    .set({ deletedAt: new Date(), editVersion: sql`${graphNodes.editVersion} + 1`, updatedBy: s.userId, updatedAt: new Date() })
    .where(and(eq(graphNodes.id, node.id), isNull(graphNodes.deletedAt), eq(graphNodes.editVersion, expectedEditVersion)))
    .returning({ id: graphNodes.id });
  if (!row) throw conflict("node", node.id);
  await logChange(q, s, { entity: "node", entityId: node.id, action: "delete", before, after: null }, how);
}

/** Create (existing = null) or update a concept. Same version rule as writeNode. */
export async function writeConcept(
  q: Q,
  s: Scope,
  existing: ConceptRow | null,
  f: ConceptFields,
  opts: { expectedEditVersion?: number; ownerId?: string | null; origin?: string } & ChangeVia = {},
): Promise<ConceptRow> {
  const row = await saveConcept(q, s, existing, f, opts);
  await logChange(
    q,
    s,
    { entity: "concept", entityId: row.id, action: existing ? "update" : "create", before: existing ? conceptFieldsOf(existing) : null, after: conceptFieldsOf(row) },
    opts,
  );
  return row;
}

async function saveConcept(
  q: Q,
  s: Scope,
  existing: ConceptRow | null,
  f: ConceptFields,
  opts: { expectedEditVersion?: number; ownerId?: string | null; origin?: string },
): Promise<ConceptRow> {
  try {
    if (existing) {
      const [row] = await q
        .update(concepts)
        .set({
          ...f,
          editVersion: sql`${concepts.editVersion} + 1`,
          updatedBy: s.userId,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(concepts.id, existing.id),
            isNull(concepts.deletedAt),
            eq(concepts.editVersion, opts.expectedEditVersion ?? existing.editVersion),
          ),
        )
        .returning();
      if (!row) throw conflict("concept", existing.id);
      return row;
    }
    const [row] = await q
      .insert(concepts)
      .values({
        ...f,
        orgId: s.orgId,
        projectId: s.projectId,
        ownerId: opts.ownerId === undefined ? s.userId : opts.ownerId,
        origin: opts.origin ?? "platform",
        createdBy: s.userId,
        updatedBy: s.userId,
      })
      .returning();
    return row;
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new HttpError(409, `A concept named "${f.name}" already exists in this project${f.sourceId ? " for that source" : ""}`);
    }
    throw err;
  }
}

/** Soft-delete a concept. Refused while a live node still links to it. */
export async function deleteConcept(q: Q, s: Scope, c: ConceptRow, expectedEditVersion: number, how: ChangeVia = {}): Promise<void> {
  const usedBy = await q
    .select({ id: graphNodes.id, name: graphNodes.name, kind: graphNodes.kind })
    .from(graphEdges)
    .innerJoin(graphNodes, eq(graphNodes.id, graphEdges.parentId))
    .where(and(eq(graphEdges.childConceptId, c.id), isNull(graphNodes.deletedAt)));
  if (usedBy.length) {
    throw new HttpError(409, `"${c.name}" is still used; remove it from those nodes first`, { usedBy });
  }
  const [row] = await q
    .update(concepts)
    .set({ deletedAt: new Date(), editVersion: sql`${concepts.editVersion} + 1`, updatedBy: s.userId, updatedAt: new Date() })
    .where(and(eq(concepts.id, c.id), isNull(concepts.deletedAt), eq(concepts.editVersion, expectedEditVersion)))
    .returning({ id: concepts.id });
  if (!row) throw conflict("concept", c.id);
  await logChange(q, s, { entity: "concept", entityId: c.id, action: "delete", before: conceptFieldsOf(c), after: null }, how);
}

function conflict(entity: "node" | "concept", id: number): HttpError {
  return new HttpError(409, `This ${entity} was changed by someone else; reload it and try again`, {
    conflict: true,
    entity,
    id,
  });
}

/** Order edges by role and position, for comparing and returning. */
export function sortedEdges(edges: EdgeRow[]): EdgeRow[] {
  return [...edges].sort(edgeOrder);
}
