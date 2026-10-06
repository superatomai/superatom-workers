import { and, eq } from "drizzle-orm";
import { graphChangeRequests } from "../../db/schema";
import type { Q } from "../../db/tx";
import { HttpError } from "./errors";
import {
  canEditDirectly,
  conceptFieldsOf,
  deleteConcept,
  deleteNode,
  getConcept,
  getNode,
  loadNodeProposal,
  writeConcept,
  writeNode,
  type Scope,
} from "./store";
import { parseConceptInput, parseNodeInput, type NodeProposal } from "./validate";

/** Change requests: edits to someone else's item, held for the owner; `proposed` is re-validated on merge. */

export type RequestRow = typeof graphChangeRequests.$inferSelect;
export type Entity = "node" | "concept";
export type Action = "create" | "update" | "delete";

/** A node proposal in the flat body shape: fields + edges + terms. */
export function flattenProposal(p: NodeProposal): Record<string, unknown> {
  return { ...p.fields, edges: p.edges, terms: p.terms };
}

export async function createRequest(
  q: Q,
  s: Scope,
  r: {
    entity: Entity;
    entityId: number | null;
    action: Action;
    baseEditVersion: number | null;
    proposed: Record<string, unknown>;
    source?: "user" | "agent" | "import";
    originRef?: string | null;
  },
): Promise<RequestRow> {
  const [row] = await q
    .insert(graphChangeRequests)
    .values({
      orgId: s.orgId,
      projectId: s.projectId,
      entity: r.entity,
      entityId: r.entityId,
      action: r.action,
      baseEditVersion: r.baseEditVersion,
      proposed: r.proposed,
      authorId: r.source === "agent" ? null : s.userId,
      source: r.source ?? "user",
      originRef: r.originRef ?? null,
    })
    .returning();
  return row;
}

export async function getRequest(q: Q, projectId: string, id: number): Promise<RequestRow> {
  const [row] = await q
    .select()
    .from(graphChangeRequests)
    .where(and(eq(graphChangeRequests.id, id), eq(graphChangeRequests.projectId, projectId)))
    .limit(1);
  if (!row) throw new HttpError(404, "Change request not found");
  return row;
}

/** The item a request targets, as it is now (null for a create, or when it was deleted). */
export async function currentTarget(q: Q, s: Scope, r: RequestRow) {
  if (r.entityId === null) return null;
  if (r.entity === "node") {
    const node = await getNode(q, s.projectId, r.entityId);
    return node ? { row: node, content: flattenProposal(await loadNodeProposal(q, node)) } : null;
  }
  const concept = await getConcept(q, s.projectId, r.entityId);
  return concept ? { row: concept, content: conceptFieldsOf(concept) as unknown as Record<string, unknown> } : null;
}

/** Owner of the target, or any admin for a new item. Throws 403 otherwise. */
async function assertMayReview(q: Q, s: Scope, r: RequestRow) {
  const target = await currentTarget(q, s, r);
  if (r.action !== "create") {
    if (!target) throw new HttpError(409, "The item this request changes no longer exists");
    if (!canEditDirectly(target.row, s)) {
      throw new HttpError(403, "Only the owner of this item can review its change requests");
    }
  }
  return target;
}

/** Apply a request (in a transaction, after lockProject); 409 if the item changed since, unless `force`. */
export async function mergeRequest(q: Q, s: Scope, id: number, force: boolean, comment: string | null) {
  const r = await getRequest(q, s.projectId, id);
  if (r.status !== "open") throw new HttpError(409, `This request is already ${r.status}`);
  const target = await assertMayReview(q, s, r);

  if (target && r.baseEditVersion !== null && target.row.editVersion !== r.baseEditVersion && !force) {
    throw new HttpError(409, "The item changed after this request was made; compare and merge again with force", {
      conflict: true,
      current: target.content,
      proposed: r.proposed,
    });
  }

  const origin = r.source === "agent" ? "agent" : r.source === "import" ? "import" : "platform";
  const how = { via: "merge" as const, changeRequestId: r.id };
  let result: unknown = null;
  if (r.entity === "node") {
    const node = target?.row as Awaited<ReturnType<typeof getNode>>;
    if (r.action === "delete") {
      await deleteNode(q, s, node!, node!.editVersion, how);
    } else {
      const base = node ? await loadNodeProposal(q, node) : undefined;
      const proposal = parseNodeInput(r.proposed, base);
      result = await writeNode(q, s, node ?? null, proposal, {
        expectedEditVersion: node?.editVersion,
        ownerId: node ? undefined : r.authorId ?? s.userId,
        origin,
        ...how,
      });
    }
  } else {
    const concept = target?.row as Awaited<ReturnType<typeof getConcept>>;
    if (r.action === "delete") {
      await deleteConcept(q, s, concept!, concept!.editVersion, how);
    } else {
      const fields = parseConceptInput(r.proposed, concept ? conceptFieldsOf(concept) : undefined);
      result = await writeConcept(q, s, concept ?? null, fields, {
        expectedEditVersion: concept?.editVersion,
        ownerId: concept ? undefined : r.authorId ?? s.userId,
        origin,
        ...how,
      });
    }
  }

  const [merged] = await q
    .update(graphChangeRequests)
    .set({ status: "merged", reviewedBy: s.userId, reviewedAt: new Date(), reviewComment: comment, updatedAt: new Date() })
    .where(and(eq(graphChangeRequests.id, r.id), eq(graphChangeRequests.status, "open")))
    .returning();
  if (!merged) throw new HttpError(409, "This request was reviewed by someone else meanwhile");
  return { request: merged, result };
}

export async function rejectRequest(q: Q, s: Scope, id: number, comment: string) {
  const r = await getRequest(q, s.projectId, id);
  if (r.status !== "open") throw new HttpError(409, `This request is already ${r.status}`);
  await assertMayReview(q, s, r);
  const [row] = await q
    .update(graphChangeRequests)
    .set({ status: "rejected", reviewedBy: s.userId, reviewedAt: new Date(), reviewComment: comment, updatedAt: new Date() })
    .where(and(eq(graphChangeRequests.id, r.id), eq(graphChangeRequests.status, "open")))
    .returning();
  if (!row) throw new HttpError(409, "This request was reviewed by someone else meanwhile");
  return row;
}

/** The author keeps editing an open request, or withdraws it. */
export async function updateOwnRequest(
  q: Q,
  s: Scope,
  id: number,
  change: { proposed?: Record<string, unknown>; withdraw?: boolean },
) {
  const r = await getRequest(q, s.projectId, id);
  if (r.authorId !== s.userId) throw new HttpError(403, "Only the author can change this request");
  if (r.status !== "open") throw new HttpError(409, `This request is already ${r.status}`);

  let proposed = r.proposed;
  if (change.proposed && r.action !== "delete") {
    // Validate now, so a broken proposal is caught when written rather than at merge.
    if (r.entity === "node") {
      const target = r.entityId !== null ? await getNode(q, s.projectId, r.entityId) : null;
      const base = target ? await loadNodeProposal(q, target) : undefined;
      proposed = flattenProposal(parseNodeInput(change.proposed, base));
    } else {
      const target = r.entityId !== null ? await getConcept(q, s.projectId, r.entityId) : null;
      proposed = parseConceptInput(change.proposed, target ? conceptFieldsOf(target) : undefined) as unknown as Record<string, unknown>;
    }
  }

  const [row] = await q
    .update(graphChangeRequests)
    .set(change.withdraw ? { status: "withdrawn", updatedAt: new Date() } : { proposed, updatedAt: new Date() })
    .where(and(eq(graphChangeRequests.id, r.id), eq(graphChangeRequests.status, "open")))
    .returning();
  if (!row) throw new HttpError(409, "This request was reviewed meanwhile");
  return row;
}
