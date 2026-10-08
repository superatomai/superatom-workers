import { and, desc, eq, gt, inArray, isNotNull, sql } from "drizzle-orm";
import { concepts, graphChanges, graphNodes, graphReleaseEvents, graphReleases, graphRevisions, users } from "../../db/schema";
import type { Q } from "../../db/tx";
import type { Env } from "../../types";
import { analyseGraph, MAX_DEPTH } from "./dag";
import { HttpError } from "./errors";
import { canonicalJson, sha256Hex } from "./hash";
import {
  conceptFieldsOf,
  edgeOrder,
  lockProject,
  loadWorkingCopy,
  logChange,
  nodeContent as flatNode,
  proposalOf,
  writeConcept,
  writeNode,
  type ConceptRow,
  type EdgeRow,
  type NodeRow,
  type Scope,
  type TermRow,
} from "./store";
import type { EdgeInput, NodeProposal, TermInput } from "./validate";

/** Releases: immutable numbered snapshots; the current one is the latest release event's to_release_id. */

export type ReleaseItem = { entity: "node" | "concept"; id: number; rev: number; hash: string };
export type ReleaseRow = typeof graphReleases.$inferSelect;

/** What a revision stores for a node: everything an engine needs, nothing volatile. */
function nodeContent(n: NodeRow, edges: EdgeRow[], terms: TermRow[]) {
  return {
    kind: n.kind,
    name: n.name,
    title: n.title,
    body: n.body,
    meta: n.meta ?? {},
    status: n.status,
    edges: [...edges].sort(edgeOrder).map((e) => ({
      role: e.role,
      position: e.position,
      nodeId: e.childNodeId,
      conceptId: e.childConceptId,
    })),
    terms: terms.map((t) => ({ term: t.term, weight: t.weight })).sort((a, b) => a.term.localeCompare(b.term)),
  };
}

function conceptContent(c: ConceptRow) {
  return {
    name: c.name,
    body: c.body,
    kind: c.kind,
    type: c.type,
    requires: c.requires,
    returns: c.returns ?? {},
    aliases: c.aliases,
    description: c.description,
    sourceId: c.sourceId,
  };
}

const itemKey = (i: { entity: string; id: number }) => `${i.entity}:${i.id}`;

export async function currentRelease(q: Q, projectId: string): Promise<{ release: ReleaseRow; eventSeq: number } | null> {
  const [event] = await q
    .select({ toReleaseId: graphReleaseEvents.toReleaseId, eventSeq: graphReleaseEvents.eventSeq })
    .from(graphReleaseEvents)
    .where(eq(graphReleaseEvents.projectId, projectId))
    .orderBy(desc(graphReleaseEvents.eventSeq))
    .limit(1);
  if (!event) return null;
  const [release] = await q.select().from(graphReleases).where(eq(graphReleases.id, event.toReleaseId)).limit(1);
  return release ? { release, eventSeq: Number(event.eventSeq) } : null;
}

export async function getRelease(q: Q, projectId: string, seq: number): Promise<ReleaseRow> {
  const [row] = await q
    .select()
    .from(graphReleases)
    .where(and(eq(graphReleases.projectId, projectId), eq(graphReleases.seq, seq)))
    .limit(1);
  if (!row) throw new HttpError(404, `Release ${seq} not found`);
  return row;
}

/** The revisions a release is made of: `{ entity, id, rev, hash, content }` per item. */
export async function releaseContent(q: Q, projectId: string, items: ReleaseItem[]) {
  if (!items.length) return [];
  const rows = await q
    .select()
    .from(graphRevisions)
    .where(
      and(
        eq(graphRevisions.projectId, projectId),
        sql`(${graphRevisions.entity}, ${graphRevisions.entityId}, ${graphRevisions.rev}) in (${sql.join(
          items.map((i) => sql`(${i.entity}, ${i.id}, ${i.rev})`),
          sql`, `,
        )})`,
      ),
    );
  return rows.map((r) => ({ entity: r.entity, id: r.entityId, rev: r.rev, hash: r.hash, content: r.content }));
}

/** Added / changed / removed items between two item lists, with names for display. */
export async function diffItems(q: Q, projectId: string, from: ReleaseItem[], to: ReleaseItem[]) {
  const before = new Map(from.map((i) => [itemKey(i), i]));
  const after = new Map(to.map((i) => [itemKey(i), i]));
  const added = to.filter((i) => !before.has(itemKey(i)));
  const changed = to.filter((i) => before.has(itemKey(i)) && before.get(itemKey(i))!.hash !== i.hash);
  const removed = from.filter((i) => !after.has(itemKey(i)));

  // Names come from the revisions themselves, so deleted items still have one.
  const named = await releaseContent(q, projectId, [...added, ...changed, ...removed]);
  const nameOf = new Map(named.map((r) => [`${r.entity}:${r.id}:${r.rev}`, (r.content as { name?: string })?.name ?? null]));
  const label = (i: ReleaseItem, fromRev?: number) => ({
    entity: i.entity,
    id: i.id,
    name: nameOf.get(`${i.entity}:${i.id}:${i.rev}`) ?? null,
    rev: i.rev,
    ...(fromRev !== undefined ? { fromRev } : {}),
  });
  return {
    added: added.map((i) => label(i)),
    changed: changed.map((i) => label(i, before.get(itemKey(i))!.rev)),
    removed: removed.map((i) => label(i)),
  };
}

/** The release the working copy would become (validated and hashed), without writing anything. */
async function buildRelease(q: Q, s: Scope) {
  const wc = await loadWorkingCopy(q, s.projectId);
  const nodeById = new Map(wc.nodes.map((n) => [n.id, n]));
  const conceptById = new Map(wc.concepts.map((c) => [c.id, c]));

  // 1. Every link points at something live.
  const problems: string[] = [];
  for (const e of wc.edges) {
    const parent = nodeById.get(e.parentId)!.name;
    if (e.childNodeId !== null && !nodeById.has(e.childNodeId)) problems.push(`"${parent}" links to a deleted node (#${e.childNodeId})`);
    if (e.childConceptId !== null && !conceptById.has(e.childConceptId)) problems.push(`"${parent}" links to a deleted concept (#${e.childConceptId})`);
  }
  if (problems.length) throw new HttpError(409, "The graph has broken links", { problems });

  // 2. No loops, not too deep.
  const links = wc.edges.flatMap((e) => (e.childNodeId !== null ? [{ parentId: e.parentId, childId: e.childNodeId }] : []));
  const dag = analyseGraph(wc.nodes.map((n) => n.id), links);
  if (!dag.ok) {
    throw new HttpError(409, "The graph has a loop", { cycle: dag.cycle.map((id) => nodeById.get(id)?.name ?? `#${id}`) });
  }
  const tooDeep = [...dag.depth.entries()].filter(([, d]) => d > MAX_DEPTH).map(([id]) => nodeById.get(id)?.name);
  if (tooDeep.length) throw new HttpError(409, `Links may be at most ${MAX_DEPTH} levels deep`, { nodes: tooDeep });

  // 3. Hashes, children first, so each node's hash covers its children's (Merkle).
  const edgesByParent = new Map<number, EdgeRow[]>();
  for (const e of wc.edges) edgesByParent.set(e.parentId, [...(edgesByParent.get(e.parentId) ?? []), e]);
  const termsByNode = new Map<number, TermRow[]>();
  for (const t of wc.terms) termsByNode.set(t.nodeId, [...(termsByNode.get(t.nodeId) ?? []), t]);

  const built: (ReleaseItem & { content: unknown })[] = [];
  const conceptHash = new Map<number, string>();
  for (const c of wc.concepts) {
    const content = conceptContent(c);
    const hash = await sha256Hex(canonicalJson(content));
    conceptHash.set(c.id, hash);
    built.push({ entity: "concept", id: c.id, rev: 0, hash, content });
  }
  const nodeHash = new Map<number, string>();
  for (const id of dag.order) {
    const node = nodeById.get(id);
    if (!node) continue;
    const edges = edgesByParent.get(id) ?? [];
    const content = nodeContent(node, edges, termsByNode.get(id) ?? []);
    const children = edges
      .map((e) => (e.childNodeId !== null ? `n${e.childNodeId}:${nodeHash.get(e.childNodeId)}` : `c${e.childConceptId}:${conceptHash.get(e.childConceptId!)}`))
      .sort();
    const hash = await sha256Hex(`${canonicalJson(content)}\n${children.join("\n")}`);
    nodeHash.set(id, hash);
    built.push({ entity: "node", id, rev: 0, hash, content });
  }

  // 4. Reuse the latest revision where the content is unchanged; add one where it changed.
  const latest = await q
    .selectDistinctOn([graphRevisions.entity, graphRevisions.entityId], {
      entity: graphRevisions.entity,
      entityId: graphRevisions.entityId,
      rev: graphRevisions.rev,
      hash: graphRevisions.hash,
    })
    .from(graphRevisions)
    .where(eq(graphRevisions.projectId, s.projectId))
    .orderBy(graphRevisions.entity, graphRevisions.entityId, desc(graphRevisions.rev));
  const latestByKey = new Map(latest.map((r) => [`${r.entity}:${r.entityId}`, r]));

  const newRevisions: (typeof graphRevisions.$inferInsert)[] = [];
  for (const item of built) {
    const prev = latestByKey.get(itemKey(item));
    if (prev && prev.hash === item.hash) {
      item.rev = prev.rev;
    } else {
      item.rev = (prev?.rev ?? 0) + 1;
      newRevisions.push({
        entity: item.entity,
        entityId: item.id,
        rev: item.rev,
        orgId: s.orgId,
        projectId: s.projectId,
        content: item.content,
        hash: item.hash,
        createdBy: s.userId,
      });
    }
  }

  const items: ReleaseItem[] = built
    .map(({ entity, id, rev, hash }) => ({ entity, id, rev, hash }))
    .sort((a, b) => a.entity.localeCompare(b.entity) || a.id - b.id);
  const rootHash = await sha256Hex(canonicalJson(items));
  const current = await currentRelease(q, s.projectId);
  return { built, items, rootHash, newRevisions, current };
}

/** What publishing now would change against the live release. Writes nothing. */
export async function pendingChanges(q: Q, s: Scope) {
  const { built, current } = await buildRelease(q, s);
  const live = (current?.release.items as ReleaseItem[] | undefined) ?? [];
  const liveByKey = new Map(live.map((i) => [itemKey(i), i]));
  const builtKeys = new Set(built.map(itemKey));
  const nameOf = (i: { content: unknown }) => (i.content as { name?: string })?.name ?? null;
  const added = built.filter((i) => !liveByKey.has(itemKey(i)));
  // Node hashes cover children, so compare content to list only what itself changed.
  const hashDiffers = built.filter((i) => liveByKey.has(itemKey(i)) && liveByKey.get(itemKey(i))!.hash !== i.hash);
  const removedItems = live.filter((i) => !builtKeys.has(itemKey(i)));
  const [liveContent, removedNamed] = await Promise.all([
    releaseContent(q, s.projectId, hashDiffers.map((i) => liveByKey.get(itemKey(i))!)),
    // Removed items are only in the live release's revisions.
    releaseContent(q, s.projectId, removedItems),
  ]);
  const liveJson = new Map(liveContent.map((r) => [`${r.entity}:${r.id}`, canonicalJson(r.content)]));
  const changed = hashDiffers.filter((i) => liveJson.get(itemKey(i)) !== canonicalJson(i.content));
  const by = await changedBy(q, s.projectId, current?.release.createdAt ?? null);
  const row = (i: { entity: string; id: number }, name: string | null) => ({
    entity: i.entity as ReleaseItem["entity"],
    id: i.id,
    name,
    changedBy: by.get(itemKey(i)) ?? [],
  });
  return {
    current: current ? { seq: current.release.seq } : null,
    added: added.map((i) => row(i, nameOf(i))),
    changed: changed.map((i) => row(i, nameOf(i))),
    removed: removedNamed.map((i) => row(i, nameOf(i))),
  };
}

/** Who changed each item since `since` (the live version), from the edit history: item key → names. */
async function changedBy(q: Q, projectId: string, since: Date | null): Promise<Map<string, string[]>> {
  const rows = await q
    .selectDistinct({ entity: graphChanges.entity, entityId: graphChanges.entityId, name: users.name, email: users.email })
    .from(graphChanges)
    .leftJoin(users, eq(users.id, graphChanges.changedBy))
    .where(and(eq(graphChanges.projectId, projectId), since ? gt(graphChanges.changedAt, since) : undefined));
  const out = new Map<string, string[]>();
  for (const r of rows) {
    const who = r.name || r.email;
    if (!who) continue;
    const k = `${r.entity}:${r.entityId}`;
    out.set(k, [...(out.get(k) ?? []), who]);
  }
  return out;
}

/**
 * Discard the draft: put the working copy back to the live release. Items the
 * draft added are removed, items it deleted come back, changed ones get their
 * live content. Every reset is in the edit history (via "discard"). Nothing is
 * published and open change requests are left alone. Run in a transaction.
 */
export async function discardDraft(q: Q, s: Scope) {
  await lockProject(q, s.projectId);
  const current = await currentRelease(q, s.projectId);
  if (!current) throw new HttpError(409, "Nothing is published yet, so there's no version to go back to");
  const counts = await resetWorkingCopy(q, s, current.release.items as ReleaseItem[], "discard");
  return { version: current.release.seq, ...counts };
}

/** Put the working copy back to a release's items (see discardDraft). The project must be locked. */
async function resetWorkingCopy(q: Q, s: Scope, items: ReleaseItem[], via: "discard" | "rollback") {
  const live = await releaseContent(q, s.projectId, items);
  const liveIds = { node: new Set<number>(), concept: new Set<number>() };
  for (const i of live) liveIds[i.entity as "node" | "concept"].add(i.id);
  const how = { via };
  const counts = { removed: 0, restored: 0, reverted: 0 };

  // 1. Remove what the draft added (first, so restored items can take back their names).
  const wc = await loadWorkingCopy(q, s.projectId);
  const newNodes = wc.nodes.filter((n) => !liveIds.node.has(n.id));
  const newConcepts = wc.concepts.filter((c) => !liveIds.concept.has(c.id));
  if (newNodes.length) {
    await q
      .update(graphNodes)
      .set({ deletedAt: new Date(), editVersion: sql`${graphNodes.editVersion} + 1`, updatedBy: s.userId, updatedAt: new Date() })
      .where(inArray(graphNodes.id, newNodes.map((n) => n.id)));
  }
  if (newConcepts.length) {
    await q
      .update(concepts)
      .set({ deletedAt: new Date(), editVersion: sql`${concepts.editVersion} + 1`, updatedBy: s.userId, updatedAt: new Date() })
      .where(inArray(concepts.id, newConcepts.map((c) => c.id)));
  }
  for (const n of newNodes) {
    const content = flatNode(proposalOf(n, wc.edges.filter((e) => e.parentId === n.id), wc.terms.filter((t) => t.nodeId === n.id)));
    await logChange(q, s, { entity: "node", entityId: n.id, action: "delete", before: content, after: null }, how);
  }
  for (const c of newConcepts) {
    await logChange(q, s, { entity: "concept", entityId: c.id, action: "delete", before: conceptFieldsOf(c), after: null }, how);
  }
  counts.removed = newNodes.length + newConcepts.length;

  // 2. Bring back what the draft deleted.
  const deletedNodes = [...liveIds.node].length
    ? await q.select().from(graphNodes).where(and(inArray(graphNodes.id, [...liveIds.node]), isNotNull(graphNodes.deletedAt)))
    : [];
  const deletedConcepts = [...liveIds.concept].length
    ? await q.select().from(concepts).where(and(inArray(concepts.id, [...liveIds.concept]), isNotNull(concepts.deletedAt)))
    : [];
  if (deletedNodes.length) {
    await q.update(graphNodes).set({ deletedAt: null, updatedBy: s.userId, updatedAt: new Date() }).where(inArray(graphNodes.id, deletedNodes.map((n) => n.id)));
  }
  if (deletedConcepts.length) {
    await q.update(concepts).set({ deletedAt: null, updatedBy: s.userId, updatedAt: new Date() }).where(inArray(concepts.id, deletedConcepts.map((c) => c.id)));
  }
  counts.restored = deletedNodes.length + deletedConcepts.length;

  // 3. Live content back onto every live item (concepts first: nodes link to them).
  const rows = await loadWorkingCopy(q, s.projectId);
  const restored = new Set([...deletedNodes.map((n) => `node:${n.id}`), ...deletedConcepts.map((c) => `concept:${c.id}`)]);
  for (const item of live.filter((i) => i.entity === "concept")) {
    const row = rows.concepts.find((c) => c.id === item.id);
    if (!row) continue;
    const target = { ...conceptFieldsOf(row), ...(item.content as Partial<ReturnType<typeof conceptFieldsOf>>) };
    if (canonicalJson(conceptFieldsOf(row)) !== canonicalJson(target)) {
      await writeConcept(q, s, row, target, how);
      if (!restored.has(`concept:${item.id}`)) counts.reverted++;
    }
  }
  for (const item of live.filter((i) => i.entity === "node")) {
    const row = rows.nodes.find((n) => n.id === item.id);
    if (!row) continue;
    const c = item.content as NodeProposal["fields"] & { edges: EdgeInput[]; terms: TermInput[] };
    const target: NodeProposal = {
      fields: { kind: c.kind, name: c.name, title: c.title, body: c.body, meta: c.meta ?? {}, status: c.status },
      edges: c.edges ?? [],
      terms: c.terms ?? [],
    };
    const now = flatNode(proposalOf(row, rows.edges.filter((e) => e.parentId === row.id), rows.terms.filter((t) => t.nodeId === row.id)));
    if (canonicalJson(now) !== canonicalJson(flatNode(target))) {
      await writeNode(q, s, row, target, how);
      if (!restored.has(`node:${item.id}`)) counts.reverted++;
    }
  }
  // A restored item is in the history as restored, whatever step 3 did with it.
  for (const n of deletedNodes) await logChange(q, s, { entity: "node", entityId: n.id, action: "restore", before: null, after: { id: n.id } }, how);
  for (const c of deletedConcepts) await logChange(q, s, { entity: "concept", entityId: c.id, action: "restore", before: null, after: { id: c.id } }, how);

  return counts;
}

/** Publish the working copy as the next release. Run in a transaction. */
export async function publish(q: Q, s: Scope, notes: string | null) {
  await lockProject(q, s.projectId);
  const { items, rootHash, newRevisions, current } = await buildRelease(q, s);
  if (current && current.release.rootHash === rootHash) {
    throw new HttpError(409, "Nothing to publish: the graph is the same as the current release");
  }

  // 5. Write revisions, release and event.
  for (let i = 0; i < newRevisions.length; i += 500) {
    await q.insert(graphRevisions).values(newRevisions.slice(i, i + 500));
  }
  const [{ maxSeq }] = await q
    .select({ maxSeq: sql<string>`coalesce(max(${graphReleases.seq}), 0)` })
    .from(graphReleases)
    .where(eq(graphReleases.projectId, s.projectId));
  const [release] = await q
    .insert(graphReleases)
    .values({
      orgId: s.orgId,
      projectId: s.projectId,
      seq: Number(maxSeq) + 1,
      items,
      rootHash,
      parentReleaseId: current?.release.id ?? null,
      notes,
      createdBy: s.userId,
    })
    .returning();
  const eventSeq = (current?.eventSeq ?? 0) + 1;
  await q.insert(graphReleaseEvents).values({
    orgId: s.orgId,
    projectId: s.projectId,
    eventSeq,
    action: "publish",
    fromReleaseId: current?.release.id ?? null,
    toReleaseId: release.id,
    actor: s.userId,
  });

  const changes = await diffItems(q, s.projectId, (current?.release.items as ReleaseItem[] | undefined) ?? [], items);
  return { release, eventSeq, changes };
}

/**
 * Make an earlier release live again: one more event, and the working copy is
 * put back to that release, so the page shows it with no draft. Releases are
 * never deleted, so the newer one can be made live again. Unpublished edits are
 * dropped (the UI lists them first). Run in a transaction.
 */
export async function rollback(q: Q, s: Scope, toSeq: number, reason: string) {
  await lockProject(q, s.projectId);
  const current = await currentRelease(q, s.projectId);
  if (!current) throw new HttpError(409, "Nothing has been published yet");
  const target = await getRelease(q, s.projectId, toSeq);
  if (target.id === current.release.id) throw new HttpError(409, `Release ${toSeq} is already current`);

  const eventSeq = current.eventSeq + 1;
  await q.insert(graphReleaseEvents).values({
    orgId: s.orgId,
    projectId: s.projectId,
    eventSeq,
    action: "rollback",
    fromReleaseId: current.release.id,
    toReleaseId: target.id,
    reason,
    actor: s.userId,
  });
  await resetWorkingCopy(q, s, target.items as ReleaseItem[], "rollback");
  return { release: target, eventSeq, from: current.release.seq };
}

/** Tell the project's DO a new release is live (a hint — engines also catch up on reconnect). No-op without BROADCASTER. */
export async function notifyRelease(
  env: Env,
  projectId: string,
  notice: { releaseId: number; seq: number; rootHash: string; eventSeq: number },
): Promise<void> {
  if (!env.BROADCASTER) return;
  try {
    const stub = env.BROADCASTER.get(env.BROADCASTER.idFromName(projectId));
    await stub.fetch(`https://do/graph-release?projectId=${encodeURIComponent(projectId)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ projectId, ...notice }),
    });
  } catch (err) {
    console.warn("[graph] release notice failed:", (err as Error)?.message ?? err);
  }
}
