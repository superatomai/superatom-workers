import { Hono } from "hono";
import { and, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { concepts, graphChangeRequests, graphChanges, graphEdges, graphEngineState, graphNodes, graphReleaseEvents, graphReleases, users } from "../db/schema";
import { withTransaction, type Tx } from "../db/tx";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly } from "../middleware/auth";
import { assertProjectAccess, type AppContext } from "../lib/project-access";
import { HttpError } from "../lib/graph/errors";
import {
  canEditDirectly,
  conceptFieldsOf,
  deleteConcept,
  deleteNode,
  getConcept,
  getNode,
  loadNodeProposal,
  loadWorkingCopy,
  lockProject,
  logChange,
  ownerNames,
  sortedEdges,
  writeConcept,
  writeNode,
  type Scope,
} from "../lib/graph/store";
import { parseConceptInput, parseEditVersion, parseId, parseNodeInput } from "../lib/graph/validate";
import {
  createRequest,
  currentTarget,
  flattenProposal,
  getRequest,
  mergeRequest,
  rejectRequest,
  updateOwnRequest,
} from "../lib/graph/requests";
import { currentRelease, diffItems, discardDraft, getRelease, notifyRelease, pendingChanges, publish, releaseContent, rollback, type ReleaseItem } from "../lib/graph/release";
import { importGraph, type ImportMode } from "../lib/graph/import";

/** Composition graph routes (/projects/:projectId/graph), org admins only; engines see edits only after a publish. */

const graphRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();
graphRouter.use("*", authMiddleware, adminOnly);

/** Resolves the project, builds the caller's scope, and turns HttpError into a JSON response. */
function handler(fn: (c: AppContext, s: Scope) => Promise<Response>) {
  return async (c: AppContext) => {
    try {
      const projectId = c.req.param("projectId") ?? "";
      const access = await assertProjectAccess(c, projectId);
      if (!access.ok) return c.json({ error: access.error }, access.status);
      return await fn(c, { projectId, orgId: access.orgId, userId: c.get("userId"), role: c.get("userRole") });
    } catch (err) {
      if (err instanceof HttpError) return c.json({ error: err.message, ...(err.details ?? {}) }, err.status);
      throw err;
    }
  };
}

async function readBody(c: AppContext): Promise<Record<string, unknown>> {
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "Invalid JSON body");
  return body as Record<string, unknown>;
}

function tx<T>(c: AppContext, fn: (q: Tx) => Promise<T>, isolationLevel?: "repeatable read" | "serializable") {
  return withTransaction(c.env.DATABASE_URL, fn, isolationLevel ? { isolationLevel } : undefined);
}

/** Runs after the response; engines catch up on their own if it fails. */
function notifyLater(c: AppContext, projectId: string, notice: Parameters<typeof notifyRelease>[2]) {
  const task = notifyRelease(c.env, projectId, notice);
  try {
    c.executionCtx.waitUntil(task);
  } catch {
    void task; // no execution context (tests): let it run unawaited
  }
}

const withOwner = <T extends { ownerId: string | null }>(row: T, owners: Map<string, { name: string; email: string }>) => ({
  ...row,
  owner: row.ownerId ? { id: row.ownerId, ...(owners.get(row.ownerId) ?? { name: null, email: null }) } : null,
});

/** The new owner must be an active org admin of the project's org. */
async function assertAdminOfOrg(c: AppContext, s: Scope, userId: unknown): Promise<string> {
  if (typeof userId !== "string" || !/^[0-9a-f-]{36}$/i.test(userId)) throw new HttpError(400, "ownerId must be a user id");
  const [u] = await c
    .get("db")
    .select({ orgId: users.orgId, role: users.role, isActive: users.isActive })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  if (!u || !u.isActive || u.orgId !== s.orgId || u.role !== "org_admin") {
    throw new HttpError(400, "The new owner must be an active org admin of this organization");
  }
  return userId;
}

// ═══ Overview ══════════════════════════════════════════

/** GET / — the whole working copy, the current release and the open request count. */
graphRouter.get(
  "/",
  handler(async (c, s) => {
    const db = c.get("db");
    const [wc, current, [open]] = await Promise.all([
      loadWorkingCopy(db, s.projectId),
      currentRelease(db, s.projectId),
      db
        .select({ count: sql<number>`count(*)::int` })
        .from(graphChangeRequests)
        .where(and(eq(graphChangeRequests.projectId, s.projectId), eq(graphChangeRequests.status, "open"))),
    ]);
    const owners = await ownerNames(db, [...wc.nodes.map((n) => n.ownerId), ...wc.concepts.map((x) => x.ownerId)]);
    return c.json({
      nodes: wc.nodes.map((n) => withOwner(n, owners)),
      concepts: wc.concepts.map((x) => withOwner(x, owners)),
      edges: sortedEdges(wc.edges),
      terms: wc.terms,
      currentRelease: current
        ? { id: current.release.id, seq: current.release.seq, rootHash: current.release.rootHash, createdAt: current.release.createdAt, eventSeq: current.eventSeq }
        : null,
      openChangeRequests: open?.count ?? 0,
    });
  }),
);

// ═══ Nodes ═════════════════════════════════════════════

/** GET /nodes?kind=domain */
graphRouter.get(
  "/nodes",
  handler(async (c, s) => {
    const db = c.get("db");
    const kind = c.req.query("kind");
    const rows = await db
      .select()
      .from(graphNodes)
      .where(and(eq(graphNodes.projectId, s.projectId), isNull(graphNodes.deletedAt), kind ? eq(graphNodes.kind, kind) : undefined))
      .orderBy(graphNodes.kind, graphNodes.name);
    const owners = await ownerNames(db, rows.map((r) => r.ownerId));
    return c.json(rows.map((r) => withOwner(r, owners)));
  }),
);

/** GET /nodes/:id — with its edges, terms and open change requests. */
graphRouter.get(
  "/nodes/:id",
  handler(async (c, s) => {
    const db = c.get("db");
    const node = await getNode(db, s.projectId, parseId(c.req.param("id"), "node"));
    if (!node) throw new HttpError(404, "Node not found");
    const [proposal, requests, owners] = await Promise.all([
      loadNodeProposal(db, node),
      db
        .select()
        .from(graphChangeRequests)
        .where(and(eq(graphChangeRequests.entity, "node"), eq(graphChangeRequests.entityId, node.id), eq(graphChangeRequests.status, "open"))),
      ownerNames(db, [node.ownerId]),
    ]);
    return c.json({ ...withOwner(node, owners), edges: proposal.edges, terms: proposal.terms, openChangeRequests: requests });
  }),
);

/** POST /nodes — { kind, name, title?, body, meta?, status?, edges?, terms? }. The creator owns it. */
graphRouter.post(
  "/nodes",
  handler(async (c, s) => {
    const p = parseNodeInput(await readBody(c));
    const node = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      return writeNode(q, s, null, p);
    });
    return c.json({ ...node, edges: p.edges, terms: p.terms }, 201);
  }),
);

/** PUT /nodes/:id — { editVersion, …fields, edges?, terms? }. Owner: applied (200); others: change request (202). */
graphRouter.put(
  "/nodes/:id",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "node");
    const body = await readBody(c);
    const editVersion = parseEditVersion(body.editVersion);
    const result = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      const node = await getNode(q, s.projectId, id);
      if (!node) throw new HttpError(404, "Node not found");
      const p = parseNodeInput(body, await loadNodeProposal(q, node));
      if (canEditDirectly(node, s)) {
        return { node: await writeNode(q, s, node, p, { expectedEditVersion: editVersion }) };
      }
      const request = await createRequest(q, s, {
        entity: "node",
        entityId: node.id,
        action: "update",
        baseEditVersion: editVersion,
        proposed: flattenProposal(p),
      });
      return { changeRequest: request };
    });
    return "node" in result ? c.json(result.node) : c.json({ changeRequest: result.changeRequest }, 202);
  }),
);

/** DELETE /nodes/:id?editVersion=N — the owner deletes (soft); anyone else requests it. */
graphRouter.delete(
  "/nodes/:id",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "node");
    const editVersion = parseEditVersion(c.req.query("editVersion"));
    const result = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      const node = await getNode(q, s.projectId, id);
      if (!node) throw new HttpError(404, "Node not found");
      if (canEditDirectly(node, s)) {
        await deleteNode(q, s, node, editVersion);
        return { deleted: true as const };
      }
      return {
        changeRequest: await createRequest(q, s, { entity: "node", entityId: id, action: "delete", baseEditVersion: editVersion, proposed: {} }),
      };
    });
    return "deleted" in result ? c.json({ message: "Node deleted" }) : c.json({ changeRequest: result.changeRequest }, 202);
  }),
);

/** PUT /nodes/:id/owner — { ownerId }: the owner hands the node to another org admin. */
graphRouter.put(
  "/nodes/:id/owner",
  handler(async (c, s) => {
    const db = c.get("db");
    const node = await getNode(db, s.projectId, parseId(c.req.param("id"), "node"));
    if (!node) throw new HttpError(404, "Node not found");
    if (!canEditDirectly(node, s)) throw new HttpError(403, "Only the owner can hand this node over");
    const ownerId = await assertAdminOfOrg(c, s, (await readBody(c)).ownerId);
    const row = await tx(c, async (q) => {
      const [updated] = await q
        .update(graphNodes)
        .set({ ownerId, updatedBy: s.userId, updatedAt: new Date() })
        .where(eq(graphNodes.id, node.id))
        .returning();
      await logChange(q, s, { entity: "node", entityId: node.id, action: "owner", before: { ownerId: node.ownerId }, after: { ownerId } });
      return updated;
    });
    return c.json(row);
  }),
);

// ═══ Concepts ══════════════════════════════════════════

/** GET /concepts?kind=&type= */
graphRouter.get(
  "/concepts",
  handler(async (c, s) => {
    const db = c.get("db");
    const kind = c.req.query("kind");
    const type = c.req.query("type");
    const rows = await db
      .select()
      .from(concepts)
      .where(
        and(
          eq(concepts.projectId, s.projectId),
          isNull(concepts.deletedAt),
          kind ? eq(concepts.kind, kind) : undefined,
          type === "global" || type === "user" || type === "group" ? eq(concepts.type, type) : undefined,
        ),
      )
      .orderBy(concepts.name);
    const owners = await ownerNames(db, rows.map((r) => r.ownerId));
    return c.json(rows.map((r) => withOwner(r, owners)));
  }),
);

/** GET /concepts/:id — with the nodes that use it and its open change requests. */
graphRouter.get(
  "/concepts/:id",
  handler(async (c, s) => {
    const db = c.get("db");
    const concept = await getConcept(db, s.projectId, parseId(c.req.param("id"), "concept"));
    if (!concept) throw new HttpError(404, "Concept not found");
    const [usedBy, requests, owners] = await Promise.all([
      db
        .select({ id: graphNodes.id, kind: graphNodes.kind, name: graphNodes.name, title: graphNodes.title, role: graphEdges.role, position: graphEdges.position })
        .from(graphEdges)
        .innerJoin(graphNodes, eq(graphNodes.id, graphEdges.parentId))
        .where(and(eq(graphEdges.childConceptId, concept.id), isNull(graphNodes.deletedAt))),
      db
        .select()
        .from(graphChangeRequests)
        .where(and(eq(graphChangeRequests.entity, "concept"), eq(graphChangeRequests.entityId, concept.id), eq(graphChangeRequests.status, "open"))),
      ownerNames(db, [concept.ownerId]),
    ]);
    return c.json({ ...withOwner(concept, owners), usedBy, openChangeRequests: requests });
  }),
);

/** POST /concepts — { name, body, kind?, type?, requires?, returns?, aliases?, description?, sourceId?, originRef? } */
graphRouter.post(
  "/concepts",
  handler(async (c, s) => {
    const fields = parseConceptInput(await readBody(c));
    const concept = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      return writeConcept(q, s, null, fields);
    });
    return c.json(concept, 201);
  }),
);

/** PUT /concepts/:id — { editVersion, …fields }. Owner: applied (200); others: change request (202). */
graphRouter.put(
  "/concepts/:id",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "concept");
    const body = await readBody(c);
    const editVersion = parseEditVersion(body.editVersion);
    const result = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      const concept = await getConcept(q, s.projectId, id);
      if (!concept) throw new HttpError(404, "Concept not found");
      const fields = parseConceptInput(body, conceptFieldsOf(concept));
      if (canEditDirectly(concept, s)) {
        return { concept: await writeConcept(q, s, concept, fields, { expectedEditVersion: editVersion }) };
      }
      return {
        changeRequest: await createRequest(q, s, {
          entity: "concept",
          entityId: id,
          action: "update",
          baseEditVersion: editVersion,
          proposed: fields as unknown as Record<string, unknown>,
        }),
      };
    });
    return "concept" in result ? c.json(result.concept) : c.json({ changeRequest: result.changeRequest }, 202);
  }),
);

/** DELETE /concepts/:id?editVersion=N */
graphRouter.delete(
  "/concepts/:id",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "concept");
    const editVersion = parseEditVersion(c.req.query("editVersion"));
    const result = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      const concept = await getConcept(q, s.projectId, id);
      if (!concept) throw new HttpError(404, "Concept not found");
      if (canEditDirectly(concept, s)) {
        await deleteConcept(q, s, concept, editVersion);
        return { deleted: true as const };
      }
      return {
        changeRequest: await createRequest(q, s, { entity: "concept", entityId: id, action: "delete", baseEditVersion: editVersion, proposed: {} }),
      };
    });
    return "deleted" in result ? c.json({ message: "Concept deleted" }) : c.json({ changeRequest: result.changeRequest }, 202);
  }),
);

/** PUT /concepts/:id/owner — { ownerId } */
graphRouter.put(
  "/concepts/:id/owner",
  handler(async (c, s) => {
    const db = c.get("db");
    const concept = await getConcept(db, s.projectId, parseId(c.req.param("id"), "concept"));
    if (!concept) throw new HttpError(404, "Concept not found");
    if (!canEditDirectly(concept, s)) throw new HttpError(403, "Only the owner can hand this concept over");
    const ownerId = await assertAdminOfOrg(c, s, (await readBody(c)).ownerId);
    const row = await tx(c, async (q) => {
      const [updated] = await q
        .update(concepts)
        .set({ ownerId, updatedBy: s.userId, updatedAt: new Date() })
        .where(eq(concepts.id, concept.id))
        .returning();
      await logChange(q, s, { entity: "concept", entityId: concept.id, action: "owner", before: { ownerId: concept.ownerId }, after: { ownerId } });
      return updated;
    });
    return c.json(row);
  }),
);

// ═══ Change requests ═══════════════════════════════════

/** GET /change-requests?status=open|merged|rejected|withdrawn|all (default open) */
graphRouter.get(
  "/change-requests",
  handler(async (c, s) => {
    const db = c.get("db");
    const status = c.req.query("status") ?? "open";
    const rows = await db
      .select()
      .from(graphChangeRequests)
      .where(and(eq(graphChangeRequests.projectId, s.projectId), status === "all" ? undefined : eq(graphChangeRequests.status, status)))
      .orderBy(desc(graphChangeRequests.createdAt))
      .limit(200);
    const people = await ownerNames(db, rows.flatMap((r) => [r.authorId, r.reviewedBy]));
    return c.json(
      rows.map((r) => ({
        ...r,
        author: r.authorId ? { id: r.authorId, ...(people.get(r.authorId) ?? {}) } : null,
        reviewer: r.reviewedBy ? { id: r.reviewedBy, ...(people.get(r.reviewedBy) ?? {}) } : null,
      })),
    );
  }),
);

/** GET /change-requests/:id — the request and the item as it is now, for a side-by-side diff. */
graphRouter.get(
  "/change-requests/:id",
  handler(async (c, s) => {
    const db = c.get("db");
    const request = await getRequest(db, s.projectId, parseId(c.req.param("id"), "change request"));
    const target = await currentTarget(db, s, request);
    // A merged request: what the merge actually changed (before → after), from the history.
    const [merged] =
      request.status === "merged"
        ? await db
            .select({ before: graphChanges.before, after: graphChanges.after, changedAt: graphChanges.changedAt })
            .from(graphChanges)
            .where(and(eq(graphChanges.projectId, s.projectId), eq(graphChanges.changeRequestId, request.id)))
            .limit(1)
        : [];
    return c.json({
      ...request,
      current: target?.content ?? null,
      currentEditVersion: target?.row.editVersion ?? null,
      conflict: !!target && request.baseEditVersion !== null && target.row.editVersion !== request.baseEditVersion,
      merged: merged ?? null,
    });
  }),
);

/** PUT /change-requests/:id — { proposed }: the author revises an open request. */
graphRouter.put(
  "/change-requests/:id",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "change request");
    const body = await readBody(c);
    if (!body.proposed || typeof body.proposed !== "object") throw new HttpError(400, "proposed is required");
    const row = await tx(c, (q) => updateOwnRequest(q, s, id, { proposed: body.proposed as Record<string, unknown> }));
    return c.json(row);
  }),
);

/** POST /change-requests/:id/withdraw — the author takes it back. */
graphRouter.post(
  "/change-requests/:id/withdraw",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "change request");
    return c.json(await tx(c, (q) => updateOwnRequest(q, s, id, { withdraw: true })));
  }),
);

/** POST /change-requests/:id/merge — { force?, comment? }. 409 with both versions if the item changed meanwhile. */
graphRouter.post(
  "/change-requests/:id/merge",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "change request");
    const body = await c.req.json().catch(() => ({}) as Record<string, unknown>);
    const force = (body as { force?: unknown }).force === true;
    const comment = typeof (body as { comment?: unknown }).comment === "string" ? ((body as { comment: string }).comment.trim() || null) : null;
    const result = await tx(c, async (q) => {
      await lockProject(q, s.projectId);
      return mergeRequest(q, s, id, force, comment);
    });
    return c.json(result);
  }),
);

/** POST /change-requests/:id/reject — { comment } (required). */
graphRouter.post(
  "/change-requests/:id/reject",
  handler(async (c, s) => {
    const id = parseId(c.req.param("id"), "change request");
    const body = await readBody(c);
    const comment = typeof body.comment === "string" ? body.comment.trim() : "";
    if (!comment) throw new HttpError(400, "A comment is required when rejecting");
    return c.json(await tx(c, (q) => rejectRequest(q, s, id, comment)));
  }),
);

// ═══ Releases ══════════════════════════════════════════

/** GET /releases — newest first, without their item lists. */
graphRouter.get(
  "/releases",
  handler(async (c, s) => {
    const db = c.get("db");
    const [rows, current] = await Promise.all([
      db
        .select({
          id: graphReleases.id,
          seq: graphReleases.seq,
          rootHash: graphReleases.rootHash,
          parentReleaseId: graphReleases.parentReleaseId,
          notes: graphReleases.notes,
          createdBy: graphReleases.createdBy,
          createdAt: graphReleases.createdAt,
          itemCount: sql<number>`jsonb_array_length(${graphReleases.items})`,
        })
        .from(graphReleases)
        .where(eq(graphReleases.projectId, s.projectId))
        .orderBy(desc(graphReleases.seq))
        .limit(200),
      currentRelease(db, s.projectId),
    ]);
    const people = await ownerNames(db, rows.map((r) => r.createdBy));
    return c.json({
      currentReleaseId: current?.release.id ?? null,
      releases: rows.map((r) => ({ ...r, isCurrent: r.id === current?.release.id, publisher: r.createdBy ? people.get(r.createdBy) ?? null : null })),
    });
  }),
);

/** GET /releases/current — the release engines should run, or null before the first publish. */
graphRouter.get(
  "/releases/current",
  handler(async (c, s) => {
    const current = await currentRelease(c.get("db"), s.projectId);
    return c.json(current ? { ...current.release, eventSeq: current.eventSeq } : null);
  }),
);

/** GET /releases/:seq — with its item list. */
graphRouter.get(
  "/releases/:seq",
  handler(async (c, s) => c.json(await getRelease(c.get("db"), s.projectId, parseId(c.req.param("seq"), "release")))),
);

/** GET /releases/:seq/content — every item's full content, as frozen in that release. */
graphRouter.get(
  "/releases/:seq/content",
  handler(async (c, s) => {
    const db = c.get("db");
    const release = await getRelease(db, s.projectId, parseId(c.req.param("seq"), "release"));
    return c.json({ ...release, content: await releaseContent(db, s.projectId, release.items as ReleaseItem[]) });
  }),
);

/** GET /releases/:seq/diff?from=<seq> — what changed since `from` (default: the release it was built on). */
graphRouter.get(
  "/releases/:seq/diff",
  handler(async (c, s) => {
    const db = c.get("db");
    const to = await getRelease(db, s.projectId, parseId(c.req.param("seq"), "release"));
    const fromParam = c.req.query("from");
    let fromItems: ReleaseItem[] = [];
    let fromSeq: number | null = null;
    if (fromParam) {
      const from = await getRelease(db, s.projectId, parseId(fromParam, "release"));
      fromItems = from.items as ReleaseItem[];
      fromSeq = from.seq;
    } else if (to.parentReleaseId !== null) {
      const [parent] = await db.select().from(graphReleases).where(eq(graphReleases.id, to.parentReleaseId)).limit(1);
      fromItems = (parent?.items as ReleaseItem[] | undefined) ?? [];
      fromSeq = parent?.seq ?? null;
    }
    return c.json({ from: fromSeq, to: to.seq, ...(await diffItems(db, s.projectId, fromItems, to.items as ReleaseItem[])) });
  }),
);

/** GET /events — publish / rollback history, newest first. */
graphRouter.get(
  "/events",
  handler(async (c, s) => {
    const db = c.get("db");
    const rows = await db
      .select()
      .from(graphReleaseEvents)
      .where(eq(graphReleaseEvents.projectId, s.projectId))
      .orderBy(desc(graphReleaseEvents.eventSeq))
      .limit(200);
    const people = await ownerNames(db, rows.map((r) => r.actor));
    return c.json(rows.map((r) => ({ ...r, actorName: r.actor ? people.get(r.actor)?.name ?? null : null })));
  }),
);

/** GET /history?entity=node|concept&entityId=N — edit history, newest first (whole project if no item). */
graphRouter.get(
  "/history",
  handler(async (c, s) => {
    const db = c.get("db");
    const entity = c.req.query("entity");
    const entityId = c.req.query("entityId");
    if (entity !== undefined && entity !== "node" && entity !== "concept") throw new HttpError(400, "entity must be node or concept");
    const rows = await db
      .select()
      .from(graphChanges)
      .where(
        and(
          eq(graphChanges.projectId, s.projectId),
          entity ? eq(graphChanges.entity, entity) : undefined,
          entity && entityId !== undefined ? eq(graphChanges.entityId, parseId(entityId, entity)) : undefined,
        ),
      )
      .orderBy(desc(graphChanges.changedAt), desc(graphChanges.id))
      .limit(200);
    // Merged changes also name the request's author.
    const requestIds = [...new Set(rows.flatMap((r) => (r.changeRequestId !== null ? [r.changeRequestId] : [])))];
    const requests = requestIds.length
      ? await db
          .select({ id: graphChangeRequests.id, authorId: graphChangeRequests.authorId })
          .from(graphChangeRequests)
          .where(inArray(graphChangeRequests.id, requestIds))
      : [];
    const authorOf = new Map(requests.map((r) => [r.id, r.authorId]));
    const people = await ownerNames(db, [
      ...rows.map((r) => r.changedBy),
      ...requests.map((r) => r.authorId),
      // Owner hand-overs name both admins.
      ...rows.flatMap((r) => (r.action === "owner" ? [(r.before as { ownerId?: string })?.ownerId ?? null, (r.after as { ownerId?: string })?.ownerId ?? null] : [])),
    ]);
    const person = (id: string | null | undefined) => (id ? { id, name: people.get(id)?.name ?? null } : null);
    return c.json(
      rows.map((r) => ({
        ...r,
        changedByUser: person(r.changedBy),
        requestAuthor: r.changeRequestId !== null ? person(authorOf.get(r.changeRequestId)) : null,
        ...(r.action === "owner"
          ? { fromOwner: person((r.before as { ownerId?: string })?.ownerId), toOwner: person((r.after as { ownerId?: string })?.ownerId) }
          : {}),
      })),
    );
  }),
);

/** GET /publish/preview — what publishing now would change; 409 if the graph can't be published. */
graphRouter.get(
  "/publish/preview",
  handler(async (c, s) => c.json(await pendingChanges(c.get("db"), s))),
);

/** POST /discard — put the working copy back to the live release (any admin). Nothing is published. */
graphRouter.post(
  "/discard",
  handler(async (c, s) => c.json(await tx(c, (q) => discardDraft(q, s)))),
);

/** POST /publish — { notes? }: freeze the working copy as the next release and make it current. */
graphRouter.post(
  "/publish",
  handler(async (c, s) => {
    const body = await c.req.json().catch(() => ({}) as Record<string, unknown>);
    const notes = typeof (body as { notes?: unknown }).notes === "string" ? ((body as { notes: string }).notes.trim() || null) : null;
    const result = await tx(c, (q) => publish(q, s, notes), "repeatable read");
    notifyLater(c, s.projectId, { releaseId: result.release.id, seq: result.release.seq, rootHash: result.release.rootHash, eventSeq: result.eventSeq });
    return c.json(result, 201);
  }),
);

/** POST /rollback — { toSeq, reason }: make an earlier release current again. */
graphRouter.post(
  "/rollback",
  handler(async (c, s) => {
    const body = await readBody(c);
    const toSeq = parseId(String(body.toSeq ?? ""), "release");
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (!reason) throw new HttpError(400, "A reason is required to roll back");
    const result = await tx(c, (q) => rollback(q, s, toSeq, reason));
    notifyLater(c, s.projectId, { releaseId: result.release.id, seq: result.release.seq, rootHash: result.release.rootHash, eventSeq: result.eventSeq });
    return c.json(result);
  }),
);

// ═══ Engines ═══════════════════════════════════════════

/** GET /engines — which release each engine runs, from its acks. */
graphRouter.get(
  "/engines",
  handler(async (c, s) => {
    const db = c.get("db");
    const [rows, current] = await Promise.all([
      db.select().from(graphEngineState).where(eq(graphEngineState.projectId, s.projectId)),
      currentRelease(db, s.projectId),
    ]);
    return c.json({ currentReleaseId: current?.release.id ?? null, engines: rows });
  }),
);

// ═══ Import ════════════════════════════════════════════

/** Thrown to roll back a dry run while keeping its result. */
class DryRun extends Error {
  constructor(public result: unknown) {
    super("dry run");
  }
}

/** POST /import — { data, mode?: "merge" | "replace", dryRun? }: the platform's export file into the working copy. */
graphRouter.post(
  "/import",
  handler(async (c, s) => {
    const body = await readBody(c);
    const mode: ImportMode = body.mode === "replace" ? "replace" : "merge";
    const dryRun = body.dryRun === true;
    let result: unknown;
    try {
      result = await tx(c, async (q) => {
        const r = await importGraph(q, s, body.data, mode);
        if (dryRun) throw new DryRun(r);
        return r;
      });
    } catch (err) {
      if (!(err instanceof DryRun)) throw err;
      result = err.result;
    }
    return c.json({ dryRun, ...(result as object) });
  }),
);

export default graphRouter;
