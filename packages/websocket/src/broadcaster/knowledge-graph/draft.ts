import type { BroadcastMessage, ClientInfo } from '../types';
import { engineIdOf, graphProjectId, isEngine, json, notifyEngines, sendToEngine, splitParts, UUID_RE } from './protocol';
import { draftHead, draftItems, recordDraftAck } from './store';
import type { GraphContext } from './types';

// ── The draft (the platform's working copy) ──────────────────────────────────
//
// Every edit on the platform takes the next graph_changes.seq for the project.
// An engine keeps the seq it has; on GRAPH_DRAFT_PULL it gets every item
// changed after that seq, as the item is now (or deleted), up to the head.
// With no seq yet, or one ahead of the platform's, it gets the whole draft.
// The engine stores the draft apart from the release it answers from.
//
//   sa-api → DO   POST /graph-changes    after a successful edit
//   DO → engine   GRAPH_CHANGED          { headSeq }  a hint: engines also pull on a timer
//   engine → DO   GRAPH_DRAFT_PULL       { engineId, haveChangeSeq }
//   DO → engine   GRAPH_DRAFT_NONE | GRAPH_DRAFT_IN_SYNC { headSeq } | GRAPH_DRAFT (in parts)
//   engine → DO   GRAPH_DRAFT_ACK        { engineId, changeSeq }

/** sa-api says the working copy changed; each engine socket gets a GRAPH_CHANGED. */
export async function handleChangesNotice(ctx: GraphContext, request: Request): Promise<Response> {
	if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
	const projectId = ctx.projectId();
	if (!UUID_RE.test(projectId)) return json({ error: 'Invalid project' }, 400);

	const headSeq = await draftHead(ctx.env.DATABASE_URL, projectId);
	if (headSeq === null) return json({ ok: true, sent: 0 });

	const sent = notifyEngines(ctx, 'GRAPH_CHANGED', { headSeq });
	return json({ ok: true, sent });
}

/** GRAPH_DRAFT_PULL — an engine asks for the draft changes after the seq it has. */
export async function handleDraftPull(ctx: GraphContext, ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
	if (!isEngine(clientInfo)) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_DRAFT_PULL is only accepted from an engine connection authenticated with the project API key');
		return;
	}
	const projectId = graphProjectId(ctx, clientInfo);
	const p = msg.payload ?? {};
	const engineId = engineIdOf(p);
	if (!projectId || !engineId) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_DRAFT_PULL needs a valid project and payload.engineId');
		return;
	}
	const have = Number.isInteger(p.haveChangeSeq) && p.haveChangeSeq >= 0 ? (p.haveChangeSeq as number) : null;
	const db = ctx.env.DATABASE_URL;
	const send = (type: string, payload: unknown) => sendToEngine(ws, clientInfo.clientId, type, payload);

	try {
		// Read the head first: items read after it are at least that new.
		const headSeq = await draftHead(db, projectId);
		if (headSeq === null) {
			send('GRAPH_DRAFT_NONE', { projectId });
			return;
		}
		if (have === headSeq) {
			send('GRAPH_DRAFT_IN_SYNC', { projectId, headSeq });
			return;
		}
		// No seq yet, or ahead of the platform (its graph was reset): the whole draft.
		const full = have === null || have > headSeq;
		const items = await draftItems(db, projectId, full ? null : have, headSeq);
		const parts = splitParts(items);
		parts.forEach((list, part) =>
			send('GRAPH_DRAFT', { projectId, fromSeq: full ? null : have, headSeq, full, part, totalParts: parts.length, items: list }),
		);
		console.log(`Broadcaster ${projectId}: GRAPH_DRAFT ${full ? 'full' : `after ${have}`} → ${headSeq} (${items.length} items, ${parts.length} part(s))`);
	} catch (error) {
		console.error(`Broadcaster ${ctx.projectId()}: GRAPH_DRAFT_PULL failed:`, error);
		ctx.sendError(clientInfo.clientId, 'Could not read the graph draft; the engine will retry');
	}
}

/** GRAPH_DRAFT_ACK — the change seq an engine's draft is at, recorded for the platform. */
export async function handleDraftAck(ctx: GraphContext, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
	if (!isEngine(clientInfo)) return;
	const projectId = graphProjectId(ctx, clientInfo);
	const p = msg.payload ?? {};
	const engineId = engineIdOf(p);
	if (!projectId || !engineId || !Number.isInteger(p.changeSeq) || p.changeSeq < 0) return;
	try {
		await recordDraftAck(ctx.env.DATABASE_URL, projectId, engineId, p.changeSeq);
	} catch (error) {
		console.error(`Broadcaster ${ctx.projectId()}: GRAPH_DRAFT_ACK could not be recorded:`, error);
	}
}
