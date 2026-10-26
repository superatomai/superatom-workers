import type { BroadcastMessage, ClientInfo } from '../types';
import { engineIdOf, graphProjectId, isEngine, json, notifyEngines, sendToEngine, splitParts } from './protocol';
import { currentRelease, recordEngine, releaseItems, releaseMatches } from './store';
import type { GraphContext, GraphHead } from './types';

// ── The live release ─────────────────────────────────────────────────────────
//
//   sa-api → DO   POST /graph-release { releaseId, seq, rootHash, eventSeq }  (publish or rollback)
//   DO → engine   GRAPH_RELEASE       { … }    a hint: engines also catch up on reconnect and a timer
//   engine → DO   GRAPH_HELLO         { engineId, haveRootHash, canSwitch?, wantSnapshot? }
//   DO → engine   GRAPH_NONE | GRAPH_IN_SYNC | GRAPH_SWITCH { head } | GRAPH_SNAPSHOT (in parts)
//   engine → DO   GRAPH_ACK { releaseId, rootHash, … } | GRAPH_NACK { …, error }

/** sa-api says a new release is live; each engine socket gets a GRAPH_RELEASE. */
export async function handleReleaseNotice(ctx: GraphContext, request: Request): Promise<Response> {
	if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

	let notice: any;
	try {
		notice = await request.json();
	} catch {
		return json({ error: 'Invalid JSON body' }, 400);
	}
	const { releaseId, seq, rootHash, eventSeq } = notice ?? {};
	if (![releaseId, seq, eventSeq].every((n) => Number.isInteger(n) && n > 0) || typeof rootHash !== 'string' || !rootHash) {
		return json({ error: 'Expected { releaseId, seq, eventSeq, rootHash }' }, 400);
	}

	const sent = notifyEngines(ctx, 'GRAPH_RELEASE', { releaseId, seq, rootHash, eventSeq });
	console.log(`Broadcaster ${ctx.projectId()}: GRAPH_RELEASE seq=${seq} event=${eventSeq} → ${sent} engine socket(s)`);
	return json({ ok: true, sent });
}

/** GRAPH_HELLO — an engine reports its release; answered with GRAPH_NONE, GRAPH_IN_SYNC, GRAPH_SWITCH or GRAPH_SNAPSHOT parts. */
export async function handleHello(ctx: GraphContext, ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
	if (!isEngine(clientInfo)) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_HELLO is only accepted from an engine connection authenticated with the project API key');
		return;
	}
	const projectId = graphProjectId(ctx, clientInfo);
	const p = msg.payload ?? {};
	const engineId = engineIdOf(p);
	if (!projectId || !engineId) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_HELLO needs a valid project and payload.engineId');
		return;
	}
	const db = ctx.env.DATABASE_URL;
	const send = (type: string, payload: unknown) => sendToEngine(ws, clientInfo.clientId, type, payload);

	try {
		const current = await currentRelease(db, projectId);
		if (!current) {
			await recordEngine(db, projectId, engineId, { status: 'in_sync' });
			send('GRAPH_NONE', { projectId });
			return;
		}
		if (p.haveRootHash === current.rootHash) {
			await recordEngine(db, projectId, engineId, { status: 'in_sync', releaseId: current.releaseId, rootHash: current.rootHash });
			send('GRAPH_IN_SYNC', current);
			return;
		}
		await recordEngine(db, projectId, engineId, { status: 'behind' });
		// An engine that builds releases from its stored history gets only which one to run;
		// the whole release goes to older engines, or when the engine asks for it (wantSnapshot).
		if (p.canSwitch === true && p.wantSnapshot !== true) {
			send('GRAPH_SWITCH', current);
			console.log(`Broadcaster ${projectId}: GRAPH_SWITCH → release ${current.seq} (event ${current.eventSeq})`);
			return;
		}
		await sendSnapshot(db, projectId, current, send);
	} catch (error) {
		console.error(`Broadcaster ${ctx.projectId()}: GRAPH_HELLO failed:`, error);
		ctx.sendError(clientInfo.clientId, 'Could not read the graph release; the engine will retry');
	}
}

/** The whole release, with every item's content, split into parts under the message size limit. */
async function sendSnapshot(db: string, projectId: string, head: GraphHead, send: (type: string, payload: unknown) => void): Promise<void> {
	const items = await releaseItems(db, projectId, head.releaseId);
	const parts = splitParts(items); // an empty release still sends one (empty) part
	parts.forEach((list, part) => send('GRAPH_SNAPSHOT', { ...head, part, totalParts: parts.length, items: list }));
	console.log(`Broadcaster ${projectId}: GRAPH_SNAPSHOT release ${head.seq} (${items.length} items, ${parts.length} part(s))`);
}

/** GRAPH_ACK / GRAPH_NACK — what the engine did with a release, recorded for the platform. */
export async function handleAck(ctx: GraphContext, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
	if (!isEngine(clientInfo)) return;
	const projectId = graphProjectId(ctx, clientInfo);
	const p = msg.payload ?? {};
	const engineId = engineIdOf(p);
	if (!projectId || !engineId) return;
	const db = ctx.env.DATABASE_URL;

	try {
		if (msg.type === 'GRAPH_NACK') {
			await recordEngine(db, projectId, engineId, { status: 'error', error: String(p.error ?? 'unknown error').slice(0, 2000) });
			console.warn(`Broadcaster ${projectId}: engine ${engineId} refused release ${p.seq}: ${p.error}`);
			return;
		}
		// Only record a release that really is this project's, with that content.
		if (!Number.isInteger(p.releaseId) || typeof p.rootHash !== 'string') return;
		if (!(await releaseMatches(db, projectId, p.releaseId, p.rootHash))) return;
		const current = await currentRelease(db, projectId);
		await recordEngine(db, projectId, engineId, {
			status: current && current.rootHash === p.rootHash ? 'in_sync' : 'behind',
			releaseId: p.releaseId,
			rootHash: p.rootHash,
			acked: true,
		});
	} catch (error) {
		console.error(`Broadcaster ${ctx.projectId()}: ${msg.type} could not be recorded:`, error);
	}
}
