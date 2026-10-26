import type { BroadcastMessage, ClientInfo } from '../types';
import { engineIdOf, graphProjectId, isEngine, sendToEngine, splitParts } from './protocol';
import { releasesAfter, revisionsAfter } from './store';
import type { GraphContext } from './types';

// ── Release history (every published version) ────────────────────────────────
//
// Releases and revisions never change once written, so an engine that holds
// every release up to seq N only needs the releases after N and the revisions
// they use that no release up to N used.
//
//   engine → DO   GRAPH_HISTORY_PULL     { engineId, haveReleaseSeq }
//   DO → engine   GRAPH_HISTORY_IN_SYNC { headReleaseSeq } | GRAPH_HISTORY (in parts)

/** GRAPH_HISTORY_PULL — an engine asks for the releases after the last one it stored. */
export async function handleHistoryPull(ctx: GraphContext, ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
	if (!isEngine(clientInfo)) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_HISTORY_PULL is only accepted from an engine connection authenticated with the project API key');
		return;
	}
	const projectId = graphProjectId(ctx, clientInfo);
	const p = msg.payload ?? {};
	const engineId = engineIdOf(p);
	if (!projectId || !engineId) {
		ctx.sendError(clientInfo.clientId, 'GRAPH_HISTORY_PULL needs a valid project and payload.engineId');
		return;
	}
	const have = Number.isInteger(p.haveReleaseSeq) && p.haveReleaseSeq > 0 ? (p.haveReleaseSeq as number) : 0;
	const db = ctx.env.DATABASE_URL;
	const send = (type: string, payload: unknown) => sendToEngine(ws, clientInfo.clientId, type, payload);

	try {
		const releases = await releasesAfter(db, projectId, have);
		if (!releases.length) {
			send('GRAPH_HISTORY_IN_SYNC', { projectId, headReleaseSeq: have });
			return;
		}
		const revisions = await revisionsAfter(db, projectId, have);
		const headReleaseSeq = releases[releases.length - 1].seq;
		// Revisions first: a release names revisions, so they are stored before it.
		const parts = splitParts([...revisions, ...releases]);
		parts.forEach((list, part) =>
			send('GRAPH_HISTORY', { projectId, fromReleaseSeq: have, headReleaseSeq, part, totalParts: parts.length, records: list }),
		);
		console.log(`Broadcaster ${projectId}: GRAPH_HISTORY after ${have} → ${headReleaseSeq} (${releases.length} release(s), ${revisions.length} revision(s), ${parts.length} part(s))`);
	} catch (error) {
		console.error(`Broadcaster ${ctx.projectId()}: GRAPH_HISTORY_PULL failed:`, error);
		ctx.sendError(clientInfo.clientId, 'Could not read the graph releases; the engine will retry');
	}
}
