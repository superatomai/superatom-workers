import type { BroadcastMessage, ClientInfo } from '../types';
import { handleChangesNotice, handleDraftAck, handleDraftPull } from './draft';
import { handleHistoryPull } from './history';
import { handleAck, handleHello, handleProgramsNotice, handleReleaseNotice } from './replication';
import type { GraphContext, GraphVersion } from './types';
import { GraphVersions } from './versions';

export type { GraphContext, GraphVersion } from './types';

/**
 * The knowledge graph's part of the project relay: keeping engines' copies of
 * the platform's graph up to date (the live release, the draft, the release
 * history) and each admin's choice of which one their chats use.
 *
 * The Durable Object owns the sockets and hands over every graph message and
 * request; nothing here is relayed to other clients.
 */
export class KnowledgeGraph {
	private versions: GraphVersions;

	constructor(private ctx: GraphContext) {
		this.versions = new GraphVersions(ctx);
	}

	/** sa-api's notices, by path. Reached only via sa-api's DO binding; the worker refuses these paths from outside. */
	handleRequest(pathname: string, request: Request): Promise<Response> | null {
		if (pathname === '/graph-release') return handleReleaseNotice(this.ctx, request);
		if (pathname === '/graph-changes') return handleChangesNotice(this.ctx, request);
		if (pathname === '/programs-changed') return handleProgramsNotice(this.ctx, request);
		return null;
	}

	/** Handles a graph message; false when the message isn't one (the DO relays it as usual). */
	async handleMessage(ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<boolean> {
		switch (msg.type) {
			case 'GRAPH_HELLO':
				await handleHello(this.ctx, ws, clientInfo, msg);
				return true;
			case 'GRAPH_ACK':
			case 'GRAPH_NACK':
				await handleAck(this.ctx, clientInfo, msg);
				return true;
			case 'GRAPH_DRAFT_PULL':
				await handleDraftPull(this.ctx, ws, clientInfo, msg);
				return true;
			case 'GRAPH_DRAFT_ACK':
				await handleDraftAck(this.ctx, clientInfo, msg);
				return true;
			case 'GRAPH_HISTORY_PULL':
				await handleHistoryPull(this.ctx, ws, clientInfo, msg);
				return true;
			case 'GRAPH_USE_VERSION':
				await this.versions.handleUseVersion(ws, clientInfo, msg);
				return true;
			case 'GRAPH_VERSIONS_REQ':
				await this.versions.handleVersionsReq(ws, clientInfo, msg);
				return true;
			default:
				return false;
		}
	}

	/** The graph a user's questions use, stamped on their messages; undefined means the live release. */
	versionFor(userId: string): Promise<GraphVersion | undefined> {
		return this.versions.versionFor(userId);
	}
}
