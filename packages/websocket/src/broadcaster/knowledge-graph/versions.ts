import type { BroadcastMessage, ClientInfo } from '../types';
import { graphProjectId, replyTo } from './protocol';
import { releaseSeqExists } from './store';
import type { GraphContext, GraphVersion, GraphVersionsMap } from './types';

// ── Graph version per user ───────────────────────────────────────────────────
//
// Which graph each admin's new chats answer from, kept in this DO's storage
// under one key: { userId: "draft" | <release seq> }. Not listed = live.
//
//   admin → DO   GRAPH_USE_VERSION  { version: "live" | "draft" | <release seq> }
//                → GRAPH_USE_VERSION_RES { userId, version }; always the sender's own choice
//   any   → DO   GRAPH_VERSIONS_REQ → GRAPH_VERSIONS_RES { versions } (an admin: every user; others: their own)

const STORAGE_KEY = 'graphVersions';
const ADMIN_ROLES = new Set(['org_admin', 'super_admin']);

function isGraphAdmin(clientInfo: ClientInfo): boolean {
	return clientInfo.authenticated === true && !!clientInfo.userId && ADMIN_ROLES.has(clientInfo.role ?? '');
}

export class GraphVersions {
	/** Read on every relayed user message, so kept in memory; storage is the record (lost memory just reloads). */
	private cache: GraphVersionsMap | null = null;

	constructor(private ctx: GraphContext) {}

	private async load(): Promise<GraphVersionsMap> {
		if (!this.cache) this.cache = (await this.ctx.storage.get<GraphVersionsMap>(STORAGE_KEY)) || {};
		return this.cache;
	}

	private async save(map: GraphVersionsMap): Promise<void> {
		await this.ctx.storage.put(STORAGE_KEY, map);
		this.cache = map;
	}

	/** The graph a user's questions use; undefined means the live release. */
	async versionFor(userId: string): Promise<GraphVersion | undefined> {
		return (await this.load())[userId];
	}

	/**
	 * GRAPH_USE_VERSION — an admin sets which graph THEIR OWN new chats answer from;
	 * "live" removes the choice. Always the sender's verified id: a payload userId is
	 * ignored, so no one can change another admin's chats.
	 */
	async handleUseVersion(ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
		const p = msg.payload ?? {};
		const fail = (error: string) => replyTo(ws, clientInfo, msg, 'GRAPH_USE_VERSION_RES', { success: false, error });
		if (!isGraphAdmin(clientInfo)) return fail('Only an org admin can choose which graph version is used');
		const projectId = graphProjectId(this.ctx, clientInfo);
		if (!projectId) return fail('This connection has no valid project');

		const userId = clientInfo.userId!;
		const version = p.version;
		if (version !== 'live' && version !== 'draft' && !(Number.isInteger(version) && version > 0)) {
			return fail('version must be "live", "draft" or a release number');
		}

		try {
			if (typeof version === 'number' && !(await releaseSeqExists(this.ctx.env.DATABASE_URL, projectId, version))) {
				return fail(`Release ${version} doesn't exist in this project`);
			}
			const map = { ...(await this.load()) };
			if (version === 'live') delete map[userId];
			else map[userId] = version;
			await this.save(map);
			console.log(`Broadcaster ${projectId}: user ${userId} now uses graph ${version}`);
			replyTo(ws, clientInfo, msg, 'GRAPH_USE_VERSION_RES', { success: true, userId, version });
		} catch (error) {
			console.error(`Broadcaster ${this.ctx.projectId()}: GRAPH_USE_VERSION failed:`, error);
			fail('Could not save the graph version');
		}
	}

	/** GRAPH_VERSIONS_REQ — every user's choice for an admin; for anyone else, just their own. */
	async handleVersionsReq(ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
		if (!clientInfo.authenticated || !clientInfo.userId) {
			return replyTo(ws, clientInfo, msg, 'GRAPH_VERSIONS_RES', { success: false, error: 'Not signed in' });
		}
		const map = await this.load();
		const versions = isGraphAdmin(clientInfo)
			? map
			: map[clientInfo.userId] !== undefined ? { [clientInfo.userId]: map[clientInfo.userId] } : {};
		replyTo(ws, clientInfo, msg, 'GRAPH_VERSIONS_RES', { success: true, versions });
	}
}
