import { BroadcastClient, BroadcastMessage, Env, DataSourceRecord } from './types';
import { UsageStats } from '../usage/types';
import { executeQuery } from '../api-keys/service';

// Composition graph replication.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENGINE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** Cloudflare caps a WebSocket message at 1 MiB; snapshot parts stay well under it. */
const SNAPSHOT_PART_BYTES = 512 * 1024;

type GraphHead = { releaseId: number; seq: number; rootHash: string; eventSeq: number };
type ClientInfo = {
	clientId: string;
	type: string;
	projectId?: string;
	userId?: string;
	orgId?: string;
	role?: string;
	config?: unknown;
	authenticated?: boolean;
};

// Storage keys
const STORAGE_KEY_TOTAL_REQUESTS = 'totalRequests';
const STORAGE_KEY_DAILY_REQUESTS = 'dailyRequests';
const STORAGE_KEY_DATA_SOURCES = 'dataSources';

// Type for daily requests map: { "2025-01-28": 150, "2025-01-27": 200, ... }
type DailyRequestsMap = Record<string, number>;

// Per-project data-source registry, KEYED BY Data Source ID.
type DataSourcesMap = Record<string, DataSourceRecord>;

/**
 * Decode the base64 config header the worker set from the verified session.
 *
 * Returns null on anything unexpected rather than throwing: a malformed header
 * must not take the socket down, and null reads downstream as "no policy
 * resolved", which the data seam already handles.
 */
function decodeSessionConfig(header: string | null): unknown {
	if (!header) return null;
	try {
		const bytes = Uint8Array.from(atob(header), (c) => c.charCodeAt(0));
		return JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		console.warn('[broadcaster] could not decode x-sa-session-config; treating as no config');
		return null;
	}
}

export class Broadcaster implements DurableObject {
	private state: DurableObjectState;
	private env: Env;
	private clients: Map<string, BroadcastClient> = new Map();
	private projectId: string;
	private lastActivity: number;

	constructor(state: DurableObjectState, env: Env) {
		this.state = state;
		this.env = env;
		this.lastActivity = Date.now();
		this.projectId = state.id.name || 'unknown';
	}

	/**
	 * Get today's date in YYYY-MM-DD format
	 */
	private getTodayDate(): string {
		return new Date().toISOString().split('T')[0];
	}

	/**
	 * Increment the request count for the project
	 */
	private async incrementRequestCount(): Promise<void> {
		const today = this.getTodayDate();

		// Increment total requests
		const totalRequests = (await this.state.storage.get<number>(STORAGE_KEY_TOTAL_REQUESTS)) || 0;
		await this.state.storage.put(STORAGE_KEY_TOTAL_REQUESTS, totalRequests + 1);

		// Get and update daily requests map
		const dailyRequests = (await this.state.storage.get<DailyRequestsMap>(STORAGE_KEY_DAILY_REQUESTS)) || {};

		// Increment today's count
		dailyRequests[today] = (dailyRequests[today] || 0) + 1;

		// Clean up old entries (keep last 30 days)
		const cutoffDate = new Date();
		cutoffDate.setDate(cutoffDate.getDate() - 30);
		const cutoffStr = cutoffDate.toISOString().split('T')[0];

		for (const date of Object.keys(dailyRequests)) {
			if (date < cutoffStr) {
				delete dailyRequests[date];
			}
		}

		// Save updated map
		await this.state.storage.put(STORAGE_KEY_DAILY_REQUESTS, dailyRequests);
	}

	/**
	 * Get usage statistics for the project
	 */
	private async getUsageStats(): Promise<UsageStats> {
		const totalRequests = (await this.state.storage.get<number>(STORAGE_KEY_TOTAL_REQUESTS)) || 0;
		const dailyRequestsMap = (await this.state.storage.get<DailyRequestsMap>(STORAGE_KEY_DAILY_REQUESTS)) || {};

		// Convert map to sorted array
		const dailyRequests = Object.entries(dailyRequestsMap)
			.map(([date, count]) => ({ date, count }))
			.sort((a, b) => b.date.localeCompare(a.date)); // Sort descending by date

		return {
			projectId: this.projectId,
			totalRequests,
			dailyRequests,
		};
	}

	// ============================================================
	// Data-source registry, KEYED BY Data Source ID, persisted so it survives
	// DO hibernation. The DO owns routing — see docs/cross-machine-source-proxy.md.
	// ============================================================

	private async loadDataSources(): Promise<DataSourcesMap> {
		return (await this.state.storage.get<DataSourcesMap>(STORAGE_KEY_DATA_SOURCES)) || {};
	}

	private async saveDataSources(records: DataSourcesMap): Promise<void> {
		await this.state.storage.put(STORAGE_KEY_DATA_SOURCES, records);
	}

	private isAuthenticated(ws: WebSocket): boolean {
		const meta = (ws as any).deserializeAttachment();
		return !!(meta && meta.authenticated);
	}

	/**
	 * REGISTER_PROXY — a proxy announces the data sources it manages. Records are
	 * keyed by Data Source ID and carry the proxy's current wsId (refreshed each
	 * call). We first clear any records previously owned by this connection so a
	 * shrunk source set doesn't leave stale entries. Requires an authenticated
	 * connection (project API key).
	 */
	private async handleRegisterProxy(ws: WebSocket, senderId: string, msg: BroadcastMessage): Promise<void> {
		if (!this.isAuthenticated(ws)) {
			this.sendError(senderId, 'REGISTER_PROXY rejected: connection is not authenticated with the project API key');
			return;
		}

		const proxyId = msg.payload?.proxyId;
		const dataSourceIds: string[] = Array.isArray(msg.payload?.dataSourceIds) ? msg.payload.dataSourceIds : [];

		if (!proxyId || typeof proxyId !== 'string') {
			this.sendError(senderId, 'REGISTER_PROXY requires payload.proxyId (string)');
			return;
		}

		const records = await this.loadDataSources();
		// Clear this connection's previous claims, then re-add the advertised set.
		for (const [id, rec] of Object.entries(records)) {
			if (rec.wsId === senderId) delete records[id];
		}
		const now = Date.now();
		for (const dataSourceId of dataSourceIds) {
			records[dataSourceId] = { dataSourceId, proxyId, wsId: senderId, lastSeen: now };
		}
		await this.saveDataSources(records);

		console.log(`Broadcaster ${this.projectId}: registered proxy ${proxyId} → [${dataSourceIds.join(', ')}]`);

		try {
			ws.send(JSON.stringify({
				id: msg.id || crypto.randomUUID(),
				type: 'PROXY_REGISTERED',
				from: { type: 'system' },
				payload: { proxyId, dataSourceCount: dataSourceIds.length, ok: true, timestamp: now }
			} as BroadcastMessage));
		} catch (error) {
			console.error(`Broadcaster ${this.projectId}: failed to ack REGISTER_PROXY:`, error);
		}
	}

	/**
	 * DS_QUERY — the requester sends only a Data Source ID (no target). The DO
	 * looks up the owner and FORWARDS the query to the owner's live socket,
	 * stamping from.id with the requester's wsId so the owner can reply straight
	 * back. If there's no owner / it's offline, the DO returns DS_ERROR to the
	 * requester immediately — the requester never waits indefinitely.
	 */
	private async handleDsQuery(ws: WebSocket, senderId: string, msg: BroadcastMessage): Promise<void> {
		const dataSourceId = msg.payload?.dataSourceId;
		const replyError = (error: string, code: string) => this.sendDsErrorTo(senderId, msg.id, error, code);

		// An unauthenticated connection may neither expose nor query data sources.
		if (!this.isAuthenticated(ws)) {
			return replyError('DS_QUERY rejected: connection is not authenticated with the project API key', 'UNAUTHENTICATED');
		}

		if (!dataSourceId || typeof dataSourceId !== 'string') {
			return replyError('DS_QUERY requires payload.dataSourceId (string)', 'BAD_REQUEST');
		}

		const records = await this.loadDataSources();
		const rec = records[dataSourceId];
		if (!rec) return replyError(`No proxy owns data source '${dataSourceId}'`, 'NO_OWNER');

		const owner = this.clients.get(rec.wsId);
		if (!owner || owner.socket.readyState !== WebSocket.OPEN) {
			return replyError(`The proxy owning data source '${dataSourceId}' is not connected`, 'NO_OWNER');
		}

		// Forward to the owner; stamp from.id so the owner replies to the requester.
		try {
			owner.socket.send(JSON.stringify({
				id: msg.id,
				type: 'DS_QUERY',
				from: { type: 'system', id: senderId },
				to: { id: rec.wsId },
				payload: { dataSourceId, sql: msg.payload?.sql, params: msg.payload?.params },
			} as BroadcastMessage));
		} catch (error) {
			replyError(`Failed to forward DS_QUERY: ${(error as Error).message}`, 'FORWARD_FAILED');
		}
	}

	private sendDsErrorTo(wsId: string, requestId: string, error: string, code: string): void {
		const client = this.clients.get(wsId);
		if (!client || client.socket.readyState !== WebSocket.OPEN) return;
		try {
			client.socket.send(JSON.stringify({
				id: requestId,
				type: 'DS_ERROR',
				from: { type: 'system' },
				payload: { error, code },
			} as BroadcastMessage));
		} catch (e) {
			console.error(`Broadcaster ${this.projectId}: failed to send DS_ERROR:`, e);
		}
	}

	/** Drop every data-source record owned by a (now gone) connection. */
	private async removeDataSourcesByWsId(wsId: string): Promise<void> {
		const records = await this.loadDataSources();
		let changed = false;
		for (const [id, rec] of Object.entries(records)) {
			if (rec.wsId === wsId) { delete records[id]; changed = true; }
		}
		if (changed) await this.saveDataSources(records);
	}

	/** Composition graph: sa-api says a new release is live; each engine socket gets a GRAPH_RELEASE (a hint — engines also catch up on reconnect). */
	private async handleGraphRelease(request: Request): Promise<Response> {
		const json = (body: unknown, status = 200) =>
			new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

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

		this.syncClientsFromWebSockets();
		let sent = 0;
		for (const [clientId, client] of this.clients.entries()) {
			if (client.type !== 'data-agent' || client.socket.readyState !== WebSocket.OPEN) continue;
			if (!this.isAuthenticated(client.socket)) continue;
			try {
				client.socket.send(JSON.stringify({
					id: crypto.randomUUID(),
					type: 'GRAPH_RELEASE',
					from: { type: 'system' },
					to: { type: 'data-agent', id: clientId },
					payload: { projectId: this.projectId, releaseId, seq, rootHash, eventSeq, timestamp: Date.now() },
				} as BroadcastMessage));
				sent++;
			} catch (error) {
				console.error(`Broadcaster ${this.projectId}: failed to send GRAPH_RELEASE to ${clientId}:`, error);
			}
		}

		console.log(`Broadcaster ${this.projectId}: GRAPH_RELEASE seq=${seq} event=${eventSeq} → ${sent} engine socket(s)`);
		return json({ ok: true, sent });
	}

	/** Composition graph queries are scoped by the socket's project, which must be a real project id. */
	private graphProjectId(clientInfo: ClientInfo): string | null {
		const id = clientInfo.projectId || this.projectId;
		return UUID_RE.test(id) ? id : null;
	}

	/** Engines (authenticated data-agent sockets) are the only ones that replicate the graph. */
	private isEngine(clientInfo: ClientInfo): boolean {
		return clientInfo.type === 'data-agent' && clientInfo.authenticated === true;
	}

	/** The release this project's engines should run: the target of its latest release event. */
	private async currentGraphRelease(projectId: string): Promise<GraphHead | null> {
		const rows = await executeQuery<any>(
			this.env.DATABASE_URL,
			`SELECT r.id::int AS release_id, r.seq::int AS seq, r.root_hash, e.event_seq::text AS event_seq
			   FROM graph_release_events e
			   JOIN graph_releases r ON r.id = e.to_release_id
			  WHERE e.project_id = $1::uuid
			  ORDER BY e.event_seq DESC
			  LIMIT 1`,
			[projectId],
		);
		if (!rows.length) return null;
		const r = rows[0];
		return { releaseId: Number(r.release_id), seq: Number(r.seq), rootHash: String(r.root_hash), eventSeq: Number(r.event_seq) };
	}

	/** Record what an engine runs (graph_engine_state); an `error` sticks until the engine is in sync again. */
	private async recordEngine(
		projectId: string,
		engineId: string,
		s: { status: 'in_sync' | 'behind' | 'error'; releaseId?: number | null; rootHash?: string | null; error?: string | null; acked?: boolean },
	): Promise<void> {
		await executeQuery(
			this.env.DATABASE_URL,
			`INSERT INTO graph_engine_state
			        (project_id, engine_id, org_id, applied_release_id, applied_root_hash, status, last_error, last_seen_at, last_ack_at)
			 SELECT $1::uuid, $2, p.org_id, $3::int, $4, $5, $6, now(), CASE WHEN $7::boolean THEN now() END
			   FROM projects p WHERE p.id = $1::uuid
			 ON CONFLICT (project_id, engine_id) DO UPDATE SET
			   status = CASE WHEN EXCLUDED.status = 'behind' AND graph_engine_state.status = 'error'
			                 THEN 'error' ELSE EXCLUDED.status END,
			   last_error = CASE WHEN EXCLUDED.status = 'behind' THEN graph_engine_state.last_error
			                     ELSE EXCLUDED.last_error END,
			   applied_release_id = COALESCE(EXCLUDED.applied_release_id, graph_engine_state.applied_release_id),
			   applied_root_hash = COALESCE(EXCLUDED.applied_root_hash, graph_engine_state.applied_root_hash),
			   last_seen_at = now(),
			   last_ack_at = COALESCE(EXCLUDED.last_ack_at, graph_engine_state.last_ack_at)`,
			[projectId, engineId, s.releaseId ?? null, s.rootHash ?? null, s.status, s.error ?? null, !!s.acked],
		);
	}

	/** GRAPH_HELLO — an engine reports its release; answered with GRAPH_NONE, GRAPH_IN_SYNC or GRAPH_SNAPSHOT parts. */
	private async handleGraphHello(ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
		if (!this.isEngine(clientInfo)) {
			this.sendError(clientInfo.clientId, 'GRAPH_HELLO is only accepted from an engine connection authenticated with the project API key');
			return;
		}
		const projectId = this.graphProjectId(clientInfo);
		const p = msg.payload ?? {};
		const engineId = typeof p.engineId === 'string' && ENGINE_ID_RE.test(p.engineId) ? p.engineId : null;
		if (!projectId || !engineId) {
			this.sendError(clientInfo.clientId, 'GRAPH_HELLO needs a valid project and payload.engineId');
			return;
		}

		const send = (type: string, payload: unknown) =>
			ws.send(JSON.stringify({
				id: crypto.randomUUID(),
				type,
				from: { type: 'system' },
				to: { type: 'data-agent', id: clientInfo.clientId },
				payload,
			} as BroadcastMessage));

		try {
			const current = await this.currentGraphRelease(projectId);
			if (!current) {
				await this.recordEngine(projectId, engineId, { status: 'in_sync' });
				send('GRAPH_NONE', { projectId });
				return;
			}
			if (p.haveRootHash === current.rootHash) {
				await this.recordEngine(projectId, engineId, { status: 'in_sync', releaseId: current.releaseId, rootHash: current.rootHash });
				send('GRAPH_IN_SYNC', current);
				return;
			}
			await this.recordEngine(projectId, engineId, { status: 'behind' });
			await this.sendGraphSnapshot(projectId, current, send);
		} catch (error) {
			console.error(`Broadcaster ${this.projectId}: GRAPH_HELLO failed:`, error);
			this.sendError(clientInfo.clientId, 'Could not read the graph release; the engine will retry');
		}
	}

	/** The whole release, with every item's content, split into parts under the message size limit. */
	private async sendGraphSnapshot(projectId: string, head: GraphHead, send: (type: string, payload: unknown) => void): Promise<void> {
		const rows = await executeQuery<any>(
			this.env.DATABASE_URL,
			`SELECT v.entity, v.entity_id::int AS id, v.rev::int AS rev, v.hash, v.content::text AS content
			   FROM graph_releases r
			   CROSS JOIN LATERAL jsonb_to_recordset(r.items) AS x(entity text, id int, rev int)
			   JOIN graph_revisions v ON v.entity = x.entity AND v.entity_id = x.id AND v.rev = x.rev
			  WHERE r.id = $1 AND r.project_id = $2::uuid AND v.project_id = $2::uuid`,
			[head.releaseId, projectId],
		);
		const items = rows.map((r) => ({
			entity: r.entity,
			id: Number(r.id),
			rev: Number(r.rev),
			hash: String(r.hash),
			content: JSON.parse(r.content),
		}));

		const encoder = new TextEncoder();
		const parts: (typeof items)[] = [];
		let current: typeof items = [];
		let bytes = 0;
		for (const item of items) {
			const size = encoder.encode(JSON.stringify(item)).length;
			if (current.length && bytes + size > SNAPSHOT_PART_BYTES) {
				parts.push(current);
				current = [];
				bytes = 0;
			}
			current.push(item);
			bytes += size;
		}
		parts.push(current); // an empty release still sends one (empty) part

		parts.forEach((list, part) => send('GRAPH_SNAPSHOT', { ...head, part, totalParts: parts.length, items: list }));
		console.log(`Broadcaster ${projectId}: GRAPH_SNAPSHOT release ${head.seq} (${items.length} items, ${parts.length} part(s))`);
	}

	/** GRAPH_ACK / GRAPH_NACK — what the engine did with a release, recorded for the platform. */
	private async handleGraphAck(clientInfo: ClientInfo, msg: BroadcastMessage): Promise<void> {
		if (!this.isEngine(clientInfo)) return;
		const projectId = this.graphProjectId(clientInfo);
		const p = msg.payload ?? {};
		const engineId = typeof p.engineId === 'string' && ENGINE_ID_RE.test(p.engineId) ? p.engineId : null;
		if (!projectId || !engineId) return;

		try {
			if (msg.type === 'GRAPH_NACK') {
				await this.recordEngine(projectId, engineId, { status: 'error', error: String(p.error ?? 'unknown error').slice(0, 2000) });
				console.warn(`Broadcaster ${projectId}: engine ${engineId} refused release ${p.seq}: ${p.error}`);
				return;
			}
			// Only record a release that really is this project's, with that content.
			if (!Number.isInteger(p.releaseId) || typeof p.rootHash !== 'string') return;
			const match = await executeQuery<any>(
				this.env.DATABASE_URL,
				`SELECT 1 FROM graph_releases WHERE id = $1 AND project_id = $2::uuid AND root_hash = $3`,
				[p.releaseId, projectId, p.rootHash],
			);
			if (!match.length) return;
			const current = await this.currentGraphRelease(projectId);
			await this.recordEngine(projectId, engineId, {
				status: current && current.rootHash === p.rootHash ? 'in_sync' : 'behind',
				releaseId: p.releaseId,
				rootHash: p.rootHash,
				acked: true,
			});
		} catch (error) {
			console.error(`Broadcaster ${this.projectId}: ${msg.type} could not be recorded:`, error);
		}
	}

	private async getRegistry(): Promise<Response> {
		this.syncClientsFromWebSockets();
		const records = await this.loadDataSources();
		const list = Object.values(records).map(r => ({
			...r,
			connected: this.clients.has(r.wsId),
		}));
		return new Response(JSON.stringify({
			projectId: this.projectId,
			dataSources: list,
			timestamp: Date.now()
		}, null, 2), {
			headers: { 'Content-Type': 'application/json' }
		});
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const urlProjectId = url.searchParams.get('projectId');

		if (!urlProjectId) {
			return new Response(JSON.stringify({
				error: 'Missing projectId parameter',
				required: 'Please provide ?projectId=your-project-id'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json' }
			});
		}

		this.projectId = urlProjectId;

		// Reached only via sa-api's DO binding; the worker refuses this path from outside.
		if (url.pathname === '/graph-release') {
			return this.handleGraphRelease(request);
		}

		if (url.pathname === '/websocket') {
			return this.handleWebSocketUpgrade(request);
		}

		if (url.pathname === '/status') {
			return this.getStatus();
		}

		if (url.pathname === '/registry') {
			return this.getRegistry();
		}

		if (url.pathname === '/health') {
			return new Response(JSON.stringify({
				status: 'healthy',
				projectId: this.projectId,
				clientCount: this.clients.size,
				lastActivity: this.lastActivity,
				timestamp: Date.now()
			}), {
				headers: { 'Content-Type': 'application/json' }
			});
		}

		if (url.pathname === '/usage') {
			const stats = await this.getUsageStats();
			return new Response(JSON.stringify({
				success: true,
				data: stats,
			}), {
				headers: { 'Content-Type': 'application/json' }
			});
		}

		return new Response('Not found', { status: 404 });
	}

	private async handleWebSocketUpgrade(request: Request): Promise<Response> {
		const upgradeHeader = request.headers.get('Upgrade');

		if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
			return new Response('Expected Upgrade: websocket', { status: 426 });
		}

		const url = new URL(request.url);
		const type = url.searchParams.get('type');

		if(!type ) {
			return new Response('Missing type parameter', { status: 400 });
		}

		if(['runtime','data-agent','db-bridge','admin'].indexOf(type) === -1) {
			return new Response('Invalid type parameter', { status: 400 });
		}

		try {
			const webSocketPair = new WebSocketPair();
			const [client, server] = Object.values(webSocketPair);

			const clientId = crypto.randomUUID();
			const connectedAt = Date.now();

			// Accept the WebSocket for hibernation
			this.state.acceptWebSocket(server);

			// Auth: src/index.ts validates the credential — a project API key for
			// server components, a verified sa-api session for browser clients —
			// and stamps the outcome here, stripping any client-supplied copy of
			// these headers first so they cannot be forged. The presence of an
			// apiKey PARAMETER is deliberately NOT used: it was never proof the key
			// was valid, and browser types were never key-checked at all, so
			// ?type=runtime&apiKey=anything used to unlock the data plane.
			const authenticated = request.headers.get('x-sa-authenticated') === 'true';

			// Attach metadata using serializeAttachment for hibernatable WebSockets
			const clientMetadata = {
				clientId: clientId,
				type: type,
				// Kept on the socket: this.projectId may be unset after hibernation.
				projectId: this.projectId,
				connectedAt: connectedAt,
				authenticated: authenticated,
				// Identity comes from the verified token, never from ?userId=.
				userId: request.headers.get('x-sa-session-user') || null,
				orgId: request.headers.get('x-sa-session-org') || null,
				role: request.headers.get('x-sa-session-role') || null,
				// The verified data-access config, decoded from the base64 header the
				// worker set. Stored on the attachment (not this.clients) so it
				// survives hibernation, exactly like userId/role.
				config: decodeSessionConfig(request.headers.get('x-sa-session-config')),
				userAgent: request.headers.get('User-Agent') || 'unknown',
				origin: request.headers.get('Origin') || 'unknown'
			};
			(server as any).serializeAttachment(clientMetadata);

			const broadcastClient: BroadcastClient = {
				id: clientId,
				socket: server,
				connectedAt: connectedAt,
				type: type,
				metadata: {
					userAgent: request.headers.get('User-Agent'),
					origin: request.headers.get('Origin')
				}
			};

			this.clients.set(clientId, broadcastClient);
			this.lastActivity = Date.now();

			// Send welcome message
			const welcomeMessage: BroadcastMessage = {
				id: crypto.randomUUID(),
				type: 'connected',
				from: {
					type: 'system'
				},
				payload: {
					clientId: clientId,
					projectId: this.projectId,
					message: `Connected to project ${this.projectId}`,
					clientCount: this.clients.size,
					timestamp: Date.now()
				}
			};

			server.send(JSON.stringify(welcomeMessage));

			return new Response(null, {
				status: 101,
				webSocket: client
			});

		} catch (error: any) {
			console.error(`Broadcaster ${this.projectId}: WebSocket upgrade error:`, error);
			return new Response(JSON.stringify({
				error: 'WebSocket upgrade failed',
				details: error.message,
				projectId: this.projectId
			}), {
				status: 500,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	}


	private broadcastToOthers(senderId: string, message: any): void {
		const messageStr = typeof message === 'string' ? message : JSON.stringify(message);

		for (const [clientId, client] of this.clients.entries()) {
			if (clientId !== senderId && client.socket.readyState === WebSocket.OPEN) {
				try {
					client.socket.send(messageStr);
				} catch (error) {
					console.error(`Broadcaster ${this.projectId}: Failed to send to client ${clientId}:`, error);
				}
			}
		}
	}


	private broadcastToadminOptimized(senderId: string, messageStr: string): void {
		for (const [clientId, client] of this.clients.entries()) {
			if (clientId !== senderId && client.type === 'admin' && client.socket.readyState === WebSocket.OPEN) {
				try {
					client.socket.send(messageStr);
				} catch (error) {
					console.error(`Broadcaster ${this.projectId}: Failed to send to admin:`, error);
				}
			}
		}
	}

	private sendError(clientId: string, message: string): void {
		const client = this.clients.get(clientId);
		if (!client || client.socket.readyState !== WebSocket.OPEN) {
			return;
		}

		try {
			const errorMessage: BroadcastMessage = {
				id: crypto.randomUUID(),
				type: 'error',
				from: {
					type: 'system'
				},
				payload: {
					message,
					projectId: this.projectId,
					timestamp: Date.now()
				}
			};
			client.socket.send(JSON.stringify(errorMessage));
		} catch (error) {
			console.error(`Broadcaster ${this.projectId}: Failed to send error to client ${clientId}:`, error);
		}
	}

	private async scheduleCleanup(): Promise<void> {
		const cleanupTime = Date.now() + 5 * 60 * 1000; // 5 minutes
		await this.state.storage.setAlarm(cleanupTime);
	}

	async alarm(): Promise<void> {
		if (this.clients.size === 0) {
			// DO will naturally hibernate and stop consuming CPU/duration
		}
	}

	private async getStatus(): Promise<Response> {
		// Sync clients to get accurate status
		this.syncClientsFromWebSockets();

		const dataSources = await this.loadDataSources();

		const status = {
			projectId: this.projectId,
			clientCount: this.clients.size,
			lastActivity: this.lastActivity,
			clients: Array.from(this.clients.values()).map(client => ({
				id: client.id,
				connectedAt: client.connectedAt,
				connectedFor: Date.now() - client.connectedAt,
				socketState: client.socket.readyState,
				metadata: client.metadata
			})),
			dataSources: Object.values(dataSources).map(r => ({
				...r,
				connected: this.clients.has(r.wsId)
			})),
			timestamp: Date.now()
		};

		return new Response(JSON.stringify(status, null, 2), {
			headers: { 'Content-Type': 'application/json' }
		});
	}

	// Hibernatable WebSocket Handlers
	// These methods replace event listeners and enable automatic hibernation

	/**
	 * Sync the clients Map from active WebSockets
	 * This is necessary after hibernation wakeup
	 */
	private syncClientsFromWebSockets(): void {
		const activeSockets = this.state.getWebSockets();
		const activeClientIds = new Set<string>();

		for (const ws of activeSockets) {
			const metadata = (ws as any).deserializeAttachment();
			if (metadata && typeof metadata === 'object' && metadata.clientId && metadata.type) {
				activeClientIds.add(metadata.clientId);

				// Add to clients Map if not already present
				if (!this.clients.has(metadata.clientId)) {
					this.clients.set(metadata.clientId, {
						id: metadata.clientId,
						socket: ws,
						connectedAt: metadata.connectedAt || Date.now(),
						type: metadata.type,
						metadata: {
							userAgent: metadata.userAgent || 'unknown',
							origin: metadata.origin || 'unknown'
						}
					});
				}
			}
		}

		// Remove disconnected clients from Map
		for (const clientId of this.clients.keys()) {
			if (!activeClientIds.has(clientId)) {
				this.clients.delete(clientId);
			}
		}
	}

	/**
	 * Extract client metadata from WebSocket attachment
	 */
	/**
	 * Sender identity, read from the socket ATTACHMENT rather than from
	 * `this.clients`.
	 *
	 * This distinction is load-bearing: `syncClientsFromWebSockets()` rebuilds
	 * that map after hibernation and deliberately keeps only display metadata
	 * (userAgent/origin), so identity read from it would be present on a fresh
	 * connection and missing after a hibernation cycle — intermittent, and
	 * failing open. The attachment is what survives hibernation.
	 */
	private getClientInfoFromWebSocket(ws: WebSocket): ClientInfo | null {
		const metadata = (ws as any).deserializeAttachment();
		if (!metadata || typeof metadata !== 'object') {
			return null;
		}

		const clientId = metadata.clientId;
		const type = metadata.type;

		return clientId && type
			? {
					clientId,
					type,
					projectId: metadata.projectId ?? undefined,
					userId: metadata.userId ?? undefined,
					orgId: metadata.orgId ?? undefined,
					role: metadata.role ?? undefined,
					config: metadata.config ?? undefined,
					authenticated: metadata.authenticated === true,
				}
			: null;
	}

	/**
	 * Called when a WebSocket message is received
	 * The DO automatically wakes up from hibernation to handle this
	 */
	async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
		this.lastActivity = Date.now();

		// Increment request count for usage tracking
		await this.incrementRequestCount();

		// Sync clients after hibernation wakeup
		this.syncClientsFromWebSockets();

		const clientInfo = this.getClientInfoFromWebSocket(ws);
		if (!clientInfo) {
			console.error(`Broadcaster ${this.projectId}: Could not extract client info from WebSocket`);
			return;
		}

		const senderId = clientInfo.clientId;

		// Convert ArrayBuffer to string if needed
		const messageStr = typeof message === 'string' ? message : new TextDecoder().decode(message);

		if (!messageStr || typeof messageStr !== 'string') {
			console.error(`Broadcaster ${this.projectId}: Invalid message format`);
			return;
		}

		let ws_json_message: any = {};

		try {
			ws_json_message = JSON.parse(messageStr) as BroadcastMessage;
		} catch (error) {
			console.error(`Broadcaster ${this.projectId}: Failed to parse message:`, error);
			this.sendError(senderId, 'Invalid JSON message format');
			return;
		}

		// Handle PING message - respond with PONG immediately
		// This keeps the connection alive and prevents idle timeout
		if (ws_json_message.type === 'PING') {
			try {
				const pongMessage: BroadcastMessage = {
					id: crypto.randomUUID(),
					type: 'PONG',
					from: {
						type: 'system'
					},
					payload: {
						timestamp: Date.now(),
						originalTimestamp: ws_json_message.payload?.timestamp
					}
				};
				ws.send(JSON.stringify(pongMessage));
				// Don't broadcast PING/PONG to other clients
				return;
			} catch (error) {
				console.error(`Broadcaster ${this.projectId}: Failed to send PONG:`, error);
				return;
			}
		}

		// Data-source registry / routing control messages — handled by the DO
		// directly and NOT relayed. See docs/cross-machine-source-proxy.md.
		// (DS_ACK / DS_RESULT / DS_ERROR from a proxy carry to:{id} and ride the
		// generic point-to-point relay below straight back to the requester.)
		if (ws_json_message.type === 'REGISTER_PROXY') {
			await this.handleRegisterProxy(ws, senderId, ws_json_message);
			return;
		}
		if (ws_json_message.type === 'UNREGISTER_PROXY') {
			await this.removeDataSourcesByWsId(senderId);
			return;
		}
		if (ws_json_message.type === 'DS_QUERY') {
			await this.handleDsQuery(ws, senderId, ws_json_message);
			return;
		}

		// Composition graph replication — answered by the DO, never relayed.
		if (ws_json_message.type === 'GRAPH_HELLO') {
			await this.handleGraphHello(ws, clientInfo, ws_json_message);
			return;
		}
		if (ws_json_message.type === 'GRAPH_ACK' || ws_json_message.type === 'GRAPH_NACK') {
			await this.handleGraphAck(clientInfo, ws_json_message);
			return;
		}

		// Adding the clientid as from.id
		if (ws_json_message.from && typeof ws_json_message.from === 'object') {
			ws_json_message.from.id = senderId;
		}

		// Stamp the sender's verified identity onto the relayed message.
		//
		// The worker (src/index.ts) verifies the sa-api session JWT at handshake
		// and the attachment records the result; this is the one hop that was
		// missing, and it is what lets the data plane tell WHOSE data a query is
		// for. Read from the attachment, not `this.clients` — see
		// getClientInfoFromWebSocket().
		//
		// Only set when the session was actually verified. A socket with no
		// session (a server component, or a browser on a deployment with
		// WS_AUTH_ENFORCE off) leaves the field absent, and consumers must read
		// absence as "unknown" rather than "trusted".
		//
		// Deleted UNCONDITIONALLY before we set our own, the same discipline
		// index.ts applies to INTERNAL_IDENTITY_HEADERS. A verified sender's
		// forgery was already overwritten below, but an UNVERIFIED sender's own
		// authContext used to pass straight through. That was tolerable while the
		// field carried identity alone and payload.userId was equally trusted. It
		// is not tolerable now that it carries `config`: a forged authContext
		// would be a forged authorization policy.
		delete ws_json_message.authContext;

		if (clientInfo.authenticated && clientInfo.userId) {
			ws_json_message.authContext = {
				userId: clientInfo.userId,
				...(clientInfo.orgId ? { orgId: clientInfo.orgId } : {}),
				...(clientInfo.role ? { role: clientInfo.role } : {}),
				...(clientInfo.config != null ? { config: clientInfo.config } : {}),
			};
		}

		const targetType = ws_json_message.to?.type;
		const targetId = ws_json_message.to?.id;

		if (targetId || targetType) {
			// Route based on to.type
			const messageToSend = JSON.stringify(ws_json_message);

			if (targetId) {
				const targetClient = this.clients.get(targetId);
				if (targetClient && targetClient.socket.readyState === WebSocket.OPEN) {
					try {
						targetClient.socket.send(messageToSend);
					} catch (error) {
						console.error(`Broadcaster ${this.projectId}: Failed to send to target:`, error);
					}
				}
			} else {
				for (const [clientId, client] of this.clients.entries()) {
					if (clientId !== senderId && client.socket.readyState === WebSocket.OPEN) {
						if (client.type === targetType) {
							try {
								client.socket.send(messageToSend);
							} catch (error) {
								console.error(`Broadcaster ${this.projectId}: Failed to send to client ${clientId}:`, error);
							}
						}
					}
				}
			}

			// Send to admin (for monitoring routed messages)
			this.broadcastToadminOptimized(senderId, messageToSend);
		}
		// If to is not present then broadcast to others
		else {
			this.broadcastToOthers(senderId, ws_json_message);
		}
	}

	/**
	 * Called when a WebSocket connection is closed
	 */
	async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
		const clientInfo = this.getClientInfoFromWebSocket(ws);
		if (!clientInfo) {
			return;
		}

		this.clients.delete(clientInfo.clientId);
		this.lastActivity = Date.now();

		// Drop any data-source records this connection owned, so queries are
		// never routed to a machine that has gone away.
		await this.removeDataSourcesByWsId(clientInfo.clientId);

		// Schedule cleanup if room is empty
		if (this.clients.size === 0) {
			this.scheduleCleanup();
		}
	}

	/**
	 * Called when a WebSocket encounters an error
	 */
	async webSocketError(ws: WebSocket, error: any): Promise<void> {
		const clientInfo = this.getClientInfoFromWebSocket(ws);
		if (clientInfo) {
			console.error(`Broadcaster ${this.projectId}: WebSocket error for client ${clientInfo.clientId}:`, error);
		} else {
			console.error(`Broadcaster ${this.projectId}: WebSocket error:`, error);
		}
	}
}
