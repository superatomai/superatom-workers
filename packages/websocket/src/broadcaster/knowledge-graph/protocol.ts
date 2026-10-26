import type { BroadcastMessage, ClientInfo } from '../types';
import type { GraphContext } from './types';

// Helpers every graph handler shares: checks on who is asking, sending, and
// splitting large replies into message-sized parts.

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENGINE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** Cloudflare caps a WebSocket message at 1 MiB; snapshot parts stay well under it. */
const SNAPSHOT_PART_BYTES = 512 * 1024;

/** Graph items split into message-sized parts; always at least one (possibly empty) part. */
export function splitParts<T>(items: T[]): T[][] {
	const encoder = new TextEncoder();
	const parts: T[][] = [];
	let current: T[] = [];
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
	parts.push(current);
	return parts;
}

/** Composition graph queries are scoped by the socket's project, which must be a real project id. */
export function graphProjectId(ctx: GraphContext, clientInfo: ClientInfo): string | null {
	const id = clientInfo.projectId || ctx.projectId();
	return UUID_RE.test(id) ? id : null;
}

/** Engines (authenticated data-agent sockets) are the only ones that replicate the graph. */
export function isEngine(clientInfo: ClientInfo): boolean {
	return clientInfo.type === 'data-agent' && clientInfo.authenticated === true;
}

/** The engine id an engine message carries, when well-formed. */
export function engineIdOf(payload: any): string | null {
	return typeof payload?.engineId === 'string' && ENGINE_ID_RE.test(payload.engineId) ? payload.engineId : null;
}

/** Sends to one engine socket: a message from the system, addressed to that client. */
export function sendToEngine(ws: WebSocket, clientId: string, type: string, payload: unknown): void {
	ws.send(JSON.stringify({
		id: crypto.randomUUID(),
		type,
		from: { type: 'system' },
		to: { type: 'data-agent', id: clientId },
		payload,
	} as BroadcastMessage));
}

/** Answers a request, under the request's id so the caller can match the answer. */
export function replyTo(ws: WebSocket, clientInfo: ClientInfo, msg: BroadcastMessage, type: string, payload: unknown): void {
	ws.send(JSON.stringify({
		id: typeof msg.id === 'string' ? msg.id : crypto.randomUUID(),
		type,
		from: { type: 'system' },
		to: { type: clientInfo.type, id: clientInfo.clientId },
		payload,
	} as BroadcastMessage));
}

/** Sends one message to every open engine socket; returns how many it reached. */
export function notifyEngines(ctx: GraphContext, type: string, payload: Record<string, unknown>): number {
	let sent = 0;
	for (const [clientId, socket] of ctx.engineSockets()) {
		try {
			sendToEngine(socket, clientId, type, { projectId: ctx.projectId(), ...payload, timestamp: Date.now() });
			sent++;
		} catch (error) {
			console.error(`Broadcaster ${ctx.projectId()}: failed to send ${type} to ${clientId}:`, error);
		}
	}
	return sent;
}

export const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
