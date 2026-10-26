import type { Env } from '../types';

/** A release as engines run it: which one, its content hash, and the release event that made it live. */
export type GraphHead = { releaseId: number; seq: number; rootHash: string; eventSeq: number };

/**
 * Which composition graph a user's questions are answered from, by user id:
 * "draft" (the platform's working copy) or a release seq. A user not listed
 * gets the live release. Stamped on the user's messages as authContext.graphVersion.
 */
export type GraphVersion = 'draft' | number;
export type GraphVersionsMap = Record<string, GraphVersion>;

/**
 * What the graph code may use of the Durable Object. Passed in rather than the
 * DO itself, so the graph code reaches only these and the DO stays the one
 * place that owns sockets.
 */
export interface GraphContext {
	env: Env;
	storage: DurableObjectStorage;
	/** The project this DO serves (set from each request's URL). */
	projectId(): string;
	/** Every open engine socket (an authenticated data-agent), by client id. */
	engineSockets(): Array<[string, WebSocket]>;
	/** An `error` message to one client. */
	sendError(clientId: string, message: string): void;
}
