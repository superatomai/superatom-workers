/**
 * Identity of the sender, stamped by the DO from the session token the worker
 * verified at handshake — never from anything the client put in the message.
 *
 * Present only when the sender's socket carries a verified session, so a
 * deployment with WS_AUTH_ENFORCE off simply never sees it. Consumers must
 * treat its ABSENCE as "unknown", never as "trusted".
 */
export interface MessageAuthContext {
	userId: string;
	orgId?: string;
	role?: string;
	/** Verified data-access config from the users table — see VerifiedSession.config. */
	config?: unknown;
}

export interface BroadcastMessage {
    id:string
	type: string;
	from:{
		type?:'runtime' | 'data-agent' | 'db-bridge' | 'admin' | 'system';
		id?: string;
	};
	payload : any;
	to?:{
		type?:'runtime' | 'data-agent' | 'db-bridge' | 'admin' | 'system';
		id?: string;
	};
	authContext?: MessageAuthContext;
}

export interface Env {
	BROADCASTER: DurableObjectNamespace;
	DATABASE_URL: string;
	SUPERATOM_SERVICE_KEY: string;
}

export interface BroadcastClient {
	id: string;
	socket: WebSocket;
	type: string;
	connectedAt: number;
	metadata?: {
		userAgent: string | null;
		origin: string | null;
	};
}

/**
 * One entry in the per-project data-source registry, KEYED BY Data Source ID.
 * The DO always looks up by Data Source ID, so that is the primary key.
 *
 * - proxyId: stable id of the proxy that manages this data source.
 * - wsId:    the CURRENT owning WebSocket connection (the DO's per-connection
 *            `clientId`). Changes on reconnect, so it's refreshed on every
 *            REGISTER_PROXY — it's where the DO forwards DS_QUERY messages.
 */
export interface DataSourceRecord {
	dataSourceId: string;
	proxyId: string;
	wsId: string;
	lastSeen: number;
}
