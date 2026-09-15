export { Broadcaster } from './broadcaster/broadcaster';
import { handleApiKeyRoutes, validateApiKey } from './api-keys';
import { extractToken, verifyBrowserSession, type VerifiedSession } from './auth/session';

export interface Env {
	BROADCASTER: DurableObjectNamespace;
	DATABASE_URL: string;
	SUPERATOM_SERVICE_KEY: string;
	/** Shared with sa-api; verifies browser session tokens. */
	JWT_SECRET: string;
	/** "true" enforces browser auth; anything else logs violations only. */
	WS_AUTH_ENFORCE: string;
}

/**
 * Identity headers this worker sets for the Durable Object. They are stripped
 * from every inbound request before being re-set, because the original client
 * request is forwarded to the DO and a caller could otherwise simply send them.
 */
const INTERNAL_IDENTITY_HEADERS = [
	'x-sa-authenticated',
	'x-sa-session-user',
	'x-sa-session-org',
	'x-sa-session-role',
	'x-sa-session-config',
];

/** Browser clients that authenticate with a user JWT rather than an API key. */
const BROWSER_TYPES = ['runtime', 'admin'];

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// Health check endpoint
		if (url.pathname === '/health' && !url.searchParams.get('projectId') && !url.searchParams.get('userId')) {
			return new Response(JSON.stringify({
				status: 'healthy',
				worker: 'main',
				timestamp: Date.now(),
				version: '1.0.0'
			}), {
				headers: { 'Content-Type': 'application/json' }
			});
		}

		// Handle API key management routes (POST/GET/DELETE /api-keys)
		const apiKeyResponse = await handleApiKeyRoutes(request, env);
		if (apiKeyResponse) {
			return apiKeyResponse;
		}

		const projectId = url.searchParams.get('projectId');
		if (!projectId) {
			return new Response(
				JSON.stringify({
					error: 'Missing projectId ',
					message: 'Please provide ?projectId=your-project-id',
					receivedUrl: url.toString(),
					examples: [
						`${url.origin}/websocket?projectId=your-project&type=runtime&apiKey=sa_live_xxx`,
					]
				}),
				{
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}

		// Auth model: the per-project API key is a SERVER-SIDE credential. Only
		// the server components that connect the relay to customer data
		// (data-agent, db-bridge) MUST present a valid key — no fail-open, no
		// demo bypass. The browser clients ('runtime', 'admin') load from public
		// bundles and cannot safely hold the secret, so they connect without one;
		// the broadcaster still blocks unauthenticated sockets from the data
		// plane (REGISTER_PROXY / DS_QUERY).
		// API key can be passed via query param or header.
		const apiKey = url.searchParams.get('apiKey') || request.headers.get('x-api-key');
		const connectionType = url.searchParams.get('type');
		const KEY_REQUIRED_TYPES = ['data-agent', 'db-bridge'];
		const requiresApiKey = KEY_REQUIRED_TYPES.includes(connectionType ?? '');

		if (requiresApiKey) {
			// Reject server-side connections that present no API key at all.
			if (!apiKey) {
				return new Response(
					JSON.stringify({
						error: 'Missing API key',
						message:
							'A per-project API key is required for this connection type. Provide it via ?apiKey=sa_live_xxx or the x-api-key header.',
						projectId,
					}),
					{
						status: 401,
						headers: { 'Content-Type': 'application/json' },
					}
				);
			}

			// Validate the API key against the database
			if (!env.DATABASE_URL) {
				return new Response(
					JSON.stringify({
						error: 'Server configuration error',
						message: 'DATABASE_URL is not configured',
					}),
					{
						status: 500,
						headers: { 'Content-Type': 'application/json' },
					}
				);
			}

			const validationResult = await validateApiKey(env.DATABASE_URL, projectId, apiKey);
			if (!validationResult.valid) {
				return new Response(
					JSON.stringify({
						error: 'Invalid API key',
						message: validationResult.error || 'API key validation failed',
						projectId,
					}),
					{
						status: 403,
						headers: { 'Content-Type': 'application/json' },
					}
				);
			}
		}

		// Browser clients authenticate with the sa-api session JWT. The session is
		// verified on every connection; WS_AUTH_ENFORCE only decides whether a
		// failure is rejected or merely logged, so a staged rollout can surface
		// which deployments still connect without a token before they start failing.
		const enforce = env.WS_AUTH_ENFORCE === 'true';
		let session: VerifiedSession | null = null;

		if (BROWSER_TYPES.includes(connectionType ?? '')) {
			const result = await verifyBrowserSession({
				token: extractToken(request, url),
				projectId,
				jwtSecret: env.JWT_SECRET,
				databaseUrl: env.DATABASE_URL,
			});

			if (result.ok) {
				session = result.session;
			} else {
				console.warn(
					`[auth] browser session rejected: reason=${result.reason} ` +
						`type=${connectionType} projectId=${projectId} enforced=${enforce}`
				);

				if (enforce) {
					return new Response(
						JSON.stringify({
							error: result.status === 403 ? 'Forbidden' : 'Unauthorized',
							message:
								result.status === 403
									? 'This session is not permitted to access the requested project.'
									: 'A valid session token is required. Provide it via ?token=<jwt> or an Authorization: Bearer header.',
							projectId,
						}),
						{
							status: result.status,
							headers: { 'Content-Type': 'application/json' },
						}
					);
				}
			}
		}

		try {
			const durableObjectId = env.BROADCASTER.idFromName(projectId);
			const durableObjectStub = env.BROADCASTER.get(durableObjectId);

			// The original client request is forwarded to the DO, so any identity
			// header a caller sent must be dropped before this worker sets its own.
			const forwardedHeaders = new Headers(request.headers);
			for (const header of INTERNAL_IDENTITY_HEADERS) {
				forwardedHeaders.delete(header);
			}

			// Authenticated means "credential actually validated": a checked API key
			// for server components, or a verified session for browser clients.
			forwardedHeaders.set('x-sa-authenticated', requiresApiKey || session ? 'true' : 'false');
			if (session) {
				forwardedHeaders.set('x-sa-session-user', session.userId);
				forwardedHeaders.set('x-sa-session-role', session.role);
				if (session.orgId) forwardedHeaders.set('x-sa-session-org', session.orgId);
				// base64 so a label with a non-ASCII character cannot break the header.
				// Headers are byte strings; JSON straight in would corrupt or throw.
				if (session.config != null) {
					forwardedHeaders.set(
						'x-sa-session-config',
						btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(session.config)))),
					);
				}
			}

			const forwardedRequest = new Request(request, { headers: forwardedHeaders });
			const response = await durableObjectStub.fetch(forwardedRequest);

			if (response.status === 101) {
				return response;
			}


			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: response.headers,
			});

		} catch (error: any) {
			return new Response(
				JSON.stringify({
					error: 'Failed to route to Broadcaster',
					projectId,
					details: error.message,
					timestamp: Date.now()
				}),
				{
					status: 500,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}
	},
};

