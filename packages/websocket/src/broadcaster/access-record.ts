import { executeQuery } from '../api-keys/service';

/**
 * Recording what a user was allowed to see — see ACCESS-AUDIT-PLAN.md.
 *
 * Access is resolved on every connection (auth/session.ts) and then thrown
 * away, so a question answered last week cannot say what it was answered under.
 * Here we write it down once, keyed by a hash of its contents, for the engine's
 * analytics rows to point at.
 *
 * Only real restrictions are written. A user with nothing restricting them needs
 * no row — chat_analytics.access_source says 'none', which is the whole answer.
 *
 * Writing on every connection would be mostly waste: a tab reconnects all day
 * on the same access. So this DO keeps the hashes it has already written, per
 * user, and a config it has seen before costs nothing at all. Kept in DO
 * storage under one key, cached in memory — the same shape as the per-user
 * graph version map in knowledge-graph/versions.ts.
 *
 * Losing the map is harmless: the next connection re-writes a row the table
 * already has, and the insert does nothing.
 */

const STORAGE_KEY = 'accessHashes';

/**
 * Hashes remembered per user. A user whose access changes often — a customer
 * dropdown, a scenario switch — would otherwise grow this without end, so only
 * the most recent are kept. Dropping one costs a single redundant insert if
 * that config comes back.
 */
const PER_USER_LIMIT = 20;

type SeenMap = Record<string, string[]>;

export interface AccessRecordContext {
	storage: DurableObjectStorage;
	databaseUrl: string | undefined;
}

export class AccessRecord {
	private cache: SeenMap | null = null;

	constructor(private ctx: AccessRecordContext) {}

	private async load(): Promise<SeenMap> {
		if (!this.cache) this.cache = (await this.ctx.storage.get<SeenMap>(STORAGE_KEY)) || {};
		return this.cache;
	}

	/**
	 * Write this user's access, unless this DO has already written it.
	 *
	 * Never throws and never blocks the handshake: an audit row is not worth a
	 * refused connection. A failure leaves the hash unremembered, so the next
	 * connection tries again.
	 */
	async record(user: { userId: string; orgId: string | null }, config: unknown, hash: string | null): Promise<void> {
		const db = this.ctx.databaseUrl;
		if (!db || !user.userId || config == null || !hash) return;

		try {
			const seen = await this.load();
			const forUser = seen[user.userId] ?? [];
			if (forUser.includes(hash)) return;

			await executeQuery(
				db,
				`INSERT INTO access_configs (user_id, access_hash, org_id, config)
				      VALUES ($1::uuid, $2, $3::uuid, $4::jsonb)
				 ON CONFLICT (user_id, access_hash) DO NOTHING`,
				[user.userId, hash, user.orgId, JSON.stringify(config)],
			);

			// Only after the write, so a failure is retried rather than remembered.
			const next = [...forUser.filter((h) => h !== hash), hash].slice(-PER_USER_LIMIT);
			const map = { ...seen, [user.userId]: next };
			await this.ctx.storage.put(STORAGE_KEY, map);
			this.cache = map;
		} catch (error: any) {
			console.warn(`[access-record] could not record access for ${user.userId}:`, error?.message);
		}
	}
}
