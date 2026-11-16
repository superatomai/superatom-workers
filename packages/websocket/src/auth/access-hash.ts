/**
 * A stable fingerprint for a user's data-access config — see ACCESS-AUDIT-PLAN.md.
 *
 * THE RULES ARE A CONTRACT. The engine hashes the same config in its own process
 * (sdk-nodejs) and the two must agree byte for byte, or every lookup misses and
 * the trail is silently useless. Change them in both places.
 *
 *   Keys sorted · arrays sorted · strings trimmed · `undefined` dropped.
 *   Arrays are sets here (sources, policies, tables, filter values), so order
 *   carries no meaning.
 *
 * Nothing is lower-cased. Folding `dbo`/`DBO` but not `Laura`/`laura` would make
 * this schema-aware, and a schema-aware rule is one the engine has to mirror as
 * it grows. Two rows instead of one is much cheaper than two different configs
 * sharing a hash.
 *
 * Only ever called with a real config: a user with no restriction is recorded by
 * chat_analytics.access_source rather than by a hash.
 */

function canonical(value: unknown): unknown {
	if (typeof value === 'string') return value.trim();
	if (value === null || typeof value !== 'object') return value;

	if (Array.isArray(value)) {
		return value
			.filter((item) => item !== undefined)
			.map(canonical)
			.map((item) => [JSON.stringify(item) ?? 'null', item] as const)
			.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
			.map(([, item]) => item);
	}

	const source = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	// Insertion order is what JSON.stringify emits, so sorting here is what makes
	// it deterministic.
	for (const key of Object.keys(source).sort()) {
		if (source[key] === undefined) continue;
		out[key] = canonical(source[key]);
	}
	return out;
}

/** The exact string that gets hashed. Exported so a mismatch can be diffed. */
export function canonicalAccessJson(config: unknown): string {
	return JSON.stringify(canonical(config)) ?? 'null';
}

/** sha256 of the canonical form, lower-case hex. Async: Workers only offer WebCrypto. */
export async function accessHash(config: unknown): Promise<string> {
	const bytes = new TextEncoder().encode(canonicalAccessJson(config));
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}
