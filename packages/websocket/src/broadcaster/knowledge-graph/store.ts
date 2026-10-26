import { executeQuery } from '../../api-keys/service';
import type { GraphHead } from './types';

// Every read and write of the platform's graph tables the relay makes, in one
// place. The rest of the folder never writes SQL, so moving these behind sa-api
// (one owner for the graph data) changes only this file.

/** The release this project's engines should run: the target of its latest release event. */
export async function currentRelease(db: string, projectId: string): Promise<GraphHead | null> {
	const rows = await executeQuery<any>(
		db,
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

/** Whether this project has a release with that id and content. */
export async function releaseMatches(db: string, projectId: string, releaseId: number, rootHash: string): Promise<boolean> {
	const rows = await executeQuery<any>(
		db,
		`SELECT 1 FROM graph_releases WHERE id = $1 AND project_id = $2::uuid AND root_hash = $3`,
		[releaseId, projectId, rootHash],
	);
	return rows.length > 0;
}

/** Whether this project has a release with that seq. */
export async function releaseSeqExists(db: string, projectId: string, seq: number): Promise<boolean> {
	const rows = await executeQuery<any>(
		db,
		`SELECT 1 FROM graph_releases WHERE project_id = $1::uuid AND seq = $2`,
		[projectId, seq],
	);
	return rows.length > 0;
}

/** Every item of a release, with its content. */
export async function releaseItems(db: string, projectId: string, releaseId: number) {
	const rows = await executeQuery<any>(
		db,
		`SELECT v.entity, v.entity_id::int AS id, v.rev::int AS rev, v.hash, v.content::text AS content
		   FROM graph_releases r
		   CROSS JOIN LATERAL jsonb_to_recordset(r.items) AS x(entity text, id int, rev int)
		   JOIN graph_revisions v ON v.entity = x.entity AND v.entity_id = x.id AND v.rev = x.rev
		  WHERE r.id = $1 AND r.project_id = $2::uuid AND v.project_id = $2::uuid`,
		[releaseId, projectId],
	);
	return rows.map((r) => ({
		entity: r.entity,
		id: Number(r.id),
		rev: Number(r.rev),
		hash: String(r.hash),
		content: JSON.parse(r.content),
	}));
}

export type EngineStatus = {
	status: 'in_sync' | 'behind' | 'error';
	releaseId?: number | null;
	rootHash?: string | null;
	error?: string | null;
	acked?: boolean;
};

/** Record what an engine runs (graph_engine_state); an `error` sticks until the engine is in sync again. */
export async function recordEngine(db: string, projectId: string, engineId: string, s: EngineStatus): Promise<void> {
	await executeQuery(
		db,
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

/** The change seq an engine's draft is at. The row exists from the engine's hello; one not yet seen there is recorded on its next hello. */
export async function recordDraftAck(db: string, projectId: string, engineId: string, changeSeq: number): Promise<void> {
	await executeQuery(
		db,
		`UPDATE graph_engine_state SET applied_change_seq = $3, last_seen_at = now()
		  WHERE project_id = $1::uuid AND engine_id = $2`,
		[projectId, engineId, changeSeq],
	);
}

/** The project's last change number, or null when the platform has no draft. */
export async function draftHead(db: string, projectId: string): Promise<number | null> {
	const rows = await executeQuery<any>(
		db,
		`SELECT seq::text AS seq FROM graph_change_heads WHERE project_id = $1::uuid`,
		[projectId],
	);
	return rows.length ? Number(rows[0].seq) : null;
}

/**
 * Draft items as they are now, in the same shape a release revision has.
 * `afterSeq` null: every live item. Otherwise every item changed in
 * (afterSeq, headSeq], deleted ones with `deleted: true` and no content.
 */
export async function draftItems(db: string, projectId: string, afterSeq: number | null, headSeq: number) {
	const changed = (entity: string, alias: string) =>
		afterSeq === null
			? `${alias}.deleted_at IS NULL`
			: `${alias}.id IN (SELECT entity_id FROM graph_changes
			                  WHERE project_id = $1::uuid AND entity = '${entity}' AND seq > $2 AND seq <= $3)`;
	const rows = await executeQuery<any>(
		db,
		`SELECT 'node' AS entity, n.id::int AS id, (n.deleted_at IS NOT NULL) AS deleted,
		        CASE WHEN n.deleted_at IS NULL THEN jsonb_build_object(
		          'kind', n.kind, 'name', n.name, 'title', n.title, 'body', n.body, 'meta', n.meta, 'status', n.status,
		          'edges', COALESCE((SELECT jsonb_agg(jsonb_build_object('role', e.role, 'position', e.position,
		                                                                 'nodeId', e.child_node_id, 'conceptId', e.child_concept_id)
		                                              ORDER BY e.role, e.position)
		                               FROM graph_edges e WHERE e.parent_id = n.id), '[]'::jsonb),
		          'terms', COALESCE((SELECT jsonb_agg(jsonb_build_object('term', t.term, 'weight', t.weight) ORDER BY t.term)
		                               FROM graph_domain_terms t WHERE t.node_id = n.id), '[]'::jsonb)
		        )::text END AS content
		   FROM graph_nodes n
		  WHERE n.project_id = $1::uuid AND ${changed('node', 'n')}
		 UNION ALL
		 SELECT 'concept', c.id::int, (c.deleted_at IS NOT NULL),
		        CASE WHEN c.deleted_at IS NULL THEN jsonb_build_object(
		          'name', c.name, 'body', c.body, 'kind', c.kind, 'type', c.type, 'requires', to_jsonb(c.requires),
		          'returns', c.returns, 'aliases', to_jsonb(c.aliases), 'description', c.description, 'sourceId', c.source_id,
		          'active', c.active
		        )::text END
		   FROM concepts c
		  WHERE c.project_id = $1::uuid AND ${changed('concept', 'c')}`,
		afterSeq === null ? [projectId] : [projectId, afterSeq, headSeq],
	);
	return rows.map((r) => ({
		entity: r.entity as 'node' | 'concept',
		id: Number(r.id),
		...(r.deleted ? { deleted: true } : { content: JSON.parse(r.content) }),
	}));
}

/** Every release after seq `have`, oldest first. */
export async function releasesAfter(db: string, projectId: string, have: number) {
	const rows = await executeQuery<any>(
		db,
		`SELECT id::int AS id, seq::int AS seq, items::text AS items, root_hash, parent_release_id::int AS parent_release_id,
		        notes, created_at
		   FROM graph_releases
		  WHERE project_id = $1::uuid AND seq > $2
		  ORDER BY seq`,
		[projectId, have],
	);
	return rows.map((r) => ({
		type: 'release' as const,
		id: Number(r.id),
		seq: Number(r.seq),
		items: JSON.parse(r.items),
		rootHash: String(r.root_hash),
		parentReleaseId: r.parent_release_id == null ? null : Number(r.parent_release_id),
		notes: r.notes ?? null,
		createdAt: r.created_at,
	}));
}

/** The revisions the releases after seq `have` use that no release up to `have` used. */
export async function revisionsAfter(db: string, projectId: string, have: number) {
	const rows = await executeQuery<any>(
		db,
		`WITH wanted AS (
		   SELECT DISTINCT x.entity, x.id, x.rev
		     FROM graph_releases r CROSS JOIN LATERAL jsonb_to_recordset(r.items) AS x(entity text, id int, rev int)
		    WHERE r.project_id = $1::uuid AND r.seq > $2
		   EXCEPT
		   SELECT x.entity, x.id, x.rev
		     FROM graph_releases r CROSS JOIN LATERAL jsonb_to_recordset(r.items) AS x(entity text, id int, rev int)
		    WHERE r.project_id = $1::uuid AND r.seq <= $2
		 )
		 SELECT v.entity, v.entity_id::int AS id, v.rev::int AS rev, v.hash, v.content::text AS content, v.created_at
		   FROM wanted w
		   JOIN graph_revisions v ON v.entity = w.entity AND v.entity_id = w.id AND v.rev = w.rev
		  WHERE v.project_id = $1::uuid`,
		[projectId, have],
	);
	return rows.map((r) => ({
		type: 'revision' as const,
		entity: r.entity,
		id: Number(r.id),
		rev: Number(r.rev),
		hash: String(r.hash),
		content: JSON.parse(r.content),
		createdAt: r.created_at,
	}));
}
