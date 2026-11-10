/**
 * Parcels — large payloads that travel beside the websocket instead of through it.
 *
 * A sender (engine SDK or browser SDK) that has more than fits comfortably in one
 * websocket message uploads it here and sends only a small receipt over the
 * socket. The receiver downloads it by that receipt. The Durable Object never
 * carries the bytes, so nothing about message size or chunking reaches it.
 *
 * Stored in their own bucket (binding R2_PARCELS: sa-parcels / sa-parcels-dev),
 * content-addressed per project:
 *
 *     <projectId>/<sha256>.<ext>
 *
 * Short-lived by design: downloadable for PARCEL_TTL_MS after upload (enforced
 * here, on read). Deletion is the bucket's lifecycle rule — delete 1 day after
 * upload — so no code here removes anything. Re-sending identical content
 * overwrites the object, which starts its window again.
 *
 * Every read and write goes through the R2 binding, on purpose — the bytes pass
 * through this worker both ways, so it never needs a presigned URL or S3 keys.
 * (Under `wrangler dev` the binding is a local simulation, and lifecycle rules
 * do not run there.)
 */

/** How long a parcel can be downloaded after it was uploaded. */
export const PARCEL_TTL_MS = 30 * 60 * 1000;

/** Largest parcel accepted. Workers cap request bodies at 100 MB on the base plan. */
export const MAX_PARCEL_BYTES = 95 * 1024 * 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const EXT = /^[a-z0-9]{1,10}$/;

export const isProjectId = (v: unknown): v is string => typeof v === "string" && UUID.test(v);
export const isSha256 = (v: unknown): v is string => typeof v === "string" && SHA256.test(v);
export const isExt = (v: unknown): v is string => typeof v === "string" && EXT.test(v);

export const parcelKey = (projectId: string, hash: string, ext: string): string =>
  `${projectId}/${hash}.${ext}`;

export const isExpired = (uploaded: Date, now = Date.now()): boolean =>
  now - uploaded.getTime() > PARCEL_TTL_MS;
