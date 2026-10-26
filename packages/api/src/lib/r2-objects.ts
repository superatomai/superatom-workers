/**
 * Calls on objects in the private source-files bucket, shared by every route that
 * keeps files there.
 *
 * Every call goes through R2's S3 API with the same credentials, never the
 * R2_SOURCE_FILES binding. Under `wrangler dev` that binding is a local simulation,
 * so it never sees what the browser (or the backend) PUT to the real bucket; the
 * S3 API sees the same bucket everywhere.
 */
import { AwsClient } from "aws4fetch";
import type { Env } from "../types";

export function r2S3Client(env: Env): AwsClient {
	return new AwsClient({
		accessKeyId: env.R2_ACCESS_KEY_ID,
		secretAccessKey: env.R2_SECRET_ACCESS_KEY,
		service: "s3",
		region: "auto",
	});
}

export function objectUrl(env: Env, key: string): string {
	return `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_SOURCE_FILES_BUCKET_NAME}/${encodeURI(key)}`;
}

/** Deletes one object. A key that is already gone counts as deleted. */
export async function deleteObject(env: Env, key: string): Promise<void> {
	const res = await r2S3Client(env).fetch(objectUrl(env, key), { method: "DELETE" });
	if (!res.ok && res.status !== 404) {
		throw new Error(`R2 DELETE failed: HTTP ${res.status} ${await res.text().catch(() => "")}`.trim());
	}
}

/**
 * A presigned URL for one object. `query` adds response overrides such as
 * `response-content-disposition`, which must be part of what is signed.
 */
export async function signObjectUrl(
	env: Env,
	key: string,
	method: "GET" | "PUT",
	ttlSeconds: number,
	query: Record<string, string> = {},
): Promise<string> {
	const url = new URL(objectUrl(env, key));
	url.searchParams.set("X-Amz-Expires", String(ttlSeconds));
	for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
	const signed = await r2S3Client(env).sign(url.toString(), { method, aws: { signQuery: true } });
	return signed.url;
}

export type ObjectCheck =
	| { state: "ok"; size: number; contentType: string | null; etag: string | null }
	| { state: "missing" }
	| { state: "empty" }
	| { state: "unreadable" }
	| { state: "error"; status: number };

/**
 * Checks an object landed, and reads its size. A one-byte ranged GET rather than
 * HEAD: its Content-Range ("bytes 0-0/<total>") always carries the size, where a
 * HEAD's Content-Length can come back empty. An empty object can't be ranged at all (416).
 */
export async function checkObject(env: Env, key: string): Promise<ObjectCheck> {
	const probe = await r2S3Client(env).fetch(objectUrl(env, key), {
		method: "GET",
		headers: { Range: "bytes=0-0" },
	});
	await probe.body?.cancel();
	if (probe.status === 404) return { state: "missing" };
	if (probe.status === 416) return { state: "empty" };
	if (!probe.ok) return { state: "error", status: probe.status };

	const size = Number(probe.headers.get("content-range")?.split("/")[1]);
	if (!Number.isFinite(size)) return { state: "unreadable" };
	return {
		state: "ok",
		size,
		contentType: probe.headers.get("content-type"),
		etag: probe.headers.get("etag")?.replace(/"/g, "") || null,
	};
}
