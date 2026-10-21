/**
 * Mirrors the third-party images the stack runs (postgres, chroma) into the
 * registry's shared `base` repository, so a VM that can only reach
 * *.superatom.ai never needs Docker Hub.
 *
 *   pnpm mirror-base-images
 *
 * Copies through Docker Hub's registry API rather than `docker push`: our
 * registry is read-only, and publishing means writing objects.
 *
 * amd64 only, matching the backend images we build.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AwsClient } from "aws4fetch";

const ACCOUNT = process.env.CLOUDFLARE_ACCOUNT_ID ?? "91e1058d99235b9c34602fb0c28916d3";
const BUCKET = "superatom-install";
const REPO = "base";
const HUB = "https://registry-1.docker.io";
const PLATFORM = { os: "linux", architecture: "amd64" };
const PART_SIZE = 64 * 1024 * 1024;

// What the stack's compose file runs, and the tag each gets in our `base` repo.
const IMAGES = [
  { source: "library/postgres", reference: "16-bookworm", tag: "postgres-16-bookworm" },
  { source: "chromadb/chroma", reference: "1.0.0", tag: "chroma-1.0.0" },
];

const MANIFEST_TYPES = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

function fail(message: string): never {
  console.error(`\n✖ ${message}`);
  process.exit(1);
}

function s3() {
  const file = join(import.meta.dirname ?? __dirname, "..", ".r2-publish.vars");
  const vars = Object.fromEntries(
    readFileSync(file, "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()])
  );
  return {
    client: new AwsClient({ accessKeyId: vars.R2_S3_ACCESS_KEY_ID, secretAccessKey: vars.R2_S3_SECRET_ACCESS_KEY,
                            service: "s3", region: "auto" }),
    base: `https://${ACCOUNT}.r2.cloudflarestorage.com/${BUCKET}`,
  };
}

/** Anonymous pull token for one Docker Hub repository. */
async function hubToken(source: string): Promise<string> {
  const res = await fetch(
    `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${source}:pull`);
  if (!res.ok) fail(`Docker Hub token for ${source} -> ${res.status}`);
  return ((await res.json()) as { token: string }).token;
}

async function hub(source: string, token: string, path: string, accept?: string): Promise<Response> {
  const res = await fetch(`${HUB}/v2/${source}/${path}`, {
    headers: { Authorization: `Bearer ${token}`, ...(accept ? { Accept: accept } : {}) },
    redirect: "follow",
  });
  if (!res.ok) fail(`${source}/${path} -> ${res.status}`);
  return res;
}

async function exists(key: string): Promise<boolean> {
  const { client, base } = s3();
  return (await client.fetch(`${base}/${key}`, { method: "HEAD" })).status === 200;
}

async function putBuffer(key: string, body: Buffer, contentType: string): Promise<void> {
  const { client, base } = s3();
  if (body.byteLength <= 100 * 1024 * 1024) {
    const res = await client.fetch(`${base}/${key}`, { method: "PUT", body, headers: { "Content-Type": contentType } });
    if (!res.ok) fail(`PUT ${key} -> ${res.status}`);
    return;
  }
  const start = await client.fetch(`${base}/${key}?uploads`, { method: "POST", headers: { "Content-Type": contentType } });
  const uploadId = /<UploadId>([^<]+)<\/UploadId>/.exec(await start.text())?.[1];
  if (!uploadId) fail(`multipart start ${key}`);
  const parts: string[] = [];
  for (let offset = 0, n = 1; offset < body.byteLength; offset += PART_SIZE, n++) {
    const chunk = body.subarray(offset, Math.min(offset + PART_SIZE, body.byteLength));
    const res = await client.fetch(`${base}/${key}?partNumber=${n}&uploadId=${uploadId}`, { method: "PUT", body: chunk });
    if (!res.ok) fail(`part ${n} of ${key} -> ${res.status}`);
    parts.push(`<Part><PartNumber>${n}</PartNumber><ETag>${res.headers.get("ETag")}</ETag></Part>`);
    process.stdout.write(`\r      part ${n}`);
  }
  const done = await client.fetch(`${base}/${key}?uploadId=${uploadId}`, {
    method: "POST", body: `<CompleteMultipartUpload>${parts.join("")}</CompleteMultipartUpload>` });
  if (!done.ok) fail(`multipart complete ${key} -> ${done.status}`);
  process.stdout.write("\r");
}

const digestOf = (body: Buffer) => "sha256:" + createHash("sha256").update(body).digest("hex");

async function mirror(image: typeof IMAGES[number]) {
  console.log(`\n${image.source}:${image.reference}  →  ${REPO}:${image.tag}`);
  const token = await hubToken(image.source);

  // A multi-arch tag resolves to an index; pick the platform we run.
  let manifestBody = Buffer.from(await (await hub(image.source, token, `manifests/${image.reference}`, MANIFEST_TYPES)).arrayBuffer());
  let manifest = JSON.parse(manifestBody.toString());
  let mediaType: string = manifest.mediaType ?? "application/vnd.oci.image.manifest.v1+json";
  if (Array.isArray(manifest.manifests)) {
    const match = manifest.manifests.find((m: any) => m.platform?.os === PLATFORM.os && m.platform?.architecture === PLATFORM.architecture);
    if (!match) fail(`${image.source}:${image.reference} has no ${PLATFORM.os}/${PLATFORM.architecture} manifest`);
    console.log(`  index → ${PLATFORM.architecture} manifest ${match.digest.slice(0, 19)}…`);
    manifestBody = Buffer.from(await (await hub(image.source, token, `manifests/${match.digest}`, MANIFEST_TYPES)).arrayBuffer());
    manifest = JSON.parse(manifestBody.toString());
    mediaType = match.mediaType ?? manifest.mediaType;
  }

  for (const d of [manifest.config, ...manifest.layers]) {
    const key = `registry/${REPO}/blobs/${d.digest}`;
    if (await exists(key)) { console.log(`  = ${d.digest.slice(0, 19)}… already present`); continue; }
    const body = Buffer.from(await (await hub(image.source, token, `blobs/${d.digest}`)).arrayBuffer());
    if (digestOf(body) !== d.digest) fail(`blob ${d.digest} failed its checksum`);
    await putBuffer(key, body, "application/octet-stream");
    console.log(`  ✓ ${d.digest.slice(0, 19)}… ${(body.byteLength / 1024 / 1024).toFixed(1)} MB`);
  }

  // By tag and by digest, as the pull protocol needs both.
  const digest = digestOf(manifestBody);
  for (const ref of [image.tag, digest]) {
    await putBuffer(`registry/${REPO}/manifests/${ref}`, manifestBody, mediaType);
  }
  console.log(`  ✓ manifests/${image.tag} and manifests/${digest.slice(0, 19)}…`);
  return { tag: image.tag, digest, from: `${image.source}:${image.reference}` };
}

async function main() {
  const mirrored = [];
  for (const image of IMAGES) mirrored.push(await mirror(image));
  // A pointer, so setup.sh and the console can see what is available.
  await putBuffer(`registry/${REPO}/current.json`,
    Buffer.from(JSON.stringify({ images: mirrored, mirroredAt: new Date().toISOString() }, null, 2) + "\n"),
    "application/json");
  console.log(`\n✔ mirrored ${mirrored.length} base images into ${REPO}`);
  for (const m of mirrored) console.log(`    ${REPO}:${m.tag}  (${m.from})`);
}

main().catch((err) => fail(err.message));
