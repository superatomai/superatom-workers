/**
 * Publishes a client release: builds the project's branch into an image, writes it
 * into the registry bucket, and uploads the deploy bundle the VM needs.
 *
 *   pnpm publish-release --project <projectId> --branch <branch> [--version <v>] [--repo <path>]
 *
 * Uploads go through R2's S3 API, not wrangler: `wrangler r2 object put` fails with
 * 502 on objects of a few hundred MB, which image layers routinely are.
 *
 * The build always runs from a pristine worktree of origin/<branch>, so nothing
 * uncommitted or unpushed can end up in a client's image.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, createReadStream, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { AwsClient } from "aws4fetch";

const run = promisify(execFile);
const BUCKET = "superatom-install";
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID ?? "91e1058d99235b9c34602fb0c28916d3";
const CREDS = join(import.meta.dirname ?? __dirname, "..", ".r2-publish.vars");
const DEFAULT_REPO = join(process.env.HOME ?? "", "superatom", "superatom-setup-code");
// R2 multipart wants equal parts; 64 MB keeps a 1 GB layer to ~16 requests.
const PART_SIZE = 64 * 1024 * 1024;
const MULTIPART_ABOVE = 100 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(message: string): never {
  console.error(`\n✖ ${message}`);
  process.exit(1);
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

/** S3 credentials for the registry bucket, from a gitignored file. */
function s3(): { client: AwsClient; base: string } {
  if (!existsSync(CREDS)) {
    fail(`Missing ${CREDS}.\n  Create an R2 API token (Object Read & Write on ${BUCKET}) and write:\n` +
         `    R2_S3_ACCESS_KEY_ID=...\n    R2_S3_SECRET_ACCESS_KEY=...`);
  }
  const vars = Object.fromEntries(
    readFileSync(CREDS, "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()])
  );
  const accessKeyId = vars.R2_S3_ACCESS_KEY_ID, secretAccessKey = vars.R2_S3_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) fail(`${CREDS} needs R2_S3_ACCESS_KEY_ID and R2_S3_SECRET_ACCESS_KEY`);
  return {
    client: new AwsClient({ accessKeyId, secretAccessKey, service: "s3", region: "auto" }),
    base: `https://${ACCOUNT_ID}.r2.cloudflarestorage.com/${BUCKET}`,
  };
}

async function exists(key: string): Promise<boolean> {
  const { client, base } = s3();
  const res = await client.fetch(`${base}/${key}`, { method: "HEAD" });
  return res.status === 200;
}

async function putSmall(key: string, body: Buffer, contentType: string): Promise<void> {
  const { client, base } = s3();
  const res = await client.fetch(`${base}/${key}`, {
    method: "PUT", body, headers: { "Content-Type": contentType },
  });
  if (!res.ok) fail(`PUT ${key} -> ${res.status} ${(await res.text()).slice(0, 200)}`);
}

/** Multipart upload, for layers too big for a single request. */
async function putLarge(key: string, file: string, contentType: string): Promise<void> {
  const { client, base } = s3();
  const start = await client.fetch(`${base}/${key}?uploads`, { method: "POST", headers: { "Content-Type": contentType } });
  if (!start.ok) fail(`multipart start ${key} -> ${start.status}`);
  const uploadId = /<UploadId>([^<]+)<\/UploadId>/.exec(await start.text())?.[1];
  if (!uploadId) fail(`no UploadId for ${key}`);

  const size = statSync(file).size;
  const parts: { n: number; etag: string }[] = [];
  const fh = await import("node:fs/promises").then((m) => m.open(file, "r"));
  try {
    for (let offset = 0, n = 1; offset < size; offset += PART_SIZE, n++) {
      const length = Math.min(PART_SIZE, size - offset);
      const buf = Buffer.alloc(length);
      await fh.read(buf, 0, length, offset);
      const res = await client.fetch(`${base}/${key}?partNumber=${n}&uploadId=${uploadId}`, { method: "PUT", body: buf });
      if (!res.ok) fail(`part ${n} of ${key} -> ${res.status}`);
      const etag = res.headers.get("ETag");
      if (!etag) fail(`part ${n} of ${key} returned no ETag`);
      parts.push({ n, etag });
      process.stdout.write(`\r    part ${n} (${((offset + length) / size * 100).toFixed(0)}%)`);
    }
  } finally {
    await fh.close();
  }
  const body = `<CompleteMultipartUpload>${parts
    .map((p) => `<Part><PartNumber>${p.n}</PartNumber><ETag>${p.etag}</ETag></Part>`).join("")}</CompleteMultipartUpload>`;
  const done = await client.fetch(`${base}/${key}?uploadId=${uploadId}`, { method: "POST", body });
  if (!done.ok) fail(`multipart complete ${key} -> ${done.status} ${(await done.text()).slice(0, 200)}`);
  process.stdout.write("\r");
}

async function upload(key: string, file: string, contentType: string): Promise<string> {
  const size = statSync(file).size;
  const mb = (size / 1024 / 1024).toFixed(1);
  if (size > MULTIPART_ABOVE) {
    await putLarge(key, file, contentType);
    return `${mb} MB (multipart)`;
  }
  await putSmall(key, await readFile(file), contentType);
  return `${mb} MB`;
}

function sh(cmd: string, args: string[], cwd?: string) {
  return run(cmd, args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

async function main() {
  const projectId = arg("project");
  const branch = arg("branch");
  const repo = arg("repo") ?? DEFAULT_REPO;
  if (!projectId || !UUID.test(projectId)) fail("--project <projectId> (a uuid) is required");
  if (!branch) fail("--branch <branch> is required");
  if (!existsSync(join(repo, "Dockerfile"))) fail(`${repo} has no Dockerfile — pass --repo <path to superatom-setup-code>`);

  // Always build what is pushed, never a working tree.
  await sh("git", ["-C", repo, "fetch", "origin", branch, "--quiet"]).catch(() =>
    fail(`origin/${branch} does not exist in ${repo}`));
  const sha = (await sh("git", ["-C", repo, "rev-parse", `origin/${branch}`])).stdout.trim();
  const version = arg("version") ??
    `${new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-")}-${sha.slice(0, 12)}`;
  console.log(`project ${projectId}\nbranch  ${branch} @ ${sha.slice(0, 12)}\nversion ${version}\n`);

  const work = mkdtempSync(join(tmpdir(), "publish-"));
  const tree = join(work, "src");
  try {
    await sh("git", ["-C", repo, "worktree", "add", "--detach", tree, sha]);
    console.log("Building image (pristine worktree)…");
    await sh("docker", ["buildx", "build", "--builder", "ocibuilder",
      "--output", `type=oci,dest=${join(work, "image.tar")}`, "-t", `superatom-${projectId}:${version}`, tree]);

    const layout = join(work, "oci");
    await sh("mkdir", ["-p", layout]);
    await sh("tar", ["-xf", join(work, "image.tar"), "-C", layout]);
    const index = JSON.parse(readFileSync(join(layout, "index.json"), "utf8"));
    const mDesc = index.manifests[0];
    const manifestFile = join(layout, "blobs", "sha256", mDesc.digest.split(":")[1]);
    const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));

    console.log("\nUploading blobs…");
    for (const d of [manifest.config, ...manifest.layers]) {
      const key = `registry/${projectId}/blobs/${d.digest}`;
      if (await exists(key)) { console.log(`  = ${d.digest.slice(0, 19)}… already present`); continue; }
      const what = await upload(key, join(layout, "blobs", "sha256", d.digest.split(":")[1]), "application/octet-stream");
      console.log(`  ✓ ${d.digest.slice(0, 19)}… ${what}`);
    }

    // By tag AND by digest: the client resolves the tag, then re-fetches by digest.
    const manifestBody = await readFile(manifestFile);
    for (const ref of [version, mDesc.digest]) {
      await putSmall(`registry/${projectId}/manifests/${ref}`, manifestBody, mDesc.mediaType);
      console.log(`  ✓ manifests/${ref}`);
    }

    console.log("\nUploading the deploy bundle…");
    const bundle = join(work, "bundle.tar.gz");
    await sh("tar", ["-czf", bundle, "-C", tree, "docker-compose.yml", "setup.sh"]);
    const what = await upload(`bundles/${projectId}/${version}/bundle.tar.gz`, bundle, "application/gzip");
    const bundleSha = createHash("sha256").update(await readFile(bundle)).digest("hex");
    console.log(`  ✓ bundles/${projectId}/${version}/bundle.tar.gz ${what}`);

    const release = {
      version, branch, commit: sha,
      image: `superatom-${projectId}:${version}`,
      imageDigest: mDesc.digest,
      bundleSha256: bundleSha,
      publishedAt: new Date().toISOString(),
    };
    console.log(`\n✔ published\n${JSON.stringify(release, null, 2)}`);
    console.log("\nNot yet registered in project_releases (schema step still to come).");
  } finally {
    await sh("git", ["-C", repo, "worktree", "remove", "--force", tree]).catch(() => {});
    rmSync(work, { recursive: true, force: true });
  }
}

main().catch((err) => fail(err.message));
