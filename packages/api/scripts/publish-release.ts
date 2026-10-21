/**
 * Publishes a client release: builds the project's branch into an image, writes it
 * into the registry bucket, and uploads the deploy bundle the VM needs.
 *
 *   pnpm publish-release --env dev|prod --project <projectId> [--branch <b>] [--version <v>] [--repo <path>]
 *   pnpm publish-release --env dev|prod --baseline [--branch main]
 *
 * --baseline builds the platform release every new client starts on, into the shared
 * "base" repo. It writes no project row: projects point at it when they are created,
 * so onboarding needs no per-client build.
 *
 * The branch defaults to the project's code_branch. The release row is written
 * only after every artifact is uploaded, so a row always has an image behind it.
 *
 * The bundle carries the release's whole source tree plus a generated RELEASE.md, so
 * a client VM can be debugged against the exact code its image was built from, and
 * can be rebuilt from the Dockerfile if a pull ever fails.
 *
 * --local builds the working tree instead of origin/<branch>, for testing before a
 * push. Versions are suffixed -local and prod is refused, so an unpushed tree can
 * never become a client's release.
 *
 * Uploads go through R2's S3 API, not wrangler: `wrangler r2 object put` fails with
 * 502 on objects of a few hundred MB, which image layers routinely are.
 *
 * Without --local the build runs from a pristine worktree of origin/<branch>, so
 * nothing uncommitted or unpushed can end up in a client's image.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { AwsClient } from "aws4fetch";
import { neon, neonConfig } from "@neondatabase/serverless";

const run = promisify(execFile);
const BUCKET = "superatom-install";
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID ?? "91e1058d99235b9c34602fb0c28916d3";
const CREDS = join(import.meta.dirname ?? __dirname, "..", ".r2-publish.vars");
const DEFAULT_REPO = join(process.env.HOME ?? "", "superatom", "superatom-setup-code");
// R2 multipart wants equal parts; 64 MB keeps a 1 GB layer to ~16 requests.
const PART_SIZE = 64 * 1024 * 1024;
const MULTIPART_ABOVE = 100 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Shared repo every active project key may pull from; must match src/install/registry.ts.
const BASE_REPO = "base";

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

/** The control-plane database for one environment, from the same files the migrations use. */
function db(env: string) {
  const file = join(import.meta.dirname ?? __dirname, "..", env === "prod" ? ".env" : ".dev.vars");
  if (!existsSync(file)) fail(`${file} not found — cannot reach the ${env} database`);
  const line = readFileSync(file, "utf8").split("\n").find((l) => l.startsWith("DATABASE_URL="));
  if (!line) fail(`${file} has no DATABASE_URL`);
  // SA_NEON_VIA_POOLER=1 where the driver's default api.<region>.neon.tech endpoint
  // has no resolvable A record; the pooler host in the URL serves the same /sql.
  if (process.env.SA_NEON_VIA_POOLER === "1") {
    neonConfig.fetchEndpoint = (host: string) => `https://${host}/sql`;
  }
  return neon(line.slice("DATABASE_URL=".length).trim());
}

/** The baseline release a new project starts on, or null if none is published. */
async function baselinePointer(env: string): Promise<{ version: string; commit: string } | null> {
  const { client, base } = s3();
  const res = await client.fetch(`${base}/registry/${BASE_REPO}/current-release.${env}.json`);
  if (!res.ok) return null;
  const j = (await res.json()) as { version?: string; commit?: string };
  return j.version && j.commit ? { version: j.version, commit: j.commit } : null;
}

/** Engine versions this release expects, pinned from the mirror's current pointer. */
async function engineVersions(): Promise<{ docker: string | null; compose: string | null }> {
  const { client, base } = s3();
  const res = await client.fetch(`${base}/engine/current.json`);
  if (!res.ok) return { docker: null, compose: null };
  const j = (await res.json()) as { docker?: string; compose?: string };
  return { docker: j.docker ?? null, compose: j.compose ?? null };
}

/** Client-database migrations in this release, so a rollback across one can warn. */
function migrationCount(tree: string): number | null {
  try {
    const journal = JSON.parse(
      readFileSync(join(tree, "database", "postgres", "drizzle", "migrations", "meta", "_journal.json"), "utf8"));
    return Array.isArray(journal.entries) ? journal.entries.length : null;
  } catch {
    return null;
  }
}

function sh(cmd: string, args: string[], cwd?: string) {
  return run(cmd, args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

/**
 * The bundle is the release's tracked source tree plus RELEASE.md: git decides what is
 * in it, so an untracked secret (a stray backend/.env.local) can never be shipped.
 */
async function makeBundle(
  repo: string, tree: string, sha: string, bundle: string, local: boolean,
): Promise<void> {
  const tar = bundle.replace(/\.gz$/, "");
  if (local) {
    // Tracked paths, working-tree content — the only way --local differs from a commit.
    const list = `${tar}.files`;
    writeFileSync(list, (await sh("git", ["-C", repo, "ls-files", "-z"])).stdout);
    await sh("tar", ["-cf", tar, "-C", tree, "--null", "-T", list]);
  } else {
    await sh("git", ["-C", repo, "archive", "--format=tar", "-o", tar, sha]);
  }
  await sh("tar", ["-rf", tar, "-C", tree, "RELEASE.md"]);
  await sh("gzip", ["-9f", tar]);
}

type Prev = { version: string; commit: string } | undefined;

/** The commit log between two releases, or why it could not be produced. */
export async function changeLog(repo: string, commit: string, prev: Prev): Promise<string> {
  const git = async (args: string[]) =>
    (await sh("git", ["-C", repo, ...args]).catch(() => ({ stdout: "" }))).stdout.trimEnd();

  if (!prev) return "First release for this project — nothing to compare against.";
  if (prev.commit === commit) return `Same commit as \`${prev.version}\`; only release metadata differs.`;

  const log = await git(["log", "--oneline", "--no-decorate", `${prev.commit}..${commit}`]);
  const stat = await git(["diff", "--stat", prev.commit, commit]);
  if (!log && !stat) {
    return `Could not diff against \`${prev.version}\` (${prev.commit.slice(0, 12)}) — that commit is ` +
      "not in the publishing clone, or the two branches are unrelated.";
  }
  const parts = [`Since \`${prev.version}\` (${prev.commit.slice(0, 12)}):`];
  if (log) parts.push("```\n" + log + "\n```");
  else parts.push("_No new commits — this release is at or behind the previous one._");
  if (stat) parts.push("```\n" + stat + "\n```");
  return parts.join("\n\n");
}

/** RELEASE.md: what this release is and what changed, for debugging on the VM itself. */
export async function releaseNotes(
  repo: string, r: Record<string, unknown>, prev: Prev, local: boolean,
): Promise<string> {
  // Untracked files count too: --local copies the whole tree into the build context.
  const status = local
    ? (await sh("git", ["-C", repo, "status", "--porcelain"]).catch(() => ({ stdout: "" }))).stdout
        .split("\n").filter(Boolean)
    : [];
  const untracked = status.filter((l) => l.startsWith("??")).length;
  const modified = status.length - untracked;

  const table = [
    "| | |",
    "|---|---|",
    `| branch | \`${r.branch}\` |`,
    `| commit | \`${r.commit}\` |`,
    `| image | \`${r.image}\` |`,
    `| digest | \`${r.imageDigest}\` |`,
    `| docker / compose | ${r.engineVersion ?? "?"} / ${r.composeVersion ?? "?"} |`,
    `| client migrations | ${r.migrations ?? "?"} |`,
    `| published | ${new Date().toISOString()} by ${r.publishedBy} |`,
  ].join("\n");

  return [
    `# Release ${r.version}`,
    table,
    status.length
      ? `> ⚠ Built with \`--local\` from a working tree with ${modified} modified and ` +
        `${untracked} untracked path(s). The commit above does **not** fully describe ` +
        "what is in the image."
      : "",
    "## Changes",
    await changeLog(repo, r.commit as string, prev),
    "## Debugging this VM",
    "The source beside this file is the tree this release's image was built from, so " +
    "reading it here matches what the container runs. It is not mounted into the " +
    "container: the backend runs the code baked into the image.",
    "```\ndocker compose logs -f backend          # logs\n" +
    "docker compose exec backend sh          # a shell in the running release\n```",
    "## Rebuilding from source",
    "If the release image cannot be pulled, the stack can be built from the Dockerfile " +
    "here instead:",
    "```\ndocker compose up -d --build\n```",
    "This needs outbound internet (npmjs.com, deb.debian.org, docker.io) and produces an " +
    "image that is **not** the published release — its dependency resolution differs. Use " +
    "it to get a client running again, then re-pull once the registry is reachable.",
  ].filter(Boolean).join("\n\n") + "\n";
}

async function main() {
  const projectId = arg("project");
  const env = arg("env");
  const repo = arg("repo") ?? DEFAULT_REPO;
  // A baseline is the platform build every new client starts on: one image in the
  // shared "base" repo instead of one per project.
  const baseline = process.argv.includes("--baseline");
  if (!baseline && (!projectId || !UUID.test(projectId))) {
    fail("--project <projectId> (a uuid) is required, or --baseline");
  }
  if (baseline && projectId) fail("--baseline publishes for every project; drop --project");
  if (env !== "dev" && env !== "prod") fail("--env dev|prod is required (which control-plane database)");
  const local = process.argv.includes("--local");
  if (local && env === "prod") fail("--local cannot publish to prod: the tree is not pushed.");
  if (!existsSync(join(repo, "Dockerfile"))) fail(`${repo} has no Dockerfile — pass --repo <path to superatom-setup-code>`);

  const sql = db(env);
  let branch: string;
  let prev: Prev;

  if (baseline) {
    branch = arg("branch") ?? "main";
    // Diff against the baseline currently published, not against a project.
    const current = await baselinePointer(env);
    prev = current ? { version: current.version, commit: current.commit } : undefined;
    console.log(`${env}: baseline (shared "${BASE_REPO}" repo, every project may pull it)`);
  } else {
    // Fail before the build if the project is unknown, and take its branch unless told otherwise.
    const [project] = await sql`select name, slug, code_branch from projects where id = ${projectId}`;
    if (!project) fail(`project ${projectId} does not exist in the ${env} database`);
    // Read before the build: RELEASE.md diffs this release against it.
    const [prevRow] = await sql`select version, commit from project_releases
      where project_id = ${projectId} order by published_at desc limit 1`;
    prev = prevRow ? { version: prevRow.version as string, commit: prevRow.commit as string } : undefined;
    branch = arg("branch") ?? (project.code_branch as string);
    if (arg("branch") && arg("branch") !== project.code_branch) {
      console.log(`note: building ${branch}, but the project's code_branch is "${project.code_branch}"`);
    }
    console.log(`${env}: ${project.name} (${project.slug})`);
  }

  let sha: string;
  if (local) {
    sha = (await sh("git", ["-C", repo, "rev-parse", "HEAD"])).stdout.trim();
    console.log("⚠ --local: building the working tree, not origin/" + branch);
  } else {
    // Normally build only what is pushed, never a working tree.
    await sh("git", ["-C", repo, "fetch", "origin", branch, "--quiet"]).catch(() =>
      fail(`origin/${branch} does not exist in ${repo}`));
    sha = (await sh("git", ["-C", repo, "rev-parse", `origin/${branch}`])).stdout.trim();
  }
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
  const version = arg("version") ?? `${stamp}-${sha.slice(0, 12)}${local ? "-local" : ""}`;
  // Everything below writes under this repo: a project id, or the shared baseline.
  const repoName = baseline ? BASE_REPO : projectId!;
  console.log(`repo    ${repoName}\nbranch  ${branch} @ ${sha.slice(0, 12)}\nversion ${version}\n`);

  const work = mkdtempSync(join(tmpdir(), "publish-"));
  const tree = join(work, "src");
  try {
    if (local) {
      await sh("cp", ["-a", `${repo}/.`, tree]);
      console.log("Building image (working tree copy)…");
    } else {
      await sh("git", ["-C", repo, "worktree", "add", "--detach", tree, sha]);
      console.log("Building image (pristine worktree)…");
    }
    // The repository name IS the project id: that is what the registry routes
    // authorise against (src/install/registry.ts), so it must match exactly.
    const repoTag = `${repoName}:${version}`;
    await sh("docker", ["buildx", "build", "--builder", "ocibuilder",
      "--output", `type=oci,dest=${join(work, "image.tar")}`, "-t", repoTag, tree]);

    const layout = join(work, "oci");
    await sh("mkdir", ["-p", layout]);
    await sh("tar", ["-xf", join(work, "image.tar"), "-C", layout]);
    const index = JSON.parse(readFileSync(join(layout, "index.json"), "utf8"));
    const mDesc = index.manifests[0];
    const manifestFile = join(layout, "blobs", "sha256", mDesc.digest.split(":")[1]);
    const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));

    console.log("\nUploading blobs…");
    for (const d of [manifest.config, ...manifest.layers]) {
      const key = `registry/${repoName}/blobs/${d.digest}`;
      if (await exists(key)) { console.log(`  = ${d.digest.slice(0, 19)}… already present`); continue; }
      const what = await upload(key, join(layout, "blobs", "sha256", d.digest.split(":")[1]), "application/octet-stream");
      console.log(`  ✓ ${d.digest.slice(0, 19)}… ${what}`);
    }

    // By tag AND by digest: the client resolves the tag, then re-fetches by digest.
    const manifestBody = await readFile(manifestFile);
    for (const ref of [version, mDesc.digest]) {
      await putSmall(`registry/${repoName}/manifests/${ref}`, manifestBody, mDesc.mediaType);
      console.log(`  ✓ manifests/${ref}`);
    }

    const engine = await engineVersions();
    const migrations = migrationCount(tree);
    const publishedBy =
      (await sh("git", ["-C", repo, "config", "user.email"]).catch(() => ({ stdout: "" }))).stdout.trim() ||
      process.env.USER || "unknown";
    const meta = {
      version, branch, commit: sha,
      image: repoTag,
      imageDigest: mDesc.digest,
      engineVersion: engine.docker,
      composeVersion: engine.compose,
      migrations,
      publishedBy,
    };

    console.log("\nUploading the deploy bundle…");
    // Written after the build, so the image stays a pure function of the commit.
    writeFileSync(join(tree, "RELEASE.md"), await releaseNotes(repo, meta, prev, local));
    // The same log goes in the release row, so the UI needs no access to the bundle.
    const notes = await changeLog(repo, sha, prev);
    const bundle = join(work, "bundle.tar.gz");
    await makeBundle(repo, tree, sha, bundle, local);
    const what = await upload(`bundles/${repoName}/${version}/bundle.tar.gz`, bundle, "application/gzip");
    const bundleSha = createHash("sha256").update(await readFile(bundle)).digest("hex");
    console.log(`  ✓ bundles/${repoName}/${version}/bundle.tar.gz ${what}`);

    // Last, so a row never points at artifacts that are not there.
    const release = { ...meta, bundleSha256: bundleSha };
    if (baseline) {
      // Per environment: dev and prod share the bucket, and this pointer is the one
      // mutable, environment-specific object in it.
      const pointer = `registry/${BASE_REPO}/current-release.${env}.json`;
      await putSmall(pointer, Buffer.from(JSON.stringify({ ...release, notes }, null, 2) + "\n"), "application/json");
      console.log(`  ✓ ${pointer}`);
      console.log(`\n✔ baseline published\n${JSON.stringify(release, null, 2)}`);
      console.log("\nNew projects start on this release; existing ones move to it from the super-admin console.");
      return;
    }
    try {
      await sql`insert into project_releases
        (project_id, version, branch, commit, image, image_digest, bundle_sha256,
         engine_version, compose_version, migrations, published_by, notes)
        values (${projectId}, ${version}, ${branch}, ${sha}, ${repoTag}, ${mDesc.digest}, ${bundleSha},
                ${engine.docker}, ${engine.compose}, ${migrations}, ${publishedBy}, ${notes})`;
    } catch (err: any) {
      // (project_id, version) is unique: a published version is immutable.
      if (String(err?.message ?? "").includes("project_releases_version_idx")) {
        fail(`version ${version} is already published for this project. Publish a new version instead.\n` +
             `  Artifacts were uploaded; they are content-addressed, so nothing is duplicated.`);
      }
      throw err;
    }
    console.log(`\n✔ published and registered in ${env}\n${JSON.stringify(release, null, 2)}`);
    console.log(`\nA VM installs it with: curl -fsSL https://${env === "prod" ? "" : "dev."}install.superatom.ai | sh`);
  } finally {
    if (!local) await sh("git", ["-C", repo, "worktree", "remove", "--force", tree]).catch(() => {});
    rmSync(work, { recursive: true, force: true });
  }
}

// Guarded so the notes helpers above can be imported and tested on their own.
if (process.argv[1]?.includes("publish-release")) main().catch((err) => fail(err.message));
