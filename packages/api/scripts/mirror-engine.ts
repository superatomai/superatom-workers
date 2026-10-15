/**
 * Mirrors the Docker Engine static binaries and the compose and buildx plugins into
 * R2, so a client VM installs them from *.superatom.ai instead of download.docker.com.
 *
 *   pnpm mirror-engine --docker 29.9.0 --compose 5.6.0 --buildx 0.38.0
 *
 * buildx is in the engine tarball's place, not the registry: it has to exist before
 * Docker can build anything, and Docker's static bundle does not ship it.
 *
 * Docker publishes no checksum for the static tarball, so we compute ours at
 * mirror time; compose and buildx publish theirs, which we verify. current.json is
 * written LAST, so a half-finished mirror is never pointed at.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync, statSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const BUCKET = "superatom-install";
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID ?? "91e1058d99235b9c34602fb0c28916d3";
const ARCHES = ["x86_64", "aarch64"] as const;
// buildx's release assets are named with Go's arch, not the engine tarball's.
const BUILDX_ARCH: Record<string, string> = { x86_64: "amd64", aarch64: "arm64" };
// pnpm hoists wrangler to the workspace root, so look there too.
const HERE = import.meta.dirname ?? __dirname;
const WRANGLER = [
  join(HERE, "..", "node_modules", ".bin", "wrangler"),
  join(HERE, "..", "..", "..", "node_modules", ".bin", "wrangler"),
].find((p) => existsSync(p)) ?? "wrangler";

function fail(msg: string): never {
  console.error(`\n✖ ${msg}`);
  process.exit(1);
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

async function wrangler(args: string[]): Promise<string> {
  try {
    const { stdout } = await run(WRANGLER, args, {
      env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID },
      maxBuffer: 16 * 1024 * 1024,
    });
    return stdout;
  } catch (err: any) {
    throw new Error(`wrangler ${args.slice(0, 4).join(" ")} failed:\n${err.stderr || err.message}`);
  }
}

async function download(url: string, to: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok || !res.body) fail(`${url} -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(to, buf);
  return createHash("sha256").update(buf).digest("hex");
}

async function put(key: string, file: string, contentType: string): Promise<void> {
  await wrangler(["r2", "object", "put", `${BUCKET}/${key}`, "--file", file, "--content-type", contentType]);
  const mb = (statSync(file).size / 1024 / 1024).toFixed(1);
  console.log(`  ✓ ${key}  (${mb} MB)`);
}

async function putText(key: string, text: string, contentType: string, dir: string): Promise<void> {
  const tmp = join(dir, key.replace(/\//g, "_"));
  writeFileSync(tmp, text);
  await wrangler(["r2", "object", "put", `${BUCKET}/${key}`, "--file", tmp, "--content-type", contentType]);
  console.log(`  ✓ ${key}`);
}

async function main() {
  const docker = arg("docker");
  const compose = arg("compose");
  const buildx = arg("buildx");
  if (!docker || !compose || !buildx) {
    fail("Usage: pnpm mirror-engine --docker <version> --compose <version> --buildx <version>");
  }
  for (const v of [docker, compose, buildx]) {
    if (!/^\d+\.\d+\.\d+$/.test(v)) fail(`Versions must be x.y.z (got ${v})`);
  }

  const dir = mkdtempSync(join(tmpdir(), "mirror-engine-"));
  try {
    for (const arch of ARCHES) {
      console.log(`\nDocker Engine ${docker} (${arch})`);
      const tgz = join(dir, `docker-${arch}.tgz`);
      const sha = await download(
        `https://download.docker.com/linux/static/stable/${arch}/docker-${docker}.tgz`, tgz);
      await put(`engine/docker/${docker}/${arch}.tgz`, tgz, "application/gzip");
      await putText(`engine/docker/${docker}/${arch}.tgz.sha256`, `${sha}\n`, "text/plain", dir);

      console.log(`\nCompose ${compose} (${arch})`);
      const bin = join(dir, `compose-${arch}`);
      const got = await download(
        `https://github.com/docker/compose/releases/download/v${compose}/docker-compose-linux-${arch}`, bin);
      // Upstream publishes "<sha>  <filename>"; verify before mirroring.
      const upstream = await (await fetch(
        `https://github.com/docker/compose/releases/download/v${compose}/docker-compose-linux-${arch}.sha256`)).text();
      const want = upstream.trim().split(/\s+/)[0];
      if (want !== got) fail(`compose ${arch} checksum mismatch: upstream ${want}, downloaded ${got}`);
      console.log(`  checksum verified against upstream`);
      await put(`engine/compose/${compose}/${arch}`, bin, "application/octet-stream");
      await putText(`engine/compose/${compose}/${arch}.sha256`, `${got}\n`, "text/plain", dir);

      console.log(`\nBuildx ${buildx} (${arch})`);
      const asset = `buildx-v${buildx}.linux-${BUILDX_ARCH[arch]}`;
      const bx = join(dir, `buildx-${arch}`);
      const bxGot = await download(
        `https://github.com/docker/buildx/releases/download/v${buildx}/${asset}`, bx);
      // One checksums.txt per release, lines of "<sha> *<asset>".
      const sums = await (await fetch(
        `https://github.com/docker/buildx/releases/download/v${buildx}/checksums.txt`)).text();
      const bxWant = sums.split("\n").map((l) => l.trim())
        .find((l) => l.endsWith(asset))?.split(/\s+/)[0];
      if (!bxWant) fail(`buildx ${buildx}: ${asset} is not listed in upstream checksums.txt`);
      if (bxWant !== bxGot) fail(`buildx ${arch} checksum mismatch: upstream ${bxWant}, downloaded ${bxGot}`);
      console.log(`  checksum verified against upstream`);
      await put(`engine/buildx/${buildx}/${arch}`, bx, "application/octet-stream");
      await putText(`engine/buildx/${buildx}/${arch}.sha256`, `${bxGot}\n`, "text/plain", dir);
    }

    // Last: nothing is served until the pointer moves.
    await putText("engine/current.json",
      JSON.stringify({ docker, compose, buildx, mirroredAt: new Date().toISOString() }) + "\n",
      "application/json", dir);
    console.log(`\n✔ mirrored docker ${docker} + compose ${compose} + buildx ${buildx} for ${ARCHES.join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err) => fail(err.message));
