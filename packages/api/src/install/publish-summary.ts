// What publish-release reports and records; kept out of the script so it can be tested.
const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;

/**
 * The publish summary. A new dependency set is uploaded before the image, so its layers then count as
 * "reused"; say what this run actually sent, or a first publish reads as a 4 MB upload.
 */
export function layerSummary(b: { newBytes: number; reusedBytes: number; depsUploadedBytes: number }): string {
  if (b.depsUploadedBytes > 0) {
    return `layers: deps ${mb(b.depsUploadedBytes)} uploaded (new dependency set), code ${mb(b.newBytes)} new`;
  }
  return `layers: new ${mb(b.newBytes)}, reused ${mb(b.reusedBytes)}`;
}

/**
 * The project's code_branch after a publish: the branch its newest release was built from, so the
 * console and Updates page never show a branch the release did not come from. A --local build is a test.
 */
export function branchToRecord(stored: string | undefined, built: string, local: boolean): string | null {
  return !local && stored !== undefined && stored !== built ? built : null;
}
