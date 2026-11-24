import type { BatchItem } from "drizzle-orm/batch";
import type { Database } from "../db";

/**
 * Runs these writes as one transaction: all of them apply, or none, so a save
 * that fails halfway leaves nothing half-made. Empty steps are skipped.
 */
export async function writeTogether(db: Database, steps: (BatchItem<"pg"> | null | false | undefined)[]): Promise<void> {
  const [first, ...rest] = steps.filter((step): step is BatchItem<"pg"> => !!step);
  if (first) await db.batch([first, ...rest]);
}
