import { Hono } from "hono";
import { and, desc, eq, gt } from "drizzle-orm";
import { projectInstalls, projectReleases, projects, users } from "../db/schema";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly } from "../middleware/auth";
import { assertProjectAccess } from "../lib/project-access";

/**
 * Release state for one project, for the "a new version is available" panel.
 * Org admins see and approve updates for their own projects; a super admin sees any.
 *
 * Only what the VM reports and what an admin approved are stored. Whether an install
 * is behind, updating or in sync is derived here, so the rows cannot go stale.
 */
const releaseRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();
releaseRouter.use("*", authMiddleware, adminOnly);

type Install = typeof projectInstalls.$inferSelect;
type Release = typeof projectReleases.$inferSelect;

/** unknown | in_sync | updating | failed | update_available */
export function statusOf(inst: Install, newest: Release | undefined, pinned: string | null): string {
  if (!inst.releaseVersion) return "unknown";
  // A recorded error outranks the version match. The previous order asked "has it
  // reached its target?" first, so a failed update that had already written its
  // marker reported success. The updater clears lastError on its next good report.
  if (inst.lastError && inst.targetVersion) return "failed";
  if (pinned) return inst.releaseVersion === pinned ? "in_sync" : "updating";
  if (inst.targetVersion && inst.targetVersion !== inst.releaseVersion) return "updating";
  return newest && inst.releaseVersion !== newest.version ? "update_available" : "in_sync";
}

/** GET /projects/:projectId/release/status */
releaseRouter.get("/status", async (c) => {
  const projectId = c.req.param("projectId")!;
  const access = await assertProjectAccess(c, projectId);
  if (!access.ok) return c.json({ error: access.error }, access.status);

  const db = c.get("db");
  const [[project], releases, installs] = await Promise.all([
    db.select({ pinnedVersion: projects.pinnedVersion, codeBranch: projects.codeBranch })
      .from(projects).where(eq(projects.id, projectId)).limit(1),
    db.select().from(projectReleases).where(eq(projectReleases.projectId, projectId))
      .orderBy(desc(projectReleases.publishedAt)).limit(20),
    db.select().from(projectInstalls).where(eq(projectInstalls.projectId, projectId))
      .orderBy(projectInstalls.installName),
  ]);

  const newest = releases[0];
  const brief = (r: Release) => ({
    version: r.version, branch: r.branch, commit: r.commit.slice(0, 12),
    migrations: r.migrations, publishedBy: r.publishedBy, publishedAt: r.publishedAt,
    notes: r.notes,
  });

  return c.json({
    codeBranch: project?.codeBranch ?? null,
    pinnedVersion: project?.pinnedVersion ?? null,
    newest: newest ? brief(newest) : null,
    releases: releases.map(brief),
    installs: installs.map((i) => {
      const running = releases.find((r) => r.version === i.releaseVersion);
      return {
        installName: i.installName,
        running: i.releaseVersion,
        runningPublishedAt: running?.publishedAt ?? null,
        target: i.targetVersion,
        targetSetBy: i.targetSetBy,
        status: statusOf(i, newest, project?.pinnedVersion ?? null),
        // Within the 20 most recent; enough to say "2 releases behind".
        behind: running ? releases.filter((r) => r.publishedAt > running.publishedAt).length : null,
        // A positive delta means the update adds migrations, which a rollback will not undo.
        migrationsDelta:
          newest?.migrations != null && running?.migrations != null
            ? newest.migrations - running.migrations
            : null,
        lastSeenAt: i.lastSeenAt,
        lastError: i.lastError,
      };
    }),
  });
});

/** POST /projects/:projectId/release/target {installName, version} — the Update button. */
releaseRouter.post("/target", async (c) => {
  const projectId = c.req.param("projectId")!;
  const access = await assertProjectAccess(c, projectId);
  if (!access.ok) return c.json({ error: access.error }, access.status);

  const body = await c.req.json<{ installName?: unknown; version?: unknown }>().catch(() => null);
  const installName = typeof body?.installName === "string" ? body.installName.trim() : "";
  const version = typeof body?.version === "string" ? body.version.trim() : "";
  if (!installName || !version) return c.json({ error: "installName and version are required" }, 400);

  const db = c.get("db");
  const [project] = await db.select({ pinnedVersion: projects.pinnedVersion })
    .from(projects).where(eq(projects.id, projectId)).limit(1);
  if (project?.pinnedVersion) {
    return c.json(
      { error: `This project is pinned to ${project.pinnedVersion}. A super admin must unpin it before it can be updated.` },
      409
    );
  }

  const [release] = await db.select({ version: projectReleases.version })
    .from(projectReleases)
    .where(and(eq(projectReleases.projectId, projectId), eq(projectReleases.version, version)))
    .limit(1);
  if (!release) return c.json({ error: `Version ${version} is not published for this project` }, 404);

  const [who] = await db.select({ email: users.email }).from(users).where(eq(users.id, c.get("userId"))).limit(1);
  const [updated] = await db
    .update(projectInstalls)
    // The previous failure is this target's, not the new one's.
    .set({ targetVersion: version, targetSetBy: who?.email ?? c.get("userId"), targetSetAt: new Date(), lastError: null, updatedAt: new Date() })
    .where(and(eq(projectInstalls.projectId, projectId), eq(projectInstalls.installName, installName)))
    .returning();
  if (!updated) return c.json({ error: `No install named "${installName}" has reported for this project` }, 404);

  // The VM applies it on its next poll; until then the panel shows "updating".
  return c.json({ installName, target: version, status: "updating" });
});

export default releaseRouter;
