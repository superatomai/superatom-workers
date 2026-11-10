import { and, eq, isNotNull } from "drizzle-orm";
import { apiKeys, installTokens, projects } from "../db/schema";
import type { Database } from "../db";
import type { Env } from "../types";
import { disableProxyClient } from "../install/lib";

export interface ProjectDeleteSteps {
  exists(): Promise<boolean>;
  proxyClientIds(): Promise<string[]>;
  disableProxyClient(clientId: string): Promise<boolean>;
  /** Deactivates the project's API keys and deletes the row, atomically. */
  deleteWithKeys(): Promise<void>;
}

export type ProjectDeleteResult =
  | { status: "deleted" }
  | { status: "not_found" }
  | { status: "proxy_failed"; clientId: string };

/**
 * A deleted project must not leave working credentials. Proxy clients go first: the
 * delete cascades install_tokens, the only link from a project to its proxy client.
 */
export async function deleteProject(steps: ProjectDeleteSteps): Promise<ProjectDeleteResult> {
  if (!(await steps.exists())) return { status: "not_found" };
  for (const clientId of await steps.proxyClientIds()) {
    if (!(await steps.disableProxyClient(clientId))) return { status: "proxy_failed", clientId };
  }
  await steps.deleteWithKeys();
  return { status: "deleted" };
}

export function projectDeleteSteps(db: Database, env: Env, orgId: string, projectId: string): ProjectDeleteSteps {
  const scoped = and(eq(projects.id, projectId), eq(projects.orgId, orgId));
  return {
    async exists() {
      const [row] = await db.select({ id: projects.id }).from(projects).where(scoped).limit(1);
      return !!row;
    },
    async proxyClientIds() {
      const rows = await db
        .selectDistinct({ id: installTokens.llmClientId })
        .from(installTokens)
        .where(and(eq(installTokens.projectId, projectId), isNotNull(installTokens.llmClientId)));
      return rows.map((r) => r.id!).filter(Boolean);
    },
    disableProxyClient: (clientId) => disableProxyClient(env, clientId),
    async deleteWithKeys() {
      await db.batch([
        db.update(apiKeys).set({ isActive: false }).where(and(eq(apiKeys.projectId, projectId), eq(apiKeys.isActive, true))),
        db.delete(projects).where(scoped),
      ]);
    },
  };
}
