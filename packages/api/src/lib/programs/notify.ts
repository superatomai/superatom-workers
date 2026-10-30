import type { Env } from "../../types";

/** Tell the project's DO the program catalogue changed, so engines re-sync (a hint; engines also sync on boot). */
export async function notifyPrograms(env: Env, projectId: string): Promise<void> {
  if (!env.BROADCASTER) return;
  try {
    const stub = env.BROADCASTER.get(env.BROADCASTER.idFromName(projectId));
    await stub.fetch(`https://do/programs-changed?projectId=${encodeURIComponent(projectId)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ projectId }),
    });
  } catch (err) {
    console.warn("[programs] change notice failed:", (err as Error)?.message ?? err);
  }
}
