import { Hono } from "hono";
import { eq, and, sql } from "drizzle-orm";
import { answerFeedback, chatAnalytics } from "../db/schema";
import type { Env, AppVariables } from "../types";

const answerFeedbackRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

/**
 * POST /answer-feedback
 * Create or update answer feedback (server-to-server from backend, authenticated via service token)
 *
 * UPSERT behavior: Updates existing record if (userId, uiBlockId) matches.
 * Otherwise creates new record. Mirrors the local upsert key in
 * superatom-setup-code's answer_feedback table.
 *
 * Receives dual-write from backend collection after local upsert succeeds.
 * Central mirror of local answer_feedback table in superatom-setup-code.
 */
answerFeedbackRouter.post("/", async (c) => {
  const db = c.get("db");

  // Verify service token
  const serviceToken = c.req.header("X-SA-Service-Token");
  const expectedToken = c.env.SA_INTERNAL_SERVICE_TOKEN;

  if (!serviceToken || serviceToken !== expectedToken) {
    return c.json({ error: "Unauthorized: invalid or missing service token" }, 401);
  }

  const payload = await c.req.json<{
    orgId?: string;
    projectId?: string;
    userId?: string;
    threadId?: string;
    uiBlockId: string;
    userPrompt: string;
    status?: string;
    feedbackText?: string;
    answerSnapshot?: unknown;
  }>();

  if (!payload.uiBlockId || !payload.userPrompt) {
    return c.json(
      { error: "uiBlockId and userPrompt are required" },
      400
    );
  }

  // Validate status is one of the enum values or null
  const validStatuses = ['correct', 'incorrect', 'partial'];
  let status: any = null;

  if (payload.status) {
    if (!validStatuses.includes(payload.status)) {
      return c.json(
        { error: `status must be one of: ${validStatuses.join(', ')}, or null` },
        400
      );
    }
    status = payload.status;
  }

  // UPSERT: Insert or update if (userId, uiBlockId) exists
  const [inserted] = await db
    .insert(answerFeedback)
    .values({
      orgId: payload.orgId || null,
      projectId: payload.projectId || null,
      userId: payload.userId || null,
      threadId: payload.threadId || null,
      uiBlockId: payload.uiBlockId,
      userPrompt: payload.userPrompt,
      status: status as any,
      feedbackText: payload.feedbackText || null,
      answerSnapshot: payload.answerSnapshot || null,
    } as any)
    .onConflictDoUpdate({
      target: [
        answerFeedback.userId,
        answerFeedback.uiBlockId,
      ] as any,
      set: {
        status: status as any,
        feedbackText: payload.feedbackText || null,
        userPrompt: payload.userPrompt,
        answerSnapshot: payload.answerSnapshot || null,
      } as any,
    })
    .returning();

  // Mirror the verdict onto the event row so the analytics list/export can show
  // it without joining answer_feedback on every read. The event is found the same
  // way the feedback is keyed: same user, and the event's saved response id is the
  // feedback's uiBlockId. Best-effort — must never fail the feedback write itself.
  if (payload.userId) {
    try {
      await db
        .update(chatAnalytics)
        .set({ feedback: status ?? (payload.feedbackText ? "comment" : null) })
        .where(
          and(
            sql`${chatAnalytics.userId}::text = ${payload.userId}`,
            sql`${chatAnalytics.response}->>'id' = ${payload.uiBlockId}`,
            eq(chatAnalytics.type, "chat_agent"),
          ),
        );
    } catch (err) {
      console.error("[answer-feedback] failed to mirror feedback onto chat_analytics:", err);
    }
  }

  // Format timestamp to ISO string to preserve timezone info
  const formattedInserted = {
    ...inserted,
    createdAt: inserted.createdAt.toISOString(),
  };

  return c.json(formattedInserted, 201);
});

export default answerFeedbackRouter;
