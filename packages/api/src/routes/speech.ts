import { Hono } from "hono";
import { eq, and, sql, desc, gte, lte, count, sum, avg } from "drizzle-orm";
import type { Env, AppVariables } from "../types";
import { authMiddleware, adminOnly, scopedOrgId } from "../middleware/auth";
import { speechUsage } from "../db/schema";

const speechRouter = new Hono<{ Bindings: Env; Variables: AppVariables }>();

const MODEL = "google/chirp-3";
const MAX_AUDIO_BYTES = 10 * 1024 * 1024;
const MAX_VOCAB_CHARS = 2000;

/**
 * Browser MIME → OpenRouter `format`. The browser sends whatever MediaRecorder
 * gave it; we never assume a container. A wrong format is not rejected upstream,
 * it silently transcribes nothing (see docs/SPEECH-TO-TEXT-DESIGN.md §2.2) — so
 * unknown types are rejected here.
 */
const FORMATS: Record<string, string> = {
  "audio/webm": "webm",   // Chrome, Edge
  "audio/ogg": "ogg",     // Firefox
  "audio/mp4": "m4a",     // Safari
  "audio/x-m4a": "m4a",
  "audio/aac": "aac",
  "audio/mpeg": "mp3",
  "audio/mp3": "mp3",
  "audio/wav": "wav",
  "audio/wave": "wav",
  "audio/x-wav": "wav",
  "audio/flac": "flac",
};

/** "audio/webm;codecs=opus" → "webm" */
function toFormat(mime: string): string | undefined {
  return FORMATS[mime.split(";")[0].trim().toLowerCase()];
}

speechRouter.use("*", authMiddleware);   // NOT adminOnly — every signed-in user gets voice

/**
 * GET /speech/capabilities
 * Lets the UI decide whether to render the mic button without a per-client build
 * flag — the worker is the single source of truth for whether voice is configured.
 */
speechRouter.get("/capabilities", (c) =>
  c.json({ available: Boolean(c.env.OPENROUTER_API_KEY), maxDurationMs: 30_000 })
);

/**
 * POST /speech/transcribe
 * multipart/form-data: audio (File), vocabulary? (string), projectId? (string)
 * → { text: string }
 */
speechRouter.post("/transcribe", async (c) => {
  const userId = c.get("userId");
  const orgId = c.get("orgId");

  if (!c.env.OPENROUTER_API_KEY) {
    return c.json({ error: "Voice input is not configured on this deployment" }, 503);
  }

  const { success } = await c.env.SPEECH_RATE_LIMITER.limit({ key: userId });
  if (!success) {
    return c.json({ error: "Too many voice requests. Wait a moment and try again." }, 429);
  }

  const form = await c.req.formData();
  const file = form.get("audio");
  if (!(file instanceof File)) return c.json({ error: "No audio provided" }, 400);

  const format = toFormat(file.type);
  if (!format) return c.json({ error: `Unsupported audio type: ${file.type}` }, 400);
  if (file.size > MAX_AUDIO_BYTES) return c.json({ error: "Audio too large" }, 400);
  if (file.size < 1024) return c.json({ text: "" });   // tapped the mic, said nothing

  const vocabulary = String(form.get("vocabulary") || "").slice(0, MAX_VOCAB_CHARS);
  const projectId = String(form.get("projectId") || "") || null;

  const startedAt = Date.now();
  let text: string;
  let seconds = 0;
  let cost = 0;

  try {
    const res = await transcribe(c.env.OPENROUTER_API_KEY, await file.arrayBuffer(), format, vocabulary);
    text = res.text;
    seconds = res.seconds;
    cost = res.cost;
  } catch (err: any) {
    c.executionCtx.waitUntil(logUsage(c, { userId, orgId, projectId, bytes: file.size, latencyMs: Date.now() - startedAt, ok: false }));
    console.error("[speech] transcription failed:", err?.message);
    return c.json({ error: "Transcription failed. Please try again." }, 502);
  }

  c.executionCtx.waitUntil(logUsage(c, {
    userId, orgId, projectId, bytes: file.size,
    latencyMs: Date.now() - startedAt, seconds, cost, ok: true,
  }));

  return c.json({ text });
});

// Shared by /usage, /usage/summary, /usage/trends — same org/project/user/date scoping.
function parseUsageScopeParams(c: any) {
  const orgId = scopedOrgId(c);
  const projectId = c.req.query("projectId");
  const userId = c.req.query("userId");
  const from = c.req.query("from");
  const to = c.req.query("to");

  const conditions = [];
  if (orgId) conditions.push(eq(speechUsage.orgId, orgId));
  if (projectId) conditions.push(eq(speechUsage.projectId, projectId));
  if (userId) conditions.push(eq(speechUsage.userId, userId));
  if (from) conditions.push(gte(speechUsage.createdAt, new Date(from)));
  if (to) conditions.push(lte(speechUsage.createdAt, new Date(to)));

  return { orgId, projectId, userId, from, to, where: conditions.length > 0 ? and(...conditions) : undefined };
}

/**
 * GET /speech/usage?orgId=&projectId=&userId=&ok=&from=&to=&limit=&offset=
 * Raw usage rows (admin only). Bytes/seconds/cost/latency only — transcript
 * content is never logged (docs/SPEECH-TO-TEXT-DESIGN.md §9), so there's
 * nothing sensitive in these rows beyond the usual usage-metering shape.
 */
speechRouter.get("/usage", adminOnly, async (c) => {
  const db = c.get("db");
  const { where } = parseUsageScopeParams(c);
  const ok = c.req.query("ok");
  const limit = Math.min(Number(c.req.query("limit") || 50), 200);
  const offset = Number(c.req.query("offset") || 0);

  const conditions = where ? [where] : [];
  if (ok === "true" || ok === "false") conditions.push(eq(speechUsage.ok, ok === "true"));
  const finalWhere = conditions.length > 0 ? and(...conditions) : undefined;

  const rows = await db
    .select()
    .from(speechUsage)
    .where(finalWhere)
    .orderBy(desc(speechUsage.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json(rows);
});

/**
 * GET /speech/usage/summary?orgId=&projectId=&from=&to=
 * Aggregated totals plus per-user and per-org breakdowns (admin only).
 */
speechRouter.get("/usage/summary", adminOnly, async (c) => {
  const db = c.get("db");
  const { where } = parseUsageScopeParams(c);

  const [overall] = await db
    .select({
      totalRequests: count(),
      totalCost: sum(speechUsage.cost),
      totalSeconds: sum(speechUsage.audioSeconds),
      avgLatencyMs: avg(speechUsage.latencyMs),
      successCount: count(sql`CASE WHEN ${speechUsage.ok} = true THEN 1 END`),
      errorCount: count(sql`CASE WHEN ${speechUsage.ok} = false THEN 1 END`),
      uniqueUsers: sql<number>`COUNT(DISTINCT ${speechUsage.userId})`,
    })
    .from(speechUsage)
    .where(where);

  const userBreakdown = await db
    .select({
      userId: speechUsage.userId,
      requestCount: count(),
      totalCost: sum(speechUsage.cost),
      totalSeconds: sum(speechUsage.audioSeconds),
    })
    .from(speechUsage)
    .where(where)
    .groupBy(speechUsage.userId)
    .orderBy(desc(count()))
    .limit(20);

  const orgBreakdown = await db
    .select({
      orgId: speechUsage.orgId,
      requestCount: count(),
      totalCost: sum(speechUsage.cost),
      totalSeconds: sum(speechUsage.audioSeconds),
    })
    .from(speechUsage)
    .where(where)
    .groupBy(speechUsage.orgId)
    .orderBy(desc(count()));

  return c.json({ overall, userBreakdown, orgBreakdown });
});

// Same rationale as analytics.ts's MAX_TRENDS_SPAN_DAYS — dailyBreakdown is
// one row per day, so an unbounded range is an unbounded response.
const MAX_USAGE_TRENDS_SPAN_DAYS = 366;

/**
 * GET /speech/usage/trends?orgId=&projectId=&from=&to=
 * Per-day request counts plus a success/error breakdown (admin only).
 */
speechRouter.get("/usage/trends", adminOnly, async (c) => {
  const db = c.get("db");
  const { where, from, to } = parseUsageScopeParams(c);

  if (from && to) {
    const spanDays = (new Date(to).getTime() - new Date(from).getTime()) / 86400000;
    if (spanDays > MAX_USAGE_TRENDS_SPAN_DAYS) {
      return c.json({ error: `from/to span too wide — max ${MAX_USAGE_TRENDS_SPAN_DAYS} days` }, 400);
    }
  }

  const dailyBreakdown = await db
    .select({
      date: sql<string>`to_char(${speechUsage.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`,
      requestCount: count(),
    })
    .from(speechUsage)
    .where(where)
    .groupBy(sql`to_char(${speechUsage.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`)
    .orderBy(sql`to_char(${speechUsage.createdAt} AT TIME ZONE 'UTC', 'YYYY-MM-DD')`);

  const statusBreakdown = await db
    .select({
      ok: speechUsage.ok,
      requestCount: count(),
    })
    .from(speechUsage)
    .where(where)
    .groupBy(speechUsage.ok);

  return c.json({ dailyBreakdown, statusBreakdown });
});

async function transcribe(apiKey: string, audio: ArrayBuffer, format: string, vocabulary: string) {
  const body: Record<string, unknown> = {
    model: MODEL,
    input_audio: { data: toBase64(audio), format },
    // NO `language` pin — see docs/SPEECH-TO-TEXT-DESIGN.md §4.4. Auto-detect,
    // and return whatever language was spoken. Forcing "en" would make the
    // recognizer decode non-English speech AS English, producing phonetic
    // garbage rather than a translation.
  };
  // Provider passthrough for vocabulary biasing — see §4.3. Harmless if unsupported:
  // unknown provider options are ignored, not rejected (verified).
  if (vocabulary) {
    body.provider = { options: { google: { prompt: `Expected vocabulary: ${vocabulary}` } } };
  }

  const res = await fetch("https://openrouter.ai/api/v1/audio/transcriptions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://superatom.ai",
      "X-Title": "Superatom Voice Input",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),   // upstream caps processing at 60s
  });

  if (!res.ok) throw new Error(`OpenRouter ${res.status}: ${(await res.text()).slice(0, 300)}`);

  const data: any = await res.json();

  // Integrity guard (§2.2). `usage.seconds` is present only when audio was really
  // ingested. Without this, a dropped upload reads to the user as "you said nothing."
  const seconds = data?.usage?.seconds ?? 0;
  if (!seconds) throw new Error("audio was not ingested (no usage.seconds in response)");

  return {
    text: String(data?.text ?? "").trim(),
    seconds,
    cost: data?.usage?.cost ?? 0,
  };
}

/** Chunked — String.fromCharCode(...bytes) blows the stack on ~1 MB inputs. */
function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** Best-effort metering — never blocks or fails the user's transcription. */
async function logUsage(c: any, row: any) {
  try {
    await c.get("db").insert(speechUsage).values({
      orgId: row.orgId, userId: row.userId, projectId: row.projectId,
      model: MODEL, audioBytes: row.bytes,
      audioSeconds: row.seconds ? String(row.seconds) : null,
      cost: row.cost ? String(row.cost) : null,
      latencyMs: row.latencyMs, ok: row.ok,
    });
  } catch (err: any) {
    console.warn("[speech] usage log failed:", err?.message);
  }
}

export default speechRouter;
