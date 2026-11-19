/**
 * The triage rule for a piece of answer feedback, as a pure function.
 *
 * Pulled out of the route so it can be tested without a database and without a
 * request, because two of its three behaviours are the kind that fail quietly:
 *
 *  - an ABSENT `resolution` must produce NO fields. The mirror's write is an
 *    upsert, so a `{}` that defaulted to `open` would reopen a closed row every
 *    time someone edited the feedback text.
 *  - the four outcomes that are a judgement call are refused without a reason,
 *    because a report that cannot say why something was dropped is no better
 *    than not having recorded it.
 *
 * MIRRORED in the engine (`database/postgres/src/project-data-db/feedback-resolution.ts`).
 * The engine refuses first; this is the second line. If the lists ever disagree,
 * a forward the engine accepted is 400ed here and the mirror silently drifts.
 */

export const FEEDBACK_RESOLUTIONS = [
  'open',
  'resolved',
  'later_scope',
  'not_an_issue',
  'duplicate',
  'needs_info',
] as const;

export type FeedbackResolution = (typeof FEEDBACK_RESOLUTIONS)[number];

/** `open` and `resolved` speak for themselves; the rest are a decision. */
export const RESOLUTIONS_NEEDING_NOTE: readonly string[] = [
  'later_scope',
  'not_an_issue',
  'duplicate',
  'needs_info',
];

export interface ResolutionInput {
  resolution?: string;
  resolutionNote?: string | null;
  resolvedBy?: string | null;
  resolvedAt?: string | null;
}

export type ResolutionUpdate =
  | { ok: true; fields: Record<string, unknown> }
  | { ok: false; error: string };

/**
 * The columns to write, or why the payload is refused.
 *
 * An empty `fields` is the correct answer for a payload that says nothing about
 * triage — spread into both halves of the upsert it changes nothing.
 */
export function resolutionUpdate(payload: ResolutionInput): ResolutionUpdate {
  if (payload.resolution === undefined) return { ok: true, fields: {} };

  if (!(FEEDBACK_RESOLUTIONS as readonly string[]).includes(payload.resolution)) {
    return {
      ok: false,
      error: `resolution must be one of: ${FEEDBACK_RESOLUTIONS.join(', ')}`,
    };
  }

  const note = payload.resolutionNote?.trim() || null;

  if (RESOLUTIONS_NEEDING_NOTE.includes(payload.resolution) && !note) {
    return {
      ok: false,
      error: `resolutionNote is required when resolution is ${payload.resolution}`,
    };
  }

  return {
    ok: true,
    fields: {
      resolution: payload.resolution,
      resolutionNote: note,
      resolvedBy: payload.resolvedBy ?? null,
      resolvedAt: payload.resolvedAt ? new Date(payload.resolvedAt) : null,
    },
  };
}
