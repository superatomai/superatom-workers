import type { ContentfulStatusCode } from "hono/utils/http-status";

/** Thrown inside graph handlers (and transactions, which it rolls back); the route turns it into a JSON response. */
export class HttpError extends Error {
  constructor(
    public status: ContentfulStatusCode,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

/** Postgres unique violation, unwrapped from Drizzle's query error if needed. */
export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string } } | null;
  return e?.code === "23505" || e?.cause?.code === "23505";
}
