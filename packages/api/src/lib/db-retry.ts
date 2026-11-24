/**
 * Bounded, retried database calls.
 *
 * Neon's HTTP SQL endpoint occasionally returns 520, drops the connection, or
 * hangs when routed through certain Cloudflare colos (and more often from a
 * developer's machine). Each attempt is bounded and retried, so a transient
 * blip costs a few seconds instead of a failed request or a long spinner.
 *
 * Only failures add attempts: a healthy database answers on the first one.
 */

/**
 * An error as plain fields, for a one-line JSON log. Logged as the object
 * itself, an Error often shows up in Cloudflare observability as `{}` — the
 * message, its cause (where Postgres and fetch put the real reason) and the
 * code are what say why.
 */
export function errorInfo(err: unknown) {
  const e = err as { name?: string; message?: string; code?: string; cause?: { message?: string; code?: string }; stack?: string };
  return {
    name: e?.name,
    message: e?.message ?? String(err),
    code: e?.code,
    cause: e?.cause?.message,
    causeCode: e?.cause?.code,
    at: e?.stack?.split("\n").slice(1, 4).map((l) => l.trim()),
  };
}

/**
 * Runs `fn`, giving each attempt `timeoutMs`, and tries again on a failure or a
 * timeout, up to `retries` more times. `fn` must start a NEW query each call.
 */
export async function withDbRetry<T>(
  label: string,
  fn: () => PromiseLike<T>,
  opts: { timeoutMs?: number; retries?: number } = {}
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 6000;
  const retries = opts.retries ?? 2;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        Promise.resolve(fn()),
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`db:${label} timed out after ${timeoutMs}ms`)), timeoutMs);
        }),
      ]);
    } catch (err) {
      lastErr = err;
      console.warn(JSON.stringify({ ev: "db_retry", label, attempt: attempt + 1, error: errorInfo(err) }));
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  throw lastErr;
}
