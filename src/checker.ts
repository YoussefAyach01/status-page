import type { Db } from './db.js';
import { safeFetch, type SafeFetchOptions, type SafeFetchResult } from './ssrf.js';
import { dueMonitors, pruneChecks, recordCheck, type CheckOutcome, type Monitor } from './store.js';

export type Fetcher = (url: string, o: SafeFetchOptions) => Promise<SafeFetchResult>;

export interface CheckerOptions {
  allowPrivate?: boolean;
  fetcher?: Fetcher;
  concurrency?: number;
}

/** Default: any 2xx or 3xx is "up" (we never follow redirects). expectedStatus overrides. */
export function isUp(status: number, expected: number | null): boolean {
  return expected !== null ? status === expected : status >= 200 && status < 400;
}

export async function checkOnce(m: Monitor, opts: CheckerOptions = {}): Promise<CheckOutcome> {
  const fetcher = opts.fetcher ?? safeFetch;
  try {
    const r = await fetcher(m.url, {
      method: m.method,
      timeoutMs: m.timeoutMs,
      allowPrivate: opts.allowPrivate,
      maxBodyBytes: 512,
    });
    const ok = isUp(r.status, m.expectedStatus);
    return {
      ok,
      statusCode: r.status,
      latencyMs: r.durationMs,
      error: ok ? null : `HTTP ${r.status}`,
    };
  } catch (e) {
    return {
      ok: false,
      statusCode: null,
      latencyMs: null,
      error: (e instanceof Error ? e.message : String(e)).slice(0, 200),
    };
  }
}

/** One pass: check every due monitor (bounded concurrency), record results. Returns how many ran. */
export async function checkerTick(
  db: Db,
  now = new Date(),
  opts: CheckerOptions = {},
): Promise<number> {
  const due = dueMonitors(db, now);
  const width = opts.concurrency ?? 10;
  for (let i = 0; i < due.length; i += width) {
    await Promise.all(
      due.slice(i, i + width).map(async (m) => {
        const outcome = await checkOnce(m, opts);
        try {
          recordCheck(db, m, outcome, now);
        } catch (e) {
          // Monitor deleted while its check was in flight: nothing to record.
          console.error('recordCheck failed', m.id, e instanceof Error ? e.message : e);
        }
      }),
    );
  }
  return due.length;
}

export { pruneChecks };
