import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { FAILURE_THRESHOLD, PLANS, type Plan } from './config.js';
import type { Db } from './db.js';

export class LimitError extends Error {}
export class ConflictError extends Error {}

const iso = (d: Date) => d.toISOString();
export const dayOf = (d: Date) => d.toISOString().slice(0, 10);

// ---------- API keys ----------
export interface ApiKey {
  id: string;
  label: string;
  plan: Plan;
}
/** 256-bit random keys: SHA-256 is sufficient (nothing to brute-force). */
export const hashKey = (k: string) => createHash('sha256').update(k).digest('hex');

export function createKey(db: Db, label: string, plan: Plan, now = new Date()) {
  const key = `sp_${randomBytes(32).toString('base64url')}`;
  const id = randomUUID();
  db.prepare(
    'INSERT INTO api_keys (id, key_hash, key_prefix, label, plan, created_at) VALUES (?,?,?,?,?,?)',
  ).run(id, hashKey(key), key.slice(0, 7), label, plan, iso(now));
  return { key, id, label, plan };
}
export function findKey(db: Db, key: string): ApiKey | null {
  const r = db
    .prepare('SELECT id, label, plan FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL')
    .get(hashKey(key));
  return (r as unknown as ApiKey) ?? null;
}
export function revokeKey(db: Db, id: string, now = new Date()): boolean {
  const r = db
    .prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
    .run(iso(now), id);
  return Number(r.changes) > 0;
}

// ---------- pages ----------
export interface Page {
  id: string;
  slug: string;
  title: string;
  createdAt: string;
}
const toPage = (r: Record<string, unknown>): Page => ({
  id: r.id as string,
  slug: r.slug as string,
  title: r.title as string,
  createdAt: r.created_at as string,
});

export function createPage(
  db: Db,
  key: ApiKey,
  slug: string,
  title: string,
  now = new Date(),
): Page {
  const n = db.prepare('SELECT COUNT(*) AS n FROM pages WHERE api_key_id = ?').get(key.id) as {
    n: number;
  };
  if (n.n >= PLANS[key.plan].maxPages) {
    throw new LimitError(`Your ${key.plan} plan allows ${PLANS[key.plan].maxPages} status page(s)`);
  }
  const id = randomUUID();
  try {
    db.prepare(
      'INSERT INTO pages (id, api_key_id, slug, title, created_at) VALUES (?,?,?,?,?)',
    ).run(id, key.id, slug, title, iso(now));
  } catch (e) {
    if (String(e).includes('UNIQUE')) throw new ConflictError('That slug is already taken');
    throw e;
  }
  return { id, slug, title, createdAt: iso(now) };
}
export function listPages(db: Db, keyId: string): Page[] {
  return db
    .prepare('SELECT * FROM pages WHERE api_key_id = ? ORDER BY created_at DESC, id')
    .all(keyId)
    .map(toPage);
}
export function getOwnedPage(db: Db, keyId: string, id: string): Page | null {
  const r = db.prepare('SELECT * FROM pages WHERE id = ? AND api_key_id = ?').get(id, keyId);
  return r ? toPage(r) : null;
}
export function deletePage(db: Db, keyId: string, id: string): boolean {
  return (
    Number(db.prepare('DELETE FROM pages WHERE id = ? AND api_key_id = ?').run(id, keyId).changes) >
    0
  );
}
export function getPageBySlug(db: Db, slug: string): Page | null {
  const r = db.prepare('SELECT * FROM pages WHERE slug = ?').get(slug);
  return r ? toPage(r) : null;
}

// ---------- monitors ----------
export interface Monitor {
  id: string;
  pageId: string;
  name: string;
  url: string;
  method: 'GET' | 'HEAD';
  intervalSeconds: number;
  expectedStatus: number | null;
  timeoutMs: number;
  status: 'unknown' | 'up' | 'down';
  consecutiveFailures: number;
  failingSince: string | null;
  lastCheckedAt: string | null;
  lastLatencyMs: number | null;
  lastError: string | null;
  nextCheckAt: string;
  createdAt: string;
}
const toMonitor = (r: Record<string, unknown>): Monitor => ({
  id: r.id as string,
  pageId: r.page_id as string,
  name: r.name as string,
  url: r.url as string,
  method: r.method as 'GET' | 'HEAD',
  intervalSeconds: r.interval_seconds as number,
  expectedStatus: (r.expected_status as number | null) ?? null,
  timeoutMs: r.timeout_ms as number,
  status: r.status as Monitor['status'],
  consecutiveFailures: r.consecutive_failures as number,
  failingSince: (r.failing_since as string | null) ?? null,
  lastCheckedAt: (r.last_checked_at as string | null) ?? null,
  lastLatencyMs: (r.last_latency_ms as number | null) ?? null,
  lastError: (r.last_error as string | null) ?? null,
  nextCheckAt: r.next_check_at as string,
  createdAt: r.created_at as string,
});

export interface NewMonitor {
  name: string;
  url: string;
  method: 'GET' | 'HEAD';
  intervalSeconds: number;
  expectedStatus?: number | null;
  timeoutMs?: number;
}

function assertInterval(plan: Plan, seconds: number) {
  if (seconds < PLANS[plan].minIntervalSeconds) {
    throw new LimitError(
      `Your ${plan} plan allows checks every ${PLANS[plan].minIntervalSeconds}s at most`,
    );
  }
}

export function createMonitor(
  db: Db,
  key: ApiKey,
  pageId: string,
  m: NewMonitor,
  now = new Date(),
): Monitor | null {
  if (!getOwnedPage(db, key.id, pageId)) return null;
  assertInterval(key.plan, m.intervalSeconds);
  const n = db
    .prepare(
      'SELECT COUNT(*) AS n FROM monitors m JOIN pages p ON p.id = m.page_id WHERE p.api_key_id = ?',
    )
    .get(key.id) as { n: number };
  if (n.n >= PLANS[key.plan].maxMonitors) {
    throw new LimitError(`Your ${key.plan} plan allows ${PLANS[key.plan].maxMonitors} monitors`);
  }
  const id = randomUUID();
  db.prepare(
    `INSERT INTO monitors (id, page_id, name, url, method, interval_seconds, expected_status, timeout_ms, next_check_at, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    id,
    pageId,
    m.name,
    m.url,
    m.method,
    m.intervalSeconds,
    m.expectedStatus ?? null,
    m.timeoutMs ?? 10_000,
    iso(now),
    iso(now),
  );
  return getOwnedMonitor(db, key.id, id);
}
export function getOwnedMonitor(db: Db, keyId: string, id: string): Monitor | null {
  const r = db
    .prepare(
      'SELECT m.* FROM monitors m JOIN pages p ON p.id = m.page_id WHERE m.id = ? AND p.api_key_id = ?',
    )
    .get(id, keyId);
  return r ? toMonitor(r) : null;
}
export function listMonitors(db: Db, keyId: string, pageId: string): Monitor[] | null {
  if (!getOwnedPage(db, keyId, pageId)) return null;
  return db
    .prepare('SELECT * FROM monitors WHERE page_id = ? ORDER BY created_at, id')
    .all(pageId)
    .map(toMonitor);
}
export function patchMonitor(
  db: Db,
  key: ApiKey,
  id: string,
  patch: Partial<NewMonitor>,
  now = new Date(),
): Monitor | null {
  const cur = getOwnedMonitor(db, key.id, id);
  if (!cur) return null;
  const m = {
    ...cur,
    ...patch,
    expectedStatus: patch.expectedStatus === undefined ? cur.expectedStatus : patch.expectedStatus,
  };
  assertInterval(key.plan, m.intervalSeconds);
  db.prepare(
    'UPDATE monitors SET name=?, url=?, method=?, interval_seconds=?, expected_status=?, timeout_ms=?, next_check_at=? WHERE id=?',
  ).run(
    m.name,
    m.url,
    m.method,
    m.intervalSeconds,
    m.expectedStatus,
    m.timeoutMs ?? 10_000,
    iso(now),
    id,
  );
  return getOwnedMonitor(db, key.id, id);
}
export function deleteMonitor(db: Db, keyId: string, id: string): boolean {
  if (!getOwnedMonitor(db, keyId, id)) return false;
  return Number(db.prepare('DELETE FROM monitors WHERE id = ?').run(id).changes) > 0;
}
export function recentChecks(db: Db, keyId: string, monitorId: string, limit: number) {
  if (!getOwnedMonitor(db, keyId, monitorId)) return null;
  return db
    .prepare(
      'SELECT at, ok, status_code, latency_ms, error FROM checks WHERE monitor_id = ? ORDER BY id DESC LIMIT ?',
    )
    .all(monitorId, limit)
    .map((r) => ({
      at: r.at as string,
      ok: r.ok === 1,
      statusCode: (r.status_code as number | null) ?? null,
      latencyMs: (r.latency_ms as number | null) ?? null,
      error: (r.error as string | null) ?? null,
    }));
}

// ---------- checking ----------
export function dueMonitors(db: Db, now: Date, limit = 50): Monitor[] {
  return db
    .prepare('SELECT * FROM monitors WHERE next_check_at <= ? ORDER BY next_check_at LIMIT ?')
    .all(iso(now), limit)
    .map(toMonitor);
}

export interface CheckOutcome {
  ok: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  error: string | null;
}

/** Records one check and updates state, daily rollup and incidents in a single transaction. */
export function recordCheck(db: Db, m: Monitor, r: CheckOutcome, now = new Date()): void {
  db.exec('BEGIN');
  try {
    db.prepare(
      'INSERT INTO checks (monitor_id, at, ok, status_code, latency_ms, error) VALUES (?,?,?,?,?,?)',
    ).run(m.id, iso(now), r.ok ? 1 : 0, r.statusCode, r.latencyMs, r.error);
    db.prepare(
      `INSERT INTO daily_stats (monitor_id, day, total, up) VALUES (?,?,1,?)
       ON CONFLICT(monitor_id, day) DO UPDATE SET total = total + 1, up = up + excluded.up`,
    ).run(m.id, dayOf(now), r.ok ? 1 : 0);

    const fails = r.ok ? 0 : m.consecutiveFailures + 1;
    const failingSince = r.ok ? null : (m.failingSince ?? iso(now));
    const status = r.ok
      ? 'up'
      : fails >= FAILURE_THRESHOLD
        ? 'down'
        : m.status === 'unknown'
          ? 'unknown'
          : m.status;
    if (!r.ok && fails === FAILURE_THRESHOLD) {
      db.prepare('INSERT INTO incidents (monitor_id, started_at, last_error) VALUES (?,?,?)').run(
        m.id,
        failingSince,
        r.error,
      );
    } else if (!r.ok && fails > FAILURE_THRESHOLD) {
      db.prepare(
        'UPDATE incidents SET last_error = ? WHERE monitor_id = ? AND resolved_at IS NULL',
      ).run(r.error, m.id);
    } else if (r.ok) {
      db.prepare(
        'UPDATE incidents SET resolved_at = ? WHERE monitor_id = ? AND resolved_at IS NULL',
      ).run(iso(now), m.id);
    }
    db.prepare(
      `UPDATE monitors SET status=?, consecutive_failures=?, failing_since=?, last_checked_at=?, last_latency_ms=?,
              last_error=?, next_check_at=? WHERE id=?`,
    ).run(
      status,
      fails,
      failingSince,
      iso(now),
      r.latencyMs,
      r.error,
      iso(new Date(now.getTime() + m.intervalSeconds * 1000)),
      m.id,
    );
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

/** Delete raw checks older than `keepDays` (daily_stats keeps the long-term history). */
export function pruneChecks(db: Db, now = new Date(), keepDays = 7, statsDays = 120): void {
  db.prepare('DELETE FROM checks WHERE at < ?').run(
    iso(new Date(now.getTime() - keepDays * 86400_000)),
  );
  db.prepare('DELETE FROM daily_stats WHERE day < ?').run(
    dayOf(new Date(now.getTime() - statsDays * 86400_000)),
  );
}

// ---------- public view ----------
export type DayClass = 'ok' | 'warn' | 'down' | 'nodata';
export interface PublicMonitor {
  name: string;
  status: Monitor['status'];
  uptime90: number | null;
  latencyMs: number | null;
  days: { day: string; pct: number | null; cls: DayClass }[];
}
export interface PublicIncident {
  monitor: string;
  startedAt: string;
  resolvedAt: string | null;
}
export interface PublicPage {
  slug: string;
  title: string;
  overall: 'operational' | 'partial' | 'major' | 'unknown';
  monitors: PublicMonitor[];
  incidents: PublicIncident[];
  generatedAt: string;
}

export const DAYS = 90;

export function dayClass(pct: number | null): DayClass {
  if (pct === null) return 'nodata';
  if (pct >= 99.9) return 'ok';
  if (pct >= 95) return 'warn';
  return 'down';
}

/** Deliberately omits monitor URLs: the public page must not reveal internal endpoints. */
export function buildPublicPage(db: Db, slug: string, now = new Date()): PublicPage | null {
  const page = getPageBySlug(db, slug);
  if (!page) return null;
  const monitors = db
    .prepare('SELECT * FROM monitors WHERE page_id = ? ORDER BY created_at, id')
    .all(page.id)
    .map(toMonitor);
  const days: string[] = [];
  for (let i = DAYS - 1; i >= 0; i--) days.push(dayOf(new Date(now.getTime() - i * 86400_000)));

  const pub: PublicMonitor[] = monitors.map((m) => {
    const rows = db
      .prepare('SELECT day, total, up FROM daily_stats WHERE monitor_id = ? AND day >= ?')
      .all(m.id, days[0]!) as { day: string; total: number; up: number }[];
    const byDay = new Map(rows.map((r) => [r.day, r]));
    let total = 0;
    let up = 0;
    const cells = days.map((day) => {
      const r = byDay.get(day);
      if (!r || r.total === 0) return { day, pct: null, cls: 'nodata' as DayClass };
      total += r.total;
      up += r.up;
      const pct = Math.round((r.up / r.total) * 10000) / 100;
      return { day, pct, cls: dayClass(pct) };
    });
    return {
      name: m.name,
      status: m.status,
      uptime90: total ? Math.round((up / total) * 10000) / 100 : null,
      latencyMs: m.lastLatencyMs,
      days: cells,
    };
  });

  const known = pub.filter((m) => m.status !== 'unknown');
  const down = known.filter((m) => m.status === 'down').length;
  const overall =
    known.length === 0
      ? 'unknown'
      : down === 0
        ? 'operational'
        : down === known.length
          ? 'major'
          : 'partial';

  const incidents = db
    .prepare(
      `SELECT m.name AS monitor, i.started_at, i.resolved_at FROM incidents i
         JOIN monitors m ON m.id = i.monitor_id
        WHERE m.page_id = ? AND i.started_at >= ? ORDER BY i.started_at DESC LIMIT 20`,
    )
    .all(page.id, iso(new Date(now.getTime() - 30 * 86400_000)))
    .map((r) => ({
      monitor: r.monitor as string,
      startedAt: r.started_at as string,
      resolvedAt: (r.resolved_at as string | null) ?? null,
    }));

  return {
    slug: page.slug,
    title: page.title,
    overall,
    monitors: pub,
    incidents,
    generatedAt: iso(now),
  };
}
