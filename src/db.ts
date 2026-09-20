import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type Db = DatabaseSync;

/** Ordered, append-only migrations tracked with PRAGMA user_version. */
const MIGRATIONS: string[] = [
  `
  CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    plan TEXT NOT NULL CHECK (plan IN ('free','pro')),
    revoked_at TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE pages (
    id TEXT PRIMARY KEY,
    api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX pages_owner_idx ON pages (api_key_id);
  CREATE TABLE monitors (
    id TEXT PRIMARY KEY,
    page_id TEXT NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('GET','HEAD')),
    interval_seconds INTEGER NOT NULL,
    expected_status INTEGER,
    timeout_ms INTEGER NOT NULL DEFAULT 10000,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','up','down')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    failing_since TEXT,
    last_checked_at TEXT,
    last_latency_ms INTEGER,
    last_error TEXT,
    next_check_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX monitors_page_idx ON monitors (page_id);
  CREATE INDEX monitors_due_idx ON monitors (next_check_at);
  CREATE TABLE checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    ok INTEGER NOT NULL,
    status_code INTEGER,
    latency_ms INTEGER,
    error TEXT
  );
  CREATE INDEX checks_monitor_idx ON checks (monitor_id, at);
  CREATE TABLE daily_stats (
    monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0,
    up INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (monitor_id, day)
  );
  CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    last_error TEXT
  );
  CREATE INDEX incidents_monitor_idx ON incidents (monitor_id, started_at);
  `,
];

export function openDb(path: string): Db {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
  for (let v = row.user_version; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]!);
      db.exec(`PRAGMA user_version = ${v + 1}`);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}
