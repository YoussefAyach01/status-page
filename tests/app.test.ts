import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { checkerTick, isUp, type Fetcher } from '../src/checker.js';
import type { Config } from '../src/config.js';
import { openDb } from '../src/db.js';
import { dayClass, pruneChecks } from '../src/store.js';

const ADMIN = 'y'.repeat(32);
const cfg = (allow: '0' | '1' = '0'): Config => ({
  PORT: 3350,
  ADMIN_TOKEN: ADMIN,
  DB_PATH: ':memory:',
  ALLOW_PRIVATE_TARGETS: allow,
  RUN_CHECKER: '0',
});
const j = (b: unknown) => JSON.stringify(b);
const auth = (k: string) => ({ Authorization: `Bearer ${k}`, 'content-type': 'application/json' });

function setup(allow: '0' | '1' = '0') {
  const db = openDb(':memory:');
  return { db, app: createApp(db, cfg(allow)) };
}
type Ctx = ReturnType<typeof setup>;

async function mint(ctx: Ctx, plan = 'pro') {
  const r = await ctx.app.request('/admin/keys', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' },
    body: j({ label: 't', plan }),
  });
  expect(r.status).toBe(201);
  return (await r.json()) as { key: string; id: string };
}
async function page(ctx: Ctx, key: string, slug = 'acme', title = 'Acme') {
  const r = await ctx.app.request('/v1/pages', {
    method: 'POST',
    headers: auth(key),
    body: j({ slug, title }),
  });
  return { r, body: (await r.json()) as { id: string } };
}
async function monitor(ctx: Ctx, key: string, pageId: string, over: Record<string, unknown> = {}) {
  const r = await ctx.app.request(`/v1/pages/${pageId}/monitors`, {
    method: 'POST',
    headers: auth(key),
    body: j({ name: 'API', url: 'https://example.com/health', intervalSeconds: 60, ...over }),
  });
  return { r, body: (await r.json()) as { id: string } };
}

// A fetcher whose responses we script per call.
const scripted = (results: (number | Error)[]): Fetcher => {
  let i = 0;
  return async () => {
    const r = results[Math.min(i++, results.length - 1)]!;
    if (r instanceof Error) throw r;
    return { status: r, bodySnippet: '', durationMs: 42 };
  };
};
// Monitors are created "now" through the API, so test times are offsets from now (all within ~20 minutes).
// BASE is recomputed per-test (see beforeEach below) rather than once at module load: a slow
// cold start (native module loading, transform) can otherwise push monitor creation past a
// fixed BASE taken at import time, making every monitor look "not due yet" and failing checks.
let BASE = Date.now() + 1000;
const at = (mins: number) => new Date(BASE + mins * 60_000);

describe('smoke + auth', () => {
  it('health and 401s', async () => {
    const { app } = setup();
    expect((await app.request('/health')).status).toBe(200);
    expect((await app.request('/v1/pages')).status).toBe(401);
    expect((await app.request('/v1/pages', { headers: auth('sp_bad') })).status).toBe(401);
    expect((await app.request('/admin/keys', { method: 'POST', body: '{}' })).status).toBe(401);
  });
  it('stores only the key hash', async () => {
    const ctx = setup();
    const { key } = await mint(ctx);
    const rows = ctx.db.prepare('SELECT * FROM api_keys').all();
    expect(JSON.stringify(rows)).not.toContain(key);
  });
});

describe('management API', () => {
  it('creates page + monitor, enforces slug rules and uniqueness', async () => {
    const ctx = setup();
    const a = await mint(ctx);
    const b = await mint(ctx);
    expect((await page(ctx, a.key)).r.status).toBe(201);
    expect((await page(ctx, b.key, 'acme')).r.status).toBe(409);
    expect((await page(ctx, b.key, 'Bad Slug!')).r.status).toBe(400);
  });
  it('rejects SSRF targets for monitors', async () => {
    const ctx = setup();
    const { key } = await mint(ctx);
    const p = await page(ctx, key);
    for (const url of [
      'http://127.0.0.1/',
      'http://169.254.169.254/',
      'file:///etc/passwd',
      'http://[::1]/',
      'https://x.test:22/',
    ]) {
      const m = await monitor(ctx, key, p.body.id, { url });
      expect(m.r.status, url).toBe(422);
    }
  });
  it('enforces plan limits: free = 1 page, 5 monitors, 300 s minimum', async () => {
    const ctx = setup();
    const { key } = await mint(ctx, 'free');
    const p = await page(ctx, key);
    expect((await page(ctx, key, 'second')).r.status).toBe(422);
    expect((await monitor(ctx, key, p.body.id, { intervalSeconds: 60 })).r.status).toBe(422);
    for (let i = 0; i < 5; i++)
      expect((await monitor(ctx, key, p.body.id, { intervalSeconds: 300 })).r.status).toBe(201);
    expect((await monitor(ctx, key, p.body.id, { intervalSeconds: 300 })).r.status).toBe(422);
  });
  it('other customers get 404 everywhere (IDOR)', async () => {
    const ctx = setup();
    const a = await mint(ctx);
    const b = await mint(ctx);
    const p = await page(ctx, a.key);
    const m = await monitor(ctx, a.key, p.body.id);
    const h = auth(b.key);
    const rs = await Promise.all([
      ctx.app.request(`/v1/pages/${p.body.id}/monitors`, { headers: h }),
      ctx.app.request(`/v1/pages/${p.body.id}/monitors`, {
        method: 'POST',
        headers: h,
        body: j({ name: 'x', url: 'https://example.com' }),
      }),
      ctx.app.request(`/v1/pages/${p.body.id}`, { method: 'DELETE', headers: h }),
      ctx.app.request(`/v1/monitors/${m.body.id}`, { headers: h }),
      ctx.app.request(`/v1/monitors/${m.body.id}`, {
        method: 'PATCH',
        headers: h,
        body: j({ name: 'pwn' }),
      }),
      ctx.app.request(`/v1/monitors/${m.body.id}`, { method: 'DELETE', headers: h }),
      ctx.app.request(`/v1/monitors/${m.body.id}/checks`, { headers: h }),
    ]);
    expect(rs.map((r) => r.status)).toEqual([404, 404, 404, 404, 404, 404, 404]);
    expect(
      (await ctx.app.request(`/v1/monitors/${m.body.id}`, { headers: auth(a.key) })).status,
    ).toBe(200);
    expect((await ctx.app.request('/v1/monitors/not-a-uuid', { headers: h })).status).toBe(404);
  });
});

describe('checking, incidents, public page', () => {
  let ctx: Ctx;
  let key: string;
  let mid: string;
  beforeEach(async () => {
    ctx = setup();
    key = (await mint(ctx)).key;
    const p = await page(ctx, key, 'acme', 'Acme Co');
    mid = (
      await monitor(ctx, key, p.body.id, {
        name: 'Web app',
        url: 'https://secret-internal.example.com/private-path',
      })
    ).body.id;
    BASE = Date.now() + 1000;
  });
  const tick = (mins: number, f: Fetcher) => checkerTick(ctx.db, at(mins), { fetcher: f });
  const pub = async () =>
    (await (await ctx.app.request('/api/public/acme')).json()) as {
      overall: string;
      monitors: { status: string; uptime90: number | null; days: { cls: string }[] }[];
      incidents: { monitor: string; resolvedAt: string | null }[];
    };

  it('classifies statuses', () => {
    expect(isUp(200, null)).toBe(true);
    expect(isUp(301, null)).toBe(true);
    expect(isUp(404, null)).toBe(false);
    expect(isUp(503, null)).toBe(false);
    expect(isUp(404, 404)).toBe(true);
    expect(isUp(200, 204)).toBe(false);
    expect(dayClass(null)).toBe('nodata');
    expect(dayClass(100)).toBe('ok');
    expect(dayClass(97)).toBe('warn');
    expect(dayClass(50)).toBe('down');
  });

  it('is unknown before any check, operational after a good one', async () => {
    expect((await pub()).overall).toBe('unknown');
    expect(await tick(0, scripted([200]))).toBe(1);
    const p = await pub();
    expect(p.overall).toBe('operational');
    expect(p.monitors[0]!.status).toBe('up');
    expect(p.monitors[0]!.uptime90).toBe(100);
    expect(p.monitors[0]!.days.at(-1)!.cls).toBe('ok');
  });
  it('does not check monitors that are not due yet', async () => {
    await tick(0, scripted([200]));
    expect(await tick(0, scripted([200]))).toBe(0); // interval is 60 s
    expect(await tick(2, scripted([200]))).toBe(1);
  });
  it('one failed check is a blip; two consecutive open an incident; recovery resolves it', async () => {
    await tick(0, scripted([200]));
    await tick(2, scripted([500]));
    let p = await pub();
    expect(p.monitors[0]!.status).toBe('up');
    expect(p.incidents).toHaveLength(0);

    await tick(4, scripted([new Error('connect ECONNREFUSED')]));
    p = await pub();
    expect(p.monitors[0]!.status).toBe('down');
    expect(p.overall).toBe('major');
    expect(p.incidents).toEqual([
      expect.objectContaining({ monitor: 'Web app', resolvedAt: null }),
    ]);

    await tick(6, scripted([503])); // still down: no second incident
    expect((await pub()).incidents).toHaveLength(1);

    await tick(8, scripted([200]));
    p = await pub();
    expect(p.monitors[0]!.status).toBe('up');
    expect(p.overall).toBe('operational');
    expect(p.incidents).toHaveLength(1);
    expect(p.incidents[0]!.resolvedAt).not.toBeNull();
  });
  it('computes daily uptime from real check counts', async () => {
    await tick(0, scripted([200]));
    await tick(2, scripted([500]));
    await tick(4, scripted([200]));
    await tick(6, scripted([200]));
    const p = await pub();
    expect(p.monitors[0]!.uptime90).toBe(75);
    expect(p.monitors[0]!.days.at(-1)!.cls).toBe('down');
  });
  it('lists recent checks for the owner', async () => {
    await tick(0, scripted([200]));
    await tick(2, scripted([500]));
    const r = (await (
      await ctx.app.request(`/v1/monitors/${mid}/checks`, { headers: auth(key) })
    ).json()) as {
      items: { ok: boolean; statusCode: number; error: string | null }[];
    };
    expect(r.items.map((c) => c.ok)).toEqual([false, true]);
    expect(r.items[0]).toMatchObject({ statusCode: 500, error: 'HTTP 500' });
  });
  it('the public page never exposes monitor URLs and escapes HTML in names', async () => {
    await ctx.app.request(`/v1/monitors/${mid}`, {
      method: 'PATCH',
      headers: auth(key),
      body: j({ name: '<script>alert(1)</script> & "co"' }),
    });
    await tick(0, scripted([200]));
    const res = await ctx.app.request('/s/acme');
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain('All systems operational');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('secret-internal');
    expect(JSON.stringify(await pub())).not.toContain('secret-internal');
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect((await ctx.app.request('/s/nope')).status).toBe(404);
    expect((await ctx.app.request('/s/..%2Fetc')).status).toBe(404);
    expect((await ctx.app.request('/status.css')).status).toBe(200);
  });
  it('prunes old raw checks but keeps daily stats', async () => {
    await tick(0, scripted([200]));
    pruneChecks(ctx.db, new Date(at(0).getTime() + 30 * 86400_000));
    expect(ctx.db.prepare('SELECT COUNT(*) n FROM checks').get()).toMatchObject({ n: 0 });
    expect(ctx.db.prepare('SELECT COUNT(*) n FROM daily_stats').get()).toMatchObject({ n: 1 });
  });
  it('deleting a page removes its monitors and history', async () => {
    await tick(0, scripted([200]));
    const pages = (await (await ctx.app.request('/v1/pages', { headers: auth(key) })).json()) as {
      items: { id: string }[];
    };
    expect(
      (
        await ctx.app.request(`/v1/pages/${pages.items[0]!.id}`, {
          method: 'DELETE',
          headers: auth(key),
        })
      ).status,
    ).toBe(204);
    for (const t of ['monitors', 'checks', 'daily_stats']) {
      expect(ctx.db.prepare(`SELECT COUNT(*) n FROM ${t}`).get()).toMatchObject({ n: 0 });
    }
  });
});

describe('real HTTP checking (local server, allowPrivate)', () => {
  let srv: http.Server;
  let url: string;
  let code = 200;
  beforeAll(async () => {
    srv = http.createServer((_q, res) => res.writeHead(code).end('x'));
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/`;
  });
  afterAll(() => {
    srv.closeAllConnections();
    srv.close();
  });
  it('marks a real endpoint up, then down when it starts failing, and blocks it when private targets are disallowed', async () => {
    const ctx = setup('1');
    const { key } = await mint(ctx);
    const p = await page(ctx, key);
    expect((await monitor(ctx, key, p.body.id, { url })).r.status).toBe(201);
    BASE = Date.now() + 1000;
    const run = (m: number) => checkerTick(ctx.db, at(m), { allowPrivate: true });
    code = 200;
    await run(0);
    code = 500;
    await run(2);
    await run(4);
    const pubj = (await (await ctx.app.request('/api/public/acme')).json()) as { overall: string };
    expect(pubj.overall).toBe('major');

    // same monitor checked by a strict checker: SSRF guard refuses to connect
    ctx.db.prepare("UPDATE monitors SET next_check_at = '2000-01-01T00:00:00.000Z'").run();
    await checkerTick(ctx.db, at(10), { allowPrivate: false });
    const last = ctx.db.prepare('SELECT error FROM checks ORDER BY id DESC LIMIT 1').get() as {
      error: string;
    };
    expect(last.error).toMatch(/public IP|non-public|not allowed/);
  });
});
