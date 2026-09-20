import { Hono, type Context } from 'hono';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { Config } from './config.js';
import type { Db } from './db.js';
import { renderPublicPage } from './render.js';
import { SsrfError, checkUrlSyntax } from './ssrf.js';
import {
  ConflictError,
  LimitError,
  buildPublicPage,
  createKey,
  createMonitor,
  createPage,
  deleteMonitor,
  deletePage,
  findKey,
  getOwnedMonitor,
  getOwnedPage,
  listMonitors,
  listPages,
  patchMonitor,
  recentChecks,
  revokeKey,
  type ApiKey,
} from './store.js';

type Status = 400 | 401 | 404 | 409 | 422 | 429 | 500;
const err = (c: Context, s: Status, code: string, message: string, details?: unknown) =>
  c.json({ error: { code, message, ...(details ? { details } : {}) } }, s);

const sha = (s: string) => createHash('sha256').update(s).digest();
const safeEqual = (a: string, b: string) => timingSafeEqual(sha(a), sha(b));

class Limiter {
  private m = new Map<string, { start: number; n: number }>();
  constructor(
    private limit: number,
    private windowMs = 60_000,
  ) {}
  ok(id: string, now = Date.now()) {
    const cur = this.m.get(id);
    if (!cur || now - cur.start >= this.windowMs) {
      this.m.set(id, { start: now, n: 1 });
      if (this.m.size > 10_000)
        for (const [k, v] of this.m) if (now - v.start >= this.windowMs) this.m.delete(k);
      return true;
    }
    return ++cur.n <= this.limit;
  }
}

const cssPath = fileURLToPath(new URL('../public/status.css', import.meta.url));
const uuid = z.string().uuid();
const slugSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/, 'slug must be 3-40 chars: a-z, 0-9, hyphens');
const monitorFields = {
  name: z.string().trim().min(1).max(80),
  url: z.string().max(2048),
  method: z.enum(['GET', 'HEAD']).default('GET'),
  intervalSeconds: z.number().int().min(30).max(86_400).default(300),
  expectedStatus: z.number().int().min(100).max(599).nullable().optional(),
  timeoutMs: z.number().int().min(1000).max(30_000).optional(),
};
const createMonitorSchema = z.object(monitorFields);
const patchMonitorSchema = z.object(monitorFields).partial();

export function createApp(db: Db, config: Config) {
  const app = new Hono<{ Variables: { key: ApiKey } }>();
  const policy = { allowPrivate: config.ALLOW_PRIVATE_TARGETS === '1' };
  const apiLimiter = new Limiter(120);
  const adminLimiter = new Limiter(60);
  const publicLimiter = new Limiter(120); // per IP-ish bucket; behind a CDN this mostly protects the DB

  app.use('*', async (c, next) => {
    await next();
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    c.header(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    if (!c.res.headers.has('Cache-Control')) c.header('Cache-Control', 'no-store');
  });

  app.get('/health', (c) => c.json({ ok: true }));
  app.get('/status.css', (c) =>
    c.body(readFileSync(cssPath, 'utf8'), 200, {
      'Content-Type': 'text/css; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    }),
  );

  // ---- public ----
  app.get('/s/:slug', (c) => {
    const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'local';
    if (!publicLimiter.ok(ip)) return err(c, 429, 'RATE_LIMITED', 'Too many requests.');
    const slug = slugSchema.safeParse(c.req.param('slug'));
    const page = slug.success ? buildPublicPage(db, slug.data) : null;
    if (!page)
      return c.html('<!doctype html><title>Not found</title><p>No status page here.</p>', 404);
    return c.html(renderPublicPage(page), 200, { 'Cache-Control': 'public, max-age=30' });
  });
  app.get('/api/public/:slug', (c) => {
    const slug = slugSchema.safeParse(c.req.param('slug'));
    const page = slug.success ? buildPublicPage(db, slug.data) : null;
    if (!page) return err(c, 404, 'NOT_FOUND', 'No such status page.');
    c.header('Access-Control-Allow-Origin', '*');
    c.header('Cache-Control', 'public, max-age=30');
    return c.json(page);
  });

  // ---- admin ----
  app.use('/admin/*', async (c, next) => {
    if (!adminLimiter.ok('admin')) return err(c, 429, 'RATE_LIMITED', 'Too many admin requests.');
    const auth = c.req.header('authorization') ?? '';
    const tok = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!tok || !safeEqual(tok, config.ADMIN_TOKEN))
      return err(c, 401, 'UNAUTHORIZED', 'Admin token required.');
    await next();
  });
  const keySchema = z.object({
    label: z.string().trim().min(1).max(80),
    plan: z.enum(['free', 'pro']).default('free'),
  });
  app.post('/admin/keys', async (c) => {
    const p = keySchema.safeParse(await c.req.json().catch(() => null));
    if (!p.success)
      return err(c, 400, 'VALIDATION_FAILED', p.error.issues[0]?.message ?? 'Invalid body.');
    return c.json(
      {
        ...createKey(db, p.data.label, p.data.plan),
        note: 'Store this key now. It cannot be shown again.',
      },
      201,
    );
  });
  app.delete('/admin/keys/:id', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    return id.success && revokeKey(db, id.data)
      ? c.body(null, 204)
      : err(c, 404, 'NOT_FOUND', 'No such active key.');
  });

  // ---- customer API: default deny ----
  app.use('/v1/*', async (c, next) => {
    const auth = c.req.header('authorization') ?? '';
    const raw = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const key = raw ? findKey(db, raw) : null;
    if (!key) return err(c, 401, 'INVALID_API_KEY', 'Missing or invalid API key.');
    if (!apiLimiter.ok(key.id)) return err(c, 429, 'RATE_LIMITED', 'Too many requests.');
    c.set('key', key);
    await next();
  });

  const invalid = (c: Context, e: z.ZodError) =>
    err(
      c,
      400,
      'VALIDATION_FAILED',
      e.issues[0] ? `${e.issues[0].path.join('.')}: ${e.issues[0].message}` : 'Invalid input.',
    );
  const mapErrors = (c: Context, e: unknown) => {
    if (e instanceof SsrfError) return err(c, 422, 'URL_NOT_ALLOWED', e.message);
    if (e instanceof LimitError) return err(c, 422, 'PLAN_LIMIT', e.message);
    if (e instanceof ConflictError) return err(c, 409, 'CONFLICT', e.message);
    throw e;
  };
  const notFound = (c: Context) => err(c, 404, 'NOT_FOUND', 'Not found.');

  app.post('/v1/pages', async (c) => {
    const p = z
      .object({ slug: slugSchema, title: z.string().trim().min(1).max(100) })
      .safeParse(await c.req.json().catch(() => null));
    if (!p.success) return invalid(c, p.error);
    try {
      return c.json(createPage(db, c.get('key'), p.data.slug, p.data.title), 201);
    } catch (e) {
      return mapErrors(c, e);
    }
  });
  app.get('/v1/pages', (c) => c.json({ items: listPages(db, c.get('key').id) }));
  app.delete('/v1/pages/:id', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    return id.success && deletePage(db, c.get('key').id, id.data) ? c.body(null, 204) : notFound(c);
  });

  app.post('/v1/pages/:id/monitors', async (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    if (!id.success || !getOwnedPage(db, c.get('key').id, id.data)) return notFound(c);
    const p = createMonitorSchema.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return invalid(c, p.error);
    try {
      checkUrlSyntax(p.data.url, policy);
      const m = createMonitor(db, c.get('key'), id.data, p.data);
      return m ? c.json(m, 201) : notFound(c);
    } catch (e) {
      return mapErrors(c, e);
    }
  });
  app.get('/v1/pages/:id/monitors', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    const items = id.success ? listMonitors(db, c.get('key').id, id.data) : null;
    return items ? c.json({ items }) : notFound(c);
  });
  app.get('/v1/monitors/:id', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    const m = id.success ? getOwnedMonitor(db, c.get('key').id, id.data) : null;
    return m ? c.json(m) : notFound(c);
  });
  app.patch('/v1/monitors/:id', async (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    if (!id.success) return notFound(c);
    const p = patchMonitorSchema.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return invalid(c, p.error);
    try {
      if (p.data.url !== undefined) checkUrlSyntax(p.data.url, policy);
      const m = patchMonitor(db, c.get('key'), id.data, p.data);
      return m ? c.json(m) : notFound(c);
    } catch (e) {
      return mapErrors(c, e);
    }
  });
  app.delete('/v1/monitors/:id', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    return id.success && deleteMonitor(db, c.get('key').id, id.data)
      ? c.body(null, 204)
      : notFound(c);
  });
  app.get('/v1/monitors/:id/checks', (c) => {
    const id = uuid.safeParse(c.req.param('id'));
    const limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .default(20)
      .safeParse(c.req.query('limit'));
    if (!limit.success) return invalid(c, limit.error);
    const items = id.success ? recentChecks(db, c.get('key').id, id.data, limit.data) : null;
    return items ? c.json({ items }) : notFound(c);
  });

  app.notFound((c) => err(c, 404, 'NOT_FOUND', 'Route not found.'));
  app.onError((e, c) => {
    console.error(e);
    return err(c, 500, 'INTERNAL', 'Something went wrong.');
  });
  return app;
}
