import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { checkerTick, pruneChecks } from './checker.js';
import { loadConfig } from './config.js';
import { openDb } from './db.js';

try {
  process.loadEnvFile();
} catch {
  // No .env file: rely on the real environment.
}
const config = loadConfig();
const db = openDb(config.DB_PATH);
const server = serve({ fetch: createApp(db, config).fetch, port: config.PORT }, (i) =>
  console.log(`status-page listening on :${i.port}`),
);

const timers: NodeJS.Timeout[] = [];
if (config.RUN_CHECKER === '1') {
  let running = false; // never overlap passes: a slow target must not stack up work
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      await checkerTick(db, new Date(), { allowPrivate: config.ALLOW_PRIVATE_TARGETS === '1' });
    } catch (e) {
      console.error('checker tick failed', e);
    } finally {
      running = false;
    }
  };
  timers.push(
    setInterval(tick, 5_000),
    setInterval(() => pruneChecks(db), 3600_000),
  );
  void tick();
}

function shutdown() {
  timers.forEach(clearInterval);
  server.close();
  db.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
