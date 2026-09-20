# status-page

Uptime monitoring plus a public status page, multi-tenant. Customers get an API key, create a page (`/s/<slug>`), add monitors (URL + interval). A background checker probes each URL, opens an incident after 2 consecutive failures, closes it on recovery, and the public page shows 90 daily uptime bars, current state and the last 30 days of incidents. Monitor URLs are never shown publicly.

Node 22.5+ (built-in `node:sqlite`, no native deps, no docker), Hono, Zod, TypeScript strict. The public page is server-rendered HTML with no JavaScript.

## Run

```bash
cp .env.example .env         # set ADMIN_TOKEN (16+ chars)
npm install
npm run dev                  # http://localhost:3350
```

```bash
# operator mints a customer key (shown once, only its SHA-256 is stored)
curl -X POST localhost:3350/admin/keys -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' -d '{"label":"acme","plan":"pro"}'

curl -X POST localhost:3350/v1/pages -H "Authorization: Bearer $KEY" -H 'content-type: application/json' -d '{"slug":"acme","title":"Acme Co"}'
curl -X POST localhost:3350/v1/pages/$PAGE_ID/monitors -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"name":"Website","url":"https://acme.example/","intervalSeconds":60}'
# public: http://localhost:3350/s/acme   JSON: /api/public/acme
```

Endpoints (Bearer key): `POST/GET /v1/pages`, `DELETE /v1/pages/:id`, `POST/GET /v1/pages/:id/monitors`, `GET/PATCH/DELETE /v1/monitors/:id`, `GET /v1/monitors/:id/checks`. Public: `GET /s/:slug`, `GET /api/public/:slug`. Errors: `{ "error": { "code", "message" } }`.

Up = 2xx/3xx by default (redirects are not followed), or exactly `expectedStatus` if set. Plans (`src/config.ts`): free = 1 page, 5 monitors, 5 min interval; pro = 10 pages, 50 monitors, 1 min.

## SSRF protection

Monitors make the server fetch customer-supplied URLs, so `src/ssrf.ts` (same module as in cron-hooks) enforces: http/https only, no URL credentials, ports 80/443/8080/8443, no private/loopback/link-local/metadata/CGNAT/multicast/reserved IPs (v4, v6, IPv4-mapped), own DNS lookup that rejects if any answer is non-public and dials the validated address (no DNS rebinding), no redirect following, 10 s timeout, tiny response cap. Checked on create/update and again on every check.

## Scripts

`npm run typecheck && npm run lint && npm test`

## Deploy

Node host with a persistent disk (Fly volume, Railway volume, VPS) for the SQLite file. Set `ADMIN_TOKEN`, `DB_PATH`, keep `ALLOW_PRIVATE_TARGETS=0`, put HTTPS in front. Single instance only (SQLite + one checker loop). Custom domains per customer would need a reverse proxy/CDN (not built).

## Known limits

No alerts (email/Telegram/webhook), no signup/billing/dashboard, no custom domains, no manual incident posts, checks run from one location (a single-region blip can look like an outage), in-memory rate limiter. Public page visuals were verified by inspecting the rendered HTML only, not in a real browser.
