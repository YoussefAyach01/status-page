import type { DayClass, PublicPage } from './store.js';

const ESC: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};
export const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]!);

const HEADLINE: Record<PublicPage['overall'], string> = {
  operational: 'All systems operational',
  partial: 'Partial outage',
  major: 'Major outage',
  unknown: 'Waiting for the first check',
};
const STATE_LABEL = { up: 'Operational', down: 'Down', unknown: 'No data yet' } as const;
const CLS_LABEL: Record<DayClass, string> = {
  ok: 'no downtime',
  warn: 'partial downtime',
  down: 'major downtime',
  nodata: 'no data',
};

const fmt = (iso: string) => iso.replace('T', ' ').slice(0, 16) + ' UTC';

/** Server-rendered, script-free. Every dynamic value goes through esc(). */
export function renderPublicPage(p: PublicPage): string {
  const monitors = p.monitors
    .map((m, idx) => {
      const bars = m.days
        .map(
          (d) =>
            `<li class="bar ${d.cls}" title="${esc(d.day)}: ${d.pct === null ? 'no data' : d.pct + '%'}"><span class="sr">${esc(d.day)} ${CLS_LABEL[d.cls]}</span></li>`,
        )
        .join('');
      return `<section class="mon" aria-labelledby="m-${idx}">
  <div class="mon-head">
    <h3 id="m-${idx}">${esc(m.name)}</h3>
    <p class="state ${m.status}"><span class="dot" aria-hidden="true"></span>${STATE_LABEL[m.status]}</p>
  </div>
  <ol class="bars" aria-label="Daily uptime for the last 90 days, oldest first">${bars}</ol>
  <p class="meta"><span>90 days ago</span><span>${m.uptime90 === null ? 'No data' : m.uptime90 + '% uptime'}${m.latencyMs !== null ? ' &middot; ' + m.latencyMs + ' ms' : ''}</span><span>Today</span></p>
</section>`;
    })
    .join('\n');
  const incidents = p.incidents.length
    ? `<ul class="incidents">${p.incidents
        .map(
          (i) =>
            `<li><strong>${esc(i.monitor)}</strong> ${i.resolvedAt ? `was down ${esc(fmt(i.startedAt))}, resolved ${esc(fmt(i.resolvedAt))}` : `is down since ${esc(fmt(i.startedAt))}`}</li>`,
        )
        .join('')}</ul>`
    : '<p class="quiet">No incidents in the last 30 days.</p>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)} status</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/status.css">
</head>
<body>
<main class="wrap">
  <p class="brand">${esc(p.title)}</p>
  <h1 class="banner ${p.overall}">${HEADLINE[p.overall]}</h1>
  ${monitors || '<p class="quiet">No monitors yet.</p>'}
  <h2>Past 30 days</h2>
  ${incidents}
  <p class="foot">Updated ${esc(fmt(p.generatedAt))}. Refreshes on reload.</p>
</main>
</body>
</html>`;
}
