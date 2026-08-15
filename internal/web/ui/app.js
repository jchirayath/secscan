/* secscan dashboard — vanilla JS, no framework, no build step.
 *
 * Two rules that shape everything here:
 *   1. Every value that reaches the DOM goes through text nodes or `esc()`.
 *      Findings contain attacker-influenced strings — file paths, process
 *      names, package names — so innerHTML with interpolation is not allowed.
 *      The CSP is the backstop, not the plan.
 *   2. Every async surface renders all five states: loading, empty, error,
 *      permission-denied, success (ARCHITECTURE.md — Findings).
 */
'use strict';

const app = document.getElementById('app');
const state = { me: null, route: { view: 'overview' }, cache: {} };

/* ------------------------------------------------------------------ utils */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

/* esc() stops attribute and element injection, but it does NOT stop a
 * `javascript:` or `data:` URL in an href — that is still script execution on
 * click. Reference URLs arrive from engine output (Trivy PrimaryURL, OSV), so
 * they are attacker-influenceable. Allow http/https only. */
function safeUrl(u) {
  try {
    const parsed = new URL(String(u), location.origin);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') ? parsed.href : null;
  } catch (_) {
    return null;
  }
}

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

function relTime(iso) {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '—';
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function scoreClass(n) { return n >= 80 ? 'good' : n >= 50 ? 'warn' : 'bad'; }

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    ...opts,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body?.error?.message || `HTTP ${res.status}`);
    err.code = body?.error?.code;
    err.status = res.status;
    throw err;
  }
  return body;
}

/* ----------------------------------------------------------------- states */

function renderLoading(what) {
  app.innerHTML = `<div class="empty"><h3>Loading ${esc(what)}…</h3></div>`;
}

function renderError(err, what) {
  // Permission-denied is its own state: telling someone "error" when the real
  // answer is "your role cannot see this" wastes their time.
  if (err.status === 403) {
    app.innerHTML = `<div class="empty">
      <h3>Not available to your role</h3>
      <p>You are signed in as <b>${esc(state.me?.role || 'unknown')}</b>, which does not
      hold the capability needed for ${esc(what)}.</p>
      <p class="muted">${esc(err.message)}</p></div>`;
    return;
  }
  if (err.status === 401) {
    app.innerHTML = `<div class="empty"><h3>Session expired</h3>
      <p><a href="/auth/login">Sign in again</a></p></div>`;
    return;
  }
  app.innerHTML = `<div class="empty">
    <h3>Could not load ${esc(what)}</h3>
    <p class="muted">${esc(err.message)}</p>
    <p><button class="ghost" id="retry">Retry</button></p></div>`;
  document.getElementById('retry')?.addEventListener('click', () => route());
}

function provenanceBanner(prov, note) {
  if (prov === 'live') return '';
  const cls = prov === 'demo' ? 'bad' : prov === 'unavailable' ? 'info' : '';
  const label = {
    demo: 'Demo data — not from a real scan',
    cached: 'Cached data',
    partial: 'Partial data — some collectors could not run',
    unavailable: 'No data yet',
  }[prov] || prov;
  return `<div class="banner ${cls}">
    <b>${esc(label)}</b>${note ? ' · ' + esc(note) : ''}</div>`;
}

/* --------------------------------------------------------------- overview */

async function viewOverview() {
  renderLoading('overview');
  let body;
  try { body = await api('/api/overview'); }
  catch (e) { return renderError(e, 'the overview'); }

  const d = body.data;
  if (!d.assets.length) {
    app.innerHTML = provenanceBanner(body.provenance, body.note) + `<div class="empty">
      <h3>No scan has run yet</h3>
      <p>Run <code>secscan scan</code>, or press <b>Scan</b> above.</p></div>`;
    return;
  }

  const hist = d.history || [];

  const tiles = d.categories.map((c) => {
    const bars = SEVS.filter((s) => c.counts[s])
      .map((s) => `<span class="badge ${s}">${esc(s)} ${c.counts[s]}</span>`).join('');
    return `<button class="tile" data-cat="${esc(c.category)}">
      <h3>${esc(c.label)}</h3>
      <div class="total">${c.total} finding${c.total === 1 ? '' : 's'}</div>
      <div class="bars">${bars || '<span class="badge ok">clear</span>'}</div>
    </button>`;
  }).join('');

  app.innerHTML = provenanceBanner(body.provenance, body.note) + `
    <div class="grid top mb">
      <div class="card score">
        <div class="label">Posture score</div>
        <div class="n ${scoreClass(d.score)}">${esc(d.score)}</div>
        <div class="label">${d.total} open findings</div>
        <div class="spark" id="spark"></div>
      </div>
      <div class="card">
        <h4 class="mt-0">Highest risk right now</h4>
        <table><tbody>${rowsFor(d.top)}</tbody></table>
      </div>
    </div>
    ${exposurePanel(d)}
    <h1 class="page">By category</h1>
    <p class="sub">Select a category to drill into its findings.</p>
    <div class="grid cats">${tiles}</div>`;

  // The sparkline's bar heights are data-driven, so they cannot live in the
  // stylesheet — and the CSP forbids inline style attributes. Setting
  // element.style via the CSSOM is not inline style, so it is allowed and we
  // keep the strict policy intact.
  const spark = document.getElementById('spark');
  hist.slice(-30).forEach((h) => {
    const bar = document.createElement('i');
    bar.style.height = `${Math.max(3, Math.round((h.score / 100) * 100))}%`;
    bar.title = `${h.at} — score ${h.score}`;
    spark.appendChild(bar);
  });

  wireRows();
  app.querySelectorAll('.tile').forEach((el) => {
    el.addEventListener('click', () => go({ view: 'category', cat: el.dataset.cat }));
  });
}

// exposurePanel answers "what can reach this host from outside?" — a different
// question from "what should I fix first", and one that must not be answerable
// only by scrolling past better-ranked findings.
function exposurePanel(d) {
  const ex = d.exposed || [];
  const controls = d.controls || [];

  const controlList = controls.length
    ? `<div class="chips mb">${controls.map((c) =>
        `<span class="badge control" title="${esc(c.limits)}">🛡 ${esc(c.name)}</span>`).join('')}</div>`
    : `<p class="muted fs-13">No compensating controls detected on this estate.</p>`;

  if (!ex.length) {
    return `<h1 class="page">Exposure</h1>
      <p class="sub">Nothing on this host was confirmed reachable from outside.</p>
      <div class="card mb">${controlList}</div>`;
  }

  return `<h1 class="page">Exposed to the network</h1>
    <p class="sub">Confirmed reachable from outside the host. These stay listed
       regardless of rank — a well-defended entry point is still an entry point.</p>
    <div class="card mb">
      <table>
        <thead><tr><th>Residual</th><th>Severity</th><th>Service</th><th></th></tr></thead>
        <tbody>${rowsFor(ex)}</tbody>
      </table>
      <h4 class="mt-16">Compensating controls in place</h4>
      ${controlList}
    </div>`;
}

function rowsFor(list) {
  if (!list || !list.length) {
    return `<tr><td class="muted">Nothing open — clear.</td></tr>`;
  }
  return list.map((f) => `<tr data-id="${esc(f.id)}">
    <td class="risk">${esc(f.residual_risk)}${
      f.mitigation_factor ? `<span class="inherent">was ${esc(f.inherent_risk)}</span>` : ''}</td>
    <td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td class="title">${esc(f.title)}${
      f.instances > 1 ? `<span class="badge medium multi">×${esc(f.instances)} places</span>` : ''}
      <small>${esc(f.asset_id)}${
        f.instances > 1 && f.locations
          ? ' · ' + esc(f.locations.slice(0, 3).join(', ')) + (f.locations.length > 3 ? ` +${f.locations.length - 3} more` : '')
          : (f.component?.name ? ' · ' + esc(f.component.name) : '')}</small>
      ${verdictChip(f)}${mitigationChips(f)}</td>
    <td>${f.exposed ? '<span class="badge exposed">exposed</span>' : ''}</td>
  </tr>`).join('');
}

// verdictChip shows whether a finding was proven or refuted by a live test.
// "confirmed" and "reported" deserve different visual weight.
function verdictChip(f) {
  const v = f.validation;
  if (!v || v.verdict === 'unverified') return '';
  const cls = v.verdict === 'confirmed' ? 'confirmed' : 'refuted';
  const label = v.verdict === 'confirmed' ? '✓ proven exploitable' : '✗ could not be exercised';
  return `<div class="chips"><span class="badge ${cls}" title="${esc(v.method)}">${label}</span></div>`;
}

// mitigationChips names the controls that lowered a finding's rank. Without
// this a mitigated item just looks inexplicably low.
function mitigationChips(f) {
  const m = f.mitigations || [];
  if (!m.length) return '';
  return `<div class="chips">` + m.map((x) =>
    `<span class="badge control" title="${esc(x.limits)}">🛡 ${esc(x.name)} ×${esc(x.factor)}</span>`
  ).join('') + `</div>`;
}

function wireRows() {
  app.querySelectorAll('tbody tr[data-id]').forEach((tr) => {
    tr.addEventListener('click', () => go({ view: 'finding', id: tr.dataset.id }));
  });
}



/* ----------------------------------------------------------------- trend */

// viewTrend draws posture over time from the snapshot metadata.
//
// Two rules shape this view. A single point is not a trend, and is labelled as
// such rather than drawn as a flat line. And a score that improved because a
// check stopped running is not an improvement — coverage is plotted alongside
// the score so the two cannot be confused.
async function viewTrend() {
  renderLoading('trend');
  let body, settings;
  try {
    [body, settings] = await Promise.all([
      api('/api/trend'),
      api('/api/snapshots/settings'),
    ]);
  } catch (e) { return renderError(e, 'the trend'); }

  const snaps = body.data.snapshots || [];
  const cfg = settings.data;
  const canManage = (state.me?.capabilities || []).includes('config.read');

  const settingsCard = `
    <div class="card mb">
      <h4 class="mt-0">Snapshot storage</h4>
      <div class="row">
        <input type="text" id="snapDir" value="${esc(cfg.dir)}" class="w-full"
               ${canManage ? '' : 'disabled'} aria-label="Snapshot directory">
      </div>
      <div class="row">
        <label class="muted fs-13">Keep per asset
          <input type="number" id="snapKeep" min="0" value="${esc(cfg.keep)}"
                 ${canManage ? '' : 'disabled'}></label>
        <span class="muted fs-13">0 keeps everything · ${esc(cfg.count)} snapshot(s) stored</span>
        ${canManage ? '<button class="ghost" id="saveSnap">Apply</button>' : ''}
      </div>
      <p class="muted fs-12">Applies to the running process. Set
         <code>SECSCAN_SNAPSHOT_DIR</code> so it survives a restart.</p>
    </div>`;

  if (!snaps.length) {
    app.innerHTML = provenanceBanner(body.provenance, body.note) + settingsCard +
      `<div class="empty"><h3>No snapshots yet</h3>
       <p>Each scan writes one. Run a scan and come back.</p></div>`;
    wireSnapSettings();
    return;
  }

  const rows = snaps.map((m) => {
    const sev = SEVS.filter((sv) => (m.counts || {})[sv])
      .map((sv) => `<span class="badge ${sv}">${esc(sv)} ${m.counts[sv]}</span>`).join(' ');
    return `<tr>
      <td>${esc(relTime(m.at))}<small>${esc(m.at)}</small></td>
      <td class="risk">${esc(m.score)}</td>
      <td>${esc(m.total)}</td>
      <td>${sev}</td>
      <td>${esc(m.checks_ran)} ran${m.checks_skipped ? `, <span class="muted">${esc(m.checks_skipped)} did not</span>` : ''}</td>
      <td class="muted">${esc(m.size_kb)} KB</td>
    </tr>`;
  }).reverse().join('');

  const first = snaps[0], last = snaps[snaps.length - 1];
  const delta = (last.score - first.score).toFixed(1);
  const dir = delta > 0 ? 'improved' : delta < 0 ? 'worsened' : 'unchanged';

  app.innerHTML = provenanceBanner(body.provenance, body.note) + `
    <h1 class="page">Posture over time</h1>
    <p class="sub">${snaps.length} snapshot(s) for <b>${esc(last.asset)}</b>.
       ${snaps.length > 1
         ? `Score has <b>${dir}</b> by ${esc(Math.abs(delta))} since ${esc(relTime(first.at))}.`
         : 'A trend needs at least two scans.'}</p>

    <div class="card mb">
      <h4 class="mt-0">Score</h4>
      <div class="trend" id="trendChart"></div>
      <div class="trend-axis">
        <span>${esc(relTime(first.at))}</span>
        <span id="axisLabel"></span>
        <span>now</span>
      </div>
      <p class="muted fs-12">Bar height is the posture score, on an axis from zero to the
         labelled ceiling rather than to 100 — otherwise a low score is an invisible sliver
         and real movement looks like none. The strip beneath each bar shows how many checks
         ran: a score that rises while coverage falls is not an improvement, and this is
         where that shows.</p>
    </div>

    ${snaps.length > 1 ? `<div class="card mb">
      <h4 class="mt-0">Since the previous scan</h4>
      <div id="diffBox" class="muted">Loading…</div>
    </div>` : ''}

    ${settingsCard}

    <div class="card">
      <h4 class="mt-0">Snapshots</h4>
      <table>
        <thead><tr><th>When</th><th>Score</th><th>Open</th><th>Severity</th><th>Coverage</th><th>Size</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  // Bars are data-driven, so their heights are set through the CSSOM rather
  // than inline style attributes, which the CSP forbids.
  const chart = document.getElementById('trendChart');
  const maxRan = Math.max(...snaps.map((m) => m.checks_ran || 1));

  // The axis keeps zero as its baseline but adapts its TOP to the data.
  //
  // A fixed 0–100 axis is unreadable when every score is 5: the bars are a few
  // pixels and a real change looks like no change. Cutting the bottom off
  // instead would exaggerate small movements, which is the more dishonest of
  // the two failures. Adapting only the top keeps proportions truthful, and the
  // ceiling is labelled so nobody reads a full-height bar as a perfect score.
  const peak = Math.max(...snaps.map((m) => m.score), 1);
  const axisTop = Math.min(100, Math.max(10, Math.ceil(peak * 1.3)));
  document.getElementById('axisLabel').textContent = `0–${axisTop} of 100`;

  snaps.slice(-40).forEach((m) => {
    const col = document.createElement('div');
    col.className = 'tcol';
    const bar = document.createElement('i');
    bar.className = 'tbar ' + scoreClass(m.score);
    bar.style.height = `${Math.max(2, Math.round((m.score / axisTop) * 100))}%`;
    bar.title = `${m.at} — score ${m.score}, ${m.total} open, ${m.checks_ran} checks ran`;
    const cov = document.createElement('i');
    cov.className = 'tcov';
    cov.style.width = `${Math.round(((m.checks_ran || 0) / maxRan) * 100)}%`;
    cov.title = `${m.checks_ran} of ${maxRan} checks ran`;
    col.appendChild(bar);
    col.appendChild(cov);
    chart.appendChild(col);
  });

  wireSnapSettings();
  if (snaps.length > 1) loadDiff(last.asset);
}

async function loadDiff(asset) {
  const box = document.getElementById('diffBox');
  if (!box) return;
  let body;
  try { body = await api(`/api/snapshots/diff?asset=${encodeURIComponent(asset)}`); }
  catch (e) { box.textContent = 'Could not compare: ' + e.message; return; }

  const d = body.data;
  const list = (fs, cls) => fs && fs.length
    ? `<ul class="difflist">${fs.slice(0, 8).map((f) =>
        `<li><span class="badge ${cls}">${esc(f.severity)}</span> ${esc(f.title)}</li>`).join('')}
       ${fs.length > 8 ? `<li class="muted">…and ${fs.length - 8} more</li>` : ''}</ul>`
    : '<p class="muted">none</p>';

  box.innerHTML = `
    ${body.note ? `<div class="banner">${esc(body.note)}</div>` : ''}
    <div class="row mb">
      <span class="badge ${d.score_delta >= 0 ? 'ok' : 'critical'}">score ${d.score_delta >= 0 ? '+' : ''}${esc(d.score_delta)}</span>
      <span class="badge high">${esc((d.new || []).length)} new</span>
      <span class="badge ok">${esc((d.fixed || []).length)} fixed</span>
      <span class="badge low">${esc(d.unchanged)} unchanged</span>
    </div>
    ${(d.coverage_lost || []).length
      ? `<div class="banner bad"><b>Coverage dropped:</b> ${esc(d.coverage_lost.join(', '))}
         — findings these would have raised are simply absent, not resolved.</div>` : ''}
    <h4>New</h4>${list(d.new, 'high')}
    <h4>Fixed</h4>${list(d.fixed, 'ok')}`;
}

function wireSnapSettings() {
  document.getElementById('saveSnap')?.addEventListener('click', async () => {
    const dir = document.getElementById('snapDir').value.trim();
    const keep = parseInt(document.getElementById('snapKeep').value, 10) || 0;
    try {
      await api('/api/snapshots/settings', {
        method: 'POST', body: JSON.stringify({ dir, keep }),
      });
      viewTrend();
    } catch (e) { alert('Could not apply: ' + e.message); }
  });
}

/* ------------------------------------------------------- check scorecard */

// checkStatusBadge and checkRow are shared by the category drill-down and the
// full coverage scorecard, so a check reads identically wherever you meet it.
function checkStatusBadge(r) {
  switch (r.status) {
    case 'findings': return `<span class="badge high">${r.found} finding${r.found === 1 ? '' : 's'}</span>`;
    case 'clean':    return `<span class="badge ok">clean</span>`;
    case 'skipped':  return `<span class="badge low">did not run</span>`;
    case 'never-run':return `<span class="badge low">never run</span>`;
    case 'disabled': return `<span class="badge medium">disabled</span>`;
    case 'applied':  return `<span class="badge ok">applied</span>`;
  }
  return '';
}

function checkRow(r) {
  const sev = SEVS.filter((sv) => r.counts[sv])
    .map((sv) => `<span class="badge ${sv}">${esc(sv)} ${r.counts[sv]}</span>`).join(' ');
  return `<tr data-check="${esc(r.id)}">
    <td class="title"><b>${esc(r.label)}</b>
      <small>${esc(r.id)}${r.kind === 'engine' ? ' · external engine' : ''}</small>
      ${r.status === 'skipped' || r.status === 'never-run'
        ? `<small class="skipreason">${esc(r.skipped || 'has not run on any recorded scan')}</small>` : ''}
      ${r.status === 'applied'
        ? `<small>raises no findings of its own — it feeds the risk model</small>` : ''}</td>
    <td>${checkStatusBadge(r)}</td>
    <td>${sev}</td>
    <td class="risk">${r.top_risk ? esc(r.top_risk) : ''}</td>
  </tr>`;
}

function wireCheckRows() {
  app.querySelectorAll('tr[data-check]').forEach((tr) => {
    tr.addEventListener('click', () => go({ view: 'check', id: tr.dataset.check }));
  });
}

/* --------------------------------------------------------------- category */

async function viewCategory(cat) {
  renderLoading(cat);
  let body, summary;
  try {
    [body, summary] = await Promise.all([
      api(`/api/findings?category=${encodeURIComponent(cat)}&page_size=500`),
      api('/api/summary'),
    ]);
  } catch (e) { return renderError(e, 'these findings'); }

  const list = body.data || [];
  // Which checks feed this category, and did they all actually run? Without
  // this, an empty category is ambiguous: it could mean nothing is wrong, or
  // that the check which would have told you never ran.
  const checks = (summary.data.checks || []).filter((c) => c.category === cat);
  const notRun = checks.filter((c) => c.status === 'skipped' || c.status === 'never-run' || c.status === 'disabled');
  const label = checks.length && checks[0].category === cat ? cat : cat;

  app.innerHTML = `
    <p><button class="ghost" id="back">← Overview</button></p>
    <h1 class="page">${esc(categoryLabel(cat, summary))}</h1>
    <p class="sub">${list.length} of ${body.total} open finding(s)${body.has_more ? ' — first page' : ''}</p>

    ${notRun.length ? `<div class="banner"><b>${notRun.length} check(s) in this category did not run.</b>
       Anything they would have found is missing from the list below.</div>` : ''}

    ${checks.length ? `<div class="card mb">
      <h4 class="mt-0">Checks feeding this category</h4>
      <table><tbody>${checks.map(checkRow).join('')}</tbody></table>
    </div>` : ''}

    ${list.length ? `<div class="card"><table>
      <thead><tr><th>Residual</th><th>Severity</th><th>Finding</th><th></th></tr></thead>
      <tbody>${rowsFor(list)}</tbody></table></div>`
      : `<div class="empty"><h3>Nothing open here</h3>
         <p>${notRun.length
              ? 'But some checks in this category did not run — see above. An empty result is only meaningful for the checks that executed.'
              : 'Every check in this category ran and found nothing. That is a genuine pass.'}</p></div>`}`;

  document.getElementById('back').addEventListener('click', () => go({ view: 'overview' }));
  wireRows();
  wireCheckRows();
}

// categoryLabel prefers the human label the server already knows.
function categoryLabel(cat, summary) {
  const cats = (summary && summary.data && summary.data.category_labels) || {};
  return cats[cat] || cat;
}

/* ---------------------------------------------------------------- finding */

async function viewFinding(id) {
  renderLoading('finding');
  let body;
  try { body = await api(`/api/findings/${encodeURIComponent(id)}`); }
  catch (e) { return renderError(e, 'this finding'); }

  const f = body.data.finding;
  const factors = body.data.risk_factors || [];

  const evidence = (f.evidence || []).map((e) => `<pre class="evidence">${
    e.command ? `<span class="cmd">$ ${esc(e.command)}</span>` : ''
  }${e.path ? `<span class="cmd">${esc(e.path)}</span>` : ''}${esc(e.output)}</pre>`).join('');

  const factorHtml = factors.map((x) => `<div class="factor">
    <b>×${esc(x.multiplier)}</b>${esc(x.name)}<br><small>${esc(x.why)}</small></div>`).join('');

  const refs = (f.references || []).map((r) => {
    const u = safeUrl(r);
    return u
      ? `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></li>`
      : `<li class="muted">${esc(r)} <small>(not a link — unsupported scheme)</small></li>`;
  }).join('');

  const canSuppress = (state.me?.capabilities || []).includes('finding.suppress');

  app.innerHTML = `
    <p><button class="ghost" id="back">← Back</button></p>
    <div class="card detail">
      <h2>${esc(f.title)}</h2>
      <div class="meta">
        <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
        ${f.exposed ? '<span class="badge exposed">exposed</span>' : ''}
        ${f.status !== 'open' ? `<span class="badge ok">${esc(f.status)}</span>` : ''}
        <span>residual risk <b>${esc(f.residual_risk)}</b></span>
        ${f.mitigation_factor ? `<span class="muted">(inherent ${esc(f.inherent_risk)})</span>` : ''}
        <span>· ${esc(f.asset_id)}</span>
        <span>· ${esc(f.category)}</span>
        <span>· found by ${esc(f.engine)}</span>
        <span>· first seen ${esc(relTime(f.first_seen))}</span>
      </div>

      ${f.description ? `<p>${esc(f.description)}</p>` : ''}

      <section>
        <h4>Inherent risk — before controls</h4>
        <div class="factors">${factorHtml}</div>
      </section>

      ${f.validation && f.validation.verdict !== 'unverified' ? `<section>
        <h4>Validation — tested, not inferred</h4>
        <div class="fix ${f.validation.verdict === 'refuted' ? 'refuted-box' : ''}">
          <b>${f.validation.verdict === 'confirmed' ? '✓ Confirmed' : '✗ Refuted'}</b>
          <div class="muted fs-13">Method: ${esc(f.validation.method)}</div>
          <code>${esc(f.validation.output || '')}</code>
          ${f.validation.note ? `<div class="limits">${esc(f.validation.note)}</div>` : ''}
        </div>
      </section>` : ''}

      ${(f.mitigations || []).length ? `<section>
        <h4>Compensating controls</h4>
        <div class="chain">
          <span class="chain-n">${esc(f.inherent_risk)}</span>
          <span class="chain-op">inherent</span>
          <span class="chain-arrow">→</span>
          <span class="chain-n mult">×${esc(f.mitigation_factor)}</span>
          <span class="chain-op">controls</span>
          <span class="chain-arrow">→</span>
          <span class="chain-n residual">${esc(f.residual_risk)}</span>
          <span class="chain-op">residual</span>
        </div>
        ${f.mitigations.map((m) => `<div class="control">
          <b>${esc(m.name)}</b> <span class="badge ok">×${esc(m.factor)}</span>
          <div class="muted fs-13">${esc(m.detail)}</div>
          <div class="limits"><b>Does not cover:</b> ${esc(m.limits)}</div>
        </div>`).join('')}
        <p class="muted fs-12">Controls reduce risk; they never clear it. The reduction is
           capped, and the inherent figure is what this returns to if a control is removed,
           fails, or turns out to have been misconfigured.</p>
      </section>` : ''}

      ${f.remediation?.summary ? `<section>
        <h4>How to fix</h4>
        <div class="fix">${esc(f.remediation.summary)}
        ${f.remediation.command ? `<code>${esc(f.remediation.command)}</code>` : ''}</div>
      </section>` : ''}

      <section id="changerisk"><h4>Risk of applying the fix</h4>
        <p class="muted fs-13">Loading…</p></section>

      <section>
        <h4>Evidence</h4>
        ${evidence || '<p class="muted">No evidence recorded.</p>'}
      </section>

      ${refs ? `<section><h4>References</h4><ul>${refs}</ul></section>` : ''}

      ${canSuppress && f.status === 'open'
        ? `<section><button class="ghost" id="suppress">Accept this risk…</button></section>` : ''}
      ${f.status === 'suppressed'
        ? `<section><p class="muted">Accepted: ${esc(f.suppress_reason)}
           (until ${esc((f.suppress_until || '').slice(0, 10))})</p></section>` : ''}
    </div>`;

  document.getElementById('back').addEventListener('click', () => history.back());
  document.getElementById('suppress')?.addEventListener('click', () => openSuppress(f.id));
  renderChangeRisk(f);
}

// ---------------------------------------------------------------- remediation

// renderChangeRisk shows how dangerous it would be to APPLY the fix, which is a
// different question from how severe the finding is. It is loaded separately
// from the finding so the detail page still renders if the endpoint is
// unavailable — a fix panel that fails to load must not take the evidence with
// it.
async function renderChangeRisk(f) {
  const box = document.getElementById('changerisk');
  if (!box) return;

  let plan;
  try {
    plan = (await api(`/api/findings/${encodeURIComponent(f.id)}/remediate`)).data;
  } catch (e) {
    box.innerHTML = `<h4>Risk of applying the fix</h4>
      <p class="muted fs-13">Could not load the change-risk assessment: ${esc(e.message)}</p>`;
    return;
  }

  // No playbook is the common case and is not a failure. Say plainly why
  // nothing can be run, rather than showing an empty panel.
  if (!plan.risk) {
    box.innerHTML = `<h4>Risk of applying the fix</h4>
      <div class="fix"><b>Not automated</b>
      <div class="muted fs-13">${esc(plan.blocked || '')}</div></div>`;
    return;
  }

  const label = { green: 'GREEN — safe to apply', amber: 'AMBER — needs a window',
                  red: 'RED — will not be applied by this tool' }[plan.risk] || plan.risk;
  const canApply = (state.me?.capabilities || []).includes('remediate.apply');
  const steps = (list, name) => (list || []).length
    ? `<div class="fs-13"><b>${name}</b>${list.map((c) => `<code>${esc(c)}</code>`).join('')}</div>` : '';

  box.innerHTML = `
    <h4>Risk of applying the fix</h4>
    <div class="fix risk-${esc(plan.risk)}">
      <span class="badge risk-${esc(plan.risk)}">${esc(label)}</span>
      <p class="fs-13">${esc(plan.why || '')}</p>
      ${/* plan.blocked restates the reason so the API stays self-contained for
            non-UI callers. Here the badge and the paragraph above have already
            said it, so repeating it verbatim just makes the panel look padded. */
        plan.blocked && !plan.why ? `<div class="limits">${esc(plan.blocked)}</div>` : ''}
      ${steps(plan.backup, 'Backup first')}
      ${steps(plan.apply, 'Then apply')}
      ${steps(plan.verify, 'Then prove it worked')}
      ${steps(plan.rollback, 'Undo if verification fails')}
      ${plan.executable ? `<p class="fs-12 muted">This rating is about the change, not the
         finding. The steps run in order and stop at the first failure; if verification
         says the weakness is still present, the change is rolled back.</p>` : ''}
    </div>
    <div id="fixactions"></div>`;

  if (!plan.executable) return;
  const actions = document.getElementById('fixactions');
  actions.innerHTML = canApply
    ? `<button class="ghost" id="fixdry">Dry run</button>
       <button class="ghost danger" id="fixapply">Apply this fix…</button>`
    : `<p class="muted fs-12">Applying a fix needs the remediate.apply capability,
       which is granted to administrators only.</p>`;

  const run = async (dryRun) => {
    if (!dryRun && !confirm(
      `Apply this fix to ${f.asset_id}?\n\n${plan.apply.join('\n')}\n\n` +
      `The change is verified afterwards and rolled back if verification fails.`)) return;
    actions.innerHTML = '<p class="muted fs-13">Running…</p>';
    try {
      const res = (await api(`/api/findings/${encodeURIComponent(f.id)}/remediate`, {
        method: 'POST',
        body: JSON.stringify({ confirm: !dryRun, dry_run: dryRun }),
      })).data.result;
      actions.innerHTML = renderFixResult(res, dryRun);
    } catch (e) {
      actions.innerHTML = `<p class="bad fs-13">${esc(e.message)}</p>`;
    }
  };
  document.getElementById('fixdry')?.addEventListener('click', () => run(true));
  document.getElementById('fixapply')?.addEventListener('click', () => run(false));
}

function renderFixResult(res, dryRun) {
  let head;
  if (dryRun) head = '<b>Dry run — nothing was changed</b>';
  else if (res.verified) head = '<b class="good">✓ Applied and verified on the host</b>';
  else if (res.rolled_back) head = '<b class="bad">✗ Failed — rolled back</b>';
  else if (res.applied) head = '<b class="bad">✗ Applied but NOT verified</b>';
  else head = '<b class="bad">✗ Not applied</b>';

  const rows = (res.steps || []).map((s) => `<tr>
      <td>${s.ok ? '·' : '<span class="bad">!</span>'}</td>
      <td class="muted">${esc(s.phase)}</td>
      <td><code>${esc(s.command)}</code>${s.output ? `<div class="muted fs-12">${esc(s.output)}</div>` : ''}</td>
    </tr>`).join('');

  return `<div class="fix">${head}
    ${res.error ? `<div class="limits">${esc(res.error)}</div>` : ''}
    <table class="steps">${rows}</table>
    ${res.verified ? `<p class="fs-12 muted">Verification tested the condition on the host, not
       the exit code of the fix. Run a scan to update the rest of the dashboard.</p>` : ''}
  </div>`;
}

/* -------------------------------------------------------------- suppress */

function openSuppress(id) {
  const dlg = document.getElementById('suppressDlg');
  const reason = document.getElementById('supReason');
  reason.value = '';
  dlg.showModal();

  document.getElementById('supCancel').onclick = () => dlg.close();
  document.getElementById('supOk').onclick = async () => {
    const days = parseInt(document.getElementById('supDays').value, 10);
    if (!reason.value.trim()) { reason.focus(); return; }
    try {
      await api(`/api/findings/${encodeURIComponent(id)}/suppress`, {
        method: 'POST',
        body: JSON.stringify({ reason: reason.value.trim(), days }),
      });
      dlg.close();
      viewFinding(id);
    } catch (e) {
      alert('Could not accept risk: ' + e.message);
    }
  };
}

/* ------------------------------------------------------------------ plan */

async function viewPlan() {
  renderLoading('remediation plan');
  let body;
  try { body = await api('/api/plan'); }
  catch (e) { return renderError(e, 'the plan'); }

  const actions = body.data || [];
  if (!actions.length) {
    app.innerHTML = `<div class="empty"><h3>Nothing to do</h3>
      <p>No open findings have a remediation attached.</p></div>`;
    return;
  }
  app.innerHTML = `
    <h1 class="page">Remediation plan</h1>
    <p class="sub">The minimum set of actions, ordered by how much risk each one clears.
       secscan never runs these — review, then apply.</p>
    <div class="card"><table>
      <thead><tr><th>#</th><th>Risk cleared</th><th>Action</th><th>Findings</th></tr></thead>
      <tbody>${actions.map((a, i) => `<tr>
        <td>${i + 1}</td>
        <td class="risk">${esc(a.risk_cleared)}</td>
        <td class="title">${esc(a.summary)}
          ${a.command ? `<small><code>${esc(a.command)}</code></small>` : '<small>manual</small>'}</td>
        <td>${esc(a.finding_count)}</td></tr>`).join('')}
      </tbody></table></div>`;
}

/* -------------------------------------------------------------- coverage */

async function viewCoverage() {
  renderLoading('checks and results');
  let body;
  try { body = await api('/api/summary'); }
  catch (e) { return renderError(e, 'the assessment summary'); }

  const d = body.data;
  const rows = d.checks || [];
  const t = d.tally || {};

  if (!d.scanned_at) {
    app.innerHTML = provenanceBanner(body.provenance, body.note) +
      `<div class="empty"><h3>No scan has run yet</h3>
       <p>Run <code>secscan scan</code>, or press <b>Scan</b> above.</p></div>`;
    return;
  }

  app.innerHTML = provenanceBanner(body.provenance, body.note) + `
    <h1 class="page">Checks &amp; results</h1>
    <p class="sub">Every check secscan can run, what it did on the last scan of
       <b>${esc(d.target)}</b> (${esc(relTime(d.scanned_at))}), and what it found.
       Select any row for detail, or turn checks on and off in
       <button class="linklike" id="toChecks">Checks</button>.</p>

    <div class="card mb">
      <h4 class="mt-0">Outcomes</h4>
      <div class="chips">
        <span class="badge high">${t.findings || 0} with findings</span>
        <span class="badge ok">${(t.clean || 0) + (t.applied || 0)} clean</span>
        <span class="badge low">${(t.skipped || 0) + (t['never-run'] || 0)} did not run</span>
        ${t.disabled ? `<span class="badge medium">${t.disabled} disabled</span>` : ''}
      </div>
      <p class="muted fs-13">A check that did not run is not a pass. Its findings are
         simply absent from this assessment, which is why those rows sort above the
         clean ones.</p>
    </div>

    <div class="card">
      <table>
        <thead><tr><th>Check</th><th>Result</th><th>Severity</th><th>Top risk</th></tr></thead>
        <tbody>${rows.map(checkRow).join('')}</tbody>
      </table>
    </div>`;

  document.getElementById('toChecks')?.addEventListener('click', () => go({ view: 'checks' }));
  wireCheckRows();
}

// viewCheck is the coverage drill-down: what this specific check inspects,
// whether it ran, and exactly which findings are attributable to it.
async function viewCheck(id) {
  renderLoading(id);
  let body;
  try { body = await api(`/api/coverage/${encodeURIComponent(id)}`); }
  catch (e) { return renderError(e, 'this check'); }

  const d = body.data;
  const feat = d.feature;
  const run = d.run;
  const found = d.findings || [];
  const counts = d.counts || {};

  const sevLine = SEVS.filter((sv) => counts[sv])
    .map((sv) => `<span class="badge ${sv}">${esc(sv)} ${counts[sv]}</span>`).join(' ');

  let status;
  if (!run) {
    status = `<div class="banner info"><b>Not in the recorded scan history</b> —
      this check has not run on any stored scan.</div>`;
  } else if (run.ran) {
    status = `<div class="card mb">
      <b>Ran</b> · ${esc(run.checks)} sub-check(s) · ${esc(run.found)} finding(s) this scan
      ${sevLine ? '<div class="chips">' + sevLine + '</div>' : ''}</div>`;
  } else {
    // The reason is the actionable part — lead with it.
    status = `<div class="banner"><div>
      <b>Did not run</b><br>${esc(run.skipped)}
    </div></div>`;
  }

  const canManage = (state.me?.capabilities || []).includes('feature.manage');

  app.innerHTML = `
    <p class="row">
      <button class="ghost" id="back">← Checks &amp; results</button>
      <button class="ghost" id="toChecksPage">All checks</button>
      ${feat && canManage
        ? `<button class="ghost" id="toggleHere">${feat.enabled ? 'Disable' : 'Enable'} this check</button>`
        : ''}
    </p>
    <h1 class="page">${esc(feat ? feat.label : id)}</h1>
    <p class="sub"><code>${esc(id)}</code>${feat ? ' · ' + esc(feat.kind) : ''}${
      feat && !feat.enabled ? ' · <b>disabled by operator</b>' : ''}</p>

    ${status}

    ${feat ? `<div class="card mb">
      <h4 class="mt-0">What this check covers</h4>
      <p>${esc(feat.description)}</p>
      ${feat.kind === 'engine' ? `<p class="muted fs-13">External engine
        <code>${esc(feat.binary)}</code> — ${feat.installed ? 'installed' : 'not installed'}
        on the target. ${esc(feat.install_hint || '')}</p>` : ''}
    </div>` : ''}

    ${(d.transcript || []).length ? `<div class="card mb">
      <h4 class="mt-0">What this check actually ran (${d.transcript.length} command(s))</h4>
      <p class="muted fs-13">The commands and their output, so you can check the
         scanner's work rather than take the conclusion on faith. Output that would
         contain secret material is withheld — the command is still shown, because
         knowing what was read is useful and the contents are not.</p>
      ${d.transcript.map((st) => `<pre class="evidence step">
<span class="cmd">$ ${esc(st.command)}<span class="exit ${st.exit_code === 0 ? 'ok' : 'bad'}">exit ${esc(st.exit_code)}</span><span class="ms">${esc(st.took_ms)}ms</span></span>${
  st.redacted ? `<span class="redacted">${esc(st.stdout)}</span>`
              : esc((st.stdout || '') + (st.stderr ? '\n' + st.stderr : '')) || '<span class="muted">(no output)</span>'}</pre>`).join('')}
    </div>` : ''}

    <div class="card">
      <h4 class="mt-0">Findings from this check (${found.length})</h4>
      ${found.length ? `<table>
        <thead><tr><th>Residual</th><th>Severity</th><th>Finding</th><th></th></tr></thead>
        <tbody>${rowsFor(found)}</tbody></table>`
        : `<p class="muted">None open. ${run && run.ran
             ? 'This check ran and found nothing — that is a genuine pass.'
             : 'This check did not run, so an empty result here means nothing.'}</p>`}
    </div>`;

  document.getElementById('back').addEventListener('click', () => go({ view: 'coverage' }));
  document.getElementById('toChecksPage')?.addEventListener('click', () => go({ view: 'checks' }));
  document.getElementById('toggleHere')?.addEventListener('click', async () => {
    try {
      await api(`/api/features/${encodeURIComponent(id)}`, {
        method: 'POST', body: JSON.stringify({ enabled: !feat.enabled }),
      });
      viewCheck(id);
    } catch (e) { alert('Could not change that: ' + e.message); }
  });
  wireRows();
}

/* ---------------------------------------------------------------- assets */

async function viewAssets() {
  renderLoading('assets');
  let body;
  try { body = await api('/api/assets'); }
  catch (e) { return renderError(e, 'assets'); }

  const list = body.data || [];
  app.innerHTML = `
    <h1 class="page">Assets</h1>
    <p class="sub">${list.length} scanned host(s)</p>
    <div class="card"><table>
      <thead><tr><th>Name</th><th>Address</th><th>OS</th><th>Kernel</th><th>Last scan</th></tr></thead>
      <tbody>${list.map((a) => `<tr data-asset="${esc(a.id)}">
        <td><b>${esc(a.name)}</b>${a.critical ? ' <span class="badge high">critical</span>' : ''}</td>
        <td>${esc(a.address)}</td><td>${esc(a.os)}</td>
        <td class="muted">${esc(a.kernel)}</td>
        <td>${esc(relTime(a.last_scan))}</td></tr>`).join('')}
      </tbody></table></div>`;
}

/* ----------------------------------------------------------------- audit */

async function viewAudit() {
  renderLoading('audit log');
  let body;
  try { body = await api('/api/audit'); }
  catch (e) { return renderError(e, 'the audit log'); }

  const list = (body.data || []).slice().reverse();
  app.innerHTML = `
    <h1 class="page">Audit</h1>
    <p class="sub">Who did what, and under which role. Both are recorded separately —
       roles are shared, so the pair is what makes the trail useful.</p>
    <div class="card"><table>
      <thead><tr><th>When</th><th>Caller</th><th>Role</th><th>Action</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>${list.map((e) => `<tr>
        <td>${esc(relTime(e.at))}</td><td>${esc(e.caller)}</td>
        <td><span class="badge low">${esc(e.role)}</span></td>
        <td>${esc(e.action)}</td>
        <td><span class="badge ${e.result === 'denied' ? 'critical' : 'ok'}">${esc(e.result)}</span></td>
        <td class="muted">${esc(e.detail || '')}</td></tr>`).join('')}
      </tbody></table></div>`;
}


/* -------------------------------------------------------------- features */

async function viewFeatures() {
  renderLoading('checks');
  let body;
  try { body = await api('/api/features'); }
  catch (e) { return renderError(e, 'the check list'); }

  const feats = body.data.features || [];
  const target = body.data.target || '';
  const canManage = (state.me?.capabilities || []).includes('feature.manage');
  const canInstall = (state.me?.capabilities || []).includes('engine.install');

  const row = (f) => {
    const status = f.kind === 'engine'
      ? (f.installed ? '<span class="badge ok">installed</span>'
                     : '<span class="badge low">not installed</span>')
      : '<span class="badge ok">built in</span>';
    const install = (f.kind === 'engine' && !f.installed && canInstall)
      ? `<button class="ghost" data-install="${esc(f.id)}">Install</button>` : '';
    return `<tr>
      <td><div class="row">
        <input type="checkbox" data-toggle="${esc(f.id)}" ${f.enabled ? 'checked' : ''}
               ${canManage ? '' : 'disabled'} aria-label="Enable ${esc(f.label)}">
        <button class="linklike" data-open="${esc(f.id)}">${esc(f.label)}</button>
      </div>
        <small>${esc(f.description)}</small>
        ${f.expensive ? `<small class="costly"><b>Off by default.</b> ${esc(f.why_costly)}</small>` : ''}</td>
      <td>${esc(f.category)}</td>
      <td>${status}</td>
      <td class="right">${install}</td>
    </tr>`;
  };

  const collectors = feats.filter((f) => f.kind === 'collector');
  const engines = feats.filter((f) => f.kind === 'engine');
  const off = feats.filter((f) => !f.enabled).length;

  app.innerHTML = provenanceBanner(body.provenance, body.note) + `
    <h1 class="page">Checks</h1>
    <p class="sub">What the scanner runs${target ? ' against <b>' + esc(target) + '</b>' : ''}.
       Select a check to see what it found and the commands it ran, or see them all
       in <button class="linklike" id="toResults">Checks &amp; results</button>.
       Disabling a check does not fix anything — it stops you being told about it,
       and it will be reported as disabled rather than quietly omitted.</p>
    ${off ? `<div class="banner"><b>${off} check(s) disabled</b> — findings they
       would raise are not being collected.</div>` : ''}

    <div class="card mb">
      <h4 class="mt-0">Built-in collectors</h4>
      <table><tbody>${collectors.map(row).join('')}</tbody></table>
    </div>

    <div class="card">
      <h4 class="mt-0">Optional engines</h4>
      <p class="muted fs-13">External scanners that add depth. They are never
         required: the scan reports exactly what did not run and why.
         ${canInstall ? 'Installing one <b>modifies the target host</b> and is audited.'
                      : 'Installing requires the admin role.'}</p>
      <table><tbody>${engines.map(row).join('')}</tbody></table>
    </div>`;

  document.getElementById('toResults')?.addEventListener('click', () => go({ view: 'coverage' }));

  app.querySelectorAll('input[data-toggle]').forEach((el) => {
    el.addEventListener('change', async () => {
      try {
        await api(`/api/features/${encodeURIComponent(el.dataset.toggle)}`, {
          method: 'POST', body: JSON.stringify({ enabled: el.checked }),
        });
        viewFeatures();
      } catch (e) {
        el.checked = !el.checked;
        alert('Could not change that: ' + e.message);
      }
    });
  });

  app.querySelectorAll('button[data-install]').forEach((el) => {
    el.addEventListener('click', () => installEngine(el.dataset.install, target));
  });
  // Each check links to its own results and command transcript, so "what does
  // this do?" and "what did it actually find?" are one click apart rather than
  // two separate pages you have to correlate yourself.
  app.querySelectorAll('button[data-open]').forEach((el) => {
    el.addEventListener('click', () => go({ view: 'check', id: el.dataset.open }));
  });
}

// installEngine shows the exact commands first. A one-click "install" that
// silently runs a shell script on a production host is not something a security
// tool should do.
async function installEngine(id, target) {
  let plan;
  try {
    plan = (await api(`/api/engines/${encodeURIComponent(id)}/install?target=${encodeURIComponent(target)}`)).data;
  } catch (e) { return alert('Could not plan the install: ' + e.message); }

  if (!plan.supported) return alert(plan.reason);

  const ok = confirm(
    `Install ${id} on ${target}?\n\n` +
    `This MODIFIES the target host and is audited. It will run, as root:\n\n` +
    plan.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')
  );
  if (!ok) return;

  const btn = app.querySelector(`button[data-install="${CSS.escape(id)}"]`);
  if (btn) { btn.disabled = true; btn.textContent = 'Installing…'; }
  try {
    const res = (await api(`/api/engines/${encodeURIComponent(id)}/install`, {
      method: 'POST', body: JSON.stringify({ target, confirm: true }),
    })).data;
    if (!res.ok) alert('Install did not complete:\n\n' + (res.error || '') + '\n\n' + (res.output || []).join('\n'));
    viewFeatures();
  } catch (e) {
    alert('Install failed: ' + e.message);
    viewFeatures();
  }
}

/* ---------------------------------------------------------------- router */

const VIEWS = [
  ['overview', 'Overview', viewOverview],
  ['assets', 'Assets', viewAssets],
  ['plan', 'Plan', viewPlan],
  ['trend', 'Trend', viewTrend],
  ['coverage', 'Checks & results', viewCoverage],
  ['checks', 'Checks', viewFeatures],
  ['audit', 'Audit', viewAudit],
];

function go(r) {
  const q = new URLSearchParams(r);
  history.pushState(r, '', '#' + q.toString());
  route();
}

function route() {
  const q = new URLSearchParams(location.hash.slice(1));
  const view = q.get('view') || 'overview';
  state.route = { view, cat: q.get('cat'), id: q.get('id') };

  document.querySelectorAll('#tabs button').forEach((b) => {
    if (b.dataset.view === view) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });

  if (view === 'category') return viewCategory(state.route.cat);
  if (view === 'check') return viewCheck(state.route.id);
  if (view === 'finding') return viewFinding(state.route.id);
  const v = VIEWS.find((x) => x[0] === view);
  (v ? v[2] : viewOverview)();
}

/* ------------------------------------------------------------------ chrome */

function applyTheme(mode) {
  document.documentElement.classList.toggle('dark', mode === 'dark');
  try { localStorage.setItem('secscan-theme', mode); } catch (_) { /* private mode */ }
}

async function boot() {
  // Theme before first paint of data, so there is no flash.
  let saved = null;
  try { saved = localStorage.getItem('secscan-theme'); } catch (_) { /* ignore */ }
  applyTheme(saved || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  document.getElementById('theme').addEventListener('click', () => {
    applyTheme(document.documentElement.classList.contains('dark') ? 'light' : 'dark');
  });

  document.getElementById('tabs').innerHTML = VIEWS
    .map(([k, label]) => `<button data-view="${k}">${esc(label)}</button>`).join('');
  document.querySelectorAll('#tabs button').forEach((b) => {
    b.addEventListener('click', () => go({ view: b.dataset.view }));
  });

  try {
    const me = (await api('/api/me')).data;
    state.me = me;
    document.getElementById('version').textContent = me.version;
    document.getElementById('who').textContent = `${me.email} · ${me.role}`;
    if (me.auth_mode === 'local') {
      document.getElementById('who').textContent = 'local mode — no authentication';
    }
    // Hide affordances the role cannot use. This is UX, not security: the
    // server denies regardless.
    if (!me.capabilities.includes('scan.run')) {
      document.getElementById('scanBtn').style.display = 'none';
    }
    const allowed = { 'audit.read': 'audit' };
    Object.entries(allowed).forEach(([cap, view]) => {
      if (!me.capabilities.includes(cap)) {
        document.querySelector(`#tabs button[data-view="${view}"]`)?.remove();
      }
    });
  } catch (e) {
    return renderError(e, 'your session');
  }

  document.getElementById('scanBtn').addEventListener('click', runScan);
  window.addEventListener('popstate', route);
  route();
}

async function runScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  try {
    await api('/api/scan', { method: 'POST', body: JSON.stringify({}) });
    route();
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
}

boot();
