import { $, $$, esc, num, pct, pill, icon, tip, words, short, clock, toast, paintRange, dialog } from '../ui.js';
import { api, store, follow } from '../api.js';
import { EvidenceRadar } from '../cloud.js';
import { CLAIM_HELP, STAGES } from '../content.js';
import { startTour } from '../tour.js';
import { packagePane, contractPane, PRESETS } from './panes.js';
import { labPane } from './lab.js';
import { scorecard } from './scorecard.js';

// State survives navigation so a running job keeps streaming into the view.
export const S = { tab: 'package', fixture: null, format: 'COCO', policy: null, preset: 'balanced',
  job: null, stop: null, feed: [], loop: [], claims: {}, counts: {}, stage: '', progress: 0, budget: null, result: null };
let radar = null, mainEl = null;

const stageIndex = s => ({ Intake: 0, Baseline: 1, 'Semantic embedding': 1, 'Model assurance': 2, Provenance: 3, 'Active assurance': 4, 'Contrarian loop': 4, Decision: 5, Complete: 5 }[s] ?? 0);

export async function render(main, params) {
  const boot = store.boot;
  mainEl = main;
  S.policy ??= structuredClone(boot.policy);
  S.fixture ??= (boot.fixtures.find(f => f.id === boot.showcase?.fixture) || boot.fixtures.find(f => f.kind === 'attack-lab') || boot.fixtures.find(f => f.id === 'hostile') || boot.fixtures[0])?.id;
  if (params.get('tab')) S.tab = ['contract', 'lab'].includes(params.get('tab')) ? params.get('tab') : 'package';
  const hidden = localStorage.getItem('sw-tutorial-hidden') === '1';
  main.innerHTML = `
    <div class="page-head frame corners">
      <div><div class="label">02 / Workbench</div><h1 class="h1">Run the assurance <em>live.</em></h1>
        <p class="lead">Choose a package, set the Assurance Contract, then watch every finding, adaptive test and claim change as it happens — computed on this machine.</p></div>
      <div class="stack" style="justify-items:end">${hidden ? '<button class="linkish" id="show-tutorial">Show the tutorial</button>' : ''}<button class="btn small" id="tour-btn">${icon.play} Guided tour</button></div>
    </div>
    ${hidden ? '' : `<div class="tutorial" id="tutorial" style="grid-template-columns:300px repeat(3,minmax(0,1fr)) auto">
      <div class="t-intro"><span class="label">Tutorial · 90 seconds</span><b>How to use the workbench</b><span class="small">Three steps from package to sealed verdict.</span></div>
      ${[['01', 'Pick a package', 'Bundled packages, imported ZIPs, or an evaluation package with a sealed answer key.', 'package'],
         ['02', 'Set the contract', 'Access tier, budget and thresholds. Hover any ? to learn what it does.', 'contract'],
         ['03', 'Run & inspect', 'Watch findings stream and the loop choose tests, then open the evidence.', 'theatre']]
        .map(([n, t, d, g]) => `<div class="t-step" data-goto="${g}" tabindex="0" role="button"><small>${n}</small><div><b>${t}</b><span>${d}</span></div></div>`).join('')}
      <div class="t-actions"><button class="btn small primary" id="quick-run">${icon.play} Quick run</button><button class="linkish" id="hide-tutorial">Hide tutorial</button></div>
    </div>`}
    <div class="wb">
      <aside class="wb-side">
        <div class="wb-tabs" role="tablist" id="wb-tabs">${[['package', '01', 'Package'], ['contract', '02', 'Contract'], ['lab', '03', 'Attack Lab']].map(([id, n, l]) => `<button role="tab" data-tab="${id}" class="${S.tab === id ? 'on' : ''}" aria-selected="${S.tab === id}"><small>${n}</small>${l}</button>`).join('')}</div>
        <div class="wb-pane" id="pane"></div>
        <div class="wb-run" id="run-bar"></div>
      </aside>
      <section class="wb-main" id="theatre">
        <div class="theatre-top"><span class="label" id="theatre-title">Live assessment</span><span class="spacer"></span><span class="small" id="theatre-meta"></span></div>
        <div class="rail" id="rail">${STAGES.map(([s, d], i) => `<div data-stage="${i}"><small>${String(i + 1).padStart(2, '0')} / ${esc(d)}</small><b>${esc(s)}</b></div>`).join('')}</div>
        <div id="banner"></div>
        <div class="theatre">
          <div class="theatre-left">
            <div class="radar"><canvas id="radar" aria-label="Evidence radar"></canvas>
              <div class="hud"><span class="label">Evidence radar ${tip('Evidence radar', 'Each dot is a real finding streamed from the running assessment, placed in the sector of the claim it affects and coloured by severity.', 'Live feed')}</span><span class="label" id="radar-n">—</span></div></div>
            <div class="counters"><div><span class="label">Findings</span><b id="c-findings">0</b></div><div><span class="label">Critical</span><b id="c-critical" class="coral">0</b></div><div><span class="label">High</span><b id="c-high" class="gold">0</b></div><div><span class="label">Loop steps</span><b id="c-loop">0</b></div></div>
            <div class="claims-board" id="claims-board">${boot.claims.map(([id, label]) => `<div class="claim-tile Unresolved" data-claim="${id}" title="${esc(CLAIM_HELP[id] || '')}"><small>${esc(words(id))}</small><b>${esc(label)}</b><i></i></div>`).join('')}</div>
            <div class="feed" id="feed" aria-live="polite"></div>
          </div>
          <div class="loop-col">
            <div class="loop-head"><div class="flex"><span class="label">Contrarian loop</span>${tip('Contrarian Loop', 'After baseline checks, open evidence becomes hypotheses. The loop picks the permitted test with the highest claim weight × discriminating value × (1 + coverage gap) / cost; results can schedule follow-ups and adaptive hits are confirmed on reserved images.', '§20 Active Assurance')}<span class="spacer"></span><span class="label" id="budget-label">Budget —</span></div><div class="budget"><i id="budget-bar" style="width:0"></i></div></div>
            <div class="loop-list" id="loop-list"></div>
          </div>
        </div>
      </section>
    </div>`;
  radar = new EvidenceRadar($('#radar'));
  bindChrome();
  paintPane(); paintRunBar(); repaintTheatre();
  if (!S.job && boot.active_job && !boot.active_job.startsWith('lab-')) attach(boot.active_job);
  return () => { mainEl = null; };
}

function bindChrome() {
  $$('#wb-tabs [data-tab]').forEach(b => b.onclick = () => setTab(b.dataset.tab));
  $('#tour-btn').onclick = tour;
  $('#quick-run')?.addEventListener('click', () => { $('#theatre').scrollIntoView({ behavior: 'smooth' }); start(); });
  $('#hide-tutorial')?.addEventListener('click', () => { localStorage.setItem('sw-tutorial-hidden', '1'); render(mainEl, new URLSearchParams()); });
  $('#show-tutorial')?.addEventListener('click', () => { localStorage.removeItem('sw-tutorial-hidden'); render(mainEl, new URLSearchParams()); });
  $$('[data-goto]').forEach(el => { const go = () => el.dataset.goto === 'theatre' ? $('#theatre').scrollIntoView({ behavior: 'smooth' }) : setTab(el.dataset.goto); el.onclick = go; el.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }; });
}

export function setTab(tab) {
  S.tab = tab;
  $$('#wb-tabs [data-tab]').forEach(b => { b.classList.toggle('on', b.dataset.tab === tab); b.setAttribute('aria-selected', b.dataset.tab === tab); });
  paintPane(); paintRunBar();
}

function tour() {
  startTour([
    { sel: '#tutorial', title: 'Your map', body: 'Three steps take you from a package to a sealed verdict. Click a step to jump there, or press Quick run.' },
    { sel: '#pkg-list', title: 'Choose a package', body: 'Bundled packages cover a real-world baseline, a curated set, an adversarial submission, a YOLO model and an evaluation package whose answer key was sealed before assessment.', before: () => setTab('package') },
    { sel: '#wb-tabs [data-tab="lab"]', title: 'Or plant your own attack', body: 'The Attack Lab forges a new package from real images with the attacks you choose. Its answer key is sealed and committed to the audit log before any assessment.' },
    { sel: '#f-access', title: 'Access changes the strategy', body: 'White-box enables gradient-based trigger reconstruction. Black-box leaves only input/output tests; the loop adapts and reports what it could not do.', before: () => setTab('contract') },
    { sel: '#f-challenge_budget', title: 'Budget forces choices', body: 'Every adaptive test has a cost. A small budget makes the loop prioritise; its stop reason is sealed into the report.' },
    { sel: '#run-bar', title: 'Run', body: 'Starts a real assessment of the selected package. One job runs at a time.' },
    { sel: '#rail', title: 'Stages', body: 'Intake, data evidence, model assurance, provenance, the Contrarian Loop and the policy decision.' },
    { sel: '.radar', title: 'Live evidence', body: 'Findings stream in as dots by domain and severity; the 19 claim tiles below change state as evidence arrives.' },
    { sel: '.loop-col', title: 'Watch the loop decide', body: 'Each card shows the hypothesis, the chosen test, its priority versus alternatives, the outcome and how the claim moved.' },
  ]);
}

// ------------------------------------------------------------------ panes
function paintPane() {
  const pane = $('#pane'); if (!pane) return;
  if (S.tab === 'lab') return labPane(pane, S, fixture => { S.fixture = fixture; setTab('package'); }).catch(e => toast(e.message, { error: true }));
  pane.innerHTML = S.tab === 'contract' ? contractPane(S) : packagePane(S);
  $$('[data-fixture]', pane).forEach(b => b.onclick = () => { S.fixture = b.dataset.fixture; paintPane(); paintRunBar(); });
  $$('[data-format]', pane).forEach(b => b.onclick = () => { S.format = b.dataset.format; paintPane(); });
  $$('[data-preset]', pane).forEach(b => b.onclick = () => { S.preset = b.dataset.preset; S.policy = { ...structuredClone(store.boot.policy), ...structuredClone(PRESETS[b.dataset.preset].policy) }; paintPane(); paintRunBar(); });
  $$('[data-seg]', pane).forEach(b => b.onclick = () => { S.policy[b.dataset.seg] = b.dataset.value; S.preset = null; paintPane(); paintRunBar(); });
  $$('[data-text]', pane).forEach(i => i.oninput = () => { S.policy[i.dataset.text] = i.value; });
  $$('[data-mandatory]', pane).forEach(c => c.onchange = () => { S.policy.mandatory = $$('[data-mandatory]:checked', pane).map(x => x.dataset.mandatory); S.preset = null; paintPane(); });
  $$('input[type=range][data-policy]', pane).forEach(r => { paintRange(r); r.oninput = () => { const v = Number(r.value); S.policy[r.dataset.policy] = v; $(`[data-val="${r.dataset.policy}"]`).textContent = v; paintRange(r); S.preset = null; paintRunBar(); }; });
  $('#reset-policy')?.addEventListener('click', () => { S.policy = structuredClone(store.boot.policy); S.preset = 'balanced'; paintPane(); paintRunBar(); });
  $('#upload')?.addEventListener('change', async e => {
    const f = e.target.files[0]; if (!f) return;
    try { toast('Importing into quarantine…'); const res = await fetch('/api/upload', { method: 'POST', body: f }); const r = await res.json(); if (!res.ok) throw Error(r.error); await store.bootstrap(); S.fixture = r.fixture; paintPane(); paintRunBar(); toast('Imported. Set the contract and run.'); }
    catch (err) { toast(err.message, { error: true }); }
  });
}

function paintRunBar() {
  const bar = $('#run-bar'); if (!bar) return;
  const f = store.boot.fixtures.find(x => x.id === S.fixture);
  bar.innerHTML = `<div class="flex" style="margin-bottom:12px"><span class="small">${esc(short(f?.name || 'No package', 40))}</span><span class="spacer"></span><span class="label">${esc(S.policy.access)} · budget ${S.policy.challenge_budget}</span></div>
    <button class="btn primary" id="run-btn" ${S.job || !f ? 'disabled' : ''}>${S.job ? 'Assessment running…' : 'Run assurance'} ${icon.right}</button>`;
  $('#run-btn').onclick = () => start();
}

// ------------------------------------------------------------------ run
export async function start() {
  if (S.job) return toast('Your assessment is already queued or running.');
  try {
    const r = await api('assess', { fixture: S.fixture, format: S.format, policy: S.policy });
    resetTheatre(); attach(r.job);
  } catch (e) { toast(e.message, { error: true }); }
}

function resetTheatre() {
  Object.assign(S, { feed: [], loop: [], claims: {}, counts: {}, stage: 'Intake', progress: 0, result: null, budget: S.policy.challenge_budget });
  radar?.reset(); repaintTheatre();
}

function attach(jobId) {
  S.job = jobId; paintRunBar();
  document.dispatchEvent(new CustomEvent('sw:run-start', { detail: jobId }));
  if (radar) radar.active = true;
  S.stop?.();
  S.stop = follow(jobId, update);
}

function update(j) {
  if (j.transient) return;
  S.stage = j.stage; S.progress = j.progress; S.counts = j.counts || S.counts; S.queued = j.position || 0;
  const changed = [];
  for (const [k, v] of Object.entries(j.claims || {})) { if (S.claims[k] && S.claims[k] !== v) changed.push(k); S.claims[k] = v; }
  for (const item of j.feed || []) {
    S.feed.push(item);
    if (item.kind === 'finding') radar?.add(item);
    if (item.kind === 'loop') S.loop.push(item);
  }
  if (S.feed.length > 1500) S.feed = S.feed.slice(-1500);
  if (mainEl) { paintLive(j.feed || [], changed); }
  if (j.error) { finish(); toast('Assessment failed: ' + j.error, { error: true }); }
  else if (j.complete) complete(j.id);
}

function finish() { S.stop?.(); S.stop = null; S.job = null; if (radar) radar.active = false; if (mainEl) paintRunBar(); }

async function complete(id) {
  finish();
  await store.bootstrap(); store.current = id; store.runs.delete(id);
  S.result = await store.run(id);
  if (mainEl) { paintBanner(); paintLoopFinal(); }
  toast(`Assessment sealed: ${S.result.decision}. ${S.result.findings.length} findings, ${S.result.loop?.steps?.length || 0} loop steps.`);
  document.dispatchEvent(new CustomEvent('sw:run-complete', { detail: S.result }));
}

// ------------------------------------------------------------------ theatre painting
function repaintTheatre() {
  if (!mainEl) return;
  $('#feed').innerHTML = ''; $('#loop-list').innerHTML = S.loop.length ? '' : `<div class="empty-theatre"><div><div class="label">Awaiting a run</div><p class="small" style="margin-top:10px;max-width:300px">Each adaptive test the loop selects appears here with its priority, the alternatives it beat, the outcome and the claim transition.</p></div></div>`;
  S.loop.forEach(addLoop);
  paintLive(S.feed.slice(-120), []);
  if (S.result) { paintBanner(); paintLoopFinal(); }
  else $('#banner').innerHTML = '';
}

function paintLive(items, changed) {
  const i = stageIndex(S.stage);
  $$('#rail [data-stage]').forEach((el, k) => { el.classList.toggle('on', k <= i && (S.job || S.result)); el.style.setProperty('--fill', S.result || k < i ? '100%' : k === i && S.job ? '55%' : '0%'); });
  const c = S.counts || {};
  $('#c-findings').textContent = num(c.findings || 0); $('#c-critical').textContent = num(c.critical || 0); $('#c-high').textContent = num(c.high || 0); $('#c-loop').textContent = num(c.loop_steps || S.loop.length);
  $('#radar-n').textContent = S.job ? (S.queued ? `Queued · ${S.queued} ahead` : `${S.stage} · ${S.progress}%`) : S.result ? 'Sealed' : '—';
  const f = store.boot.fixtures.find(x => x.id === S.fixture);
  $('#theatre-meta').textContent = S.job || S.result ? `${f?.name || S.fixture} · ${S.policy.access} · budget ${S.policy.challenge_budget}` : 'Press Run assurance to start';
  for (const [k, v] of Object.entries(S.claims)) { const t = $(`[data-claim="${k}"]`); if (t) { t.className = `claim-tile ${v}`; if (changed.includes(k)) t.classList.add('flash'); } }
  const feed = $('#feed');
  for (const it of items.filter(x => x.kind !== 'loop')) {
    const row = document.createElement('div');
    row.className = 'feed-item' + (it.kind === 'stage' ? ' stage' : '');
    row.innerHTML = it.kind === 'finding' ? `<time>${clock(it.t)}</time><i class="sev ${esc(it.severity)}"></i><div><b>${esc(words(it.type))}</b> <span>${esc(short(it.asset, 46))} · ${esc(it.source)}</span></div>`
      : it.kind === 'check' ? `<time>${clock(it.t)}</time><i class="sev low"></i><div><b>${esc(it.name)}</b> <span>${esc(it.status)} — ${esc(short(it.detail, 90))}</span></div>`
      : `<time>${clock(it.t)}</time><i class="sev" style="background:var(--mint)"></i><div><b>${esc(it.stage)}</b> <span>${esc(it.reason || '')}</span></div>`;
    feed.prepend(row);
  }
  while (feed.children.length > 160) feed.lastChild.remove();
  for (const it of items.filter(x => x.kind === 'loop')) addLoop(it);
}

function addLoop(s) {
  const list = $('#loop-list'); if (!list) return;
  if (list.querySelector('.empty-theatre')) list.innerHTML = '';
  const el = document.createElement('div'); el.className = 'loop-step';
  el.innerHTML = `<div class="top"><span class="n">${String(s.step).padStart(2, '0')}</span><b>${esc(s.test)}</b><span class="spacer"></span>${pill(s.outcome)}</div>
    <div class="hyp">${esc(s.hypothesis)}</div><div class="sum">${esc(s.summary)}</div>
    <div class="trans">${esc(words(s.claim))}: ${esc(s.claim_before)} → ${esc(s.claim_after)}${s.spawned ? ` · scheduled ${s.spawned} follow-up` : ''}</div>
    <div class="why">priority ${s.score}${s.alternatives?.length ? ` · beat ${s.alternatives.map(a => `${esc(a.test)} (${a.score})`).join(', ')}` : ''} · seed ${s.seed} · budget left ${s.budget_left}</div>`;
  list.prepend(el);
  const budget = S.budget || S.policy.challenge_budget || 1;
  $('#budget-label').textContent = `Budget ${budget - s.budget_left} / ${budget}`;
  $('#budget-bar').style.width = `${(budget - s.budget_left) / budget * 100}%`;
}

function paintLoopFinal() {
  const L = S.result?.loop; if (!L) return;
  $('#budget-label').textContent = `Budget ${L.spent} / ${L.budget}`;
  $('#budget-bar').style.width = `${L.spent / Math.max(1, L.budget) * 100}%`;
  const list = $('#loop-list');
  const stop = document.createElement('div'); stop.className = 'loop-step';
  stop.innerHTML = `<div class="top"><span class="n">STOP</span><b>${esc(L.stop_reason || '')}</b></div>${L.unavailable?.length ? `<div class="why">Not eligible under ${esc(S.result.policy.access)} access: ${L.unavailable.map(u => esc(u.test)).join(', ')}</div>` : ''}`;
  list.prepend(stop);
}

function paintBanner() {
  const r = S.result; if (!r) return;
  const lab = r.fixture.startsWith('lab-');
  $('#banner').innerHTML = `<div class="decision-banner ${esc(r.decision)}"><div><div class="label">Policy recommendation</div><div class="word">${esc(r.decision)}</div></div>
    <div class="small">${r.findings.length} findings · ${r.claims.filter(c => c.mandatory && c.state !== 'Supported').length} mandatory claims not supported · report <span class="mono">${esc(short(r.report_digest, 20))}</span> signed with Ed25519</div>
    <div class="flex">${lab ? `<button class="btn small" id="score-btn">Score against sealed key</button>` : ''}<a class="btn small primary" href="#/evidence/summary">Open evidence ${icon.arrow}</a></div></div>`;
  $('#score-btn')?.addEventListener('click', async () => {
    try { const e = await api('evaluate', { run: r.id }); dialog('Independent evaluation', scorecard(e.lab), 'Sealed answer key'); }
    catch (err) { toast(err.message, { error: true }); }
  });
}
