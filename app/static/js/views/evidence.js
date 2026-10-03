// Evidence: every sealed report, explored by domain. Everything shown is read from the signed report.
import { $, $$, esc, num, pct, pill, icon, tip, words, short, when, toast, dialog, reveal } from '../ui.js';
import { api, store } from '../api.js';
import { PointCloud, CLASS_COLOURS } from '../cloud.js';
import { CLAIM_HELP } from '../content.js';
import { scorecard } from './scorecard.js';

const TABS = [['summary', 'Decision'], ['findings', 'Findings'], ['data', 'Data map'], ['source', 'Contributors'], ['model', 'Model'], ['pipeline', 'Pipeline'],
  ['provenance', 'Records'], ['shift', 'Context'], ['loop', 'Contrarian loop'], ['reports', 'Reports & audit']];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const PAGE = 40;
const F = { q: '', severity: '', claim: '', source: '', page: 0 };
let cloud = null;

export async function render(main, params, sub) {
  const tab = TABS.some(t => t[0] === sub) ? sub : 'summary';
  if (params.get('run')) store.current = params.get('run');
  const boot = store.boot;
  if (!boot.runs.length) {
    main.innerHTML = `<div class="page-head frame corners"><div><div class="label">03 / Evidence</div><h1 class="h1">No sealed assessments <em>yet.</em></h1><p class="lead">Run an assessment in the workbench; its evidence appears here.</p></div><a class="btn primary" href="#/workbench">Open the workbench ${icon.arrow}</a></div>`;
    return;
  }
  const run = await store.run();
  main.innerHTML = `
    <div class="page-head frame corners">
      <div><div class="label">03 / Evidence</div><h1 class="h1">${esc(short(run.name, 60))}</h1>
        <p class="lead">${num(run.images)} images · ${num(run.objects)} objects · ${esc(run.format)} · sealed ${esc(when(run.completed))}</p></div>
      <div class="stack run-picker"><span class="label">Assessment</span>
        <select id="run-pick" aria-label="Choose an assessment">${boot.runs.map(r => `<option value="${esc(r.id)}" ${r.id === run.id ? 'selected' : ''}>${esc(short(r.name, 44))} · ${esc(r.decision)}</option>`).join('')}</select></div>
    </div>
    <nav class="subnav" id="subnav">${TABS.map(([id, l], i) => `<a href="#/evidence/${id}" class="${id === tab ? 'on' : ''}"><small>${String(i + 1).padStart(2, '0')}</small>${l}</a>`).join('')}</nav>
    <div class="page-body" id="ev-body"></div>`;
  $('#run-pick').onchange = e => { store.current = e.target.value; F.page = 0; render(main, new URLSearchParams(), tab); };
  const body = $('#ev-body');
  cloud = null;
  await PANES[tab](body, run);
  reveal(body);
  return () => { cloud = null; };
}

// ------------------------------------------------------------------ helpers
const panel = (title, html, extra = '') => `<div class="panel reveal"><div class="panel-head"><span class="label">${title}</span>${extra}</div>${html}</div>`;
const row = (k, v) => `<div class="row"><span class="k">${k}</span><span>${v}</span></div>`;
const imgUrl = (run, asset, scope = 'submission') => `/api/image?fixture=${encodeURIComponent(run.fixture)}&format=${encodeURIComponent(run.format)}&scope=${scope}&asset=${encodeURIComponent(asset)}`;
const isImage = a => /\.(jpe?g|png)$/i.test(a || '');

function findingDetail(run, f) {
  const asset = run.assets.find(a => a.id === f.asset);
  const boxes = asset && asset.stats?.width ? asset.annotations.map(a => {
    const [x, y, w, h] = a.bbox, W = asset.stats.width, H = asset.stats.height;
    return `<div class="bbox" style="left:${x / W * 100}%;top:${y / H * 100}%;width:${w / W * 100}%;height:${h / H * 100}%"><span>${esc(a.label)}</span></div>`;
  }).join('') : '';
  dialog(words(f.type), `<div class="grid g2" style="gap:26px">
    ${isImage(f.asset) ? `<div class="detail-image" style="align-self:start"><img src="${imgUrl(run, f.asset)}" alt="${esc(f.asset)}">${boxes}</div>` : `<div class="hash">${esc(f.asset)}</div>`}
    <div><div class="flex">${pill(f.severity)}${pill(run.claims.find(c => c.id === f.claim)?.state || 'Unresolved', words(f.claim))}</div>
      <p class="lead" style="margin-top:16px">${esc(f.reason)}</p>
      ${row('Asset', `<span class="mono small">${esc(short(f.asset, 40))}</span>`)}${row('Contributor', esc(f.source || '—'))}${row('Recommended action', esc(f.action))}
      ${row('Access', esc(f.access))}${row('Confidence', `<span class="small">${esc(f.confidence_status || '—')}</span>`)}${row('Method', `<span class="mono small">${esc(f.method_version)}</span>`)}
      <div class="group-title label">Measurement</div><pre class="hash" style="white-space:pre-wrap;max-height:240px;overflow:auto">${esc(JSON.stringify(f.measurement, null, 2))}</pre></div></div>`, f.id);
}

// ------------------------------------------------------------------ panes
const PANES = {
  async summary(body, run) {
    const notSupported = run.claims.filter(c => c.mandatory && c.state !== 'Supported');
    const sev = run.severity_counts || {};
    body.innerHTML = `
      <div class="decision-banner ${esc(run.decision)} reveal"><div><div class="label">Policy recommendation</div><div class="word">${esc(run.decision)}</div></div>
        <div class="small">${run.findings.length} findings · ${notSupported.length} mandatory claims not supported · policy ${esc(run.policy.version || run.policy_version || '')}</div>
        <div class="flex"><a class="btn small" href="/api/export/${esc(run.id)}?format=bundle">${icon.down} Evidence bundle</a></div></div>
      <div class="claim-bars reveal" aria-hidden="true">${run.claims.filter(c => c.applicable).map(c => `<span class="${esc(c.state)}" title="${esc(c.label)}: ${esc(c.state)}"></span>`).join('')}</div>
      <div class="grid g4 reveal">
        <div class="cell"><div class="label">Findings</div><div class="stat">${num(run.findings.length)}</div><div class="small">${num(new Set(run.findings.map(f => f.asset)).size)} distinct assets</div></div>
        <div class="cell"><div class="label">Critical / high</div><div class="stat"><span class="coral">${sev.critical || 0}</span><small> / ${sev.high || 0}</small></div><div class="small">${sev.medium || 0} medium</div></div>
        <div class="cell"><div class="label">Loop steps</div><div class="stat">${run.loop?.steps?.length || 0}</div><div class="small">${esc(run.loop?.stop_reason || 'No adaptive loop')}</div></div>
        <div class="cell"><div class="label">Records verified</div><div class="stat">${run.records?.verified ?? '—'}<small> / ${run.records?.total ?? '—'}</small></div><div class="small">${run.records?.failed || 0} failed verification</div></div>
      </div>
      <div class="grid g2" style="margin-top:20px;gap:20px">
        ${panel('Claims · why this decision', `<div class="table-wrap"><table><thead><tr><th>Claim</th><th>State</th><th>Findings</th></tr></thead><tbody>${run.claims.filter(c => c.applicable).sort((a, b) => b.mandatory - a.mandatory).map(c => `<tr><td>${esc(c.label)} ${c.mandatory ? '<span class="tag">Mandatory</span>' : ''}<span class="sub">${esc(CLAIM_HELP[c.id] || '')}</span></td><td>${pill(c.state)}</td><td class="mono">${c.findings}</td></tr>`).join('')}</tbody></table></div>`)}
        <div>${panel('Seal', `${row('Report digest · SHA-384', '')}<div class="hash">${esc(run.report_digest)}</div>${row('Signature · Ed25519', '')}<div class="hash">${esc(run.report_signature)}</div>
          <div class="cmd" style="margin-top:16px"><span>python3 shockwave.py verify ${esc(run.id)}.json --public-key &lt;assessor key&gt;</span></div>`)}
          ${panel('Stated limitations', run.limitations.map(l => `<div class="row"><span class="small">${esc(l)}</span></div>`).join(''))}
          ${run.fixture.startsWith('lab-') ? panel('Independent evaluation', `<p class="small">The answer key was committed to the audit log before this assessment ran. Score only after sealing.</p><button class="btn small primary" id="score-btn">Score against sealed key</button>`) : ''}</div>
      </div>`;
    $('#score-btn')?.addEventListener('click', async () => {
      try { const e = await api('evaluate', { run: run.id }); dialog('Independent evaluation', scorecard(e.lab), 'Sealed answer key'); }
      catch (err) { toast(err.message, { error: true }); }
    });
  },

  async findings(body, run) {
    const claims = [...new Set(run.findings.map(f => f.claim))], sources = [...new Set(run.findings.map(f => f.source).filter(Boolean))];
    body.innerHTML = `<div class="filters">
        <input type="search" id="f-q" placeholder="Search type, asset or reason" value="${esc(F.q)}" aria-label="Search findings">
        <select id="f-severity" aria-label="Severity"><option value="">All severities</option>${['critical', 'high', 'medium', 'low'].map(s => `<option ${F.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
        <select id="f-claim" aria-label="Claim"><option value="">All claims</option>${claims.map(c => `<option value="${esc(c)}" ${F.claim === c ? 'selected' : ''}>${esc(words(c))}</option>`).join('')}</select>
        <select id="f-source" aria-label="Contributor"><option value="">All contributors</option>${sources.map(s => `<option ${F.source === s ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select></div>
      <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Type</th><th>Asset</th><th>Claim</th><th>Contributor</th></tr></thead><tbody id="f-rows"></tbody></table></div>
      <div class="pager" id="f-pager"></div>`;
    const paint = () => {
      const q = F.q.toLowerCase();
      const list = run.findings.filter(f => (!F.severity || f.severity === F.severity) && (!F.claim || f.claim === F.claim) && (!F.source || f.source === F.source)
        && (!q || `${f.type} ${f.asset} ${f.reason}`.toLowerCase().includes(q))).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
      const pages = Math.max(1, Math.ceil(list.length / PAGE)); F.page = Math.min(F.page, pages - 1);
      const slice = list.slice(F.page * PAGE, F.page * PAGE + PAGE);
      $('#f-rows').innerHTML = slice.map(f => `<tr class="click" data-f="${esc(f.id)}"><td>${pill(f.severity)}</td><td>${esc(words(f.type))}<span class="sub">${esc(short(f.reason, 90))}</span></td><td class="mono small">${esc(short(f.asset, 38))}</td><td>${esc(words(f.claim))}</td><td>${esc(f.source || '—')}</td></tr>`).join('') || '<tr><td colspan="5" class="small">No findings match these filters.</td></tr>';
      $('#f-pager').innerHTML = `<span>${num(list.length)} findings · page ${F.page + 1} of ${pages}</span><span class="flex"><button class="btn tiny" id="f-prev" ${F.page ? '' : 'disabled'}>Previous</button><button class="btn tiny" id="f-next" ${F.page < pages - 1 ? '' : 'disabled'}>Next</button></span>`;
      $('#f-prev').onclick = () => { F.page--; paint(); }; $('#f-next').onclick = () => { F.page++; paint(); };
      $$('[data-f]', body).forEach(tr => tr.onclick = () => findingDetail(run, run.findings.find(f => f.id === tr.dataset.f)));
    };
    $('#f-q').oninput = e => { F.q = e.target.value; F.page = 0; paint(); };
    for (const k of ['severity', 'claim', 'source']) $('#f-' + k).onchange = e => { F[k] = e.target.value; F.page = 0; paint(); };
    paint();
  },

  async data(body, run) {
    const map = await store.map(run.id);
    const lq = run.label_quality;
    body.innerHTML = `<div class="explorer reveal" id="explorer">${map?.available ? '<canvas id="explore-cloud" aria-label="Interactive embedding map"></canvas>' : ''}
        <div class="hud"><span class="label">${map?.available ? `${num(map.points.length)} DINOv2 object embeddings · drag to rotate · scroll to zoom` : 'No embedding projection for this assessment'}</span>
          ${map?.available ? `<div class="seg" id="colour-by"><button data-c="class" class="on">Class</button><button data-c="evidence">Evidence</button></div>` : ''}</div>
        <div class="hover-card" id="hover-card"></div></div>
      ${map?.available ? `<div class="legend" style="margin:14px 0 24px">${map.labels.map((l, i) => `<span><i style="background:${CLASS_COLOURS[i % CLASS_COLOURS.length]}"></i>${esc(words(l))}</span>`).join('')}</div>` : ''}
      <div class="grid g2" style="gap:20px">
        ${lq?.confident_joint ? panel(`Label agreement · ${esc(words(run.policy.label_method))} ${tip('Confident joint', 'Rows are declared labels, columns are the label suggested by independent visual neighbours. Off-diagonal mass is disagreement.', '§11.3')}`, matrix(lq)) : ''}
        ${panel('Patterns and sub-populations', `${row('Recurring compact patterns', `${run.patch_clusters?.length || 0} clusters`)}${(run.patch_clusters || []).slice(0, 4).map(c => row(`<span class="mono small">${esc(short(c.exemplar?.image, 34))}</span>`, `${c.distinct_pictures} pictures`)).join('')}
          ${row('Robust sub-population screen', `${run.subpopulation?.flagged ?? 0} / ${num(run.subpopulation?.scored ?? 0)} flagged`)}<p class="tiny">${esc(run.subpopulation?.method || '')}</p>`)}
      </div>`;
    if (!map?.available) return;
    cloud = new PointCloud($('#explore-cloud'), { interactive: true, ring: false });
    cloud.setData(map); cloud.target = 1; cloud.colourBy = 'class'; cloud.spin = .0008;
    $$('#colour-by button').forEach(b => b.onclick = () => {
      $$('#colour-by button').forEach(x => x.classList.toggle('on', x === b));
      cloud.glowTarget = b.dataset.c === 'evidence' ? 1 : 0; cloud.kick();
    });
    const card = $('#hover-card');
    cloud.onHover = (i, p) => {
      if (i < 0 || !p) { card.style.display = 'none'; return; }
      const m = cloud.meta[i], img = map.images?.[m.img];
      card.innerHTML = `${img ? `<img src="${imgUrl(run, img)}" alt="">` : ''}<b>${esc(words(map.labels[m.cls]))}</b><div class="tiny mono">${esc(short(img || '', 28))}</div>`;
      Object.assign(card.style, { display: 'block', left: Math.min(p[0] + 14, cloud.w - 210) + 'px', top: Math.min(p[1] + 14, cloud.h - 250) + 'px' });
    };
    cloud.onClick = i => { const img = map.images?.[cloud.meta[i].img]; const f = img && run.findings.find(x => x.asset === img); if (f) findingDetail(run, f); };
  },

  async source(body, run) {
    const max = Math.max(...run.sources.map(s => s.rate), .01);
    body.innerHTML = panel(`Contributors ${tip('Contributor risk', 'Findings are aggregated per contributor with denominators, so a large contributor is not penalised for volume alone.', '§12')}`,
      `<div class="table-wrap"><table><thead><tr><th>Contributor</th><th>Images</th><th>Affected</th><th style="width:30%">Affected rate</th><th>Findings</th><th>Status</th></tr></thead><tbody>
      ${run.sources.map(s => `<tr><td>${esc(s.source)}<span class="sub">${esc(Object.entries(s.classes).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `${k} ${v}`).join(' · '))}</span></td><td class="mono">${num(s.images)}</td><td class="mono">${num(s.affected)}</td>
        <td><div class="flex"><div class="bar ${s.rate / max > .8 ? 'bad' : s.rate / max > .5 ? 'warn' : ''}" style="flex:1"><i style="width:${s.rate / max * 100}%"></i></div><span class="mono small">${pct(s.rate, 1)}</span></div></td><td class="mono">${num(s.findings)}</td><td>${pill(s.status)}</td></tr>`).join('')}</tbody></table></div>`);
  },

  async model(body, run) {
    const m = run.model || {}, b = m.behaviour || {}, c = m.conditional || {};
    body.innerHTML = `<div class="grid g2" style="gap:20px">
      ${panel('Submitted artifacts', (m.artifacts || []).map(a => `<div class="row"><div>${esc(a.name)}<div class="tiny">${esc(a.format)}${a.nodes ? ` · ${a.nodes} nodes` : ''}</div></div>${pill(a.approved_identity ? 'Supported' : 'Contradicted', a.approved_identity ? 'approved identity' : 'differs from approved')}</div>`).join('') || '<p class="small">No model submitted.</p>')}
      ${panel('Behaviour battery', `${row('Agreement with approved model', pct(b.agreement))}${row('Fingerprint', `<span class="mono small">${esc(short(b.fingerprint, 24))}</span>`)}<p class="tiny">${esc(b.limitation || '')}</p>`)}
      ${panel('Weight comparison', (m.weight_comparisons || []).map(w => row(esc(w.name || 'tensor set'), `${w.changed_tensors ?? 0} changed tensors`) + (w.layers || []).filter(l => l.changed).slice(0, 6).map(l => row(`<span class="mono small">${esc(l.name)}</span>`, `<span class="mono small">rel L2 ${Number(l.relative_l2).toFixed(4)}</span>`)).join('')).join('') || '<p class="small">No comparable weights.</p>')}
      ${panel(`Conditional tests ${tip('Conditional behaviour', 'Candidate triggers from data evidence and reconstruction are applied to clean images; a flip toward one class that the approved model does not show is a conditional difference.', '§14')}`, `${row('Budget', c.budget ?? '—')}${row('Differential outcomes', c.differential ?? 0)}${(c.tests || []).slice(0, 6).map(t => row(`<span class="small">${esc(short(t.name || t.input || 'test', 44))}</span>`, t.flip_rate !== undefined ? pct(t.flip_rate) : pill(t.outcome || t.status || 'Measured'))).join('')}`)}
    </div>`;
  },

  async pipeline(body, run) {
    const t = run.model?.twin || {};
    const cmp = t.comparisons || [];
    body.innerHTML = panel(`Twin pipeline ${tip('Twin pipeline', 'The same inputs run through the authorised pipeline and the submitted one. Differences are localised to a stage by swapping one stage at a time.', '§15')}`,
      `<div class="grid g3" style="margin-bottom:18px"><div class="cell"><div class="label">Inputs compared</div><div class="stat">${cmp.length}</div></div><div class="cell"><div class="label">Outputs changed</div><div class="stat ${t.changed ? 'coral' : ''}">${t.changed ?? 0}</div></div><div class="cell"><div class="label">Localised stage</div><div class="stat" style="font-size:24px">${esc(words(t.stage || t.localised || '—'))}</div></div></div>
      <div class="table-wrap"><table><thead><tr><th>Input</th><th>Authorised</th><th>Submitted</th><th>Result</th></tr></thead><tbody>${cmp.slice(0, 30).map(r => `<tr><td class="mono small">${esc(short(r.input, 40))}</td><td>${esc(r.authorised)} <span class="sub">${r.authorised_score ?? ''}</span></td><td>${esc(r.submitted ?? '—')} <span class="sub">${r.submitted_score ?? ''}</span></td><td>${pill(r.different ? 'Contradicted' : 'Supported', r.different ? 'different' : 'same')}</td></tr>`).join('')}</tbody></table></div>`);
  },

  async provenance(body, run) {
    const r = run.records || {};
    body.innerHTML = `<div class="notice ${r.failed ? '' : 'mint'} reveal">${r.verified ?? 0} of ${r.total ?? 0} signed records verified. ${esc(r.profile || '')}</div>
      ${panel('Signed inference records', `<div class="table-wrap"><table><thead><tr><th>Record</th><th>Model</th><th>Hash</th><th>Result</th></tr></thead><tbody>${(r.rows || []).map(x => `<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.model)}</td><td class="mono small">${esc(short(x.hash, 18))}</td><td>${x.issues?.length ? x.issues.map(i => pill('Contradicted', words(i.type || i))).join(' ') : pill('Verified')}</td></tr>`).join('')}</tbody></table></div><p class="tiny" style="margin-top:12px">${esc(r.limitation || '')}</p>`)}`;
  },

  async shift(body, run) {
    const d = run.drift || {};
    if (!d.available) { body.innerHTML = '<p class="small">No reference distribution was available for this assessment.</p>'; return; }
    const max = Math.max(...d.distances, d.threshold);
    body.innerHTML = `<div class="grid g2" style="gap:20px">
      ${panel(`Distribution shift · ${esc(d.encoder)}`, `<div class="spark">${d.distances.map(x => `<span class="${x > d.threshold ? 'over' : ''}" style="height:${x / max * 100}%"></span>`).join('')}</div>
        ${row('Statistic / threshold', `<span class="mono">${Number(d.statistic).toFixed(4)} / ${Number(d.threshold).toFixed(4)}</span>`)}${row('Permutation p-value', d.p_value)}${row('Novel images', `${d.ood_images} vs ${d.reference_images} references`)}${row('Cause', pill(d.cause))}<p class="tiny">${esc(d.limitation)}</p>`)}
      ${panel('Image factors · current vs reference', Object.entries(d.factors || {}).map(([k, v]) => { const hi = Math.max(v.current, v.reference) * 1.25 || 1; return `<div class="factor"><span>${esc(words(k))}</span><div class="track"><div class="cur" style="width:${v.current / hi * 100}%"></div><div class="ref" style="left:${v.reference / hi * 100}%"></div></div><span class="mono small">${Number(v.current).toFixed(3)}</span></div>`; }).join('') + '<p class="tiny">Gold bar: submission. Slate mark: approved reference.</p>')}
      ${run.risk ? panel('Calibration', `${row('Calibrated', run.risk.calibrated ? 'Yes' : 'No')}${row('Abstained', run.risk.abstained ? 'Yes — no independent calibration data' : 'No')}`) : ''}
    </div>`;
  },

  async loop(body, run) {
    const L = run.loop;
    if (!L?.steps) { body.innerHTML = '<p class="small">This assessment did not run the Contrarian Loop.</p>'; return; }
    body.innerHTML = `<div class="grid g4 reveal"><div class="cell"><div class="label">Budget spent</div><div class="stat">${L.spent}<small> / ${L.budget}</small></div></div><div class="cell"><div class="label">Hypotheses</div><div class="stat">${L.hypotheses.length}</div></div><div class="cell"><div class="label">Mode</div><div class="stat" style="font-size:26px">${esc(words(L.mode))}</div></div><div class="cell"><div class="label">Stop reason</div><div class="small" style="margin-top:14px">${esc(L.stop_reason)}</div></div></div>
      <p class="small" style="margin:18px 0">Priority rule: <span class="mono">${esc(L.priority_rule || '')}</span></p>
      <div class="timeline reveal">${L.steps.map(s => `<div><div><span class="mono">${String(s.step).padStart(2, '0')}</span> ${pill(s.outcome)}<div class="tiny">priority ${esc(s.priority?.score ?? s.priority)} · cost ${s.test.cost}</div></div><div><b>${esc(s.test.name)}</b><div class="small">${esc(s.hypothesis?.statement ?? s.hypothesis)}</div><div class="small" style="color:var(--text)">${esc(s.summary)}</div><div class="tiny">${esc(words(s.claim))}: ${esc(s.claim_before)} → ${esc(s.claim_after)}${s.alternatives?.length ? ` · beat ${s.alternatives.map(a => esc(a.test?.name || a.test)).join(', ')}` : ''}</div></div></div>`).join('')}</div>
      ${L.unavailable?.length ? `<div class="notice" style="margin-top:20px">Not eligible under ${esc(run.policy.access)} access: ${L.unavailable.map(u => esc(u.test?.name || u.test)).join(', ')}</div>` : ''}`;
  },

  async reports(body) {
    const audit = await api('audit').catch(e => ({ verified: false, errors: [e.message] }));
    const show = store.boot.showcase;
    body.innerHTML = `<div class="notice ${audit.verified ? 'mint' : ''} reveal">${audit.verified ? 'Audit log verified: every event is hash-linked and checkpoints carry valid Ed25519 signatures.' : `Audit verification failed: ${esc((audit.errors || []).join('; '))}`} <span class="mono">${esc(short(audit.checkpoint?.root, 20))}</span></div>
      ${show ? panel('Latest evaluation package', `<div class="grid g4"><div class="cell"><div class="label">Planted samples caught</div><div class="stat">${show.caught_samples}<small> / ${show.planted_samples}</small></div></div><div class="cell"><div class="label">Tampered records caught</div><div class="stat">${show.records_caught}<small> / ${show.records_tampered}</small></div></div><div class="cell"><div class="label">Untouched images flagged</div><div class="stat">${show.untouched_flagged}<small> / ${show.untouched}</small></div></div><div class="cell"><div class="label">Answer key</div><div class="stat" style="font-size:24px">${show.answer_key_intact ? 'Intact' : 'Mismatch'}</div></div></div>`) : ''}
      ${panel('Sealed assessments', `<div class="table-wrap"><table><thead><tr><th>Assessment</th><th>Decision</th><th>Images</th><th>Findings</th><th>Completed</th><th></th></tr></thead><tbody>${store.boot.runs.map(r => `<tr class="click" data-run="${esc(r.id)}"><td>${esc(r.name)}<span class="sub">${esc(r.id)} · ${esc(r.engine)}</span></td><td>${pill(r.decision)}</td><td class="mono">${num(r.images)}</td><td class="mono">${num(Object.values(r.finding_types || {}).reduce((a, b) => a + b, 0))}</td><td class="small">${esc(when(r.completed))}</td><td><a class="btn tiny" href="/api/export/${esc(r.id)}" download>JSON</a></td></tr>`).join('')}</tbody></table></div>`)}
      ${panel('Coverage', store.boot.capabilities.map(([n, d, , s]) => `<div class="row"><div>${esc(n)}<div class="tiny">${esc(d)}</div></div>${pill(s)}</div>`).join(''))}`;
    $$('[data-run]', body).forEach(tr => tr.onclick = e => { if (e.target.closest('a')) return; store.current = tr.dataset.run; location.hash = '#/evidence/summary?t=' + Date.now(); });
  },
};

function matrix(lq) {
  const n = lq.classes.length, cj = lq.confident_joint, max = Math.max(1, ...cj.flat());
  const cells = cj.map((r, i) => r.map((v, j) => {
    const a = v ? .15 + .85 * v / max : 0, col = i === j ? '168,211,184' : '227,144,127';
    return `<div style="background:rgba(${col},${a.toFixed(2)})" title="${esc(lq.classes[i])} → ${esc(lq.classes[j])}: ${v}">${v || ''}</div>`;
  }).join('')).join('');
  return `<div class="matrix" style="grid-template-columns:repeat(${n},1fr)">${lq.classes.map(c => `<div class="h" title="${esc(c)}">${esc(short(c, 6))}</div>`).join('')}${cells}</div><p class="tiny" style="margin-top:10px">Rows: declared label · columns: neighbour-suggested label.</p>`;
}
