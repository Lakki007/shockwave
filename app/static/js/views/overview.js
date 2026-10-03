import { $, $$, esc, num, pct, pill, icon, words, when, short, reveal, reduced, toast, countUp } from '../ui.js';
import { store } from '../api.js';
import { PointCloud, CLASS_COLOURS } from '../cloud.js';

const CHAIN = [
  ['Contributor', ['source_risk']], ['Dataset', ['data_schema', 'duplication', 'split_integrity']], ['Labels', ['labels', 'poisoning']],
  ['Model', ['model_identity', 'safe_intake']], ['Behaviour', ['behaviour', 'backdoor']], ['Pipeline', ['pipeline']],
  ['Output', ['reproduction']], ['Record', ['provenance', 'replay', 'history']], ['Context', ['distribution', 'calibration']],
];
const RANK = { Contradicted: 4, Weakened: 3, Unresolved: 2, Stale: 2, Supported: 1 };

export async function render(main) {
  const boot = store.boot, run = await store.run(), map = run ? await store.map(run.id) : null;
  const objects = map?.available ? map.points.length : 0, show = boot.showcase;
  const loop = run?.loop, affected = run ? new Set(run.findings.map(f => f.asset)).size : 0;
  const crit = run?.severity_counts?.critical || 0, high = run?.severity_counts?.high || 0;
  main.innerHTML = `
  <section class="frame corners hero">
    <div class="meta-row"><span>Computer vision assurance / multi-contributor pipelines</span><span>${run ? `${num(run.images)} images · ${num(run.objects)} objects / ${esc(run.decision)}` : 'Awaiting first assessment'}</span></div>
    <div class="hero-body">
      <div class="hero-copy" data-parallax="-0.10">
        <div class="label dot">Evidence, before conclusions</div>
        <h1 class="display">Every contribution<br>leaves <em>evidence.</em></h1>
        <p class="lead">Inspect the data. Challenge the model. Verify the record.<br>Know what remains unknown.</p>
        <div class="hero-actions">
          <a class="btn primary" href="#/workbench">Enter the workbench ${icon.arrow}</a>
          <a class="btn" href="#/workbench?tab=lab">Plant your own attack ${icon.flask}</a>
        </div>
        <div class="hero-foot label"><span>Analyst-assisted</span><span>/</span><span>Fully offline</span><span>/</span><span>Policy ${esc(boot.policy.version)}</span></div>
      </div>
      <div class="hero-stage" data-parallax="0.06">
        <canvas id="hero-cloud" aria-label="${objects ? `${objects} real DINOv2 object embeddings from ${esc(run.name)}` : 'Placeholder sphere awaiting an assessment'}"></canvas>
        <div class="stage-caption label">${objects ? 'Dataset / a shared witness' : 'Awaiting an assessment'}</div>
        <span class="stage-bracket tl"></span><span class="stage-bracket br"></span>
        <span class="plus" style="right:14%;top:12%">+</span><span class="plus" style="right:14%;top:52%">+</span><span class="plus" style="right:14%;bottom:5%">+</span>
        <div class="stage-steps" id="hero-steps">
          <div class="on"><small>01</small><div><b>Inspect</b><span>The data trail</span></div></div>
          <div><small>02</small><div><b>Challenge</b><span>The model's behaviour</span></div></div>
          <div><small>03</small><div><b>Verify</b><span>The signed record</span></div></div>
        </div>
      </div>
    </div>
    <div class="ticker"><span>Inspect. Challenge. Verify.</span><span>${objects ? `${num(objects)} real object embeddings · DINOv2-S/14 · scroll to unfold` : 'Run an assessment to project its embeddings'}</span></div>
  </section>

  <section class="story" id="story">
    <div class="story-pin frame">
      <canvas id="story-cloud"></canvas>
      <div class="story-hud"><span class="label" id="story-mode">Sphere · ${num(objects || 1600)} points</span><span class="label">${run ? esc(short(run.name, 48)) : ''}</span></div>
    </div>
    <div class="story-steps">
      ${storyStep(0, '01 / Observe', 'It starts as a sphere.', `<p class="lead">${objects ? `${num(objects)} dots. Each is a real object crop from <b>${esc(run.name)}</b>, embedded on this machine by DINOv2. Nothing here is drawn by hand.` : 'Run an assessment and this sphere becomes the real embedding of every annotated object.'}</p>`)}
      ${storyStep(1, '02 / Map', 'Then it becomes a map.', `<p class="lead">Similar objects settle together. Every label is checked against independent neighbours in this space — never against its own duplicates.</p>${map?.available ? `<div class="legend">${map.labels.map((l, i) => `<span><i style="background:${CLASS_COLOURS[i % CLASS_COLOURS.length]}"></i>${esc(words(l))}</span>`).join('')}</div>` : ''}`)}
      ${storyStep(2, '03 / Evidence', 'Then the evidence lights up.', run ? `<div class="big" data-count="${run.findings.length}">0</div><p class="lead">findings across <b>${num(affected)}</b> assets — ${crit} critical, ${high} high. Gold and coral points are objects carrying evidence.</p><div class="legend"><span><i style="background:var(--coral)"></i>critical</span><span><i style="background:var(--gold)"></i>high</span><span><i style="background:#cdbf95"></i>medium</span></div>` : '<p class="lead">Findings appear here once an assessment has run.</p>')}
      ${storyStep(3, '04 / Challenge', 'Then the model is challenged.', loop?.steps?.length ? `<div class="big">${loop.steps.length}</div><p class="lead">adaptive tests chosen by the Contrarian Loop within a budget of ${loop.budget}. Each one was picked because it could most usefully challenge an open claim.</p><div class="stack" style="margin-top:14px">${loop.steps.filter(s => s.outcome === 'challenged').slice(0, 3).map(s => `<div class="row"><span class="small">${esc(s.test.name)}</span>${pill(s.outcome)}</div>`).join('')}</div>` : '<p class="lead">The Contrarian Loop records every test it selects, why, and what changed.</p>')}
      ${storyStep(4, '05 / Seal', 'And the decision is sealed.', run ? `<div class="flex" style="margin:8px 0 14px">${pill(run.decision)}<span class="label">${esc(run.policy.version)}</span></div><p class="lead">Every finding, claim and test is bound into a SHA-384 digest and signed with Ed25519.</p><div class="hash" style="margin-top:16px">${esc(run.report_digest)}</div><a class="btn small" style="margin-top:18px" href="#/evidence/summary">Inspect the decision ${icon.arrow}</a>` : '')}
    </div>
  </section>

  <section class="section frame">
    <div class="section-head reveal"><div><div class="label">The chain under test</div><h2 class="h1">Nine places trust can break.<br><em>One connected verdict.</em></h2></div><p class="lead">High accuracy does not prove integrity. A valid signature does not prove a prediction is correct. Each link is assessed separately, then reconciled.</p></div>
    <div class="chain reveal">${CHAIN.map(([name, claims], i) => {
      const states = run ? claims.map(c => run.claims.find(x => x.id === c)).filter(c => c?.applicable).map(c => c.state) : [];
      const worst = states.sort((a, b) => RANK[b] - RANK[a])[0];
      return `<a class="chain-node" href="#/evidence/${['source', 'data', 'data', 'model', 'model', 'pipeline', 'provenance', 'provenance', 'shift'][i]}"><small>${String(i + 1).padStart(2, '0')}</small><b>${name}</b>${worst ? pill(worst) : '<span class="pill">Not applicable</span>'}</a>`;
    }).join('')}</div>
  </section>

  <section class="section frame">
    <div class="section-head reveal"><div><div class="label">Not a simulation</div><h2 class="h1">Plant the attack yourself.<br><em>Then watch it get caught.</em></h2></div>
      <p class="lead">The Attack Lab forges a brand-new package from 1,000 real images: stamped triggers, flipped labels, a model genuinely fine-tuned on the poison, tampered signed records. The answer key is sealed and committed to the audit log <i>before</i> the assessor ever runs.</p></div>
    ${show ? `<div class="grid g4 reveal">
      <div class="cell"><div class="label">Planted samples caught</div><div class="stat"><span data-count="${show.caught_samples}">0</span><small> / ${num(show.planted_samples)}</small></div><div class="small">${pct(show.caught_samples / Math.max(1, show.planted_samples))} recall across data attacks</div></div>
      <div class="cell"><div class="label">Tampered records caught</div><div class="stat">${show.records_caught}<small> / ${show.records_tampered}</small></div><div class="small">Altered, fabricated, replayed, deleted, substituted, untrusted</div></div>
      <div class="cell"><div class="label">Implanted backdoor</div><div class="stat">${show.model?.detected ? 'Caught' : show.model?.detected === false ? 'Missed' : '—'}</div><div class="small">${show.model?.implant ? `Trigger success ${pct(show.model.implant.attack_success)} vs approved ${pct(show.model.implant.approved_attack_success)}` : 'No backdoor in this package'}</div></div>
      <div class="cell"><div class="label">Answer keys read by the assessor</div><div class="stat">0</div><div class="small mono">commit ${esc(short(show.commitment, 18))}</div></div>
    </div>
    <div class="flex reveal" style="margin-top:26px"><a class="btn primary" href="#/workbench?tab=lab">Open the Attack Lab ${icon.arrow}</a><a class="btn" href="#/evidence/reports">See the full scorecard</a><span class="small">Latest package: ${esc(show.attacks.slice(0, 3).join(' · '))}…</span></div>`
    : `<div class="notice mint reveal">No Attack Lab package has been assessed yet. Open the workbench and press <b>Load the judge demo</b>.</div>`}
  </section>

  <section class="section frame">
    <div class="section-head reveal"><div><div class="label">Assessment history</div><h2 class="h2">${boot.runs.length} sealed local assessments</h2></div><a class="btn small" href="#/evidence/reports">Reports & coverage ${icon.arrow}</a></div>
    <div class="grid g3 reveal">${boot.runs.slice(0, 6).map(r => `<div class="cell link" data-run="${esc(r.id)}"><div class="flex"><span class="label">${esc(r.format)} / ${esc(r.id.slice(-6))}</span><span class="spacer"></span>${pill(r.decision)}</div><div class="h3" style="margin-top:16px">${esc(r.name)}</div><div class="small">${num(r.images)} images · ${num(Object.values(r.finding_types || {}).reduce((a, b) => a + b, 0))} findings${r.loop_steps ? ` · ${r.loop_steps} loop steps` : ''}</div><div class="tiny" style="margin-top:12px">${when(r.completed)}</div></div>`).join('')}</div>
  </section>`;

  // ---------------------------------------------------------------- canvases
  const hero = new PointCloud($('#hero-cloud'), { ring: true });
  hero.setData(map); hero.target = 0; hero.glowTarget = 0;
  const story = new PointCloud($('#story-cloud'), { ring: false });
  story.setData(map);
  $$('[data-run]', main).forEach(el => el.onclick = () => { store.current = el.dataset.run; location.hash = '#/evidence/summary'; });

  // ---------------------------------------------------------------- scroll choreography
  const steps = $$('.story-step', main), heroSteps = $$('#hero-steps > div', main), modeEl = $('#story-mode');
  const para = $$('[data-parallax]', main);
  let last = -1, raf = 0, prevY = scrollY;
  const counted = new Set();
  const onScroll = () => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const y = scrollY, vh = innerHeight;
      if (!reduced()) para.forEach(el => el.style.transform = `translate3d(0, ${y * parseFloat(el.dataset.parallax)}px, 0)`);
      document.body.style.setProperty('--gy', `${-y * .12}px`);
      heroSteps.forEach((el, i) => el.classList.toggle('on', i === Math.min(2, Math.floor(y / (vh * .35)))));
      story.yaw += (y - prevY) * .0018; prevY = y;
      // continuous progress through the five story steps
      let p = 0;
      steps.forEach((s, i) => { const r = s.getBoundingClientRect(); const c = (vh / 2 - r.top) / r.height; if (c > 0) p = Math.max(p, i + Math.min(1, c)); s.classList.toggle('active', r.top < vh * .6 && r.bottom > vh * .4); });
      story.target = Math.max(0, Math.min(1, p - .7));
      story.colourBy = p > 1.4 && p < 2.6 ? 'class' : 'mono';
      story.glowTarget = Math.max(0, Math.min(1, p - 2.4));
      story.spin = reduced() ? 0 : (p > 3.3 ? .004 : .0012);
      story.kick();
      const idx = Math.max(0, Math.min(4, Math.floor(p - .2)));
      if (idx !== last) { last = idx; modeEl.textContent = ['Sphere', 'Embedding map · class colours', 'Evidence · severity', 'Challenged claims', 'Sealed'][idx] + ` · ${num(objects || 1600)} points`; }
      $$('[data-count]', main).forEach(el => { const r = el.getBoundingClientRect(); if (!counted.has(el) && r.top < vh * .85 && r.bottom > 0) { counted.add(el); countUp(el, Number(el.dataset.count)); } });
    });
  };
  addEventListener('scroll', onScroll, { passive: true }); onScroll();
  reveal(main);
  if (show && !sessionStorage.getItem('sw-showcase')) {
    sessionStorage.setItem('sw-showcase', '1');
    setTimeout(() => toast(`${show.caught_samples}/${show.planted_samples} planted samples and ${show.records_caught}/${show.records_tampered} tampered records caught live. 0 answer keys read.`, { timeout: 9000 }), 900);
  }
  return () => { removeEventListener('scroll', onScroll); document.body.style.removeProperty('--gy'); };
}

function storyStep(i, kicker, title, body) {
  return `<div class="story-step" data-step="${i}"><div class="story-card"><div class="label">${kicker}</div><h2 class="h1" style="font-size:clamp(30px,3vw,44px)">${title}</h2>${body}</div></div>`;
}
