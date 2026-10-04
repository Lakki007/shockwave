// Attack Lab: forge a brand-new package from the real-world baseline with attacks the user chooses.
// The answer key is sealed outside the package and committed to the audit log before any assessment.
import { $, $$, esc, words, tip, toast, paintRange, icon } from '../ui.js';
import { api, store, follow } from '../api.js';
import { ATTACK_HELP } from '../content.js';

const TOGGLED = ['label_flip', 'trigger', 'flood', 'leakage', 'ood', 'records'];
const ORDER = ['label_flip', 'trigger', 'flood', 'leakage', 'ood', 'model', 'pipeline', 'records'];
const RECORD_KINDS = { altered: 'Output edited', fabricated: 'Wrong output re-signed', replayed: 'Replayed', deleted: 'Deleted', reordered: 'Reordered', substituted: 'Input swapped', untrusted: 'Untrusted signer' };
let options = null;

function control(name, field, rule, value) {
  const id = `${name}.${field}`;
  switch (rule.type) {
    case 'class': return `<select data-f="${id}">${options.classes.map(c => `<option ${c === value ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>`;
    case 'contributor': return `<select data-f="${id}">${options.contributors.map(c => `<option ${c === value ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>`;
    case 'int': return `<input type="range" data-f="${id}" min="${rule.min}" max="${rule.max}" step="${rule.step || 1}" value="${value}">`;
    case 'choice': return `<div class="seg">${rule.options.map(o => `<button type="button" data-f="${id}" data-v="${o}" class="${o === value ? 'on' : ''}">${esc(words(o))}</button>`).join('')}</div>`;
    case 'multi': return `<div class="chips">${rule.options.map(o => `<button type="button" class="chip ${value.includes(o) ? 'on' : ''}" data-f="${id}" data-m="${o}">${esc(RECORD_KINDS[o] || words(o))}</button>`).join('')}</div>`;
    case 'bool': return `<label class="check"><input type="checkbox" data-f="${id}" ${value ? 'checked' : ''}> ${esc(words(field))}</label>`;
  }
  return '';
}

function attackCard(S, name) {
  const cat = options.catalogue[name], spec = S.lab[name], on = !TOGGLED.includes(name) || spec.enabled;
  const fields = Object.entries(cat.fields).map(([f, rule]) =>
    `<div class="field"><div class="field-label">${esc(words(f))}${rule.type === 'int' ? `<span class="val" data-val="${name}.${f}">${spec[f]}</span>` : ''}</div>${control(name, f, rule, spec[f])}</div>`).join('');
  return `<div class="attack ${on ? '' : 'off'}" data-attack="${name}"><div class="attack-head">
      ${TOGGLED.includes(name) ? `<label class="switch"><input type="checkbox" data-toggle="${name}" ${on ? 'checked' : ''} aria-label="Enable ${esc(cat.title)}"><span></span></label>` : ''}
      <b>${esc(cat.title)}</b> ${tip(cat.title, ATTACK_HELP[name] || '', cat.section)}<span class="label">${esc(cat.section)}</span></div>
    <div class="attack-body">${fields}</div></div>`;
}

export async function labPane(pane, S, onForged) {
  if (!options) options = await api('lab/options');
  S.lab ??= structuredClone(options.preset);
  const draw = () => {
    pane.innerHTML = `<p class="small" style="margin-top:0">Forge a new package from ${options.base.images.toLocaleString()} real images. Pixels are stamped, labels rewritten, a model is fine-tuned on the poison and records are signed then tampered. The answer key is sealed <i>before</i> the assessor runs.</p>
      <div class="flex" style="margin:14px 0"><button class="btn tiny" id="lab-preset">Preset mix</button><button class="btn tiny" id="lab-random">Randomise</button><span class="spacer"></span><span class="label">Seed <input type="number" id="lab-seed" value="${S.lab.seed}" min="0" max="99999" style="width:90px;display:inline-block;padding:6px 8px"></span></div>
      ${ORDER.filter(n => options.catalogue[n]).map(n => attackCard(S, n)).join('')}
      <div id="lab-progress"></div>
      <button class="btn primary" id="lab-forge" style="width:100%;margin-top:8px">${icon.flask} Forge package</button>`;
    $$('input[type=range]', pane).forEach(r => { paintRange(r); r.oninput = () => { const [n, f] = r.dataset.f.split('.'); S.lab[n][f] = Number(r.value); $(`[data-val="${r.dataset.f}"]`).textContent = r.value; paintRange(r); }; });
    $$('select[data-f]', pane).forEach(el => el.onchange = () => { const [n, f] = el.dataset.f.split('.'); S.lab[n][f] = el.value; });
    $$('button[data-v]', pane).forEach(b => b.onclick = () => { const [n, f] = b.dataset.f.split('.'); S.lab[n][f] = b.dataset.v; draw(); });
    $$('button[data-m]', pane).forEach(b => b.onclick = () => { const [n, f] = b.dataset.f.split('.'); const set = new Set(S.lab[n][f]); set.has(b.dataset.m) ? set.delete(b.dataset.m) : set.add(b.dataset.m); S.lab[n][f] = [...set]; b.classList.toggle('on'); });
    $$('input[type=checkbox][data-f]', pane).forEach(c => c.onchange = () => { const [n, f] = c.dataset.f.split('.'); S.lab[n][f] = c.checked; });
    $$('[data-toggle]', pane).forEach(c => c.onchange = () => { S.lab[c.dataset.toggle].enabled = c.checked; c.closest('.attack').classList.toggle('off', !c.checked); });
    $('#lab-seed').onchange = e => { S.lab.seed = Number(e.target.value) || 0; };
    $('#lab-preset').onclick = () => { S.lab = structuredClone(options.preset); draw(); };
    $('#lab-random').onclick = () => { randomise(S.lab); draw(); };
    $('#lab-forge').onclick = () => forge(pane, S, onForged);
  };
  draw();
}

function randomise(spec) {
  const r = n => Math.floor(Math.random() * n), pick = xs => xs[r(xs.length)];
  const two = () => { const a = pick(options.classes); let b = pick(options.classes); while (b === a) b = pick(options.classes); return [a, b]; };
  spec.seed = r(100000);
  [spec.label_flip.source, spec.label_flip.target] = two();
  [spec.trigger.source, spec.trigger.target] = two();
  for (const n of TOGGLED) spec[n].enabled = Math.random() < .7;
  spec.model.mode = pick(['backdoor', 'benign_retrain', 'approved', 'unsafe']);
  spec.pipeline.mode = pick(['authorised', 'class_map', 'bgr', 'threshold']);
  [spec.pipeline.source, spec.pipeline.target] = two();
}

async function forge(pane, S, onForged) {
  const btn = $('#lab-forge'), box = $('#lab-progress');
  btn.disabled = true;
  try {
    const { job } = await api('lab/forge', { spec: S.lab });
    box.innerHTML = `<div class="panel" style="margin:12px 0"><div class="flex"><span class="label" id="lab-stage">Queued</span><span class="spacer"></span><span class="mono small" id="lab-pct">0%</span></div><div class="budget" style="margin-top:10px"><i id="lab-bar" style="width:0"></i></div><div class="tiny" id="lab-reason" style="margin-top:10px"></div></div>`;
    const stop = follow(job, async j => {
      if (j.transient) return;
      $('#lab-stage') && ($('#lab-stage').textContent = j.position ? `Queued · ${j.position} ahead` : j.stage);
      $('#lab-pct') && ($('#lab-pct').textContent = `${j.progress}%`);
      $('#lab-bar') && ($('#lab-bar').style.width = `${j.progress}%`);
      const last = (j.feed || []).at(-1); if (last && $('#lab-reason')) $('#lab-reason').textContent = last.reason || '';
      if (j.error) { stop(); btn.disabled = false; toast('Forge failed: ' + j.error, { error: true }); }
      else if (j.complete && j.result) {
        stop(); await store.bootstrap();
        toast(`Forged ${j.result.name}. Answer key sealed (${j.result.commitment.slice(0, 12)}…). Now run assurance.`, { timeout: 9000 });
        onForged(j.result.fixture);
      }
    });
  } catch (e) { btn.disabled = false; toast(e.message, { error: true }); }
}
