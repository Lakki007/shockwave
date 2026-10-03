// Workbench configuration panes: package selection and the Assurance Contract.
import { esc, num, words, tip } from '../ui.js';
import { store } from '../api.js';
import { HELP, CLAIM_HELP } from '../content.js';

export const PRESETS = {
  balanced: { label: 'Balanced', note: 'Default contract', policy: {} },
  strict: { label: 'Strict', note: 'More mandatory claims', policy: { mandatory: ['data_schema', 'model_identity', 'provenance', 'safe_intake', 'labels', 'poisoning', 'pipeline'], label_threshold: .6, robust_margin: 1.0, ood_quantile: .98, challenge_budget: 48, loop_mode: 'exhaustive' } },
  fast: { label: 'Fast triage', note: 'Small budget, decisive', policy: { challenge_budget: 12, loop_mode: 'decisive', trigger_steps: 80 } },
};
const STEP = { challenge_budget: 1, trigger_steps: 10, neighbours: 1, label_threshold: .05, duplicate_distance: 1, ood_quantile: .001, texture_z: .5, robust_margin: .05, patch_similarity: .01, patch_min_images: 1, numerical_tolerance: .001 };

function field(name, control, extra = '') {
  const [title, text, ref] = HELP[name] || [words(name), '', ''];
  return `<div class="field" id="f-${name}"><div class="field-label">${esc(title)} ${tip(title, text, ref)}${extra}</div>${control}</div>`;
}

export function packagePane(S) {
  const fx = store.boot.fixtures, sel = fx.find(f => f.id === S.fixture);
  if (sel && !sel.formats.includes(S.format)) S.format = sel.formats[0];
  return `<div class="field-label">Submission package ${tip('Submission package', 'Contributed images and annotations, optional models, a pipeline configuration and signed inference records. Approved references and keys come from the separate trust registry, never from the package.', '§5, §9')}</div>
    <div id="pkg-list" style="margin-top:12px">${fx.map(f => `<button class="pkg ${f.id === S.fixture ? 'on' : ''}" data-fixture="${esc(f.id)}">
      <span class="flex"><b>${esc(f.name)}</b><span class="spacer"></span>${f.kind === 'attack-lab' ? '<span class="tag">Sealed key</span>' : ''}</span>
      <span class="tiny"><span>${num(f.images)} images</span><span>${f.models} models</span><span>${f.records} records</span><span>${f.reference_images} refs</span><span>${f.formats.join(' / ')}</span></span></button>`).join('')}</div>
    <div class="field" style="margin-top:20px"><div class="field-label">Annotation format ${tip('Annotation format', 'COCO JSON and YOLO text labels use separate adapters normalised into one schema.', '§5')}</div>
      <div class="seg">${['COCO', 'YOLO'].map(x => `<button data-format="${x}" class="${S.format === x ? 'on' : ''}" ${sel?.formats.includes(x) ? '' : 'disabled'}>${x}</button>`).join('')}</div></div>
    <label class="dropzone">Import a submission ZIP<input type="file" accept=".zip" id="upload"><span class="tiny">Bounded intake rejects traversal, encrypted entries and symlinks. Imported trust material cannot approve itself.</span></label>`;
}

function rangeField(S, name) {
  const [lo, hi] = store.boot.ranges[name], v = S.policy[name];
  return field(name, `<input type="range" data-policy="${name}" min="${lo}" max="${hi}" step="${STEP[name]}" value="${v}" aria-label="${esc(HELP[name]?.[0] || name)}">`, `<span class="val" data-val="${name}">${v}</span>`);
}

function segField(S, name, labels = {}) {
  return field(name, `<div class="seg">${store.boot.choices[name].map(o => `<button data-seg="${name}" data-value="${o}" class="${S.policy[name] === o ? 'on' : ''}">${esc(labels[o] || words(o))}</button>`).join('')}</div>`);
}

export function contractPane(S) {
  const p = S.policy;
  return `<div class="presets">${Object.entries(PRESETS).map(([k, v]) => `<button data-preset="${k}" class="${S.preset === k ? 'on' : ''}"><b>${v.label}</b><span>${v.note}</span></button>`).join('')}</div>
    ${field('task', `<input type="text" data-text="task" value="${esc(p.task)}" maxlength="200">`)}
    ${field('context', `<input type="text" data-text="context" value="${esc(p.context)}" maxlength="200">`)}
    ${segField(S, 'access')}
    <div class="field" id="f-mandatory"><div class="field-label">${esc(HELP.mandatory[0])} ${tip(...HELP.mandatory)}<span class="val">${p.mandatory.length} selected</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 12px">${store.boot.claims.map(([id, label]) => `<label class="check" title="${esc(CLAIM_HELP[id] || '')}"><input type="checkbox" data-mandatory="${id}" ${p.mandatory.includes(id) ? 'checked' : ''}>${esc(label)}</label>`).join('')}</div></div>
    <div class="group-title label">Contrarian loop</div>
    ${rangeField(S, 'challenge_budget')}${segField(S, 'loop_mode')}${rangeField(S, 'trigger_steps')}
    <div class="group-title label">Data evidence</div>
    ${segField(S, 'label_method', { neighbour_plurality: 'Neighbour vote', confident_learning: 'Confident Learning' })}
    ${['neighbours', 'label_threshold', 'duplicate_distance', 'texture_z', 'robust_margin', 'patch_similarity', 'patch_min_images', 'ood_quantile'].map(n => rangeField(S, n)).join('')}
    <div class="group-title label">Records & pipeline</div>
    ${rangeField(S, 'numerical_tolerance')}
    <button class="btn small" id="reset-policy">Reset to defaults</button>`;
}
