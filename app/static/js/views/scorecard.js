// Detection results versus a sealed answer key, computed only after the report was sealed.
import { esc, pct, pill, words, short } from '../ui.js';
import { RECORD_HELP } from '../content.js';

const bar = r => `<div class="bar ${r < .5 ? 'bad' : r < .8 ? 'warn' : ''}"><i style="width:${Math.round(r * 100)}%"></i></div>`;

export function scorecard(lab) {
  if (!lab) return '<p class="small">No sealed answer key is available for this assessment.</p>';
  const m = lab.model || {}, p = lab.pipeline || {};
  return `<div class="notice ${lab.answer_key_intact ? 'mint' : ''}">${lab.answer_key_intact ? 'Answer key matches the SHA-384 commitment logged before assessment.' : 'Answer key does not match its commitment — treat this score as invalid.'} <span class="mono">${esc(short(lab.commitment, 24))}</span></div>
  <div class="table-wrap"><table><thead><tr><th>Condition</th><th>Planted</th><th>Detected</th><th style="width:28%">Recall</th><th>Detectors</th></tr></thead><tbody>
    ${lab.attacks.map(a => `<tr><td>${esc(words(a.attack))}</td><td>${a.planted}</td><td>${a.detected}</td><td><div class="flex">${bar(a.recall)}<span class="mono small">${pct(a.recall)}</span></div></td><td class="small">${esc(a.detectors.map(words).join(', ') || '—')}</td></tr>`).join('')}
  </tbody></table></div>
  ${lab.records?.length ? `<div class="group-title label">Signed records</div><div class="table-wrap"><table><thead><tr><th>Record</th><th>Condition</th><th>Result</th><th>Detectors</th></tr></thead><tbody>${lab.records.map(r => `<tr><td class="mono">${esc(r.record)}</td><td>${esc(RECORD_HELP[r.kind] || r.kind)}</td><td>${pill(r.detected ? 'detected' : 'missed')}</td><td class="small">${esc(r.detectors.map(words).join(', ') || '—')}</td></tr>`).join('')}</tbody></table></div>` : ''}
  <div class="group-title label">Model and pipeline</div>
  <div class="row"><div><div>Submitted model: ${esc(words(m.mode || '—'))}</div>${m.implant ? `<div class="tiny">Measured on held-out images: ${pct(m.implant.attack_success)} conditional success vs ${pct(m.implant.approved_attack_success)} for the approved model; clean accuracy ${pct(m.implant.clean_accuracy)} vs ${pct(m.implant.approved_clean_accuracy)}</div>` : ''}</div>${m.detected === null || m.detected === undefined ? pill(m.benign_control_flagged ? 'Weakened' : 'Supported', m.benign_control_flagged ? 'control flagged' : 'control clean') : pill(m.detected ? 'detected' : 'missed')}</div>
  <div class="row"><div>Pipeline: ${esc(words(p.mode || '—'))}<div class="tiny">${esc((p.detectors || []).map(words).join(', '))}</div></div>${p.detected === null || p.detected === undefined ? pill(p.false_alarm ? 'Weakened' : 'Supported', p.false_alarm ? 'false alarm' : 'no false alarm') : pill(p.detected ? 'detected' : 'missed')}</div>
  <div class="row"><div>Untouched baseline images flagged<div class="tiny">${esc(lab.note)}</div></div><span class="mono">${lab.untouched_images_flagged} / ${lab.untouched_images}</span></div>`;
}
