// Spotlight walkthrough. Steps point at real controls; `before` can switch tabs first.
import { $, esc } from './ui.js';

export function startTour(steps, { onEnd } = {}) {
  let i = 0;
  const hole = document.createElement('div'); hole.className = 'tour-hole';
  const card = document.createElement('div'); card.className = 'tour-card'; card.setAttribute('role', 'dialog'); card.setAttribute('aria-live', 'polite');
  document.body.append(hole, card);
  const end = () => { hole.remove(); card.remove(); window.removeEventListener('keydown', key); window.removeEventListener('resize', place); onEnd?.(); };
  const key = e => { if (e.key === 'Escape') end(); if (e.key === 'ArrowRight') go(1); if (e.key === 'ArrowLeft') go(-1); };
  function place() {
    const s = steps[i], el = s.sel && $(s.sel);
    if (el) {
      const r = el.getBoundingClientRect(), pad = 8;
      Object.assign(hole.style, { left: r.left - pad + 'px', top: r.top - pad + 'px', width: r.width + pad * 2 + 'px', height: r.height + pad * 2 + 'px', opacity: 1 });
      const cw = card.offsetWidth || 360, ch = card.offsetHeight || 200;
      let left = r.right + 22, top = r.top;
      if (left + cw > innerWidth - 16) left = Math.max(16, r.left - cw - 22);
      if (left < 16 || r.width > innerWidth * .55) { left = Math.min(innerWidth - cw - 16, Math.max(16, r.left)); top = r.bottom + 18; }
      if (top + ch > innerHeight - 16) top = Math.max(16, r.top - ch - 18);
      Object.assign(card.style, { left: left + 'px', top: Math.max(16, top) + 'px' });
    } else {
      Object.assign(hole.style, { left: '50%', top: '50%', width: '0px', height: '0px' });
      Object.assign(card.style, { left: (innerWidth - 360) / 2 + 'px', top: innerHeight / 3 + 'px' });
    }
  }
  async function go(d) {
    const next = i + d;
    if (next < 0) return;
    if (next >= steps.length) return end();
    i = next;
    const s = steps[i];
    if (s.before) await s.before();
    const el = s.sel && $(s.sel);
    if (el) { el.scrollIntoView({ block: 'center', behavior: 'smooth' }); await new Promise(r => setTimeout(r, 380)); }
    card.innerHTML = `<div class="flex"><span class="label">Step ${i + 1} of ${steps.length}</span><span class="tour-dots">${steps.map((_, k) => `<i class="${k === i ? 'on' : ''}"></i>`).join('')}</span></div>
      <div class="h3">${esc(s.title)}</div><p class="small">${esc(s.body)}</p>
      <div class="flex"><button class="btn tiny" data-t="skip">Close</button><span class="spacer"></span>${i ? '<button class="btn tiny" data-t="prev">Back</button>' : ''}<button class="btn tiny primary" data-t="next">${i === steps.length - 1 ? 'Finish' : 'Next'}</button></div>`;
    card.querySelector('[data-t=next]').onclick = () => go(1);
    card.querySelector('[data-t=skip]').onclick = end;
    card.querySelector('[data-t=prev]')?.addEventListener('click', () => go(-1));
    place();
    card.querySelector('[data-t=next]').focus({ preventScroll: true });
  }
  window.addEventListener('keydown', key); window.addEventListener('resize', place);
  go(0);
  return end;
}
