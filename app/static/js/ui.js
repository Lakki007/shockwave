// Shared UI primitives. Everything rendered from data passes through esc().
export const $ = (s, root = document) => root.querySelector(s);
export const $$ = (s, root = document) => [...root.querySelectorAll(s)];
export const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const reduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
export const num = v => (v ?? 0).toLocaleString();
export const pct = (v, d = 0) => v === null || v === undefined ? '—' : `${(v * 100).toFixed(d)}%`;
export const words = s => String(s ?? '').replaceAll('_', ' ');
export const short = (s, n = 16) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '…' : s; };
export const when = t => t ? new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
export const clock = t => t ? new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';

export function pill(state, text) {
  const cls = String(state ?? '').replace(/\s+/g, '-');
  return `<span class="pill ${esc(cls)}">${esc(text ?? state)}</span>`;
}

export const icon = {
  arrow: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 12L12 4M6 4h6v6"/></svg>',
  right: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4"/></svg>',
  down: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3v10M4 9l4 4 4-4"/></svg>',
  check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3L13 4.5"/></svg>',
  play: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 3l8 5-8 5z"/></svg>',
  expand: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M9.5 2.5h4v4M13.5 2.5L9 7M6.5 13.5h-4v-4M2.5 13.5L7 9"/></svg>',
  menu: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2 5h12M2 11h12"/></svg>',
  flask: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 2h4M7 2v4l-4 7.5c-.3.6.1 1.5.9 1.5h8.2c.8 0 1.2-.9.9-1.5L9 6V2"/></svg>',
};

export const diamond = '<svg viewBox="0 0 26 26" aria-hidden="true"><path d="M13 1.5L24.5 13 13 24.5 1.5 13z" fill="none" stroke="#a8d3b8" stroke-width="1.4"/><path d="M13 6.5L19.5 13 13 19.5 6.5 13z" fill="#a8d3b8" opacity=".9"/></svg>';

// ------------------------------------------------------------------ tooltips
// Any element with data-tip shows an explanatory popover on hover or focus.
export function tip(title, text, ref = '') {
  return `<span class="tip" tabindex="0" role="button" aria-label="${esc('About ' + title)}" data-tip="${esc(text)}" data-tip-title="${esc(title)}" data-tip-ref="${esc(ref)}">?</span>`;
}
let tipEl;
function placeTip(target) {
  if (!tipEl) return;
  tipEl.innerHTML = `${target.dataset.tipTitle ? `<b>${esc(target.dataset.tipTitle)}</b>` : ''}${esc(target.dataset.tip)}${target.dataset.tipRef ? `<span class="ref">${esc(target.dataset.tipRef)}</span>` : ''}`;
  tipEl.classList.add('on');
  const r = target.getBoundingClientRect(), w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  let left = Math.min(window.innerWidth - w - 12, Math.max(12, r.left + r.width / 2 - w / 2));
  let top = r.bottom + 10;
  if (top + h > window.innerHeight - 12) top = r.top - h - 10;
  tipEl.style.left = left + 'px'; tipEl.style.top = top + 'px';
}
export function initTooltips() {
  tipEl = $('#tooltip');
  const show = e => { const t = e.target.closest?.('[data-tip]'); if (t) placeTip(t); };
  const hide = e => { if (e.target.closest?.('[data-tip]')) tipEl.classList.remove('on'); };
  document.addEventListener('mouseover', show); document.addEventListener('focusin', show);
  document.addEventListener('mouseout', hide); document.addEventListener('focusout', hide);
  window.addEventListener('scroll', () => tipEl.classList.remove('on'), { passive: true });
}

// ------------------------------------------------------------------ toast
let toastTimer;
export function toast(message, { error = false, timeout = 5200 } = {}) {
  const el = $('#toast');
  el.className = 'toast on' + (error ? ' err' : '');
  el.innerHTML = `${error ? '' : icon.check}<span>${esc(message)}</span><button aria-label="Dismiss">×</button>`;
  el.querySelector('button').onclick = () => el.classList.remove('on');
  clearTimeout(toastTimer);
  if (timeout) toastTimer = setTimeout(() => el.classList.remove('on'), timeout);
}

// ------------------------------------------------------------------ dialog
export function dialog(title, html, kicker = 'Evidence detail') {
  const d = $('#dlg');
  d.innerHTML = `<div class="dlg-head"><div><div class="label">${esc(kicker)}</div><div class="h3" style="margin:6px 0 0">${esc(title)}</div></div><button class="icon-btn" data-close aria-label="Close">×</button></div><div class="dlg-body">${html}</div>`;
  d.querySelector('[data-close]').onclick = () => d.close();
  d.onclick = e => { if (e.target === d) d.close(); };
  d.showModal();
  return d;
}

// ------------------------------------------------------------------ reveal + ranges
let revealer;
export function reveal(root = document) {
  const els = $$('.reveal', root);
  if (reduced() || !('IntersectionObserver' in window)) { els.forEach(e => e.classList.add('in')); return; }
  revealer ??= new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); revealer.unobserve(e.target); } }), { rootMargin: '0px 0px -8% 0px' });
  els.forEach(e => revealer.observe(e));
}
export function paintRange(input) {
  const p = (input.value - input.min) / (input.max - input.min) * 100;
  input.style.setProperty('--p', p + '%');
}

// Animated counter for big numbers.
export function countUp(el, to, ms = 900) {
  if (reduced()) { el.textContent = num(to); return; }
  const start = performance.now(), from = 0;
  const step = t => { const k = Math.min(1, (t - start) / ms), e = 1 - Math.pow(1 - k, 3); el.textContent = num(Math.round(from + (to - from) * e)); if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
