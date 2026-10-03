// 80-second autopilot: drives the real interface (real assessment, real evidence) with captions.
// Start with ?demo in the URL. Press Esc to stop.
import { $, esc } from './ui.js';
import { store } from './api.js';

const LENGTH = 80;
let t0 = 0, stopped = false, hud, cursor;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async s => { const ms = t0 + s * 1000 - performance.now(); if (ms > 0) await sleep(ms); if (stopped) throw new Error('stopped'); };
const ease = k => k < .5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;

function caption(kicker, text) {
  hud.querySelector('.demo-cap').innerHTML = `<span class="label">${esc(kicker)}</span><b>${esc(text)}</b>`;
  hud.classList.remove('flip'); void hud.offsetWidth; hud.classList.add('flip');
}

function scrollTo(y, ms) {
  const from = scrollY, to = Math.max(0, Math.min(y, document.documentElement.scrollHeight - innerHeight)), start = performance.now();
  return new Promise(res => {
    const step = now => { const k = Math.min(1, (now - start) / ms); window.scrollTo({ top: from + (to - from) * ease(k), behavior: 'instant' }); k < 1 && !stopped ? requestAnimationFrame(step) : res(); };
    requestAnimationFrame(step);
  });
}
const scrollToEl = (sel, ms = 1200, offset = 120) => { const el = $(sel); return el ? scrollTo(scrollY + el.getBoundingClientRect().top - offset, ms) : Promise.resolve(); };

async function point(sel, click = true) {
  const el = typeof sel === 'string' ? $(sel) : sel; if (!el) return;
  const r = el.getBoundingClientRect();
  cursor.style.transform = `translate(${r.left + r.width / 2}px, ${r.top + r.height / 2}px)`;
  await sleep(650);
  if (click) { cursor.classList.add('press'); await sleep(160); cursor.classList.remove('press'); el.click(); }
}

async function go(hash) {
  const done = new Promise(r => { const h = () => { removeEventListener('hashchange', h); r(); }; addEventListener('hashchange', h); });
  location.hash = hash; await done;
  for (let i = 0; i < 40 && $('#main .loading'); i++) await sleep(100);
  await sleep(250);
}

const runDone = () => new Promise(r => document.addEventListener('sw:run-complete', r, { once: true }));

export async function autopilot() {
  document.body.classList.add('demo');
  hud = document.createElement('div'); hud.className = 'demo-hud';
  hud.innerHTML = '<div class="demo-cap"></div><div class="demo-progress"><i></i></div>';
  cursor = document.createElement('div'); cursor.className = 'demo-cursor';
  cursor.style.transform = `translate(${innerWidth * .6}px, ${innerHeight * .6}px)`;
  document.body.append(hud, cursor);
  addEventListener('keydown', e => { if (e.key === 'Escape') stopped = true; });
  t0 = performance.now();
  const bar = hud.querySelector('.demo-progress i');
  const tick = () => { const k = Math.min(1, (performance.now() - t0) / (LENGTH * 1000)); bar.style.width = k * 100 + '%'; if (k < 1 && !stopped) requestAnimationFrame(tick); };
  tick();
  window.__demo = { done: false };
  // Drop ?demo so a reload or later navigation never restarts the autopilot.
  history.replaceState(null, '', location.pathname + location.hash);
  try { await script(); } catch (e) { if (e.message !== 'stopped') console.error(e); }
  window.__demo.done = true;
  await sleep(stopped ? 0 : 1500); // let the closing caption be seen (and recorded)
  hud.remove(); cursor.remove(); document.body.classList.remove('demo');
}

async function script() {
  // 0–20 s · Overview story
  if (!location.hash.startsWith('#/overview')) await go('#/overview');
  window.scrollTo({ top: 0, behavior: 'instant' });
  caption('Shockwave · computer vision assurance', 'Every contribution leaves evidence.');
  await until(4);
  caption('01 / Observe', 'Every dot is a real object crop, embedded locally by DINOv2.');
  await scrollToEl('.story-step[data-step="0"]', 1800, 0);
  await until(8);
  caption('02 / Map', 'Labels are checked against independent visual neighbours.');
  await scrollToEl('.story-step[data-step="1"]', 1800, 0);
  await until(12);
  caption('03 / Evidence', 'Objects carrying evidence light up by severity.');
  await scrollToEl('.story-step[data-step="2"]', 1800, 0);
  await until(16);
  caption('04 / Seal', 'The decision is bound into a signed SHA-384 digest.');
  await scrollToEl('.story-step[data-step="4"]', 1800, 0);
  await until(19);

  // 20–50 s · Workbench: a real assessment of a package the assessor has never seen
  caption('Workbench', 'Pick a package. Set the Assurance Contract.');
  await go('#/workbench');
  const wb = await import('./views/workbench.js');
  await point('#wb-tabs [data-tab="contract"]');
  await scrollToEl('#f-access', 900, 200);
  await until(25);
  await point('#wb-tabs [data-tab="package"]');
  await scrollToEl('#theatre', 1000, 100);
  await until(27);
  caption('Run · live', 'Findings stream in. The Contrarian Loop picks each next test.');
  const finished = runDone();
  if (wb.S.job) { /* already running: follow it */ } else await point('#run-btn');
  await scrollToEl('#theatre', 600, 100);
  await until(38);
  caption('Contrarian loop', 'Highest weight × value × (1 + gap) / cost goes next.');
  await scrollToEl('.loop-col', 900, 160);
  await Promise.race([finished, until(50).catch(() => {})]);
  await scrollToEl('#banner', 700, 160);
  caption('Sealed', 'Policy, not AI, maps 19 claims to Accept, Review or Quarantine.');
  await until(53);

  // 53–74 s · Evidence
  await go('#/evidence/summary');
  caption('Evidence', 'Every number comes from the sealed report.');
  await scrollTo(380, 1600);
  await until(57);
  await go('#/evidence/findings');
  caption('Findings', 'Open any finding: the image, the boxes, the raw measurement.');
  await point([...document.querySelectorAll('#f-rows tr.click')].find(tr => /(jpe?g|png)/i.test(tr.textContent)) || '#f-rows tr.click');
  await until(61.5);
  $('#dlg')?.close();
  await go('#/evidence/data');
  caption('Data map', 'The embedding itself is explorable — evidence in context.');
  await sleep(900);
  await point('#colour-by [data-c="evidence"]');
  await until(66);
  await go('#/evidence/loop');
  caption('Contrarian loop', 'Why each test was chosen, what it beat, how the claim moved.');
  await scrollTo(260, 2200);
  await until(70);
  await go('#/evidence/reports');
  caption('Audit', 'Hash-linked log, signed Merkle checkpoints, answer keys never read.');
  await until(74);

  // 74–80 s · Method
  await go('#/method');
  caption('The Method', 'Contract. Challenge. Verify. Fully offline.');
  await scrollTo(document.documentElement.scrollHeight * .35, 4000);
  await until(LENGTH - .2);
  caption('Shockwave', 'Know what remains unknown.');
}
