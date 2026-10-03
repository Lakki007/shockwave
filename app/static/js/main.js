// App shell: header, hash router, bootstrap. Views render into <main> and return a cleanup function.
import { $, $$, esc, diamond, icon, toast, initTooltips } from './ui.js';
import { store } from './api.js';

const ROUTES = [['overview', '01', 'Overview'], ['workbench', '02', 'Workbench'], ['evidence', '03', 'Evidence'], ['method', '04', 'The Method']];
const VIEWS = { overview: () => import('./views/overview.js'), workbench: () => import('./views/workbench.js'), evidence: () => import('./views/evidence.js'), method: () => import('./views/method.js') };
let cleanup = null, token = 0;

function header() {
  $('#topbar').innerHTML = `<a class="brand" href="#/overview" aria-label="Shockwave overview">${diamond}<b>SHOCK<i>WAVE</i></b></a>
    <nav class="nav" id="nav">${ROUTES.map(([id, n, l]) => `<a href="#/${id}" data-route="${id}"><small>${n}</small>${l}</a>`).join('')}</nav>
    <div class="top-right"><span class="status" id="status"><i></i><span>Local · offline</span></span>
      <button class="icon-btn menu-btn" id="menu-btn" aria-label="Toggle navigation" aria-expanded="false">${icon.menu}</button></div>`;
  const nav = $('#nav'), btn = $('#menu-btn');
  btn.onclick = () => { const open = nav.classList.toggle('open'); btn.setAttribute('aria-expanded', open); };
  nav.onclick = e => { if (e.target.closest('a')) { nav.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); } };
}

// Hash format: #/route/sub?params
export function parse(hash = location.hash) {
  const [path, query = ''] = hash.replace(/^#\/?/, '').split('?');
  const [route, ...rest] = path.split('/');
  return { route: VIEWS[route] ? route : 'overview', sub: rest.join('/'), params: new URLSearchParams(query) };
}

async function route() {
  const { route, sub, params } = parse(), mine = ++token, main = $('#main');
  $$('#nav [data-route]').forEach(a => a.classList.toggle('active', a.dataset.route === route));
  try { cleanup?.(); } catch { /* a view's teardown must never block navigation */ }
  cleanup = null;
  try {
    const view = await VIEWS[route]();
    if (mine !== token) return;
    main.innerHTML = '<div class="loading">Loading…</div>';
    const done = await view.render(main, params, sub);
    if (mine !== token) { done?.(); return; }
    cleanup = done || null;
    document.title = `Shockwave · ${ROUTES.find(r => r[0] === route)[2]}`;
    if (!params.has('keep')) window.scrollTo({ top: 0, behavior: 'instant' });
  } catch (e) {
    if (mine !== token) return;
    console.error(e);
    main.innerHTML = `<div class="loading">This view could not load: ${esc(e.message)}</div>`;
  }
}

// Reflects whether an assessment is running anywhere in the app.
export function setBusy(busy, text) {
  const s = $('#status'); if (!s) return;
  s.classList.toggle('busy', !!busy);
  s.querySelector('span').textContent = text || (busy ? 'Assessing…' : 'Local · offline');
}

async function boot() {
  header(); initTooltips();
  try { await store.bootstrap(); }
  catch (e) { $('#main').innerHTML = `<div class="loading">The local server did not respond: ${esc(e.message)}</div>`; return; }
  if (!location.hash) history.replaceState(null, '', '#/overview');
  const demo = new URLSearchParams(location.search).has('demo');
  if (demo) sessionStorage.setItem('sw-showcase', '1'); // keep the overview toast out of the recording
  addEventListener('hashchange', route);
  document.addEventListener('sw:run-start', () => setBusy(true));
  document.addEventListener('sw:run-complete', () => setBusy(false));
  await route();
  if (demo) (await import('./demo.js')).autopilot();
}

boot().catch(e => toast(e.message, { error: true }));
