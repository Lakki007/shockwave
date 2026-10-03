// The Method: how evidence becomes a sealed, policy-driven decision, with the code that does it.
import { $$, esc, icon, pill, reveal } from '../ui.js';
import { store } from '../api.js';
import { METHOD, FAQ } from '../content.js';

export async function render(main) {
  const boot = store.boot;
  main.innerHTML = `
    <div class="page-head frame corners">
      <div><div class="label">04 / The Method</div><h1 class="h1">Contract. Challenge. <em>Verify.</em></h1>
        <p class="lead">Eight steps from an untrusted submission to a sealed recommendation. Every step is deterministic, versioned and reproducible from the signed log.</p></div>
      <div class="stack" style="justify-items:end"><span class="label">Policy ${esc(boot.policy.version)}</span><a class="btn small primary" href="#/workbench">Try it live ${icon.arrow}</a></div>
    </div>
    <section class="frame">${METHOD.map(([title, text, refs, code], i) => `
      <div class="method-step reveal"><div class="n">${String(i + 1).padStart(2, '0')}</div>
        <div><h2 class="h2" style="margin-top:0">${esc(title)}</h2><p class="lead">${esc(text)}</p></div>
        <div class="refs"><div class="label">Specification</div>${esc(refs)}<div class="label" style="margin-top:14px">Implementation</div>${esc(code)}</div></div>`).join('')}
    </section>
    <section class="section frame">
      <div class="section-head reveal"><div><div class="label">Claims under the contract</div><h2 class="h1">${boot.claims.length} claims.<br><em>Four possible states.</em></h2></div>
        <div class="flex">${['Supported', 'Weakened', 'Contradicted', 'Unresolved'].map(s => pill(s)).join('')}</div></div>
      <div class="grid g3 reveal">${boot.claims.map(([id, label, domain]) => `<div class="cell"><div class="flex"><span class="label">${esc(domain)}</span><span class="spacer"></span>${boot.policy.mandatory.includes(id) ? '<span class="tag">Mandatory</span>' : ''}</div><div class="h3" style="margin-top:12px">${esc(label)}</div><div class="tiny mono">${esc(id)}</div></div>`).join('')}</div>
    </section>
    <section class="section frame">
      <div class="section-head reveal"><div><div class="label">Verify it yourself</div><h2 class="h2">Nothing here needs to be taken on trust.</h2></div></div>
      <div class="stack reveal">
        <div class="cmd"><span>python3 shockwave.py audit</span><span class="tiny">hash-linked log & checkpoints</span></div>
        <div class="cmd"><span>python3 shockwave.py doctor</span><span class="tiny">environment & weights</span></div>
        <div class="cmd"><span>python3 shockwave.py verify report.json --public-key &lt;key&gt;</span><span class="tiny">report digest & signature</span></div>
        <div class="cmd"><span>python3 -m pytest tests</span><span class="tiny">including the answer-key isolation test</span></div>
      </div>
    </section>
    <section class="section frame">
      <div class="section-head reveal"><div><div class="label">Questions judges ask</div><h2 class="h2">Frequently asked</h2></div></div>
      <div class="faq reveal">${FAQ.map(([q, a], i) => `<details ${i === 0 ? 'open' : ''}><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join('')}</div>
    </section>`;
  // only one answer open at a time keeps the page scannable
  $$('.faq details', main).forEach(d => d.addEventListener('toggle', () => { if (d.open) $$('.faq details', main).forEach(o => o !== d && (o.open = false)); }));
  reveal(main);
}
