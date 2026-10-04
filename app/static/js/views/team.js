// Multi-analyst workspace: sign-in, password change and (for admins) the team roster.
import { $, $$, esc, pill, icon, toast, dialog, when } from '../ui.js';
import { api, store } from '../api.js';

const ROLE_HELP = { analyst: 'Run assessments and record finding dispositions', reviewer: 'Everything an analyst can do, plus count as the reviewer in two-person sign-off', admin: 'Everything, plus manage analysts' };

// Full-page sign-in. Resolves once the analyst is signed in and has a permanent password.
export function signIn(main) {
  return new Promise(resolve => {
    const form = () => {
      main.innerHTML = `<div class="page-head frame corners"><div><div class="label">Multi-analyst workspace</div><h1 class="h1">Sign in to <em>assess.</em></h1>
          <p class="lead">Findings, dispositions and sign-offs are attributed to you and written to the signed audit log.</p></div></div>
        <div class="page-body"><form class="panel auth-form" id="login" autocomplete="on">
          <div class="field"><div class="field-label">Username</div><input type="text" name="username" autocomplete="username" required autofocus></div>
          <div class="field"><div class="field-label">Password</div><input type="password" name="password" autocomplete="current-password" required></div>
          <button class="btn primary" type="submit">Sign in ${icon.right}</button>
          <p class="tiny" style="margin-top:16px">First sign-in? The administrator account's temporary password is in <span class="mono">data/state/initial-admin.txt</span> on the server.</p></form></div>`;
      $('#login').onsubmit = async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        try {
          const r = await api('login', { username: f.get('username'), password: f.get('password') });
          store.session.analyst = r.analyst;
          r.analyst.must_change ? changePassword(main, true).then(resolve) : resolve(r.analyst);
        } catch (err) { toast(err.message, { error: true }); }
      };
    };
    form();
  });
}

export function changePassword(main, forced = false) {
  return new Promise(resolve => {
    main.innerHTML = `<div class="page-head frame corners"><div><div class="label">${forced ? 'First sign-in' : 'Account'}</div><h1 class="h1">Choose a <em>password.</em></h1>
        <p class="lead">${forced ? 'Your account has a temporary password. Replace it before continuing.' : 'At least 12 characters.'}</p></div></div>
      <div class="page-body"><form class="panel auth-form" id="pw">
        <div class="field"><div class="field-label">Current password</div><input type="password" name="current" autocomplete="current-password" required></div>
        <div class="field"><div class="field-label">New password · 12+ characters</div><input type="password" name="new" autocomplete="new-password" minlength="12" required></div>
        <div class="field"><div class="field-label">Repeat new password</div><input type="password" name="again" autocomplete="new-password" minlength="12" required></div>
        <button class="btn primary" type="submit">Save password ${icon.check}</button></form></div>`;
    $('#pw').onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      if (f.get('new') !== f.get('again')) return toast('The new passwords do not match.', { error: true });
      try { const r = await api('password', { current: f.get('current'), new: f.get('new') }); store.session.analyst = r.analyst; toast('Password changed.'); resolve(r.analyst); }
      catch (err) { toast(err.message, { error: true }); }
    };
  });
}

// One-time display of a temporary password the admin must pass on out of band.
function showTemporary(who, password) {
  dialog(`Temporary password for ${who}`, `<p class="small">Pass this on privately. It is shown once and must be changed at first sign-in.</p>
    <div class="cmd" style="margin-top:14px"><span id="tmp-pw">${esc(password)}</span><button class="btn tiny" id="copy-pw">Copy</button></div>`, 'New credentials');
  $('#copy-pw').onclick = () => navigator.clipboard?.writeText(password).then(() => toast('Copied.'));
}

export async function render(main) {
  const me = store.session.analyst;
  if (store.session.mode !== 'multi') {
    main.innerHTML = `<div class="page-head frame corners"><div><div class="label">05 / Team</div><h1 class="h1">Single-user <em>workspace.</em></h1><p class="lead">Configure PostgreSQL and run <span class="mono">python3 shockwave.py analysts init</span> to enable sign-in, dispositions and two-person sign-off.</p></div></div>`;
    return;
  }
  const paint = async () => {
    const [team, check] = await Promise.all([api('analysts'), api('analysts/verify').catch(e => ({ verified: false, problems: [e.message] }))]);
    main.innerHTML = `<div class="page-head frame corners"><div><div class="label">05 / Team</div><h1 class="h1">Analysts & <em>roles.</em></h1>
        <p class="lead">Signed in as ${esc(me.name)} (${esc(me.role)}). Two-person rule: a run is signed off only when two people agree, at least one a reviewer.</p></div></div>
      <div class="page-body">
        <div class="notice ${check.verified ? 'mint' : ''}">${check.verified ? `Database cross-checked against the signed audit log: ${check.rows_checked} dispositions and sign-offs match.` : `Database and audit log disagree: ${esc((check.problems || []).slice(0, 3).join('; '))}`}</div>
        <div class="grid g2" style="gap:20px">
          <div class="panel"><div class="panel-head"><span class="label">Roster</span></div><div class="table-wrap"><table><thead><tr><th>Analyst</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>
            ${team.map(a => `<tr><td>${esc(a.name)}<span class="sub">${esc(a.username)}</span></td><td>${esc(a.role)}</td><td>${a.disabled ? pill('Failed', 'disabled') : a.must_change ? pill('Review', 'temporary password') : pill('Supported', 'active')}</td>
              <td class="flex">${a.id === me.id ? '<span class="tiny">you</span>' : `<button class="btn tiny" data-reset="${a.id}" data-name="${esc(a.username)}">Reset password</button><button class="btn tiny" data-toggle="${a.id}" data-disabled="${a.disabled}">${a.disabled ? 'Enable' : 'Disable'}</button>`}</td></tr>`).join('')}
          </tbody></table></div></div>
          <form class="panel" id="add"><div class="panel-head"><span class="label">Add an analyst</span></div>
            <div class="field"><div class="field-label">Username</div><input type="text" name="username" pattern="[a-z0-9._-]{3,32}" required placeholder="lowercase, 3-32 characters"></div>
            <div class="field"><div class="field-label">Display name</div><input type="text" name="name" maxlength="80" required></div>
            <div class="field"><div class="field-label">Role</div><div class="seg" id="role">${Object.keys(ROLE_HELP).map((r, i) => `<button type="button" data-role="${r}" class="${i ? '' : 'on'}" title="${esc(ROLE_HELP[r])}">${r}</button>`).join('')}</div><p class="tiny" id="role-help">${ROLE_HELP.analyst}</p></div>
            <button class="btn primary small" type="submit">Create account</button></form>
        </div></div>`;
    let role = 'analyst';
    $$('#role [data-role]').forEach(b => b.onclick = () => { role = b.dataset.role; $$('#role [data-role]').forEach(x => x.classList.toggle('on', x === b)); $('#role-help').textContent = ROLE_HELP[role]; });
    $('#add').onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      try { const r = await api('analysts', { username: f.get('username'), name: f.get('name'), role }); await paint(); showTemporary(r.analyst.username, r.temporary_password); }
      catch (err) { toast(err.message, { error: true }); }
    };
    $$('[data-toggle]', main).forEach(b => b.onclick = async () => { try { await api('analysts/disable', { id: Number(b.dataset.toggle), disabled: b.dataset.disabled !== 'true' }); paint(); } catch (err) { toast(err.message, { error: true }); } });
    $$('[data-reset]', main).forEach(b => b.onclick = async () => { try { const r = await api('analysts/reset', { id: Number(b.dataset.reset) }); paint(); showTemporary(b.dataset.name, r.temporary_password); } catch (err) { toast(err.message, { error: true }); } });
  };
  await paint();
}

// ------------------------------------------------------------------ review widgets used by the Evidence page
const DECISIONS = [['confirmed', 'Confirm'], ['dismissed', 'Dismiss'], ['escalated', 'Escalate'], ['needs_info', 'Needs info']];

export function dispositionBlock(run, finding, state) {
  if (store.session.mode !== 'multi' || !store.session.analyst) return '';
  const rows = state?.dispositions?.[finding.id] || [];
  return `<div class="group-title label">Analyst dispositions</div>
    ${rows.length ? rows.map(d => `<div class="row"><div><b>${esc(d.name)}</b> · ${pill(d.decision === 'confirmed' ? 'Contradicted' : d.decision === 'dismissed' ? 'Supported' : 'Review', d.decision.replace('_', ' '))}<div class="tiny">${esc(d.note)}</div></div><span class="tiny">${esc(when(d.created))} · audit #${d.audit_sequence}</span></div>`).join('') : '<p class="tiny">No dispositions yet. The computed result is never overwritten.</p>'}
    <form id="dispose" style="margin-top:12px"><div class="seg" id="decision">${DECISIONS.map(([v, l], i) => `<button type="button" data-d="${v}" class="${i ? '' : 'on'}">${l}</button>`).join('')}</div>
      <textarea name="note" rows="2" maxlength="2000" required placeholder="Why? (recorded with your name in the signed audit log)" style="margin-top:10px"></textarea>
      <button class="btn small primary" type="submit" style="margin-top:10px">Record disposition</button></form>`;
}

export function bindDisposition(run, finding, onChange) {
  const form = $('#dispose'); if (!form) return;
  let decision = 'confirmed';
  $$('#decision [data-d]').forEach(b => b.onclick = () => { decision = b.dataset.d; $$('#decision [data-d]').forEach(x => x.classList.toggle('on', x === b)); });
  form.onsubmit = async e => {
    e.preventDefault();
    try { const state = await api('disposition', { run: run.id, finding: finding.id, decision, note: new FormData(form).get('note') }); toast('Disposition recorded and signed into the audit log.'); onChange(state); }
    catch (err) { toast(err.message, { error: true }); }
  };
}

export function signoffPanel(run, state) {
  if (store.session.mode !== 'multi' || !store.session.analyst || !state) return '';
  const me = store.session.analyst, mine = state.signoffs.some(s => s.username === me.username);
  return `<div class="panel reveal in"><div class="panel-head"><span class="label">Two-person sign-off</span>${pill(state.status === 'Signed off' ? 'Supported' : state.status === 'Disagreement' ? 'Contradicted' : 'Review', state.status + (state.agreed ? ` · ${state.agreed}` : ''))}</div>
    <p class="tiny">${esc(state.rule)}</p>
    <div class="row"><span class="k">Findings with a disposition</span><span class="mono">${state.disposed} / ${state.findings}</span></div>
    <div class="row"><span class="k">Critical findings still undisposed</span><span class="mono ${state.undisposed_critical.length ? 'coral' : ''}">${state.undisposed_critical.length}</span></div>
    ${state.signoffs.map(s => `<div class="row"><div><b>${esc(s.name)}</b> <span class="tiny">${esc(s.role)}</span><div class="tiny">${esc(s.note)}</div></div>${pill(s.recommendation === 'accept' ? 'Accept' : s.recommendation === 'quarantine' ? 'Quarantine' : 'Review', s.recommendation)}</div>`).join('')}
    ${mine ? '<p class="tiny" style="margin-top:12px">You have signed off this assessment.</p>' : `<form id="signoff" style="margin-top:14px"><div class="seg" id="rec">${['accept', 'review', 'quarantine'].map(r => `<button type="button" data-r="${r}" class="${r === run.decision.toLowerCase() ? 'on' : ''}">${r}</button>`).join('')}</div>
      <textarea name="note" rows="2" maxlength="2000" required placeholder="Basis for your recommendation" style="margin-top:10px"></textarea>
      <button class="btn small primary" type="submit" style="margin-top:10px" ${state.undisposed_critical.length ? 'disabled title="Disposition every critical finding first"' : ''}>Sign off as ${esc(me.name)}</button></form>`}</div>`;
}

export function bindSignoff(run, onChange) {
  const form = $('#signoff'); if (!form) return;
  let rec = run.decision.toLowerCase();
  $$('#rec [data-r]').forEach(b => b.onclick = () => { rec = b.dataset.r; $$('#rec [data-r]').forEach(x => x.classList.toggle('on', x === b)); });
  form.onsubmit = async e => {
    e.preventDefault();
    try { onChange(await api('signoff', { run: run.id, recommendation: rec, note: new FormData(form).get('note') })); toast('Sign-off recorded.'); }
    catch (err) { toast(err.message, { error: true }); }
  };
}
