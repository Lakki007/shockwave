"""Multi-analyst workspace (§28), stored in PostgreSQL.

* Analysts authenticate with a password (scrypt) and an HttpOnly, SameSite=Strict session cookie.
* Roles: analyst (assess, disposition findings), reviewer (+ sign-off), admin (+ manage analysts).
* Dispositions are append-only per finding; the computed recommendation is never overwritten.
* Two-person rule: a run is signed off only when two different people record the same
  recommendation, at least one of them a reviewer or admin, after every critical finding
  carries a disposition.
* Every database write is also appended to the signed audit log, and the row stores the audit
  sequence, so rows edited directly in the database are detectable (verify()).

Enabled when data/state/database.json or SHOCKWAVE_DATABASE_URL names a reachable database;
otherwise the workspace stays single-user and nothing here is used.
"""
import base64, hashlib, hmac, json, os, re, secrets, threading, time
import core

ROLES = ('analyst', 'reviewer', 'admin')
RANK = {r: i for i, r in enumerate(ROLES)}
DISPOSITIONS = ('confirmed', 'dismissed', 'escalated', 'needs_info')
RECOMMENDATIONS = ('accept', 'review', 'quarantine')
SESSION_SECONDS = 12 * 3600
COOKIE = 'sw_session'
USERNAME = re.compile(r'^[a-z0-9._-]{3,32}$')

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysts (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9._-]{3,32}$'),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  role TEXT NOT NULL CHECK (role IN ('analyst','reviewer','admin')),
  password_hash TEXT NOT NULL,
  must_change BOOLEAN NOT NULL DEFAULT TRUE,
  disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions (
  token_sha256 TEXT PRIMARY KEY,
  analyst_id BIGINT NOT NULL REFERENCES analysts(id) ON DELETE CASCADE,
  created TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS dispositions (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  analyst_id BIGINT NOT NULL REFERENCES analysts(id),
  decision TEXT NOT NULL CHECK (decision IN ('confirmed','dismissed','escalated','needs_info')),
  note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 2000),
  report_digest TEXT NOT NULL, audit_sequence INT NOT NULL,
  created TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS dispositions_run ON dispositions (run_id, finding_id, created);
CREATE TABLE IF NOT EXISTS signoffs (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  analyst_id BIGINT NOT NULL REFERENCES analysts(id),
  recommendation TEXT NOT NULL CHECK (recommendation IN ('accept','review','quarantine')),
  note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 2000),
  report_digest TEXT NOT NULL, audit_sequence INT NOT NULL,
  created TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (run_id, analyst_id));
"""

_lock = threading.Lock()
_state = {'checked': 0.0, 'enabled': False, 'reason': 'Not configured'}
_failures = {}


# --------------------------------------------------------------------------- connection

def url():
    return os.environ.get('SHOCKWAVE_DATABASE_URL') or (core.read_json(core.STATE / 'database.json', {}) or {}).get('url')


def connect():
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(url(), autocommit=True, row_factory=dict_row, connect_timeout=3)


def enabled():
    """Multi-analyst mode is on when a database is configured, reachable and migrated (re-checked every 30 s)."""
    if os.environ.get('SHOCKWAVE_MULTI') == '0':  # operator switch back to the single-user demo workspace
        _state.update(enabled=False, reason='Disabled by operator (SHOCKWAVE_MULTI=0)')
        return False
    with _lock:
        if time.time() - _state['checked'] < 30:
            return _state['enabled']
        _state['checked'] = time.time()
        if not url():
            _state.update(enabled=False, reason='No database configured')
            return False
        try:
            with connect() as c:
                c.execute(SCHEMA)
            _state.update(enabled=True, reason='PostgreSQL reachable')
        except Exception as e:
            _state.update(enabled=False, reason=f'Database unavailable: {type(e).__name__}')
        return _state['enabled']


def mode():
    on = enabled()
    return {'mode': 'multi' if on else 'single', 'database': _state['reason']}


# --------------------------------------------------------------------------- passwords + sessions

def hash_password(password):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        raise ValueError('Passwords must be 12-256 characters')
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return 'scrypt$32768$8$1$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(dk).decode()


def check_password(password, stored):
    try:
        _, n, r, p, salt, dk = stored.split('$')
        got = hashlib.scrypt(str(password).encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got, base64.b64decode(dk))
    except Exception:
        return False


def _public(a):
    return {'id': a['id'], 'username': a['username'], 'name': a['display_name'], 'role': a['role'], 'must_change': a['must_change'], 'disabled': a.get('disabled', False)}


def login(username, password, client):
    username = str(username or '').strip().lower()
    key = (username, client)
    fails, until = _failures.get(key, (0, 0))
    if until > time.time():
        raise PermissionError(f'Too many attempts. Try again in {int(until - time.time()) + 1} s.')
    with connect() as c:
        a = c.execute('SELECT * FROM analysts WHERE username=%s', (username,)).fetchone()
        dummy = 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + 'A' * 44  # equalise timing for unknown users
        ok = check_password(password, a['password_hash'] if a else dummy) and a and not a['disabled']
        if not ok:
            fails += 1
            _failures[key] = (fails, time.time() + min(300, 2 ** fails) if fails >= 5 else 0)
            raise PermissionError('Unknown username or password')
        _failures.pop(key, None)
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions (token_sha256, analyst_id, expires) VALUES (%s, %s, now() + make_interval(secs => %s))",
                  (hashlib.sha256(token.encode()).hexdigest(), a['id'], SESSION_SECONDS))
        c.execute('DELETE FROM sessions WHERE expires < now()')
    core.log_event('analyst_login', {'analyst': a['username']})
    return token, _public(a)


def session(token):
    if not token:
        return None
    with connect() as c:
        a = c.execute('SELECT a.* FROM sessions s JOIN analysts a ON a.id=s.analyst_id WHERE s.token_sha256=%s AND s.expires>now() AND NOT a.disabled',
                      (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    return _public(a) if a else None


def logout(token):
    with connect() as c:
        c.execute('DELETE FROM sessions WHERE token_sha256=%s', (hashlib.sha256(str(token).encode()).hexdigest(),))


def require(analyst, role):
    if not analyst:
        raise PermissionError('Sign in required')
    if analyst['must_change'] and role != 'self':
        raise PermissionError('Change your temporary password first')
    if role != 'self' and RANK[analyst['role']] < RANK[role]:
        raise PermissionError(f'This action needs the {role} role')


# --------------------------------------------------------------------------- analysts

def create(actor, username, name, role):
    require(actor, 'admin')
    username = str(username or '').strip().lower()
    if not USERNAME.match(username):
        raise ValueError('Usernames are 3-32 characters: a-z, 0-9, dot, dash, underscore')
    if role not in ROLES:
        raise ValueError('Unknown role')
    temporary = secrets.token_urlsafe(12)
    with connect() as c:
        if c.execute('SELECT 1 FROM analysts WHERE username=%s', (username,)).fetchone():
            raise ValueError('That username is taken')
        a = c.execute('INSERT INTO analysts (username, display_name, role, password_hash) VALUES (%s,%s,%s,%s) RETURNING *',
                      (username, str(name or username)[:80], role, hash_password(temporary))).fetchone()
    core.log_event('analyst_created', {'analyst': username, 'role': role, 'by': actor['username'] if actor else 'bootstrap'})
    return _public(a), temporary


def bootstrap_admin():
    """Create the first admin if none exists; the temporary password goes to a 0600 file, never to logs."""
    with connect() as c:
        c.execute(SCHEMA)
        if c.execute("SELECT 1 FROM analysts WHERE role='admin' AND NOT disabled").fetchone():
            return None
    a, temporary = create({'username': 'bootstrap', 'role': 'admin', 'must_change': False}, 'admin', 'Administrator', 'admin')
    p = core.STATE / 'initial-admin.txt'
    p.write_text(f'username: admin\ntemporary password: {temporary}\nYou will be asked to change it at first sign-in. Delete this file afterwards.\n')
    os.chmod(p, 0o600)
    return {'username': a['username'], 'password_file': str(p)}


def listing(actor):
    require(actor, 'admin')
    with connect() as c:
        return [_public(a) for a in c.execute('SELECT * FROM analysts ORDER BY created').fetchall()]


def set_disabled(actor, analyst_id, disabled):
    require(actor, 'admin')
    if int(analyst_id) == actor['id']:
        raise ValueError('You cannot disable your own account')
    with connect() as c:
        a = c.execute('UPDATE analysts SET disabled=%s WHERE id=%s RETURNING *', (bool(disabled), int(analyst_id))).fetchone()
        if not a:
            raise ValueError('Unknown analyst')
        c.execute('DELETE FROM sessions WHERE analyst_id=%s', (a['id'],))
    core.log_event('analyst_disabled' if disabled else 'analyst_enabled', {'analyst': a['username'], 'by': actor['username']})
    return _public(a)


def reset_password(actor, analyst_id):
    require(actor, 'admin')
    temporary = secrets.token_urlsafe(12)
    with connect() as c:
        a = c.execute('UPDATE analysts SET password_hash=%s, must_change=TRUE WHERE id=%s RETURNING *', (hash_password(temporary), int(analyst_id))).fetchone()
        if not a:
            raise ValueError('Unknown analyst')
        c.execute('DELETE FROM sessions WHERE analyst_id=%s', (a['id'],))
    core.log_event('analyst_password_reset', {'analyst': a['username'], 'by': actor['username']})
    return _public(a), temporary


def change_password(actor, current, new):
    require(actor, 'self')
    with connect() as c:
        a = c.execute('SELECT * FROM analysts WHERE id=%s', (actor['id'],)).fetchone()
        if not check_password(current, a['password_hash']):
            raise PermissionError('Current password is incorrect')
        if current == new:
            raise ValueError('Choose a different password')
        c.execute('UPDATE analysts SET password_hash=%s, must_change=FALSE WHERE id=%s', (hash_password(new), actor['id']))
    core.log_event('analyst_password_changed', {'analyst': actor['username']})
    return {**actor, 'must_change': False}


# --------------------------------------------------------------------------- dispositions + sign-off

def _report(run_id):
    r = core.read_json(core.safe_path(core.STATE / 'runs', str(run_id) + '.json'))
    if not r:
        raise ValueError('Unknown assessment')
    return r


def dispose(actor, run_id, finding_id, decision, note):
    require(actor, 'analyst')
    r = _report(run_id)
    if decision not in DISPOSITIONS:
        raise ValueError('Unknown disposition')
    note = str(note or '').strip()
    if not note:
        raise ValueError('A disposition needs a note')
    if not any(f['id'] == finding_id for f in r['findings']):
        raise ValueError('Unknown finding for this assessment')
    event = core.log_event('finding_disposition', {'run': run_id, 'finding': finding_id, 'decision': decision, 'note': note,
                                                   'analyst': actor['username'], 'report_digest': r['report_digest']})
    with connect() as c:
        c.execute('INSERT INTO dispositions (run_id, finding_id, analyst_id, decision, note, report_digest, audit_sequence) VALUES (%s,%s,%s,%s,%s,%s,%s)',
                  (run_id, finding_id, actor['id'], decision, note, r['report_digest'], event['sequence']))
    return review(actor, run_id)


def signoff(actor, run_id, recommendation, note):
    require(actor, 'analyst')
    r = _report(run_id)
    if recommendation not in RECOMMENDATIONS:
        raise ValueError('Unknown recommendation')
    note = str(note or '').strip()
    if not note:
        raise ValueError('A sign-off needs a note')
    state = review(actor, run_id)
    if state['undisposed_critical']:
        raise ValueError(f'{len(state["undisposed_critical"])} critical findings have no disposition yet')
    if any(s['username'] == actor['username'] for s in state['signoffs']):
        raise ValueError('You have already signed off this assessment')
    event = core.log_event('assessment_signoff', {'run': run_id, 'recommendation': recommendation, 'note': note, 'analyst': actor['username'],
                                                  'role': actor['role'], 'computed_decision': r['decision'], 'report_digest': r['report_digest']})
    with connect() as c:
        c.execute('INSERT INTO signoffs (run_id, analyst_id, recommendation, note, report_digest, audit_sequence) VALUES (%s,%s,%s,%s,%s,%s)',
                  (run_id, actor['id'], recommendation, note, r['report_digest'], event['sequence']))
    return review(actor, run_id)


def review(actor, run_id):
    require(actor, 'analyst')
    r = _report(run_id)
    with connect() as c:
        rows = c.execute('SELECT d.*, a.username, a.display_name FROM dispositions d JOIN analysts a ON a.id=d.analyst_id WHERE run_id=%s ORDER BY d.created', (run_id,)).fetchall()
        signs = c.execute('SELECT s.*, a.username, a.display_name, a.role FROM signoffs s JOIN analysts a ON a.id=s.analyst_id WHERE run_id=%s ORDER BY s.created', (run_id,)).fetchall()
    by_finding = {}
    for d in rows:
        by_finding.setdefault(d['finding_id'], []).append({'decision': d['decision'], 'note': d['note'], 'username': d['username'], 'name': d['display_name'],
                                                           'created': d['created'].isoformat(), 'audit_sequence': d['audit_sequence']})
    critical = [f['id'] for f in r['findings'] if f['severity'] == 'critical']
    signoffs = [{'username': s['username'], 'name': s['display_name'], 'role': s['role'], 'recommendation': s['recommendation'], 'note': s['note'],
                 'created': s['created'].isoformat(), 'audit_sequence': s['audit_sequence']} for s in signs]
    status, agreed = 'Open', None
    for rec in RECOMMENDATIONS:
        who = [s for s in signoffs if s['recommendation'] == rec]
        if len({s['username'] for s in who}) >= 2 and any(s['role'] in ('reviewer', 'admin') for s in who):
            status, agreed = 'Signed off', rec
    if status == 'Open' and signoffs:
        status = 'Awaiting second sign-off' if len({s['recommendation'] for s in signoffs}) == 1 else 'Disagreement'
    return {'run': run_id, 'computed_decision': r['decision'], 'dispositions': by_finding, 'signoffs': signoffs, 'status': status, 'agreed': agreed,
            'undisposed_critical': [f for f in critical if f not in by_finding], 'disposed': len(by_finding), 'findings': len(r['findings']),
            'rule': 'Two different people must record the same recommendation, at least one a reviewer or admin, after every critical finding has a disposition.'}


def verify():
    """Cross-check every database row against its signed audit-log event."""
    events = {e['sequence']: e for e in core.read_json(core.STATE / 'audit.json', [])}
    problems, checked = [], 0
    with connect() as c:
        for d in c.execute('SELECT d.*, a.username FROM dispositions d JOIN analysts a ON a.id=d.analyst_id').fetchall():
            e, checked = events.get(d['audit_sequence']), checked + 1
            b = (e or {}).get('body', {})
            if not e or e['kind'] != 'finding_disposition' or (b.get('run'), b.get('finding'), b.get('decision'), b.get('note'), b.get('analyst')) != (d['run_id'], d['finding_id'], d['decision'], d['note'], d['username']):
                problems.append(f'disposition {d["id"]} does not match audit event {d["audit_sequence"]}')
        for s in c.execute('SELECT s.*, a.username FROM signoffs s JOIN analysts a ON a.id=s.analyst_id').fetchall():
            e, checked = events.get(s['audit_sequence']), checked + 1
            b = (e or {}).get('body', {})
            if not e or e['kind'] != 'assessment_signoff' or (b.get('run'), b.get('recommendation'), b.get('note'), b.get('analyst')) != (s['run_id'], s['recommendation'], s['note'], s['username']):
                problems.append(f'sign-off {s["id"]} does not match audit event {s["audit_sequence"]}')
    return {'verified': not problems, 'rows_checked': checked, 'problems': problems}
