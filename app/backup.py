"""Backup and restore of everything the workspace cannot regenerate.

A backup directory holds:
  state.tar.gz      data/state (reports, audit log, keys, answer keys, queue) minus rebuildable caches
  registry.json     data/trust-registry.json
  analysts.dump     pg_dump (custom format) of the analyst database, when multi-analyst mode is configured
  manifest.json     SHA-256 of each file, created time, audit-log size and head hash

The backup contains private signing material: it is written owner-only (0700 / 0600). Restore checks
every digest first, moves the current state aside instead of deleting it, and verifies the restored
audit log before reporting success.
"""
import hashlib, json, os, shutil, subprocess, tarfile, time
from pathlib import Path
import core

CACHES = {'embeddings', 'maps', 'forge-cache'}
PG = Path('/opt/homebrew/opt/postgresql@17/bin')


def _sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _tool(name):
    for p in (PG / name, Path(shutil.which(name) or '')):
        if p.is_file():
            return str(p)
    raise FileNotFoundError(f'{name} not found; install PostgreSQL client tools')


def backup(dest, database_url=None):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=False)
    os.chmod(dest, 0o700)
    with core._AuditFileLock(), tarfile.open(dest / 'state.tar.gz', 'w:gz') as t:  # no audit append mid-archive
        for p in sorted(core.STATE.iterdir()):
            if p.name not in CACHES and not p.name.startswith('.'):
                t.add(p, arcname=p.name)
    shutil.copy2(core.DATA / 'trust-registry.json', dest / 'registry.json')
    url = database_url
    if url is None:
        import analysts
        url = analysts.url()
    if url:
        subprocess.run([_tool('pg_dump'), '--format=custom', '--no-owner', f'--dbname={url}', f'--file={dest / "analysts.dump"}'], check=True, capture_output=True, timeout=600)
    events = core.audit_events()
    files = {p.name: _sha(p) for p in sorted(dest.iterdir())}
    for p in dest.iterdir():
        os.chmod(p, 0o600)
    manifest = {'created': core.now(), 'files': files, 'audit_events': len(events), 'audit_head': events[-1]['hash'] if events else None,
                'excluded_caches': sorted(CACHES), 'warning': 'Contains private signing keys and answer keys. Store encrypted, offline.'}
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=1))
    os.chmod(dest / 'manifest.json', 0o600)
    core.log_event('backup_created', {'files': files, 'audit_events': len(events)})
    return manifest


def restore(src, state_dir=None, database_url=None):
    src = Path(src)
    manifest = json.loads((src / 'manifest.json').read_text())
    for name, digest in manifest['files'].items():
        if _sha(src / name) != digest:
            raise ValueError(f'{name} does not match the backup manifest; nothing restored')
    state = Path(state_dir or core.STATE)
    if state.exists() and any(state.iterdir()):
        aside = state.with_name(state.name + '.before-restore-' + time.strftime('%Y%m%d-%H%M%S'))
        state.rename(aside)
    else:
        aside = None
    state.mkdir(parents=True, exist_ok=True)
    with tarfile.open(src / 'state.tar.gz') as t:
        t.extractall(state, filter='data')
    if aside:  # keep rebuildable caches so the restored workspace does not re-encode everything
        for c in CACHES:
            if (aside / c).exists() and not (state / c).exists():
                shutil.copytree(aside / c, state / c)
    if state_dir is None:
        shutil.copy2(src / 'registry.json', core.DATA / 'trust-registry.json')
    restored_db = False
    if (src / 'analysts.dump').exists():
        url = database_url
        if url is None:
            import analysts
            url = analysts.url()
        if url:
            subprocess.run([_tool('pg_restore'), '--clean', '--if-exists', '--no-owner', f'--dbname={url}', str(src / 'analysts.dump')], check=True, capture_output=True, timeout=600)
            restored_db = True
    old = core.STATE
    core.STATE = state
    try:
        check = core.verify_audit()
    finally:
        core.STATE = old
    return {'restored_state': str(state), 'previous_state_moved_to': str(aside) if aside else None, 'database_restored': restored_db,
            'audit_verified': check['verified'], 'audit_events': len(check['events']), 'expected_events': manifest['audit_events']}
