"""Hardware-backed assessor key custody (§17).

On a Mac with a Secure Enclave the assessor holds a second, non-exportable signing key inside the
enclave and co-signs every sealed report and every audit checkpoint with it. The Ed25519 software
signature is kept for compatibility, so a report carries:

  report_signature     Ed25519, key file on disk (data/state/assessor.key)
  hardware_signature   ECDSA P-256 / SHA-256, key inside the Secure Enclave (device-bound)

Verification of the hardware signature needs only the public key; it works on any machine.
Where no Secure Enclave is available the co-signature is omitted and reports say so: hardware
custody is never claimed without one.
"""
import base64, hashlib, subprocess, threading
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import core

SOURCE = core.ROOT / 'native' / 'se_signer.swift'
HELPER = core.ROOT / '.runtime' / 'bin' / 'shockwave-se'
BLOB = core.STATE / 'hardware' / 'assessor-se.key'
ALGORITHM = 'ECDSA-P256-SHA256'
CUSTODY = 'Apple Secure Enclave (generated in-enclave, non-exportable, device-bound)'
_LOCK = threading.RLock()  # re-entrant: initialising the key logs an audit event, which co-signs
_STATE = {}


def _helper():
    if not HELPER.exists() or HELPER.stat().st_mtime < SOURCE.stat().st_mtime:
        HELPER.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['/usr/bin/swiftc', '-O', str(SOURCE), '-o', str(HELPER)], check=True, capture_output=True, timeout=300)
    return str(HELPER)


def _run(*args, data=None):
    r = subprocess.run([_helper(), *args], input=data, capture_output=True, timeout=30)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace').strip() or 'Secure Enclave helper failed')
    return r.stdout.decode().strip()


def status():
    """Cached: {'available': bool, 'public_key': b64 DER, 'key_id': ...} or a reason."""
    import os
    if os.environ.get('SHOCKWAVE_HARDWARE_KEYS') == '0':
        return {'available': False, 'reason': 'Disabled by operator (SHOCKWAVE_HARDWARE_KEYS=0)'}
    with _LOCK:
        if 'available' in _STATE:
            return dict(_STATE)
        try:
            if not SOURCE.exists() or not Path('/usr/bin/swiftc').exists():
                raise RuntimeError('Secure Enclave helper requires macOS with Swift command-line tools')
            if _run('available') != 'yes':
                raise RuntimeError('This device has no Secure Enclave')
            BLOB.parent.mkdir(parents=True, exist_ok=True)
            created = not BLOB.exists()
            public = _run('create', str(BLOB)) if created else _run('public', str(BLOB))
            BLOB.chmod(0o600)
            _STATE.update(available=True, public_key=public, key_id='se_' + hashlib.sha256(base64.b64decode(public)).hexdigest()[:16],
                          algorithm=ALGORITHM, custody=CUSTODY)
            if created:  # the enclave key's public half is committed to the log once, when it is made
                core.log_event('hardware_key_created', {'key_id': _STATE['key_id'], 'public_key': public, 'algorithm': ALGORITHM, 'custody': CUSTODY})
        except Exception as e:
            _STATE.clear()
            _STATE.update(available=False, reason=str(e)[:300])
        return dict(_STATE)


def cosign(message: bytes):
    s = status()
    if not s['available']:
        return None
    return {'algorithm': ALGORITHM, 'custody': CUSTODY, 'key_id': s['key_id'], 'public_key': s['public_key'],
            'signature': _run('sign', str(BLOB), data=message)}


def verify(message: bytes, cosignature, trusted_public_key=None):
    """True if the co-signature verifies. Pass trusted_public_key to pin the key instead of trusting the embedded one."""
    public = trusted_public_key or cosignature['public_key']
    if cosignature.get('algorithm') != ALGORITHM:
        return False
    try:
        key = serialization.load_der_public_key(base64.b64decode(public))
        key.verify(base64.b64decode(cosignature['signature']), message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
