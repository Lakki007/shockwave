"""Fetch the model weights that are not committed, and refuse them unless every file matches data/models.lock.json.

Run once on a connected preparation machine (`python3 shockwave.py fetch-models`); assessment itself never downloads.
"""
import hashlib, json, os, shutil, tempfile, urllib.request
from pathlib import Path
import core

LOCK = core.DATA / 'models.lock.json'


def _sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def status():
    lock = json.loads(LOCK.read_text())
    w, y = lock['semantic-witness'], lock['yolox-nano']
    wdir = core.ROOT / w['dir']
    return {'semantic-witness': all((wdir / n).is_file() and _sha(wdir / n) == h for n, h in w['files'].items()),
            'yolox-nano': (core.ROOT / y['path']).is_file() and _sha(core.ROOT / y['path']) == y['sha256']}


def fetch(log=print):
    lock = json.loads(LOCK.read_text())
    have = status()
    w = lock['semantic-witness']
    if not have['semantic-witness']:
        from huggingface_hub import hf_hub_download
        os.environ['HF_HUB_OFFLINE'] = '0'
        with tempfile.TemporaryDirectory() as tmp:
            for name, digest in w['files'].items():
                got = hf_hub_download(w['repo'], name, revision=w['revision'], local_dir=tmp)
                if _sha(got) != digest:
                    raise ValueError(f'{name}: downloaded bytes do not match the lock; refusing')
            dest = core.ROOT / w['dir']
            dest.mkdir(parents=True, exist_ok=True)
            for name in w['files']:
                shutil.copy2(Path(tmp) / name, dest / name)
        (dest / 'APPROVED.json').write_text(json.dumps({'model': w['repo'], 'revision': w['revision'], 'license': w['license'], 'approved_by': 'operator (models.lock.json)',
                                                        'role': w['role'], 'files': w['files']}, indent=1))
        log(f"semantic witness: {len(w['files'])} files verified")
    y = lock['yolox-nano']
    if not have['yolox-nano']:
        dest = core.ROOT / y['path']
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, dir=dest.parent) as tmp:
            with urllib.request.urlopen(y['url'], timeout=120) as r:
                shutil.copyfileobj(r, tmp)
        if _sha(tmp.name) != y['sha256']:
            os.unlink(tmp.name)
            raise ValueError('yolox_nano.onnx does not match the lock; refusing')
        os.replace(tmp.name, dest)
        log('YOLOX-nano verified')
    return status()
