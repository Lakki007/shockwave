"""Content-addressed DINOv2 object embeddings.

Each vector is keyed by the encoder weight digest, the exact image bytes digest
and the annotation box, so a changed image or box only re-encodes that crop.
Changing the encoder weights changes every key (Assurance Delta: an encoder
upgrade invalidates dependent representation evidence).
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path

import numpy as np
from PIL import Image

import core

ENCODER_DIR = core.DATA / 'encoders/dinov2-small'
BATCH = 16
_LOCK = threading.Lock()
_ENCODER = None
_WEIGHTS_DIGEST = None


def available() -> bool:
    return (ENCODER_DIR / 'model.safetensors').exists()


def weights_digest() -> str:
    global _WEIGHTS_DIGEST
    if _WEIGHTS_DIGEST is None:
        _WEIGHTS_DIGEST = core.digest((ENCODER_DIR / 'model.safetensors').read_bytes())
    return _WEIGHTS_DIGEST


def _key(sha: str, box) -> str:
    rounded = [round(float(v), 2) for v in box] if box else None
    return hashlib.sha256(core.canonical({'w': weights_digest(), 'sha': sha, 'box': rounded})).hexdigest()


def _db() -> sqlite3.Connection:
    path = core.STATE / 'embeddings' / 'store.sqlite'
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.execute('CREATE TABLE IF NOT EXISTS vectors (key TEXT PRIMARY KEY, vec BLOB NOT NULL)')
    return db


def _load_encoder():
    global _ENCODER
    if _ENCODER is None:
        import torch
        from transformers import AutoImageProcessor, AutoModel
        device = 'mps' if torch.backends.mps.is_available() else 'cpu'
        processor = AutoImageProcessor.from_pretrained(ENCODER_DIR, local_files_only=True, use_fast=False)
        model = AutoModel.from_pretrained(ENCODER_DIR, local_files_only=True).eval().to(device)
        _ENCODER = (processor, model, device)
    return _ENCODER


def _crop(path: str, box):
    with Image.open(path) as im:
        rgb = im.convert('RGB')
        if not box:
            return rgb
        x, y, w, h = box
        crop = rgb.crop((max(0, x), max(0, y), min(rgb.width, x + w), min(rgb.height, y + h)))
        return crop if min(crop.size) > 0 else rgb


def encode(objects: list[dict], progress=None) -> tuple[np.ndarray, int]:
    """Return (matrix, newly_encoded) for objects with 'path', 'sha' and 'box'.

    `progress(done, total)` is called while new crops are encoded.
    """
    keys = [_key(o['sha'], o.get('box')) for o in objects]
    found: dict[str, np.ndarray] = {}
    db = _db()
    try:
        unique = list(dict.fromkeys(keys))
        for start in range(0, len(unique), 900):
            chunk = unique[start:start + 900]
            rows = db.execute(f'SELECT key, vec FROM vectors WHERE key IN ({",".join("?" * len(chunk))})', chunk).fetchall()
            for k, blob in rows:
                found[k] = np.frombuffer(blob, dtype=np.float32)
        missing = [i for i, k in enumerate(keys) if k not in found]
        missing_unique = list(dict.fromkeys(keys[i] for i in missing))
        first = {keys[i]: i for i in reversed(missing)}
        if missing_unique:
            import torch
            with _LOCK:
                processor, model, device = _load_encoder()
                for start in range(0, len(missing_unique), BATCH):
                    batch_keys = missing_unique[start:start + BATCH]
                    images = [_crop(objects[first[k]]['path'], objects[first[k]].get('box')) for k in batch_keys]
                    inputs = {k: v.to(device) for k, v in processor(images=images, return_tensors='pt').items()}
                    with torch.inference_mode():
                        f = model(**inputs).last_hidden_state[:, 0].float()
                        f = f / (f.norm(dim=1, keepdim=True) + 1e-8)
                    vectors = f.cpu().numpy().astype(np.float32)
                    db.executemany('INSERT OR REPLACE INTO vectors VALUES (?, ?)', [(k, v.tobytes()) for k, v in zip(batch_keys, vectors)])
                    db.commit()
                    for k, v in zip(batch_keys, vectors):
                        found[k] = v
                    if progress:
                        progress(min(start + BATCH, len(missing_unique)), len(missing_unique))
    finally:
        db.close()
    return np.vstack([found[k] for k in keys]).astype(np.float32), len(missing_unique)
