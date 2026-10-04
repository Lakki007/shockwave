"""Independent calibration set (§25).

Calibration needs labelled evidence scores from assets that never appear in an assessed
submission. Every bundled submission reuses the same 1,000 baseline pictures, so this module
builds its packages from the approved *reference* pictures instead (disjoint by SHA-256 from
every submission), split three ways by content digest:

  calib-fit         -> forged twice (different seeds)   -> isotonic fit samples
  calib-validation  -> forged once                      -> held-out validation samples
  shared reference  -> the approved references both calibration bases are assessed against

Fit and validation bases share no pictures, so validation is genuinely held out. Each package
is a real Attack Lab forge (pixels stamped, labels rewritten, copies and renders inserted) with
a sealed answer key; every submitted picture is labelled 1 if the key says it was planted and 0
otherwise, and scored with the assessor's own evidence-group risk score. The result is written
to data/calibration/independent.json and its digest committed to the signed audit log.
"""
import csv, hashlib, json, shutil
from pathlib import Path
import core, forge

SOURCE = 'clean'                       # fixture whose approved references are partitioned
OUT = core.DATA / 'calibration' / 'independent.json'
BASES = {'fit': 'calib-fit', 'validation': 'calib-validation'}
PLAN = [('fit', 101), ('fit', 102), ('validation', 103)]
SPEC = {'label_flip': {'enabled': True, 'source': 'land', 'target': 'civ_hel', 'count': 12, 'contributor': 'unit_d'},
        'trigger': {'enabled': True, 'source': 'jet', 'target': 'stealth', 'count': 10, 'size': 32, 'contributor': 'unit_c'},
        'flood': {'enabled': True, 'contributor': 'unit_a', 'count': 8, 'mode': 'near'},
        'ood': {'enabled': True, 'count': 6, 'contributor': 'unit_b', 'label': 'land'},
        'model': {'mode': 'approved', 'export_onnx': False}, 'pipeline': {'mode': 'authorised'}}


def _bucket(sha):
    """0-1: fit base, 2-3: validation base, 4: shared reference (by content digest, so stable)."""
    return int(sha[:8], 16) % 5


def build_bases():
    src = core.DATA / 'fixtures' / SOURCE / 'reference' / 'coco'
    contributors = {}
    with (src / 'contributors.csv').open() as f:
        for r in csv.DictReader(f):
            contributors[r['path_prefix']] = r['contributor']
    parts = {name: {'submission': [], 'reference': []} for name in BASES.values()}
    for ann in sorted(src.rglob('_annotations.coco.json')):
        d = json.loads(ann.read_text())
        for im in d['images']:
            sha = hashlib.sha256((ann.parent / im['file_name']).read_bytes()).hexdigest()
            b = _bucket(sha)
            row = (ann.parent.name, im, [a for a in d['annotations'] if a['image_id'] == im['id']], d['categories'])
            if b == 4:
                for name in BASES.values():
                    parts[name]['reference'].append(row)
            else:
                parts[BASES['fit' if b < 2 else 'validation']]['submission'].append(row)
    for name, sides in parts.items():
        root = core.DATA / 'fixtures' / name
        shutil.rmtree(root, ignore_errors=True)
        for side, rows in sides.items():
            out = root / side / 'coco'
            by_split = {}
            for split, im, anns, cats in rows:
                by_split.setdefault(split, ([], [], cats))
                by_split[split][0].append(im)
                by_split[split][1].extend(anns)
            for split, (images, anns, cats) in by_split.items():
                (out / split).mkdir(parents=True, exist_ok=True)
                for im in images:
                    shutil.copy2(src / split / im['file_name'], out / split / im['file_name'])
                (out / split / '_annotations.coco.json').write_text(json.dumps({'images': images, 'annotations': anns, 'categories': cats}))
            with (out / 'contributors.csv').open('w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['path_prefix', 'contributor'])
                for split, im, _, _ in rows:
                    rel = f'{split}/{im["file_name"]}'
                    w.writerow([rel, contributors.get(rel, 'unit_a')])
        (root / 'manifest.json').write_text(json.dumps({'name': f'Calibration base · {name.split("-")[1]}', 'kind': 'calibration'}, indent=2))
    return {name: {k: len(v) for k, v in sides.items()} for name, sides in parts.items()}


def planted(key):
    stems = set()
    for fam in key['families'].values():
        rows = fam if isinstance(fam, list) else fam.get('stems', [])
        stems |= {r['stem'] if isinstance(r, dict) else r for r in rows}
    return stems


def build(log=print):
    sizes = build_bases()
    log(json.dumps({'bases': sizes}))
    samples, packages = [], []
    for split, seed in PLAN:
        job = forge.ForgeJob({**SPEC, 'seed': seed}, base=BASES[split], prefix='cal-', kind='calibration')
        job.run()
        if job.error:
            raise RuntimeError(f'Calibration forge failed: {job.error}')
        a = core.Assessment(job.id)
        a.run()
        if a.error:
            raise RuntimeError(f'Calibration assessment failed: {a.error}')
        r, key = a.result, core.read_json(forge.KEYS / f'{job.id}.json')
        scores = {s['asset']: s['score'] for s in r['risk']['samples']}
        positives = planted(key)
        rows = [{'asset_sha256': x['sha256'], 'score': float(scores.get(x['id'], 0.0)), 'label': int(Path(x['id']).stem in positives),
                 'split': split, 'package': job.id, 'run': r['id']} for x in r['assets']]
        samples += rows
        packages.append({'fixture': job.id, 'run': r['id'], 'split': split, 'seed': seed, 'report_digest': r['report_digest'],
                         'answer_key_sha384': key['commitment'], 'samples': len(rows), 'planted': sum(x['label'] for x in rows)})
        log(json.dumps(packages[-1]))
    body = {'policy_version': core.POLICY['version'], 'context': core.POLICY['context'], 'created': core.now(),
            'method': 'Attack Lab packages forged from approved reference pictures held out of every submission; label = planted per the sealed answer key; score = assessor evidence-group risk score.',
            'bases': sizes, 'packages': packages, 'samples': samples,
            'limitation': 'Calibrates against the attack families the Attack Lab can plant. Probabilities do not transfer to unseen attack types or operating contexts.'}
    core.atomic(OUT, body)
    digest = core.digest(OUT.read_bytes())
    core.log_event('calibration_set_built', {'sha256': digest, 'samples': len(samples), 'packages': [p['fixture'] for p in packages]})
    return {'path': str(OUT), 'sha256': digest, 'samples': len(samples), 'fit': sum(s['split'] == 'fit' for s in samples),
            'validation': sum(s['split'] == 'validation' for s in samples), 'positives': sum(s['label'] for s in samples)}
