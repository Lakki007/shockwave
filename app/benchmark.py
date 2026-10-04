"""Evaluation at scale (§31): many seeded Attack Lab packages, scored against their sealed keys.

Each package gets a seeded, varied attack mix; model and pipeline modes are cycled so every mode,
including clean controls, appears in balanced numbers. Every package is assessed with the default
contract and scored only after its report is sealed. Results are reported as pooled rates with
Wilson 95% intervals, so a reader sees how much the sample size supports each number.

The optional witness study asks the semantic witness about planted and untouched pictures from the
first packages and measures each question type against the answer key (TPR, FPR, AUROC).
"""
import json, math, os, shutil, time
from pathlib import Path
import numpy as np
from PIL import Image
import core, forge

OUT_JSON = core.ROOT / 'docs' / 'benchmark.json'
OUT_MD = core.ROOT / 'docs' / 'benchmark.md'
MODEL_MODES = ['backdoor', 'benign_retrain', 'approved', 'unsafe']
PIPELINE_MODES = ['authorised', 'class_map', 'bgr', 'threshold']
TAMPERS = forge.CATALOGUE['records']['fields']['tamper']['options']


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {'rate': p, 'low': max(0.0, c - h), 'high': min(1.0, c + h), 'k': k, 'n': n}


def spec_for(i, seed):
    rng = np.random.default_rng(seed)
    pick = lambda xs: xs[int(rng.integers(len(xs)))]
    two = lambda: [str(x) for x in rng.choice(forge.CLASSES, 2, replace=False)]
    s, t = two()
    ts, tt = two()
    spec = {'seed': seed,
            'label_flip': {'enabled': bool(rng.random() < .85), 'source': s, 'target': t, 'count': int(rng.integers(10, 41)), 'contributor': pick(forge.CONTRIBUTORS)},
            'trigger': {'enabled': bool(rng.random() < .75), 'source': ts, 'target': tt, 'count': int(rng.integers(10, 41)), 'size': int(pick([24, 28, 32])), 'contributor': pick(forge.CONTRIBUTORS)},
            'flood': {'enabled': bool(rng.random() < .6), 'contributor': pick(forge.CONTRIBUTORS), 'count': int(rng.integers(5, 31)), 'mode': pick(['near', 'exact'])},
            'leakage': {'enabled': bool(rng.random() < .5), 'count': int(rng.integers(2, 11))},
            'ood': {'enabled': bool(rng.random() < .6), 'count': int(rng.integers(3, 16)), 'contributor': pick(forge.CONTRIBUTORS), 'label': pick(forge.CLASSES)},
            'model': {'mode': MODEL_MODES[i % 4], 'export_onnx': bool(rng.random() < .5)},
            'pipeline': {'mode': PIPELINE_MODES[(i // 4) % 4], 'source': s, 'target': t},
            'records': {'enabled': bool(rng.random() < .7), 'count': int(rng.integers(12, 31)),
                        'tamper': [str(x) for x in rng.choice(TAMPERS, int(rng.integers(2, 6)), replace=False)]}}
    return forge.validate(spec)


def _cleanup(ident):
    shutil.rmtree(core.safe_path(core.DATA / 'fixtures', ident), ignore_errors=True)
    with forge.REGISTRY_LOCK:
        reg = core.read_json(core.DATA / 'trust-registry.json', {})
        reg.pop(ident, None)
        core.atomic(core.DATA / 'trust-registry.json', reg)


# --------------------------------------------------------------------------- witness study

def witness_samples(fixture, key, rng):
    items, _, _ = core.inventory(fixture)
    by_stem = {Path(x['id']).stem: x for x in items if x['annotations']}
    fam = key['families']
    planted = set()
    for f in fam.values():
        rows = f if isinstance(f, list) else f.get('stems', [])
        planted |= {r['stem'] if isinstance(r, dict) else r for r in rows}
    out = []
    take = lambda stems, k: [by_stem[s] for s in list(rng.permutation(sorted(s for s in stems if s in by_stem)))[:k]]
    for x in take((fam.get('trigger') or {}).get('stems', []), 4):
        out.append((x, 'marking', True))
    for x in take((fam.get('ood') or {}).get('stems', []), 3):
        out.append((x, 'photograph', True))
    for x in take([r['stem'] for r in fam.get('label_flips', [])], 4):
        out.append((x, 'label', True))
    for x in take([s for s in by_stem if s not in planted], 6):
        out += [(x, 'marking', False), (x, 'photograph', False), (x, 'label', False)]
    return out


def auroc(pos, neg):
    if not pos or not neg:
        return None
    wins = sum((p > n) + .5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def witness_study(rows):
    """rows: (kind, is_concern, p_concern). A 'concern' is a planted picture: marking=Yes, photograph/label=No."""
    out = {}
    for kind in ('marking', 'photograph', 'label'):
        pos = [p for k, c, p in rows if k == kind and c]
        neg = [p for k, c, p in rows if k == kind and not c]
        out[kind] = {'planted': len(pos), 'untouched': len(neg), 'tpr': wilson(sum(p >= .5 for p in pos), len(pos)),
                     'fpr': wilson(sum(p >= .5 for p in neg), len(neg)), 'auroc': auroc(pos, neg)}
    return out


# --------------------------------------------------------------------------- run

def run(packages=24, witness_packages=8, first_seed=5000, log=print):
    os.environ['SHOCKWAVE_WITNESS'] = '0'  # the witness is studied separately; keep assessments comparable and fast
    results, wrows = [], []
    for i in range(packages):
        seed = first_seed + i
        spec = spec_for(i, seed)
        t0 = time.time()
        job = forge.ForgeJob(spec, prefix='bench-', kind='benchmark')
        job.run()
        if job.error:
            log(json.dumps({'package': i, 'seed': seed, 'error': job.error}))
            continue
        a = core.Assessment(job.id)
        a.run()
        if a.error:
            log(json.dumps({'package': i, 'seed': seed, 'fixture': job.id, 'error': a.error}))
            _cleanup(job.id)
            continue
        sc = forge.score(a.result)
        key = core.read_json(forge.KEYS / f'{job.id}.json')
        if i < witness_packages:
            import extensions
            pin, reason = extensions.witness_pin()
            if pin:
                rng = np.random.default_rng(seed)
                for item, kind, concern in witness_samples(job.id, key, rng):
                    ann = item['annotations'][0]
                    with Image.open(item['path']) as im:
                        _, p_yes = extensions.ask_witness(im.convert('RGB'), kind, ann['label'], ann['bbox'])
                    wrows.append((kind, concern, p_yes if kind == 'marking' else 1 - p_yes))
        results.append({'package': i, 'seed': seed, 'fixture': job.id, 'run': a.result['id'], 'decision': a.result['decision'], 'seconds': round(time.time() - t0, 1),
                        'spec': spec, 'score': sc, 'answer_key_sha384': key['commitment'], 'report_digest': a.result['report_digest']})
        log(json.dumps({'package': i, 'seed': seed, 'decision': a.result['decision'], 'seconds': results[-1]['seconds'],
                        'caught': sum(x['detected'] for x in sc['attacks']), 'planted': sum(x['planted'] for x in sc['attacks'])}))
        _cleanup(job.id)
    summary = aggregate(results, witness_study(wrows) if wrows else None)
    OUT_JSON.write_text(json.dumps({'summary': summary, 'packages': results}, indent=1, default=str))
    OUT_MD.write_text(markdown(summary))
    core.log_event('benchmark_completed', {'packages': len(results), 'sha256': core.digest(OUT_JSON.read_bytes())})
    return summary


def aggregate(results, witness):
    fam, rec = {}, {}
    for r in results:
        for x in r['score']['attacks']:
            f = fam.setdefault(x['attack'], [0, 0, []])
            f[0] += x['detected']; f[1] += x['planted']; f[2].append(x['recall'])
        for x in r['score']['records']:
            g = rec.setdefault(x['kind'], [0, 0])
            g[0] += bool(x['detected']); g[1] += 1
    model, pipe, decisions = {}, {}, {}
    for r in results:
        m = r['score']['model']; mode = m['mode']
        alarm = m['detected'] if m['detected'] is not None else m['benign_control_flagged']
        model.setdefault(mode, [0, 0]); model[mode][0] += bool(alarm); model[mode][1] += 1
        p = r['score']['pipeline']; pm = p['mode']
        hit = p['detected'] if p['detected'] is not None else p['false_alarm']
        pipe.setdefault(pm, [0, 0]); pipe[pm][0] += bool(hit); pipe[pm][1] += 1
        decisions.setdefault(r['decision'], 0); decisions[r['decision']] += 1
    untouched = sum(r['score']['untouched_images'] for r in results)
    flagged = sum(r['score']['untouched_images_flagged'] for r in results)
    return {'packages': len(results), 'policy_version': core.POLICY['version'], 'created': core.now(),
            'families': {k: {**wilson(v[0], v[1]), 'per_package_median': float(np.median(v[2]))} for k, v in sorted(fam.items()) if v[1]},
            'records': {k: wilson(*v) for k, v in sorted(rec.items())},
            'model': {k: {**wilson(*v), 'meaning': 'detection rate' if k in ('backdoor', 'unsafe') else 'false-alarm rate (clean control)'} for k, v in sorted(model.items())},
            'pipeline': {k: {**wilson(*v), 'meaning': 'false-alarm rate (clean control)' if k == 'authorised' else 'detection rate'} for k, v in sorted(pipe.items())},
            'untouched_images': wilson(flagged, untouched), 'decisions': decisions,
            'mean_seconds': round(float(np.mean([r['seconds'] for r in results])), 1) if results else None,
            'witness': witness,
            'note': 'Untouched images are pictures the forge did not modify; flags on them are natural data issues in the real-world baseline or false alarms, counted not hidden.'}


def markdown(s):
    pct = lambda w: '—' if not w else f"{w['rate']:.1%} ({w['low']:.1%}–{w['high']:.1%}), {w['k']}/{w['n']}"
    lines = [f"# Benchmark: {s['packages']} seeded Attack Lab packages", '',
             f"Policy `{s['policy_version']}` · generated {s['created'][:19]}Z · mean {s['mean_seconds']} s per package (forge + assessment).",
             'Rates are pooled across packages with Wilson 95% intervals. Each package was scored against its sealed answer key only after its report was sealed.', '',
             '## Data attacks (planted samples caught)', '', '| Attack | Recall (95% CI), caught/planted | Per-package median |', '|---|---|---|']
    lines += [f"| {k.replace('_', ' ')} | {pct(v)} | {v['per_package_median']:.0%} |" for k, v in s['families'].items()]
    lines += ['', '## Signed records (tampered records caught)', '', '| Tampering | Detection (95% CI) |', '|---|---|']
    lines += [f"| {k} | {pct(v)} |" for k, v in s['records'].items()]
    lines += ['', '## Submitted model', '', '| Mode | Rate (95% CI) | Meaning |', '|---|---|---|']
    lines += [f"| {k.replace('_', ' ')} | {pct(v)} | {v['meaning']} |" for k, v in s['model'].items()]
    lines += ['', '## Processing pipeline', '', '| Mode | Rate (95% CI) | Meaning |', '|---|---|---|']
    lines += [f"| {k.replace('_', ' ')} | {pct(v)} | {v['meaning']} |" for k, v in s['pipeline'].items()]
    lines += ['', '## Untouched images flagged', '', pct(s['untouched_images']), '', s['note'], '',
              '## Decisions', '', ', '.join(f'{k}: {v}' for k, v in sorted(s['decisions'].items()))]
    if s.get('witness'):
        lines += ['', '## Semantic witness (SmolVLM-500M) against the answer key', '',
                  'Positive = planted picture (trigger-stamped for *marking*, synthetic render for *photograph*, flipped label for *label*). Threshold 0.5 on the forced-choice token score.', '',
                  '| Question | Planted / untouched | TPR (95% CI) | FPR (95% CI) | AUROC |', '|---|---|---|---|---|']
        auc = lambda v: '—' if v['auroc'] is None else f"{v['auroc']:.2f}"
        lines += [f"| {k} | {v['planted']} / {v['untouched']} | {pct(v['tpr'])} | {pct(v['fpr'])} | {auc(v)} |" for k, v in s['witness'].items()]
        lines += ['', 'AUROC 0.5 is chance. The witness stays advisory: its findings never change a claim on their own.']
    return '\n'.join(lines) + '\n'
