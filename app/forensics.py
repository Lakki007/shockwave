"""Data-side forensic methods referenced by the submission.

* Confident Learning over duplicate-excluded DINOv2 neighbour votes (§11.3)
* Spectral-signature scores per declared class (§11.6)
* Recurring compact-patch mining across samples (§11.5)
* DINOv2 reference-neighbourhood novelty (§11.7)

Each function returns measurements; the caller turns them into findings so the
evidence schema and policy stay in one place.
"""
from __future__ import annotations

import collections

import numpy as np
from PIL import Image


# --------------------------------------------------------------------------- labels

def neighbour_votes(objects, ds, js, k):
    """Duplicate-excluded neighbour lists: same image bytes and same image never vote."""
    votes = []
    for i, obj in enumerate(objects):
        row = [(float(d), int(j)) for d, j in zip(ds[i], js[i])
               if j != i and objects[j]['sha'] != obj['sha'] and objects[j]['image'] != obj['image']][:k]
        votes.append(row)
    return votes


def confident_learning(objects, votes, classes, min_share):
    """Confident-joint estimate with neighbour vote shares as out-of-sample probabilities.

    Per-class thresholds t_j are the mean self-share of objects declared j
    (Northcutt et al.). An object is a candidate issue when another class j
    reaches max(t_j, min_share) and is the most supported such class.
    """
    index = {c: n for n, c in enumerate(classes)}
    P = np.zeros((len(objects), len(classes)))
    sim = np.zeros(len(objects))
    for i, row in enumerate(votes):
        if not row:
            continue
        for d, j in row:
            P[i, index[objects[j]['label']]] += 1
        P[i] /= len(row)
        sim[i] = float(np.mean([1 - d for d, _ in row]))
    declared = np.array([index[o['label']] for o in objects])
    thresholds = np.array([P[declared == c, c].mean() if (declared == c).sum() >= 3 else 1.0 for c in range(len(classes))])
    joint = np.zeros((len(classes), len(classes)), dtype=int)
    issues = []
    for i in range(len(objects)):
        if not votes[i]:
            continue
        eligible = [c for c in range(len(classes)) if P[i, c] >= max(thresholds[c], min_share)]
        if not eligible:
            continue
        best = max(eligible, key=lambda c: P[i, c])
        joint[declared[i], best] += 1
        if best != declared[i]:
            issues.append({'index': i, 'alternative': classes[best], 'share': float(P[i, best]),
                           'self_share': float(P[i, declared[i]]), 'threshold': float(thresholds[best]), 'similarity': float(sim[i])})
    return {'thresholds': {classes[c]: round(float(t), 4) for c, t in enumerate(thresholds)},
            'joint': joint.tolist(), 'classes': list(classes), 'issues': issues}


def contributor_pairs(objects, issues):
    """Class-pair disagreements grouped by contributor, with denominators (§12)."""
    totals = collections.Counter((o['source'], o['label']) for o in objects)
    pairs = collections.Counter((objects[x['index']]['source'], objects[x['index']]['label'], x['alternative']) for x in issues)
    rows = [{'source': s, 'declared': d, 'alternative': a, 'count': n, 'declared_total': totals[(s, d)],
             'rate': n / max(1, totals[(s, d)])} for (s, d, a), n in pairs.items()]
    return sorted(rows, key=lambda r: (-r['count'], r['source']))


# --------------------------------------------------------------------------- poisoning

def spectral_signatures(matrix, objects, min_class=10):
    """Per-class squared projection on the top singular vector of centred features.

    Returns robust z-scores; Tran et al. motivate the score, it is not a verdict.
    """
    out = {}
    for label in sorted(set(o['label'] for o in objects)):
        ids = [i for i, o in enumerate(objects) if o['label'] == label]
        if len(ids) < min_class:
            continue
        m = matrix[ids] - matrix[ids].mean(0)
        _, _, vt = np.linalg.svd(m, full_matrices=False)
        score = (m @ vt[0]) ** 2
        med = float(np.median(score)); mad = float(np.median(abs(score - med))) + 1e-9
        for i, s in zip(ids, score):
            out[i] = {'score': float(s), 'robust_z': float(.6745 * (s - med) / mad), 'class': label, 'class_size': len(ids)}
    return out


def _self_robust_distance(X, k):
    """Median-normalised MCD Mahalanobis distance after PCA, fitted on X itself."""
    from sklearn.covariance import MinCovDet
    from sklearn.decomposition import PCA
    mu = X.mean(0)
    p = PCA(k, random_state=0).fit_transform(X - mu)
    d = MinCovDet(random_state=0, support_fraction=.75).fit(p).mahalanobis(p)
    return d / np.median(d)


def robust_subpopulations(matrix, objects, ref_matrix, ref_objects, margin=1.1, min_class=25):
    """SPECTRE-inspired robust-covariance screening with a reference-calibrated threshold.

    The robust covariance is fitted on the submitted class itself, so a planted
    sub-population separates from the robust core. The same procedure applied to
    the approved reference class gives an empirical null: the threshold is the
    largest reference self-score times `margin`. Classes without enough approved
    references abstain rather than borrowing a parametric cut-off.
    """
    out, abstained = {}, []
    for label in sorted(set(o['label'] for o in objects)):
        sid = [i for i, o in enumerate(objects) if o['label'] == label]
        rid = [i for i, o in enumerate(ref_objects) if o['label'] == label]
        if len(sid) < min_class or len(rid) < min_class:
            abstained.append({'class': label, 'submitted': len(sid), 'reference': len(rid)})
            continue
        k = int(min(16, len(rid) // 4, len(sid) // 4))
        threshold = float(np.max(_self_robust_distance(ref_matrix[rid], k))) * margin
        d = _self_robust_distance(matrix[sid], k)
        centred = matrix[sid] - matrix[sid].mean(0)
        _, _, vt = np.linalg.svd(centred, full_matrices=False)
        spectral = (centred @ vt[0]) ** 2
        for i, dist, s in zip(sid, d, spectral):
            out[i] = {'robust_distance': float(dist), 'threshold': threshold, 'pca_components': k, 'class': label,
                      'class_size': len(sid), 'spectral_score': float(s)}
    return out, abstained


def _corner_response(gray, window):
    """Shi-Tomasi minimum-eigenvalue response, box-summed over `window` pixels."""
    gy, gx = np.gradient(gray)
    def box(a):
        c = np.cumsum(np.cumsum(np.pad(a, ((1, 0), (1, 0))), 0), 1)
        return c[window:, window:] - c[:-window, window:] - c[window:, :-window] + c[:-window, :-window]
    xx, yy, xy = box(gx * gx), box(gy * gy), box(gx * gy)
    tr = xx + yy; det = xx * yy - xy * xy
    return tr / 2 - np.sqrt(np.maximum(tr * tr / 4 - det, 0))


def mine_patches(items, window=20, per_image=2, size=256):
    """Extract the strongest corner-dense compact windows of every image.

    Checkerboards, stickers and printed patterns have strong gradients in two
    directions; ordinary straight edges do not, which keeps natural edges from
    forming recurring clusters.
    """
    rows = []
    for n, item in enumerate(items):
        with Image.open(item['path']) as im:
            rgb = np.asarray(im.convert('RGB').resize((size, size), Image.Resampling.BILINEAR), dtype=np.float32) / 255
        gray = rgb.mean(2)
        resp = _corner_response(gray, window)
        floor = float(np.percentile(resp, 50)) + 1e-9
        taken = []
        for _ in range(per_image):
            y, x = np.unravel_index(int(np.argmax(resp)), resp.shape)
            peak = float(resp[y, x])
            if peak <= 0:
                break
            patch = gray[y:y + window, x:x + window]
            desc = np.asarray(Image.fromarray((patch * 255).astype(np.uint8)).resize((12, 12), Image.Resampling.BILINEAR), dtype=np.float32).ravel()
            desc -= desc.mean(); norm = float(np.linalg.norm(desc))
            if norm > 1e-6:
                bx = by = None
                if item['annotations']:
                    ax, ay, aw, ah = item['annotations'][0]['bbox']
                    sx, sy = size / item['width'], size / item['height']
                    bx = ((x + window / 2) / sx - ax) / max(1, aw); by = ((y + window / 2) / sy - ay) / max(1, ah)
                taken.append({'image': n, 'x': int(x), 'y': int(y), 'peak_ratio': peak / floor, 'desc': desc / norm,
                              'box_rel': [bx, by], 'rgb': rgb[y:y + window, x:x + window].copy()})
            resp[max(0, y - window):y + window, max(0, x - window):x + window] = 0
        rows.extend(taken)
    return rows


def recurring_patches(items, rows, image_groups, similarity=0.9, min_images=6):
    """Star-cluster near-identical compact patterns that recur across distinct images.

    Clustering is non-transitive (every member must match the seed), so chains of
    loosely similar edges cannot merge into one blob. `image_groups` maps each
    image index to its near-duplicate group; repeated copies of one picture count
    once, because duplication is reported by its own detector.
    """
    if len(rows) < 2:
        return []
    D = np.stack([r['desc'] for r in rows])
    S = D @ D.T
    adjacency = S >= similarity
    np.fill_diagonal(adjacency, False)
    degree = adjacency.sum(1)
    assigned = np.zeros(len(rows), dtype=bool)
    clusters = []
    for seed in np.argsort(-degree):
        if assigned[seed] or degree[seed] < min_images - 1:
            continue
        members = [int(seed)] + [int(j) for j in np.where(adjacency[seed] & ~assigned)[0] if rows[j]['image'] != rows[seed]['image']]
        images = sorted(set(rows[i]['image'] for i in members))
        if len(set(image_groups[n] for n in images)) < min_images:
            continue
        assigned[members] = True
        sub = S[np.ix_(members, members)]
        rel = [rows[i]['box_rel'] for i in members if rows[i]['box_rel'][0] is not None]
        sources = collections.Counter(items[n]['contributor'] for n in images)
        labels = collections.Counter(a['label'] for n in images for a in items[n]['annotations'][:1])
        exemplar = max(members, key=lambda i: sub[members.index(i)].mean())
        clusters.append({
            'images': [items[n]['id'] for n in images], 'members': members,
            'distinct_pictures': len(set(image_groups[n] for n in images)),
            'mean_similarity': float(sub[np.triu_indices(len(members), 1)].mean()) if len(members) > 1 else 1.0,
            'sources': dict(sources), 'declared_labels': dict(labels),
            'box_relative_position': [float(np.median([r[0] for r in rel])), float(np.median([r[1] for r in rel]))] if rel else None,
            'position_spread': float(np.mean(np.std(np.array(rel), 0))) if len(rel) > 1 else None,
            'exemplar_rgb': rows[exemplar]['rgb'], 'window': int(rows[exemplar]['rgb'].shape[0]),
            'exemplar': {'image': items[rows[exemplar]['image']]['id'], 'path': items[rows[exemplar]['image']]['path'], 'x': rows[exemplar]['x'], 'y': rows[exemplar]['y']},
        })
    return sorted(clusters, key=lambda c: -len(c['images']))


# --------------------------------------------------------------------------- novelty

def reference_novelty(sub_matrix, ref_matrix, quantile):
    """Nearest approved-reference cosine distance with a leave-one-out reference envelope."""
    import faiss
    faiss.omp_set_num_threads(1)
    index = faiss.IndexFlatIP(ref_matrix.shape[1]); index.add(np.ascontiguousarray(ref_matrix))
    self_sim, _ = index.search(np.ascontiguousarray(ref_matrix), 2)
    envelope = 1 - self_sim[:, 1]
    threshold = float(np.quantile(envelope, quantile))
    sim, _ = index.search(np.ascontiguousarray(sub_matrix), 1)
    return 1 - sim[:, 0], threshold


def extract_trigger(path, x, y, window, size=256):
    """Grow the mined window to the extent of the strong-gradient region around it."""
    with Image.open(path) as im:
        rgb = np.asarray(im.convert('RGB').resize((size, size), Image.Resampling.BILINEAR), dtype=np.float32) / 255
    gray = rgb.mean(2)
    gy, gx = np.gradient(gray)
    mag = np.hypot(gx, gy)
    x0, y0 = max(0, x - window), max(0, y - window)
    x1, y1 = min(size, x + 2 * window), min(size, y + 2 * window)
    region = mag[y0:y1, x0:x1]
    ys, xs = np.where(region > .35 * region.max())
    if not len(xs):
        return rgb[y:y + window, x:x + window]
    bx0, bx1 = x0 + int(np.percentile(xs, 2)), x0 + int(np.percentile(xs, 98)) + 1
    by0, by1 = y0 + int(np.percentile(ys, 2)), y0 + int(np.percentile(ys, 98)) + 1
    side = int(np.clip(max(bx1 - bx0, by1 - by0), 8, 48))
    cx, cy = (bx0 + bx1) // 2, (by0 + by1) // 2
    sx, sy = int(np.clip(cx - side // 2, 0, size - side)), int(np.clip(cy - side // 2, 0, size - side))
    return rgb[sy:sy + side, sx:sx + side].copy()


def patch_png(rgb):
    """Small data-URI PNG of a patch or mask for the analyst view."""
    import base64, io
    arr = np.clip(np.asarray(rgb) * 255, 0, 255).astype(np.uint8)
    if arr.ndim == 2:
        arr = np.stack([arr] * 3, -1)
    im = Image.fromarray(arr).resize((96, 96), Image.Resampling.NEAREST)
    buf = io.BytesIO(); im.save(buf, 'PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()
