"""Tests for the forensic methods, the Contrarian Loop scheduler and the Attack Lab harness."""
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.runtime'), str(ROOT / 'app')]
import core, forensics, loop, forge, server  # noqa: E402


class ForensicsTests(unittest.TestCase):
    def test_confident_learning_flags_off_diagonal(self):
        objects = [{'label': 'a', 'source': 's', 'image': f'i{i}', 'sha': str(i)} for i in range(10)] + \
                  [{'label': 'b', 'source': 's', 'image': f'j{i}', 'sha': f'j{i}'} for i in range(10)]
        objects[0]['label'] = 'b'  # declared b, but its neighbours are all a
        votes = [[(0.1, j) for j in range(1, 10)] if i < 10 else [(0.1, j) for j in range(11, 20) if j != i] for i in range(20)]
        cl = forensics.confident_learning(objects, votes, ['a', 'b'], 0.5)
        self.assertEqual([x['index'] for x in cl['issues']], [0])
        self.assertEqual(cl['issues'][0]['alternative'], 'a')

    def test_robust_subpopulation_flags_planted_cluster_not_clean(self):
        # ~7% contamination, the regime validated on the real development set.
        rng = np.random.default_rng(0)
        def unit(x):
            return x / np.linalg.norm(x, axis=1, keepdims=True)
        base = rng.normal(size=(1, 64))
        clean = unit(base + rng.normal(scale=.3, size=(200, 64)))
        planted = unit(base + rng.normal(scale=.3, size=(15, 64)) + 2.5 * np.eye(64)[0])
        ref = unit(base + rng.normal(scale=.3, size=(120, 64)))
        sub = np.vstack([clean, planted]).astype(np.float32)
        objects = [{'label': 'x'} for _ in range(len(sub))]
        scores, abstained = forensics.robust_subpopulations(sub, objects, ref.astype(np.float32), [{'label': 'x'}] * len(ref))
        flagged = {i for i, s in scores.items() if s['robust_distance'] > s['threshold']}
        self.assertFalse(abstained)
        self.assertGreaterEqual(len(flagged & set(range(200, 215))), 12)
        self.assertLessEqual(len(flagged & set(range(200))), 2)

    def test_robust_subpopulation_abstains_without_references(self):
        sub = np.random.default_rng(1).normal(size=(40, 16)).astype(np.float32)
        scores, abstained = forensics.robust_subpopulations(sub, [{'label': 'x'}] * 40, sub[:5], [{'label': 'x'}] * 5)
        self.assertEqual(scores, {})
        self.assertEqual(abstained[0]['class'], 'x')

    def test_recurring_patch_found_and_star_clustering_does_not_chain(self):
        from PIL import Image
        rng = np.random.default_rng(3)
        with tempfile.TemporaryDirectory() as tmp:
            items = []
            for n in range(14):
                arr = (rng.random((256, 256, 3)) * 40 + 100).astype(np.uint8)
                if n < 8:
                    cell = (np.indices((24, 24)) // 6).sum(0) % 2 * 255
                    arr[100:124, 60:84] = cell[:, :, None]
                p = Path(tmp) / f'{n}.png'
                Image.fromarray(arr).save(p)
                items.append({'id': f'train/{n}.png', 'path': str(p), 'width': 256, 'height': 256, 'contributor': 'u1' if n < 8 else 'u2',
                              'annotations': [{'label': 'jet', 'bbox': [40, 80, 80, 80]}]})
            rows = forensics.mine_patches(items, per_image=2)
            clusters = forensics.recurring_patches(items, rows, list(range(len(items))), .9, 6)
            self.assertTrue(clusters)
            top = clusters[0]
            self.assertGreaterEqual(len(set(top['images']) & {f'train/{n}.png' for n in range(8)}), 6)
            self.assertFalse(set(top['images']) - {f'train/{n}.png' for n in range(8)})
            self.assertLess(top['position_spread'], .05)
            # Near-duplicate copies of one picture cannot form a recurring-pattern cluster on their own.
            same_group = forensics.recurring_patches(items, rows, [0] * len(items), .9, 6)
            self.assertEqual(same_group, [])


class LoopTests(unittest.TestCase):
    def fake(self, budget=6, mode='exhaustive'):
        a = core.Assessment.__new__(core.Assessment)
        a.policy = {**core.POLICY, 'challenge_budget': budget, 'loop_mode': mode}
        a.findings, a.checks, a.timeline, a.feed, a.items, a.model = [], [], [], [], [], {}
        a.ctx = None
        a.ref_matrix = None
        a.stage, a.progress = 'x', 0
        return a

    def test_priority_budget_and_spawned_follow_up(self):
        calls = []

        class Cheap(loop.Challenge):
            id, name, claim, cost, requires = 'cheap', 'Cheap', 'labels', 1, set()
            def value(self, a, h): return .2
            def run(self, a, h, seed):
                calls.append(self.id); return loop.Outcome('supported', 'ok')

        class Strong(loop.Challenge):
            id, name, claim, cost, requires = 'strong', 'Strong', 'labels', 2, set()
            def applies(self, h): return h.claim == 'labels' and not h.params.get('confirm')
            def value(self, a, h): return 1.0
            def run(self, a, h, seed):
                calls.append(self.id)
                return loop.Outcome('challenged', 'hit', {}, [loop.Hypothesis('labels', 'confirm', self.id, confirm=True)])

        class Confirm(loop.Challenge):
            id, name, claim, cost, requires = 'confirm', 'Confirm', 'labels', 2, set()
            def applies(self, h): return h.params.get('confirm')
            def value(self, a, h): return 1.0
            def run(self, a, h, seed):
                calls.append(self.id); a.finding('x', 'labels', 'a', 'confirmed', 'critical'); return loop.Outcome('challenged', 'confirmed')

        a = self.fake(budget=5)
        with patch.object(loop, 'REGISTRY', [Cheap(), Strong(), Confirm()]), \
             patch.object(loop, 'seed_hypotheses', lambda a: [loop.Hypothesis('labels', 'h', 'contract')]):
            loop.run(a)
        # Highest priority first, its spawned confirmation next, then the cheap test with the budget left.
        self.assertEqual(calls, ['strong', 'confirm', 'cheap'])
        self.assertEqual(a.loop['spent'], 5)
        self.assertEqual(a.loop['stop_reason'], 'Budget exhausted.')
        steps = a.loop['steps']
        self.assertEqual(steps[1]['claim_after'], 'Contradicted')
        self.assertTrue(all('seed' in s and 'priority' in s and 'alternatives' in s for s in steps))

    def test_decisive_mode_stops_on_blocking_contradiction(self):
        class Block(loop.Challenge):
            id, name, claim, cost, requires = 'block', 'Block', 'labels', 1, set()
            def run(self, a, h, seed):
                a.finding('x', 'labels', 'a', 'blocking', 'critical'); return loop.Outcome('challenged', 'blocked')

        class Other(loop.Challenge):
            id, name, claim, cost, requires = 'other', 'Other', 'labels', 1, set()
            def value(self, a, h): return .1
            def run(self, a, h, seed): return loop.Outcome('supported', 'ok')

        a = self.fake(budget=10, mode='decisive')
        with patch.object(loop, 'REGISTRY', [Block(), Other()]), \
             patch.object(loop, 'seed_hypotheses', lambda a: [loop.Hypothesis('labels', 'h1', 'contract'), loop.Hypothesis('labels', 'h2', 'contract')]):
            loop.run(a)
        self.assertEqual(len(a.loop['steps']), 1)
        self.assertIn('critical contradiction', a.loop['stop_reason'])

    def test_unavailable_access_is_reported_not_passed(self):
        a = self.fake(budget=8)
        with patch.object(loop, 'seed_hypotheses', lambda a: []):
            loop.run(a)
        missing = {u['test'] for u in a.loop['unavailable']}
        self.assertIn('Class-pair trigger reconstruction', missing)
        self.assertIn('Trigger transfer (behaviour forensics)', missing)

    def test_zero_budget_abstains(self):
        a = self.fake(budget=0)
        loop.run(a)
        self.assertEqual(a.loop['steps'], [])
        self.assertTrue(any(c['name'] == 'Contrarian loop' and c['status'] == 'Unavailable' for c in a.checks))


class ContractTests(unittest.TestCase):
    def test_policy_validation(self):
        server.validate_policy({'label_method': 'confident_learning', 'loop_mode': 'decisive', 'challenge_budget': 12})
        for bad in ({'label_method': 'vote'}, {'loop_mode': 'fast'}, {'robust_margin': 5}, {'trigger_steps': True},
                    {'mandatory': ['nonexistent']}, {'unknown': 1}, {'context': 'x' * 500}):
            with self.assertRaises(ValueError):
                server.validate_policy(bad)


class AttackLabTests(unittest.TestCase):
    def test_spec_validation(self):
        spec = forge.validate(forge.PRESET)
        self.assertEqual(spec['trigger']['size'], 32)
        for bad in ({'trigger': {'enabled': True, 'size': 64}}, {'label_flip': {'enabled': True, 'source': 'jet', 'target': 'jet'}},
                    {'records': {'enabled': True, 'tamper': ['delete_everything']}}, {'model': {'mode': 'weights_from_internet'}},
                    {'flood': {'enabled': True, 'contributor': 'mallory'}}):
            with self.assertRaises(ValueError):
                forge.validate({**forge.PRESET, **bad})

    def test_trigger_stamp_size_and_position(self):
        from PIL import Image
        img = Image.new('RGB', (640, 640), (120, 120, 120))
        out, (sx, sy, side) = forge.stamp(img, [100, 200, 200, 100], 32)
        self.assertEqual(side, 80)
        self.assertEqual((sx + side // 2, sy + side // 2), (200, 250))
        arr = np.asarray(out)
        self.assertEqual(set(np.unique(arr[sy:sy + side, sx:sx + side])), {0, 255})

    def test_answer_key_tamper_detected_and_truth_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(forge, 'KEYS', Path(tmp)):
                key = {'id': 'lab-test', 'families': {'ood': {'stems': ['a']}}, 'records': [], 'model': {'mode': 'approved'}, 'pipeline': {'mode': 'authorised'}}
                key['commitment'] = core.digest(core.canonical(key), 'sha384')
                (Path(tmp) / 'lab-test.json').write_text(json.dumps(key))
                run = {'fixture': 'lab-test', 'findings': [{'asset': 'train/a.jpg', 'type': 'out_of_distribution'}], 'assets': [{'id': 'train/a.jpg'}, {'id': 'train/b.jpg'}]}
                result = forge.score(run)
                self.assertTrue(result['answer_key_intact'])
                self.assertEqual(result['attacks'][0]['detected'], 1)
                key['families']['ood']['stems'].append('b')
                (Path(tmp) / 'lab-test.json').write_text(json.dumps(key))
                self.assertFalse(forge.score(run)['answer_key_intact'])
        import embeddings, extensions, models
        detection = ''.join(inspect.getsource(m) for m in (core, models, extensions, loop, forensics, embeddings))
        self.assertNotIn('answer-keys', detection)
        self.assertNotIn('ground_truth.json', detection)
        self.assertNotIn('import forge', detection)


@unittest.skipUnless(os.environ.get('SHOCKWAVE_SLOW'), 'Set SHOCKWAVE_SLOW=1 to forge and blindly assess a full Attack Lab package (~1 min).')
class AttackLabIntegration(unittest.TestCase):
    def test_forge_then_blind_assessment_detects_attacks(self):
        job = forge.ForgeJob(forge.PRESET); job.run()
        self.assertIsNone(job.error)
        try:
            a = core.Assessment(job.id); a.run()
            self.assertIsNone(a.error)
            result = forge.score(a.result)
            self.assertTrue(result['answer_key_intact'])
            by = {x['attack']: x for x in result['attacks']}
            self.assertGreaterEqual(by['trigger']['recall'], .8)
            self.assertEqual(by['split_leakage']['recall'], 1.0)
            self.assertGreaterEqual(by['ood']['recall'], .8)
            self.assertTrue(all(r['detected'] for r in result['records']))
            self.assertTrue(result['pipeline']['detected'])
            if result['model']['implant']['implanted']:
                self.assertTrue(result['model']['detected'])
            self.assertEqual(a.result['decision'], 'Quarantine')
        finally:
            forge.delete(job.id)


if __name__ == '__main__':
    unittest.main()
