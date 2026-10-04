"""Tests for the YOLO adapters, sandboxed worker, Secure Enclave co-signing, calibration set and analyst rules."""
import base64, hashlib, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.runtime'), str(ROOT / 'app')]
import core, yolo, sandbox, keystore, calibration, analysts  # noqa: E402

YOLOX = ROOT / 'data/models/yolox/yolox_nano.onnx'
TINY = ROOT / 'data/fixtures/hostile/suite/models/clean.onnx'


class YoloTests(unittest.TestCase):
    def test_layouts_from_shapes(self):
        self.assertEqual(yolo.detect_layout([[1, 12, 8400]], 640), 'yolov8')
        self.assertEqual(yolo.detect_layout([[1, 3549, 85]], 416), 'yolox')
        self.assertEqual(yolo.detect_layout([[1, 3 * 3549, 85]], 416), 'yolov5')
        self.assertEqual(yolo.detect_layout([[1, 300, 6]], 640), 'e2e')
        self.assertIsNone(yolo.detect_layout([[1, 8], [1, 4], [1]], 256))
        with self.assertRaises(ValueError):
            yolo.detect_layout([[1, 12, 8400]], 640, 'not-a-layout')

    def test_v8_decode_and_class_aware_nms(self):
        # Two overlapping boxes of class 0 (one must be suppressed) and one overlapping box of class 1 (kept).
        out = np.zeros((4 + 2, 3), np.float32)
        out[:4, 0] = [100, 100, 50, 50]; out[4, 0] = .9
        out[:4, 1] = [102, 101, 50, 50]; out[4, 1] = .8
        out[:4, 2] = [101, 100, 50, 50]; out[5, 2] = .7
        dets = yolo.decode('yolov8', out, 640, conf=.25)
        self.assertEqual([(c, round(s, 2)) for c, s, _ in dets], [(0, .9), (1, .7)])
        self.assertEqual([round(v) for v in dets[0][2]], [75, 75, 125, 125])

    def test_letterbox_conventions(self):
        from PIL import Image
        im = Image.new('RGB', (200, 100), (255, 0, 0))
        x, (r, px, py) = yolo.letterbox(im, 64, 'yolov8')
        self.assertEqual((r, px, py), (.32, 0, 16))
        self.assertAlmostEqual(float(x[0, 0, 32, 32]), 1.0)          # RGB, unit scale, centred
        x, (r, px, py) = yolo.letterbox(im, 64, 'yolox')
        self.assertEqual((px, py), (0, 0))                          # YOLOX pads bottom/right
        self.assertAlmostEqual(float(x[0, 2, 5, 5]), 255.0)         # BGR, 0-255

    @unittest.skipUnless(YOLOX.exists(), 'YOLOX-nano weights not provisioned')
    def test_real_yolox_finds_aircraft(self):
        import onnxruntime as ort
        s = ort.InferenceSession(str(YOLOX), providers=['CPUExecutionProvider'])
        d = yolo.Detector(lambda x: s.run(None, {'images': x}), 'yolox', 416)
        jets = sorted((ROOT / 'data/fixtures/clean/submission/coco/train').glob('jet*'))[:6]
        hits = [d.detect(p) for p in jets]
        self.assertGreaterEqual(sum(any(x['class_id'] == 4 for x in h) for h in hits), 3)  # COCO class 4 = airplane


@unittest.skipUnless(sandbox.available(), 'macOS Seatbelt not available')
class SandboxTests(unittest.TestCase):
    def test_probe_denies_network_write_read_exec(self):
        r = sandbox.probe()
        self.assertTrue(r['enforced'], r)

    def test_sandboxed_output_matches_in_process(self):
        import onnxruntime as ort
        x = np.random.default_rng(0).random((1, 3, 256, 256), dtype=np.float32)
        session = ort.InferenceSession(str(TINY), providers=['CPUExecutionProvider'])
        expected = session.run(None, {session.get_inputs()[0].name: x})
        m = sandbox.SandboxedModel(TINY)
        try:
            got = m(x)
        finally:
            m.close()
        for a, b in zip(expected, got):
            np.testing.assert_allclose(a, b, rtol=1e-5, atol=1e-6)

    def test_garbage_model_is_contained(self):
        with tempfile.NamedTemporaryFile(suffix='.onnx') as f:
            f.write(b'not an onnx graph'); f.flush()
            with self.assertRaises(sandbox.SandboxError):
                sandbox.SandboxedModel(f.name)

    def test_call_timeout_terminates_worker(self):
        import time
        w = sandbox.Worker()
        try:
            w._send({'op': 'load'}, TINY.read_bytes())
            w._read(time.monotonic() + 30)              # consume the load reply
            with self.assertRaises(sandbox.SandboxError):
                w._read(time.monotonic() + 0.2)         # nothing pending: the call times out...
            self.assertIsNotNone(w.p.poll())            # ...and the worker is killed
        finally:
            w.close()


@unittest.skipUnless(keystore.status().get('available'), 'No Secure Enclave on this machine')
class KeystoreTests(unittest.TestCase):
    def test_cosign_verifies_and_detects_tampering(self):
        digest = hashlib.sha384(b'report').digest()
        sig = keystore.cosign(digest)
        self.assertEqual(sig['algorithm'], 'ECDSA-P256-SHA256')
        self.assertTrue(keystore.verify(digest, sig))
        self.assertTrue(keystore.verify(digest, sig, keystore.status()['public_key']))
        self.assertFalse(keystore.verify(hashlib.sha384(b'other').digest(), sig))
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        other = base64.b64encode(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        self.assertFalse(keystore.verify(digest, sig, other))  # pinned key must match

    def test_report_verify_requires_pinned_hardware_signature(self):
        import provenance
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        body = {'decision': 'Review', 'findings': []}
        d = core.digest(core.canonical(body), 'sha384')
        report = {**body, 'report_digest': d, 'report_signature': base64.b64encode(core.key().sign(bytes.fromhex(d))).decode(),
                  'hardware_signature': keystore.cosign(bytes.fromhex(d))}
        pub = base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        hw = keystore.status()['public_key']
        self.assertTrue(provenance.report_verify(report, pub, hw)['verified'])
        stripped = {k: v for k, v in report.items() if k != 'hardware_signature'}
        self.assertFalse(provenance.report_verify(stripped, pub, hw)['verified'])


class CalibrationTests(unittest.TestCase):
    def test_partition_is_disjoint(self):
        buckets = {calibration._bucket(hashlib.sha256(bytes([i])).hexdigest()) for i in range(256)}
        self.assertEqual(buckets, {0, 1, 2, 3, 4})

    @unittest.skipUnless((ROOT / 'data/calibration/independent.json').exists(), 'Calibration set not built')
    def test_set_is_independent_of_every_submission(self):
        d = json.loads((ROOT / 'data/calibration/independent.json').read_text())
        fit = {s['asset_sha256'] for s in d['samples'] if s['split'] == 'fit'}
        val = {s['asset_sha256'] for s in d['samples'] if s['split'] == 'validation'}
        self.assertFalse(fit & val, 'fit and validation share pictures')
        submitted = set()
        for fx in ('clean', 'hostile', 'approved', 'synthetic', 'yolo'):
            for p in (ROOT / 'data/fixtures' / fx / 'submission').rglob('*'):
                if p.suffix.lower() in ('.jpg', '.jpeg', '.png'):
                    submitted.add(hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertFalse((fit | val) & submitted, 'calibration pictures appear in a bundled submission')
        self.assertEqual(d['policy_version'], core.POLICY['version'])
        self.assertGreaterEqual(len(val), 20)
        self.assertEqual({s['label'] for s in d['samples'] if s['split'] == 'fit'}, {0, 1})


class AnalystRuleTests(unittest.TestCase):
    def test_password_hashing(self):
        h = analysts.hash_password('correct horse battery')
        self.assertTrue(analysts.check_password('correct horse battery', h))
        self.assertFalse(analysts.check_password('correct horse batterz', h))
        with self.assertRaises(ValueError):
            analysts.hash_password('short')

    def test_roles(self):
        a = {'role': 'analyst', 'must_change': False}
        analysts.require(a, 'analyst')
        for role in ('reviewer', 'admin'):
            with self.assertRaises(PermissionError):
                analysts.require(a, role)
        with self.assertRaises(PermissionError):
            analysts.require({'role': 'admin', 'must_change': True}, 'analyst')  # temporary password blocks work
        analysts.require({'role': 'admin', 'must_change': True}, 'self')         # ...but not changing it
        with self.assertRaises(PermissionError):
            analysts.require(None, 'analyst')


if __name__ == '__main__':
    unittest.main()
