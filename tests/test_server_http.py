"""End-to-end HTTP tests of the multi-analyst server against a throwaway PostgreSQL database.

Skipped unless PostgreSQL is reachable over the local socket (or SHOCKWAVE_TEST_ADMIN_URL is set).
Each run creates its own database and state directory and removes both afterwards.
"""
import json, os, secrets, sys, tempfile, threading, unittest, urllib.error, urllib.request, http.cookiejar
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.runtime'), str(ROOT / 'app')]
import core, analysts  # noqa: E402

ADMIN = os.environ.get('SHOCKWAVE_TEST_ADMIN_URL', 'dbname=postgres host=/tmp')


def _admin():
    import psycopg
    return psycopg.connect(ADMIN, autocommit=True, connect_timeout=3)


def _reachable():
    try:
        with _admin():
            return True
    except Exception:
        return False


@unittest.skipUnless(_reachable(), 'PostgreSQL not reachable for integration tests')
class MultiAnalystHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = 'shockwave_test_' + secrets.token_hex(4)
        with _admin() as c:
            c.execute(f'CREATE DATABASE {cls.db}')
        cls.addClassCleanup(cls._drop)  # runs even if the rest of setup fails
        cls.tmp = tempfile.TemporaryDirectory()
        cls.old_state, cls.old_env, cls.old_hw = core.STATE, os.environ.get('SHOCKWAVE_DATABASE_URL'), os.environ.get('SHOCKWAVE_HARDWARE_KEYS')
        os.environ['SHOCKWAVE_HARDWARE_KEYS'] = '0'  # hermetic for this class only: no Secure Enclave use
        core.STATE = Path(cls.tmp.name)
        (core.STATE / 'runs').mkdir()
        os.environ['SHOCKWAVE_DATABASE_URL'] = f'dbname={cls.db} host=/tmp'
        analysts._state.update(checked=0)
        assert analysts.enabled(), analysts._state  # also applies the schema
        # A sealed-looking report with one critical and one medium finding.
        cls.run_id = 'sw-test000001'
        core.atomic(core.STATE / 'runs' / f'{cls.run_id}.json', {'id': cls.run_id, 'decision': 'Quarantine', 'report_digest': 'ab' * 48, 'fixture': 'synthetic', 'findings': [
            {'id': 'f-1', 'severity': 'critical'}, {'id': 'f-2', 'severity': 'medium'}]})
        import server
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_port}/api/'
        boot = {'username': 'bootstrap', 'role': 'admin', 'must_change': False}
        cls.pw = {}
        for user, role in (('ana', 'analyst'), ('rev', 'reviewer'), ('adm', 'admin')):
            _, temporary = analysts.create(boot, user, user.title(), role)
            cls.pw[user] = temporary

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        core.STATE = cls.old_state
        if cls.old_env is None:
            os.environ.pop('SHOCKWAVE_DATABASE_URL', None)
        else:
            os.environ['SHOCKWAVE_DATABASE_URL'] = cls.old_env
        analysts._state.update(checked=0)
        if cls.old_hw is None:
            os.environ.pop('SHOCKWAVE_HARDWARE_KEYS', None)
        else:
            os.environ['SHOCKWAVE_HARDWARE_KEYS'] = cls.old_hw
        cls.tmp.cleanup()

    @classmethod
    def _drop(cls):
        with _admin() as c:
            c.execute(f'DROP DATABASE IF EXISTS {cls.db} WITH (FORCE)')

    def client(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, op, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with op.open(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def signed_in(self, user):
        op = self.client()
        code, body = self.call(op, 'login', {'username': user, 'password': self.pw[user]})
        self.assertEqual(code, 200, body)
        if body['analyst']['must_change']:
            new = 'Permanent-' + secrets.token_urlsafe(12)
            self.assertEqual(self.call(op, 'bootstrap')[0], 403)  # temporary password blocks work
            self.assertEqual(self.call(op, 'password', {'current': self.pw[user], 'new': new})[0], 200)
            self.pw[user] = new
        return op

    def test_1_unauthenticated_and_bad_login(self):
        op = self.client()
        self.assertEqual(self.call(op, 'session')[1]['mode'], 'multi')
        self.assertEqual(self.call(op, 'bootstrap')[0], 401)
        self.assertEqual(self.call(op, 'login', {'username': 'ana', 'password': 'wrong-password-123'})[0], 403)
        self.assertEqual(self.call(op, 'login', {'username': 'nobody', 'password': 'wrong-password-123'})[0], 403)

    def test_2_roles_dispositions_and_two_person_signoff(self):
        ana, rev, adm = self.signed_in('ana'), self.signed_in('rev'), self.signed_in('adm')
        self.assertEqual(self.call(ana, 'analysts')[0], 403)
        self.assertEqual(self.call(adm, 'analysts')[0], 200)
        code, body = self.call(ana, 'signoff', {'run': self.run_id, 'recommendation': 'quarantine', 'note': 'x'})
        self.assertEqual(code, 400)
        self.assertIn('critical', body['error'])
        self.assertEqual(self.call(ana, 'disposition', {'run': self.run_id, 'finding': 'f-9', 'decision': 'confirmed', 'note': 'n'})[0], 400)
        code, state = self.call(ana, 'disposition', {'run': self.run_id, 'finding': 'f-1', 'decision': 'confirmed', 'note': 'Checked.'})
        self.assertEqual((code, state['undisposed_critical']), (200, []))
        code, state = self.call(ana, 'signoff', {'run': self.run_id, 'recommendation': 'quarantine', 'note': 'Confirmed.'})
        self.assertEqual(state['status'], 'Awaiting second sign-off')
        self.assertEqual(self.call(ana, 'signoff', {'run': self.run_id, 'recommendation': 'quarantine', 'note': 'again'})[0], 400)
        code, state = self.call(rev, 'signoff', {'run': self.run_id, 'recommendation': 'quarantine', 'note': 'Concur.'})
        self.assertEqual((state['status'], state['agreed']), ('Signed off', 'quarantine'))
        self.assertTrue(self.call(adm, 'analysts/verify')[1]['verified'])
        # A row edited directly in the database is detected.
        with analysts.connect() as c:
            c.execute("UPDATE dispositions SET decision='dismissed' WHERE finding_id='f-1'")
        self.assertFalse(self.call(adm, 'analysts/verify')[1]['verified'])
        with analysts.connect() as c:
            c.execute("UPDATE dispositions SET decision='confirmed' WHERE finding_id='f-1'")

    def test_3_cross_origin_logout_and_disable(self):
        ana, adm = self.signed_in('ana'), self.signed_in('adm')
        self.assertEqual(self.call(ana, 'disposition', {'run': self.run_id}, {'Origin': 'http://evil.example'})[0], 403)
        roster = self.call(adm, 'analysts')[1]
        ana_id = next(a['id'] for a in roster if a['username'] == 'ana')
        self.assertEqual(self.call(adm, 'analysts/disable', {'id': ana_id, 'disabled': True})[0], 200)
        self.assertEqual(self.call(ana, 'bootstrap')[0], 401)  # disabling ends existing sessions
        self.assertEqual(self.call(adm, 'analysts/disable', {'id': ana_id, 'disabled': False})[0], 200)
        self.assertEqual(self.call(adm, 'logout', {})[0], 200)
        self.assertEqual(self.call(adm, 'bootstrap')[0], 401)


if __name__ == '__main__':
    unittest.main()
