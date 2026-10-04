"""Sandboxed execution of submitted models (§13.4).

Submitted ONNX graphs run in a separate worker process, never inside the assessor:

* macOS: Seatbelt (sandbox-exec) with a deny-by-default profile. The worker may read only the
  Python runtime and system libraries, may not open network sockets, may not write files, and
  may not execute other programs.
* Every worker gets CPU-time, file-size, open-file and data-segment limits, an empty working
  directory, a scrubbed environment and a per-call wall-clock timeout.
* The model bytes are streamed over a pipe; the worker never sees package paths.

If no OS sandbox is available the submitted model is not executed, unless the operator sets
SHOCKWAVE_ALLOW_UNSANDBOXED=1, in which case execution is reported as Limited.
"""
import io, json, os, resource, select, shutil, struct, subprocess, sys, sysconfig, tempfile, time
from pathlib import Path
import numpy as np

APP = Path(__file__).resolve().parent
ROOT = APP.parent
WORKER = APP / 'worker.py'
LIMITS = {'cpu_seconds': 900, 'data_bytes': 6 << 30, 'open_files': 256, 'call_timeout': 120}


def available():
    return sys.platform == 'darwin' and Path('/usr/bin/sandbox-exec').exists()


def _readable():
    """Directories the worker needs to start Python and import numpy/onnxruntime."""
    exe = Path(sys.executable).resolve()
    paths = {exe.parent.parent, Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(),
             Path(sysconfig.get_paths()['stdlib']).resolve(), (ROOT / '.runtime').resolve()}
    for p in sys.path:
        if p and Path(p).exists() and 'site-packages' in p:
            paths.add(Path(p).resolve())
    return sorted({str(p) for p in paths if str(p) not in ('/', str(Path.home()))})


def profile():
    q = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    reads = '\n'.join(f'  (subpath {q(p)})' for p in _readable())
    return f"""(version 1)
(deny default)
(allow file-map-executable)
(allow process-exec (literal {q(str(Path(sys.executable).resolve()))}))
(allow file-read*
  (literal {q(str(WORKER))})
{reads}
  (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath "/Library/Apple")
  (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes")
  (literal "/") (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/null") (literal "/dev/dtracehelper"))
(allow file-read-metadata)
(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper"))
(allow sysctl-read)
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.system.logger"))
(allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))
(deny network*)
(deny process-fork)
"""


def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (LIMITS['cpu_seconds'], LIMITS['cpu_seconds']))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS['open_files'], LIMITS['open_files']))
    try:
        resource.setrlimit(resource.RLIMIT_DATA, (LIMITS['data_bytes'], LIMITS['data_bytes']))
    except (ValueError, OSError):
        pass
    os.setsid()


class SandboxError(RuntimeError):
    pass


class Worker:
    """One sandboxed worker process holding one loaded model."""

    def __init__(self, sandboxed=True):
        self.cwd = tempfile.mkdtemp(prefix='sw-worker-')
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.cwd, 'TMPDIR': self.cwd, 'PYTHONPATH': os.pathsep.join(_readable()),
               'PYTHONDONTWRITEBYTECODE': '1', 'OMP_NUM_THREADS': '2', 'ORT_DISABLE_TELEMETRY': '1', 'LANG': 'C'}
        cmd = [sys.executable, '-B', str(WORKER)]
        if sandboxed:
            self.profile_path = os.path.join(self.cwd, 'profile.sb')
            Path(self.profile_path).write_text(profile())
            cmd = ['/usr/bin/sandbox-exec', '-f', self.profile_path] + cmd
        self.sandboxed = sandboxed
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cwd,
                                  env=env, preexec_fn=_limits, close_fds=True)

    def _send(self, header, payload=None):
        if self.p.poll() is not None:
            raise SandboxError(f'Worker exited ({self.p.returncode}): {self.p.stderr.read().decode(errors="replace")[-400:]}')
        for data in [json.dumps(header).encode()] + ([payload] if payload is not None else []):
            self.p.stdin.write(struct.pack('>I', len(data)) + data)
        self.p.stdin.flush()

    def _read(self, deadline):
        buf = b''
        for need in (4, None):
            want = 4 if need else struct.unpack('>I', buf)[0]
            got = b''
            while len(got) < want:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([self.p.stdout], [], [], left)[0]:
                    self.close()
                    raise SandboxError('Worker call exceeded its time limit and was terminated')
                chunk = os.read(self.p.stdout.fileno(), want - len(got))
                if not chunk:
                    err = self.p.stderr.read().decode(errors='replace')[-400:]
                    raise SandboxError(f'Worker terminated: {err}')
                got += chunk
            buf = got
        return buf

    def call(self, header, payload=None, timeout=None):
        self._send(header, payload)
        deadline = time.monotonic() + (timeout or LIMITS['call_timeout'])
        reply = json.loads(self._read(deadline))
        if not reply.get('ok'):
            raise SandboxError(reply.get('error', 'worker error'))
        arrays = [np.load(io.BytesIO(self._read(deadline)), allow_pickle=False) for _ in range(reply.get('n', 0))]
        return reply, arrays

    def close(self):
        try:
            if self.p.poll() is None:
                self.p.kill()
                self.p.wait(5)
        finally:
            for pipe in (self.p.stdin, self.p.stdout, self.p.stderr):
                try:
                    pipe.close()
                except Exception:
                    pass
            shutil.rmtree(self.cwd, ignore_errors=True)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def probe():
    """Confirm the sandbox is enforced: network, file write, package read and exec must all be denied."""
    if not available():
        return {'available': False}
    w = Worker()
    try:
        target = str((ROOT / 'data' / 'trust-registry.json').resolve())
        reply, _ = w.call({'op': 'probe', 'write_target': str(Path.home()), 'read_target': target}, timeout=30)
        result = {k: reply[k] for k in ('network', 'write', 'read', 'exec')}
        result['enforced'] = all(v.startswith('denied') for v in result.values())
        result['available'] = True
        return result
    finally:
        w.close()


class SandboxedModel:
    """Raw-output callable for an untrusted ONNX graph, executed in a sandboxed worker."""

    def __init__(self, path):
        sandboxed = available()
        if not sandboxed and os.environ.get('SHOCKWAVE_ALLOW_UNSANDBOXED') != '1':
            raise SandboxError('No OS sandbox available; submitted model not executed (set SHOCKWAVE_ALLOW_UNSANDBOXED=1 to override).')
        self.worker = Worker(sandboxed)
        self.isolation = 'macOS Seatbelt worker (no network, no file writes, no exec, rlimits)' if sandboxed else 'separate process without OS sandbox (operator override)'
        reply, _ = self.worker.call({'op': 'load'}, Path(path).read_bytes(), timeout=180)
        self.inputs, self.outputs = reply['inputs'], reply['outputs']
        self.calls = 0

    def __call__(self, x):
        self.calls += 1
        buf = io.BytesIO()
        np.save(buf, np.ascontiguousarray(x, dtype=np.float32), allow_pickle=False)
        return self.worker.call({'op': 'run'}, buf.getvalue())[1]

    def close(self):
        self.worker.close()
