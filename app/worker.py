"""Sandboxed model-execution worker (§13.4). Runs under sandbox.py; never imported by the assessor.

Protocol over stdin/stdout, every frame = 4-byte big-endian length + payload:
  request  : JSON header, then (for "load") model bytes or (for "run") one .npy input
  response : JSON header, then one .npy frame per output
The worker receives model bytes over the pipe, so it needs no read access to the package, and
it has no network or file-write permission. .npy frames are loaded with allow_pickle=False.
"""
import io, json, os, struct, sys


def read_frame(f):
    head = f.read(4)
    if len(head) < 4:
        raise EOFError
    (n,) = struct.unpack('>I', head)
    if n > 1 << 30:
        raise ValueError('frame too large')
    data = f.read(n)
    if len(data) < n:
        raise EOFError
    return data


def write_frame(f, data):
    f.write(struct.pack('>I', len(data)))
    f.write(data)


def main():
    import numpy as np
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    session = None
    while True:
        try:
            req = json.loads(read_frame(stdin))
        except EOFError:
            return
        try:
            if req['op'] == 'load':
                import onnxruntime as ort
                ort.disable_telemetry_events()
                o = ort.SessionOptions()
                o.intra_op_num_threads, o.inter_op_num_threads = int(req.get('threads', 2)), 1
                session = ort.InferenceSession(read_frame(stdin), sess_options=o, providers=['CPUExecutionProvider'])
                reply = {'ok': True, 'inputs': [[i.name, i.shape] for i in session.get_inputs()],
                         'outputs': [[x.name, x.shape] for x in session.get_outputs()]}
                write_frame(stdout, json.dumps(reply).encode())
            elif req['op'] == 'run':
                x = np.load(io.BytesIO(read_frame(stdin)), allow_pickle=False)
                outs = session.run(None, {session.get_inputs()[0].name: x})
                write_frame(stdout, json.dumps({'ok': True, 'n': len(outs)}).encode())
                for o in outs:
                    buf = io.BytesIO()
                    np.save(buf, np.asarray(o), allow_pickle=False)
                    write_frame(stdout, buf.getvalue())
            elif req['op'] == 'probe':
                # Self-test used by the assessor to confirm the sandbox is actually enforced.
                result = {}
                try:
                    import socket
                    socket.create_connection(('1.1.1.1', 80), timeout=2).close()
                    result['network'] = 'allowed'
                except Exception as e:
                    result['network'] = 'denied: ' + type(e).__name__
                try:
                    with open(os.path.join(req['write_target'], 'escape.txt'), 'w') as f:
                        f.write('x')
                    result['write'] = 'allowed'
                except Exception as e:
                    result['write'] = 'denied: ' + type(e).__name__
                try:
                    with open(req['read_target'], 'rb') as f:
                        f.read(1)
                    result['read'] = 'allowed'
                except Exception as e:
                    result['read'] = 'denied: ' + type(e).__name__
                try:
                    import subprocess
                    subprocess.run(['/bin/echo', 'x'], capture_output=True, timeout=2)
                    result['exec'] = 'allowed'
                except Exception as e:
                    result['exec'] = 'denied: ' + type(e).__name__
                write_frame(stdout, json.dumps({'ok': True, **result}).encode())
            else:
                write_frame(stdout, json.dumps({'ok': False, 'error': 'unknown op'}).encode())
        except Exception as e:
            write_frame(stdout, json.dumps({'ok': False, 'error': f'{type(e).__name__}: {e}'[:400]}).encode())
        stdout.flush()


if __name__ == '__main__':
    main()
