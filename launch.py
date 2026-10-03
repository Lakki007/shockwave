"""Launch the offline workspace with a compatible local Python runtime."""
import importlib.util,os,subprocess,sys,webbrowser
from pathlib import Path
root=Path(__file__).resolve().parent
# macOS package dependencies are built for Python 3.12 / Apple silicon.
runtime=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
configured=os.environ.get('SHOCKWAVE_PYTHON')
if not configured and sys.version_info[:2]!=(3,12) and runtime.exists():
 os.execv(str(runtime),[str(runtime),str(__file__),*sys.argv[1:]])
if configured and Path(configured).resolve()!=Path(sys.executable).resolve():os.execv(configured,[configured,str(__file__),*sys.argv[1:]])
os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1';os.environ['ORT_DISABLE_TELEMETRY']='1';sys.path[:0]=[str(root/'.runtime'),str(root/'app')]
if not all(importlib.util.find_spec(m) for m in ('numpy','PIL','cryptography','onnxruntime','sklearn','torch')):
 print('Install the local dependencies first: python3 -m pip install -r requirements.txt');sys.exit(1)
if '--doctor' in sys.argv:
 import shockwave;sys.argv=[sys.argv[0],'doctor'];raise SystemExit(shockwave.main())
port=int(os.environ.get('SHOCKWAVE_PORT','8765'))
if '--no-browser' not in sys.argv:webbrowser.open(f'http://127.0.0.1:{port}')
from http.server import ThreadingHTTPServer
from server import Handler
print(f'Shockwave ready at http://127.0.0.1:{port}',flush=True)
try:ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
except OSError as e:
 if e.errno==48:print(f'Port {port} is already in use. Open the running workspace or set SHOCKWAVE_PORT.')
 else:raise
