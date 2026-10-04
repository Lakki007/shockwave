#!/usr/bin/env python3
"""Shockwave CLI. Local data, local models, verifiable decisions."""
import argparse,importlib.util,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
runtime=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
if sys.version_info[:2]!=(3,12) and runtime.exists():os.execv(str(runtime),[str(runtime),str(__file__),*sys.argv[1:]])
sys.path[:0]=[str(ROOT/'.runtime'),str(ROOT/'app')]

def main():
 p=argparse.ArgumentParser(prog='shockwave');sub=p.add_subparsers(dest='command',required=True)
 sub.add_parser('doctor');server=sub.add_parser('serve');server.add_argument('--port',type=int,default=8765)
 run=sub.add_parser('run');run.add_argument('fixture');run.add_argument('--format',choices=['COCO','YOLO'],default='COCO');run.add_argument('--policy',type=Path)
 view=sub.add_parser('view');view.add_argument('run');sub.add_parser('audit');sub.add_parser('keys',help='Show assessor key custody (Ed25519 file key and Secure Enclave co-signer)');sub.add_parser('sandbox',help='Self-test the model-execution sandbox');team=sub.add_parser('analysts',help='Multi-analyst workspace: init creates the schema and first admin; verify cross-checks rows against the audit log');team.add_argument('action',choices=['init','verify','list']);sub.add_parser('calibrate',help='Build the independent calibration set from held-out reference pictures');sub.add_parser('warm',help='Assess bundled packages and the preset Attack Lab so caches and demo runs are ready')
 verify=sub.add_parser('verify');verify.add_argument('report',type=Path);verify.add_argument('--public-key',required=True,help='Independently trusted base64 Ed25519 public key');verify.add_argument('--hardware-key',help='Pinned base64 DER P-256 public key of the Secure Enclave co-signer')
 args=p.parse_args()
 if args.command=='doctor':
  modules=['numpy','PIL','cryptography','onnx','onnxruntime','torch','safetensors','sklearn','transformers','faiss'];rows={m:bool(importlib.util.find_spec(m)) for m in modules};rows['local_dinov2_weights']=(ROOT/'data/encoders/dinov2-small/model.safetensors').exists();print(json.dumps({'python':sys.version.split()[0],'dependencies':rows,'offline_ready':all(rows.values()),'semantic_witness':'Configured' if (ROOT/'data/encoders/semantic-witness/config.json').exists() else 'Weights required','training_attribution':'Compatible checkpoints required'},indent=2));return 0 if all(rows.values()) else 1
 import core
 if args.command=='serve':
  from http.server import ThreadingHTTPServer
  from server import Handler
  print(f'Shockwave ready at http://127.0.0.1:{args.port}',flush=True);ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
 elif args.command=='run':
  policy=json.loads(args.policy.read_text()) if args.policy else None;a=core.Assessment(args.fixture,policy,args.format);a.run()
  if a.error:print(a.error,file=sys.stderr);return 1
  print(json.dumps({'run':a.id,'decision':a.result['decision'],'images':a.result['images'],'findings':a.result['finding_types']},indent=2))
 elif args.command=='view':
  report=core.read_json(core.safe_path(core.STATE/'runs',args.run+'.json'))
  if not report:raise ValueError('Unknown assessment')
  print(json.dumps(report,indent=2))
 elif args.command=='warm':
  import forge
  for fixture,fmt in [('clean','COCO'),('approved','COCO'),('synthetic','COCO'),('yolo','YOLO'),('hostile','COCO')]:
   a=core.Assessment(fixture,None,fmt);a.run();print(json.dumps({'fixture':fixture,'run':a.id,'decision':a.result and a.result['decision'],'error':a.error}),flush=True)
  job=forge.ForgeJob(forge.PRESET);job.run()
  if job.error:print(job.error,file=sys.stderr);return 1
  a=core.Assessment(job.id);a.run();print(json.dumps({'fixture':job.id,'run':a.id,'decision':a.result and a.result['decision'],'error':a.error}),flush=True)
 elif args.command=='keys':
  import keystore,base64
  from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
  print(json.dumps({'ed25519_public_key':base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),'hardware':keystore.status()},indent=2))
 elif args.command=='sandbox':
  import sandbox
  result=sandbox.probe();print(json.dumps(result,indent=2));return 0 if result.get('enforced') else 1
 elif args.command=='analysts':
  import analysts
  if not analysts.enabled():print(json.dumps(analysts.mode()),file=sys.stderr);return 1
  if args.action=='init':
   made=analysts.bootstrap_admin();print(json.dumps(made or {'admin':'already exists'},indent=2))
  elif args.action=='verify':
   result=analysts.verify();print(json.dumps(result,indent=2));return 0 if result['verified'] else 1
  else:
   with analysts.connect() as c:print(json.dumps([{k:str(v) for k,v in r.items() if k!='password_hash'} for r in c.execute('SELECT id,username,display_name,role,disabled,must_change FROM analysts ORDER BY id').fetchall()],indent=2))
 elif args.command=='calibrate':
  import calibration
  print(json.dumps(calibration.build(lambda m:print(m,flush=True)),indent=2))
 elif args.command=='audit':
  result=core.verify_audit();print(json.dumps(result,indent=2));return 0 if result['verified'] else 1
 elif args.command=='verify':
  from provenance import report_verify
  result=report_verify(json.loads(args.report.read_text()),args.public_key,args.hardware_key);print(json.dumps(result,indent=2));return 0 if result['verified'] else 1
 return 0
if __name__=='__main__':raise SystemExit(main())
