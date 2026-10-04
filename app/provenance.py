"""Fresh local inference receipts and independent verification helpers."""
import base64,json,sqlite3,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import core
DOMAIN=b'SHOCKWAVE-INFERENCE-v1\x00'

def report_verify(report,public_key,hardware_public_key=None):
 body={k:v for k,v in report.items() if k not in ('report_digest','report_signature','hardware_signature')};actual=core.digest(core.canonical(body),'sha384')
 if actual!=report.get('report_digest'):return {'verified':False,'reason':'Report content differs from its sealed digest.'}
 try:Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(base64.b64decode(report['report_signature']),bytes.fromhex(actual))
 except Exception:return {'verified':False,'reason':'Report signature does not verify under the trusted key.'}
 hw=report.get('hardware_signature')
 if hardware_public_key and not hw:return {'verified':False,'reason':'A hardware co-signature was required but the report has none.'}
 if hw:
  import keystore
  if not keystore.verify(bytes.fromhex(actual),hw,hardware_public_key):return {'verified':False,'reason':'Hardware co-signature does not verify'+(' under the pinned hardware key.' if hardware_public_key else '.')}
  return {'verified':True,'hardware':{'key_id':hw['key_id'],'algorithm':hw['algorithm'],'pinned':bool(hardware_public_key)},'reason':'Content, Ed25519 signature and Secure Enclave co-signature verified'+(' under the pinned keys.' if hardware_public_key else '; pin --hardware-key to trust the enclave key independently.')}
 return {'verified':True,'reason':'Content and signature verified under the supplied trusted public key.'}

def inclusion(sequence):
 events=core.audit_events()
 if sequence<0 or sequence>=len(events):raise ValueError('Event sequence out of range')
 import hashlib
 index=sequence;nodes=[hashlib.sha256(b'\x00'+bytes.fromhex(e['hash'])).digest() for e in events];proof=[]
 while len(nodes)>1:
  sibling=index^1
  if sibling<len(nodes):proof.append({'side':'left' if sibling<index else 'right','hash':nodes[sibling].hex()})
  nodes=[hashlib.sha256(b'\x01'+nodes[i]+nodes[i+1]).digest() if i+1<len(nodes) else nodes[i] for i in range(0,len(nodes),2)];index//=2
 return {'sequence':sequence,'event_hash':events[sequence]['hash'],'tree_size':len(events),'root':nodes[0].hex(),'proof':proof,'checkpoint':core.read_json(core.STATE/'checkpoint.json')}

def inclusion_verify(proof):
 import hashlib
 value=hashlib.sha256(b'\x00'+bytes.fromhex(proof['event_hash'])).digest()
 for node in proof['proof']:
  sibling=bytes.fromhex(node['hash']);value=hashlib.sha256(b'\x01'+(sibling+value if node['side']=='left' else value+sibling)).digest()
 return value.hex()==proof['root']

def infer(body):
 from models import Runtime,input_array,output_envelope,inspect_model
 fixture=body['fixture'];registry=core.read_json(core.DATA/'trust-registry.json',{}).get(fixture,{})
 if not registry:raise ValueError('No approved deployment registry for this submission')
 root=core.safe_path(core.DATA/'fixtures',fixture);refs=[core.safe_path(root,e['path']) for e in registry.get('approved_model_artifacts',[]) if e['path'].endswith('.onnx') and core.safe_path(root,e['path']).is_file() and core.digest(core.safe_path(root,e['path']).read_bytes())==e['sha256']]
 if not refs:raise ValueError('An approved ONNX runtime is required')
 model=refs[0]
 if not inspect_model(model)['safe']:raise ValueError('Runtime artifact did not pass static inspection')
 rt=Runtime(model);items,classes,_=core.inventory(fixture,body.get('format','COCO'));item=next((i for i in items if i['id']==body['asset']),None)
 if not item:raise ValueError('Unknown original image')
 from safetensors import safe_open
 weights=next(iter((root/'suite/models').glob('clean.safetensors')),None) or next(iter((root/'trust/models').glob('*.safetensors')),None)
 if weights:
  with safe_open(weights,framework='np') as f:classes=json.loads((f.metadata() or {}).get('classes','[]')) or classes
 pre={'resize':[rt.size,rt.size],'channel_order':'RGB','normalize':'unit'};post={'score_threshold':.25,'max_detections':1,'class_map':None};out=output_envelope(rt.prediction(input_array(item['path'],rt.size)),classes,item['width'],item['height'],post)
 db=sqlite3.connect(core.STATE/'receipts.sqlite',timeout=20)
 try:
  db.execute('CREATE TABLE IF NOT EXISTS receipts (sequence INTEGER PRIMARY KEY AUTOINCREMENT, nonce TEXT UNIQUE NOT NULL, digest TEXT NOT NULL, record TEXT NOT NULL)');db.execute('BEGIN IMMEDIATE');prev=db.execute('SELECT sequence,digest FROM receipts ORDER BY sequence DESC LIMIT 1').fetchone();sequence=(prev[0]+1 if prev else 1)
  record={'schema':'shockwave-inference-v1','canonicalisation':'sorted-json-utf8-v1','digest_algorithm':'SHA-384','signature_algorithm':'Ed25519 / domain-separated canonical bytes','session':'local-assessor','sequence':sequence,'nonce':uuid.uuid4().hex,'timestamp':core.now(),'input':{'asset':item['id'],'fixture':fixture,'sha384':core.digest(Path(item['path']).read_bytes(),'sha384')},'model':{'artifact':model.name,'sha384':core.digest(model.read_bytes(),'sha384')},'processing':{'preprocess':pre,'postprocess':post,'sha384':core.digest(core.canonical({'preprocess':pre,'postprocess':post}),'sha384')},'output':out,'output_sha384':core.digest(core.canonical(out),'sha384'),'previous':prev[1] if prev else '0'*96}
  raw=core.canonical(record);record['digest']=core.digest(raw,'sha384');record['signature']=base64.b64encode(core.key().sign(DOMAIN+raw)).decode();record['public_key']=base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode();db.execute('INSERT INTO receipts(sequence,nonce,digest,record) VALUES (?,?,?,?)',(sequence,record['nonce'],record['digest'],json.dumps(record)));db.commit()
 finally:db.close()
 core.log_event('inference_sealed',{'sequence':sequence,'nonce':record['nonce'],'record_digest':record['digest'],'input':item['id']});return record

def receipt_verify(record,trusted_public_key):
 raw=core.canonical({k:v for k,v in record.items() if k not in ('digest','signature','public_key')})
 if core.digest(raw,'sha384')!=record.get('digest'):return {'verified':False,'reason':'Receipt content altered.'}
 try:Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_key)).verify(base64.b64decode(record['signature']),DOMAIN+raw)
 except Exception:return {'verified':False,'reason':'Receipt signature invalid under trusted key.'}
 return {'verified':True,'reason':'Receipt binding verified. Freshness requires a separate persisted receiver ledger.'}

def receive(record,trusted_public_key):
 verified=receipt_verify(record,trusted_public_key)
 if not verified['verified']:return verified
 db=sqlite3.connect(core.STATE/'receiver.sqlite',timeout=20)
 try:
  db.execute('CREATE TABLE IF NOT EXISTS accepted (nonce TEXT PRIMARY KEY, session TEXT, sequence INTEGER, digest TEXT, UNIQUE(session,sequence))');db.execute('BEGIN IMMEDIATE');last=db.execute('SELECT sequence,digest FROM accepted WHERE session=? ORDER BY sequence DESC LIMIT 1',(record['session'],)).fetchone()
  if last and (record['sequence']!=last[0]+1 or record['previous']!=last[1]):db.rollback();return {'verified':False,'reason':'Sequence discontinuity or chain inconsistency in persisted receiver state.'}
  if not last and (record['sequence']!=1 or record['previous']!='0'*96):db.rollback();return {'verified':False,'reason':'A new session requires its authorised opening record.'}
  try:db.execute('INSERT INTO accepted VALUES (?,?,?,?)',(record['nonce'],record['session'],record['sequence'],record['digest']))
  except sqlite3.IntegrityError:db.rollback();return {'verified':False,'reason':'Duplicate nonce or sequence: replay rejected.'}
  db.commit()
 finally:db.close()
 core.log_event('receipt_accepted',{'session':record['session'],'sequence':record['sequence'],'digest':record['digest']});return {'verified':True,'reason':'Signature, nonce, sequence and predecessor accepted against persisted receiver state.'}
