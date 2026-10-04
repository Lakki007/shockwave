"""Shockwave: offline evidence, policy and signed lifecycle records."""
from __future__ import annotations
import base64, collections, csv, hashlib, io, json, os, pickletools, struct, threading, time, uuid, zipfile
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
os.environ.setdefault('OMP_NUM_THREADS','1');os.environ.setdefault('MKL_NUM_THREADS','1')
import torch
torch.set_num_threads(1)
import numpy as np
from PIL import Image, ImageOps, ImageStat, ImageFilter
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data'; STATE=DATA/'state'; STATE.mkdir(parents=True,exist_ok=True)
LOCK=threading.RLock()
LABELS={'synthetic':'Synthetic challenge','clean':'Real-world baseline','hostile':'Adversarial submission','approved':'Curated submission','yolo':'YOLO model challenge'}
POLICY={'version':'shockwave-1.1','task':'Object detection / classification','context':'Multi-contributor imagery','access':'white-box','neighbours':20,'duplicate_distance':5,'label_threshold':0.65,'label_method':'neighbour_plurality','ood_quantile':0.99,'texture_z':4.5,'robust_margin':1.1,'patch_similarity':0.9,'patch_min_images':6,'challenge_budget':32,'loop_mode':'exhaustive','trigger_steps':150,'mandatory':['data_schema','model_identity','provenance','safe_intake'],'numerical_tolerance':0.005}
CLAIMS=[('data_schema','Dataset structure','data'),('data_identity','Artifact traceability','data'),('duplication','Duplicate concentration','data'),('split_integrity','Split independence','data'),('labels','Annotation consistency','data'),('poisoning','Poisoning evidence','data'),('source_risk','Contributor attribution','data'),('model_identity','Approved model identity','model'),('safe_intake','Safe artifact inspection','model'),('behaviour','Reference behaviour','model'),('backdoor','Conditional behaviour','model'),('pipeline','Authorised pipeline','pipeline'),('provenance','Inference record integrity','records'),('replay','Record freshness','records'),('history','History consistency','records'),('reproduction','Output reproduction','records'),('distribution','Operating distribution','context'),('calibration','Confidence calibration','calibration'),('audit','Assessment auditability','audit')]
DEPENDENCIES={'data':['data_schema','data_identity','duplication','split_integrity','labels','poisoning','source_risk','distribution','calibration'], 'model':['model_identity','provenance','behaviour','backdoor','pipeline','reproduction','calibration'], 'pipeline':['pipeline','provenance','reproduction'], 'reference':['labels','distribution','behaviour','backdoor','calibration'], 'policy':[x[0] for x in CLAIMS], 'context':['distribution','calibration'], 'keys':['provenance','history','audit']}
CAPABILITIES=[
('Data schema','COCO and YOLO parsers with annotation validation','data','Implemented'),
('Exact identity','SHA-384 / SHA-256 artifact digests','data','Implemented'),
('Near duplicates','Perceptual hashing, near-duplicate groups, cross-split leakage and flooding clusters','data','Implemented'),
('Labels','DINOv2 + FAISS duplicate-excluded neighbour votes; Confident-Learning confident joint and contributor class pairs (§11.3)','data','Implemented'),
('Contributors','Source aggregation with denominators; Fisher-exact concentration tests in the Contrarian Loop (§12)','data','Implemented'),
('Recurring patterns','Corner-dense compact patches star-clustered across samples; position and source consistency (§11.5)','data','Implemented'),
('Robust sub-populations','SPECTRE-inspired robust covariance with spectral score, reference-calibrated threshold (§11.6)','data','Implemented'),
('Semantic novelty','DINOv2 nearest approved-reference crop with reference envelope (§11.7)','data','Implemented'),
('Model intake','Static pickle/op/path/archive screening; never executes rejected files','model','Implemented'),
('Model substitution','Weight hashes and tensor comparison','model','Implemented'),
('Behaviour battery','Approved ONNX runtime reference comparisons and adaptive battery expansion','model','Implemented'),
('Detector adapters','YOLO family: v5/v7, v8/v9/v11, YOLOX and NMS-free exports; letterbox, decoding and class-aware NMS (§13)','model','Implemented'),
('Sandboxed execution','Submitted graphs run in a macOS Seatbelt worker: no network, writes, package reads or exec; rlimits and per-call timeouts, self-tested every run','model','Implemented'),
('Trigger transfer','Behaviour forensics: mined data patterns transplanted onto independent references, approved and occlusion controls, reserved confirmation (§21)','model','Implemented'),
('Trigger reconstruction','Neural-Cleanse-style class-pair and all-target search in detector crop space, approved model as control (§14.1)','model','Conditional'),
('STRIP','Superimposition entropy with clean null for score-access models (§14.3)','model','Implemented'),
('Provenance','Digest binding, Ed25519 signatures, trust registry','records','Implemented'),
('Replay','Session/sequence collision and chain consistency','records','Implemented'),
('Re-execution','Approved model and original input required','records','Conditional'),
('Twin pipeline','Same-model processing differential with single-stage localisation (§15)','pipeline','Implemented'),
('Distribution','Reference distance and kernel two-sample comparison','context','Implemented'),
('Calibration','Isotonic fit on an independent Attack Lab set forged from held-out reference pictures (fit/validation disjoint); abstains on context shift or overlap (§25)','calibration','Implemented'),
('Contrarian loop','Registry of 10 challenges; eligibility by access, priority = weight × value × (1 + gap) / cost, spawned follow-ups, seeds and stop reasons (§20)','workflow','Implemented'),
('Attack Lab','Operator-forged packages with sealed, pre-committed answer keys for live evaluation (§31)','evaluation','Implemented'),
('Delta','Dependency closure, stale claims and targeted reassessment','workflow','Implemented'),
('Audit','Signed Merkle checkpoints and retained consistency history','audit','Implemented'),
('Key custody','Reports and checkpoints co-signed by a non-exportable Secure Enclave P-256 key; Ed25519 file key retained','audit','Implemented'),
('Multi-analyst review','PostgreSQL accounts and roles, per-finding dispositions, two-person sign-off, rows bound to the signed audit log (§28)','workflow','Implemented'),
('Semantic witness','Bundled SmolVLM-500M, SHA-256 pinned; 12 bounded forced-choice questions; advisory only','AI','Implemented'),
('Training attribution','Compatible local TRAK adapter, approved checkpoints and exact training membership required','AI','Conditional'),
('TorchScript execution','Static intake supported; execution requires approved graph adapter','model','Conditional'),
('Air gap','All application assets and analysis execute locally','deployment','Implemented')]

def claim_state(findings,checks,id):
 """Deterministic claim state from evidence; shared by the Contrarian Loop and the final policy."""
 fs=[f for f in findings if f['claim']==id];cs=[c for c in checks if c['claim']==id]
 if any(f['severity']=='critical' for f in fs):return 'Contradicted'
 if fs:return 'Weakened'
 if any(c['status'] in ('Unavailable','Limited','Failed') for c in cs):return 'Unresolved'
 if cs or id in ('data_identity','audit'):return 'Supported'
 return 'Unresolved'

def now(): return datetime.now(timezone.utc).isoformat()
def canonical(d): return json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(b,algorithm='sha256'): return hashlib.new(algorithm,b).hexdigest()
def read_json(p,default=None):
 try:return json.loads(Path(p).read_text())
 except (FileNotFoundError,ValueError):return default

def atomic(p,d):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_suffix('.tmp');t.write_text(json.dumps(d,indent=2,allow_nan=False));t.replace(p)

def safe_path(root,rel):
 path=(Path(root)/rel).resolve()
 if not path.is_relative_to(Path(root).resolve()):raise ValueError('Path escapes asset root')
 return path

_UNSEALED={}
def key():
 """The assessor's Ed25519 key. If sealed (assessor.key.sealed), it is unsealed by the Secure Enclave once per process."""
 p=STATE/'assessor.key';sealed=STATE/'assessor.key.sealed'
 with LOCK:
  if sealed.exists():
   if str(sealed) not in _UNSEALED:
    import keystore
    _UNSEALED[str(sealed)]=Ed25519PrivateKey.from_private_bytes(keystore.unseal(read_json(sealed),STATE))
   return _UNSEALED[str(sealed)]
  if not p.exists():p.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()));os.chmod(p,0o600)
  return Ed25519PrivateKey.from_private_bytes(p.read_bytes())

def seal_key(remove_plaintext=False):
 """Seal assessor.key under the Secure Enclave; verify the round trip before anything is removed."""
 import keystore
 p=STATE/'assessor.key';sealed=STATE/'assessor.key.sealed'
 if sealed.exists():return {'sealed':True,'already':True,'plaintext_present':p.exists()}
 raw=p.read_bytes();record=keystore.seal(raw,STATE)
 if keystore.unseal(record,STATE)!=raw:raise RuntimeError('Seal round trip failed; nothing changed')
 atomic(sealed,record);os.chmod(sealed,0o600);_UNSEALED.clear()
 if key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)!=Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw):
  sealed.unlink();raise RuntimeError('Sealed key does not match; seal removed')
 log_event('assessor_key_sealed',{'algorithm':'AES-256-GCM under ECDH(P-256 Secure Enclave key agreement)+HKDF-SHA256','plaintext_removed':bool(remove_plaintext)})
 if remove_plaintext:p.unlink()
 return {'sealed':True,'plaintext_present':p.exists()}

def merkle(hashes):
 nodes=[hashlib.sha256(b'\x00'+bytes.fromhex(h)).digest() for h in hashes]
 if not nodes:return digest(b'')
 while len(nodes)>1:
  nodes=[hashlib.sha256(b'\x01'+nodes[i]+nodes[i+1]).digest() if i+1<len(nodes) else nodes[i] for i in range(0,len(nodes),2)]
 return nodes[0].hex()

_AUDIT_HELD=threading.local()
class _AuditFileLock:
 """Cross-process exclusive lock: the server, CLI and analyst workers may all append to the audit log.
 Re-entrant per thread, because co-signing a checkpoint can itself log the hardware key's creation."""
 def __enter__(self):
  import fcntl
  depth=getattr(_AUDIT_HELD,'depth',0)
  if not depth:_AUDIT_HELD.f=open(STATE/'.audit.lock','a');fcntl.flock(_AUDIT_HELD.f,fcntl.LOCK_EX)
  _AUDIT_HELD.depth=depth+1;return self
 def __exit__(self,*exc):
  import fcntl
  _AUDIT_HELD.depth-=1
  if not _AUDIT_HELD.depth:fcntl.flock(_AUDIT_HELD.f,fcntl.LOCK_UN);_AUDIT_HELD.f.close()

# The audit log and checkpoint history are append-only JSON Lines: one signed record per line,
# appended and fsynced, never rewritten. A torn final line fails verification instead of vanishing.
AUDIT_LOG='audit.jsonl';CHECKPOINT_LOG='checkpoints.jsonl'

def _read_jsonl(name,legacy):
 p=STATE/name
 if not p.exists() and (STATE/legacy).exists():  # one-time migration from the original rewrite-in-place files
  rows=read_json(STATE/legacy,[]);p.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows));(STATE/legacy).rename(STATE/(legacy+'.migrated'))
 if not p.exists():return []
 out=[]
 for n,line in enumerate(p.read_text().splitlines()):
  try:out.append(json.loads(line))
  except ValueError:raise ValueError(f'{name} line {n+1} is not a complete record (torn write or tampering)')
 return out

def _append_jsonl(name,row):
 with open(STATE/name,'a') as f:f.write(json.dumps(row,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())

def audit_events():return _read_jsonl(AUDIT_LOG,'audit.json')
def checkpoint_history():return _read_jsonl(CHECKPOINT_LOG,'checkpoints.json')

def log_event(kind,body):
 with LOCK,_AuditFileLock():
  events=audit_events();checkpoint_history()  # migrate both logs together
  event={'sequence':len(events),'timestamp':now(),'kind':kind,'body':body,'previous':events[-1]['hash'] if events else '0'*64}
  event['hash']=digest(canonical(event));event['signature']=base64.b64encode(key().sign(bytes.fromhex(event['hash']))).decode()
  hashes=[e['hash'] for e in events]+[event['hash']]
  cp={'size':len(hashes),'root':merkle(hashes),'previous_checkpoint':digest(canonical(read_json(STATE/'checkpoint.json',{}))),'timestamp':now()}
  body=canonical(cp);cp['signature']=base64.b64encode(key().sign(body)).decode()
  hw=hardware_cosign(body)  # computed before anything is written, so a slow or failing co-signer cannot leave an event without its checkpoint
  if hw:cp['hardware_signature']=hw
  _append_jsonl(AUDIT_LOG,event);atomic(STATE/'checkpoint.json',cp);_append_jsonl(CHECKPOINT_LOG,cp)
  return event

def hardware_cosign(message):
 try:
  import keystore
  return keystore.cosign(message)
 except Exception:return None  # custody is reported from keystore.status(); never claimed on failure

def verify_audit():
 errors=[]
 try:es=audit_events();history=checkpoint_history()
 except ValueError as e:es,history=[],[];errors.append(str(e))
 cp=read_json(STATE/'checkpoint.json',{});pub=key().public_key();previous='0'*64
 for e in es:
  body={k:v for k,v in e.items() if k not in ('hash','signature')}
  try:pub.verify(base64.b64decode(e['signature']),bytes.fromhex(e['hash']))
  except Exception:errors.append('Event signature failure')
  if digest(canonical(body))!=e['hash'] or e['previous']!=previous:errors.append('History inconsistency')
  previous=e['hash']
 if cp:
  try:pub.verify(base64.b64decode(cp['signature']),canonical({k:v for k,v in cp.items() if k not in ('signature','hardware_signature')}))
  except Exception:errors.append('Checkpoint signature failure')
  if cp['size']!=len(es) or cp['root']!=merkle([e['hash'] for e in es]):errors.append('Checkpoint root mismatch')
 prior=digest(canonical({}));size=0;hw_total=hw_ok=0
 for checkpoint in history:
  try:
   body=canonical({k:v for k,v in checkpoint.items() if k not in ('signature','hardware_signature')});pub.verify(base64.b64decode(checkpoint['signature']),body)
   if checkpoint.get('hardware_signature'):
    import keystore
    hw_total+=1;hw_ok+=keystore.verify(body,checkpoint['hardware_signature'])
   n=checkpoint['size']
   if n<=size or n>len(es) or checkpoint['root']!=merkle([e['hash'] for e in es[:n]]) or checkpoint['previous_checkpoint']!=prior:errors.append('Checkpoint consistency failure')
   size=n;prior=digest(canonical(checkpoint))
  except Exception:errors.append('Historical checkpoint verification failure')
 if history and cp!=history[-1]:errors.append('Current checkpoint differs from retained history')
 if hw_ok!=hw_total:errors.append('Hardware co-signature failure on a checkpoint')
 return {'verified':not errors,'errors':errors,'events':es,'checkpoint':cp,'checkpoints':history,'public_key':base64.b64encode(pub.public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),'hardware':{'cosigned_checkpoints':hw_total,'verified':hw_ok,'algorithm':'ECDSA-P256-SHA256' if hw_total else None},'limitation':'Completeness is relative to retained signed checkpoints; trusted assessor key required.'}

def fixtures():
 rows=[]
 for p in (DATA/'fixtures').iterdir() if (DATA/'fixtures').exists() else []:
  if not p.is_dir() or p.name.startswith(('cal-','calib-','bench-')):continue  # calibration material is not offered for assessment
  images=sum(1 for x in (p/'submission').rglob('*') if x.suffix.lower() in ('.jpg','.png','.jpeg') and '/yolo/' not in str(x))
  models=list((p/'submission/models').glob('*'));records=p/'submission/records/records.jsonl'
  rows.append({'id':p.name,'name':LABELS.get(p.name) or (read_json(p/'manifest.json',{}) or {}).get('name',p.name),'kind':'attack-lab' if p.name.startswith('lab-') else 'bundled','images':images,'models':len(models),'records':len(records.read_text().splitlines()) if records.exists() else 0,'formats':['COCO']+(['YOLO'] if (p/'submission/yolo').exists() else []),'reference_images':sum(1 for x in (p/'reference').rglob('*') if x.suffix.lower() in ('.jpg','.png','.jpeg'))})
 return sorted(rows,key=lambda r:list(LABELS).index(r['id']) if r['id'] in LABELS else 99)

def inventory(fixture,format='COCO'):
 root=safe_path(DATA/'fixtures',fixture);items=[];classes=[];schema=[]
 contributors={}
 for p in (root/'submission').rglob('contributors.csv'):
  with p.open() as f:
   for r in csv.DictReader(f):contributors[r.get('path_prefix','')]=r.get('contributor','unknown')
 if format=='YOLO':
  base=root/'submission/yolo';classes=read_json(base/'classes.json',[])
  if not base.exists():raise ValueError('This submission has no YOLO dataset')
  if not classes:
   import yaml
   cfg=yaml.safe_load((base/'dataset.yaml').read_text());names=cfg.get('names',[]);classes=list(names.values()) if isinstance(names,dict) else names
  for image in sorted((base/'images').rglob('*')):
   if image.suffix.lower() not in ('.jpg','.jpeg','.png'):continue
   split=image.parent.name;rel=split+'/'+image.name
   with Image.open(image) as im:W,H=im.size
   anns=[];lab=base/'labels'/split/(image.stem+'.txt')
   for line in lab.read_text().splitlines() if lab.exists() else []:
    try:
     c,x,y,w,h=map(float,line.split());ci=int(c)
     if c!=ci or ci not in range(len(classes)) or not all(0<=v<=1 for v in (x,y,w,h)):raise ValueError('Invalid normalised label')
     anns.append({'id':len(anns),'label':classes[ci],'bbox':[(x-w/2)*W,(y-h/2)*H,w*W,h*H]})
    except Exception:schema.append({'asset':rel,'reason':'Invalid YOLO annotation row'})
   items.append({'id':rel,'path':str(image),'split':split,'width':W,'height':H,'annotations':anns,'contributor':contributors.get(rel,'unknown')})
 else:
  for annpath in sorted((root/'submission/coco').rglob('_annotations.coco.json')):
   d=read_json(annpath,{});cats={c['id']:c['name'] for c in d.get('categories',[])};classes=sorted(set(classes+list(cats.values())));by=collections.defaultdict(list)
   for a in d.get('annotations',[]):by[a['image_id']].append({'id':a['id'],'label':cats.get(a['category_id'],'unknown'),'bbox':a['bbox']})
   for im in d.get('images',[]):
    rel=annpath.parent.name+'/'+im['file_name'];path=safe_path(annpath.parent,im['file_name']);anns=by[im['id']]
    if not path.exists():schema.append({'asset':rel,'reason':'Annotation refers to a missing image'});continue
    for a in anns:
     x,y,w,h=a['bbox']
     if w<=0 or h<=0 or x<0 or y<0 or x+w>im['width']+2 or y+h>im['height']+2:schema.append({'asset':rel,'reason':'Annotation box is outside the declared image bounds'})
    items.append({'id':rel,'path':str(path),'split':annpath.parent.name,'width':im['width'],'height':im['height'],'annotations':anns,'contributor':contributors.get(rel,'unknown')})
 return items,classes,schema

def reference_items(root):
 out=[]
 for p in (root/'reference/coco').rglob('_annotations.coco.json'):
  d=read_json(p,{});cats={c['id']:c['name'] for c in d['categories']};by=collections.defaultdict(list)
  for a in d['annotations']:by[a['image_id']].append({'label':cats[a['category_id']],'bbox':a['bbox']})
  for im in d['images']:
   path=safe_path(p.parent,im['file_name'])
   if path.exists():out.append({'id':p.parent.name+'/'+im['file_name'],'path':str(path),'annotations':by[im['id']]})
 return out

def image_features(path,bbox=None):
 with Image.open(path) as src:
  im=src.convert('RGB')
  if bbox:
   x,y,w,h=bbox;im=im.crop((max(0,x),max(0,y),min(src.width,x+w),min(src.height,y+h)))
  if min(im.size)<1:im=src.convert('RGB')
  small=np.asarray(im.resize((32,32)),dtype=np.float32)/255
  gray=small.mean(2);lap=np.roll(gray,1,0)+np.roll(gray,-1,0)+np.roll(gray,1,1)+np.roll(gray,-1,1)-4*gray
  tiny=np.asarray(im.convert('L').resize((9,8)),dtype=float);dh=(tiny[:,1:]>tiny[:,:-1]).ravel();bits=sum(int(v)<<i for i,v in enumerate(dh))
  hist=np.concatenate([np.histogram(small[:,:,c],bins=16,range=(0,1),density=False)[0] for c in range(3)]).astype(float);hist/=hist.sum()+1e-8
  coarse=np.asarray(im.resize((8,8)),dtype=float).ravel()/255;f=np.r_[coarse*0.15,hist*5];f/=np.linalg.norm(f)+1e-8
  energy=np.abs(lap);cells=[float(energy[i:i+8,j:j+8].mean()) for i in range(0,32,8) for j in range(0,32,8)];sort=sorted(cells,reverse=True)
  texture=np.log10((sort[0]+1e-6)/(sort[3]+1e-6))
  return f,{'brightness':float(gray.mean()),'blur':float(lap.var()),'texture':float(texture),'texture_cell':int(np.argmax(cells)),'dhash':f'{bits:016x}','width':src.width,'height':src.height}

class Assessment:
 FEED_LIMIT=4000
 def __init__(self,fixture,policy=None,format='COCO'):
  self.fixture=fixture;self.root=safe_path(DATA/'fixtures',fixture);self.policy={**POLICY,**(policy or {})};self.format=format;self.id='sw-'+uuid.uuid4().hex[:10];self.started=now();self.findings=[];self.checks=[];self.timeline=[];self.progress=0;self.stage='Intake';self.result=None;self.error=None
  # Live evidence feed for the workbench; purely observational, never read by policy.
  self.feed=[];self.loop_steps=[]
 def _emit(self,item):
  if len(self.feed)<self.FEED_LIMIT:self.feed.append({'t':now(),**item})
 def event(self,stage,reason,progress):self.stage=stage;self.progress=progress;self.timeline.append({'stage':stage,'reason':reason,'time':now()});self._emit({'kind':'stage','stage':stage,'reason':reason,'progress':progress})
 def progress_only(self,stage,progress):self.stage=stage;self.progress=progress
 def finding(self,type,claim,asset,reason,severity='medium',measurement=None,confidence=None,source=None,action=None,**extra):
  f={'id':f'f-{len(self.findings)+1:05}','type':type,'claim':claim,'asset':asset,'reason':reason,'severity':severity,'action':action or ('quarantine' if severity=='critical' else 'review'),'measurement':measurement or {},'confidence':confidence,'confidence_status':'measured statistic; not a calibrated compromise probability','source':source or 'unknown','evidence_group':extra.pop('group',type),'time':now(),'policy_version':self.policy['version'],'access':self.policy['access'],'method_version':'shockwave-1.1',**extra};self.findings.append(f)
  self._emit({'kind':'finding','id':f['id'],'type':type,'claim':claim,'asset':asset,'severity':severity,'source':f['source']});return f
 def check(self,name,status,detail,claim,**extra):self.checks.append({'name':name,'status':status,'detail':detail,'claim':claim,**extra});self._emit({'kind':'check','name':name,'status':status,'claim':claim,'detail':detail})
 def run(self):
  try:
   self.event('Intake','Preserving exact artifact identities and profiling access.',5)
   items,classes,schema=inventory(self.fixture,self.format);self.items=items;self.classes=classes
   for s in schema:self.finding('invalid_annotation','data_schema',s['asset'],s['reason'],'high')
   self.check('Dataset schema','Completed',f'{len(items)} images parsed as {self.format}; {len(schema)} structural concerns.','data_schema')
   if not items:raise ValueError('No supported annotated images found')
   self.event('Baseline','Computing local visual evidence and exact identities.',15)
   self.data_checks(items)
   self.event('Model assurance','Inspecting serialization, graph structure and model identity.',55)
   from models import analyse_models,behaviour_checks
   model=analyse_models(self);self.model=model
   self.event('Provenance','Verifying signed bindings, freshness and recorded history.',62)
   verify_records(self)
   self.event('Active assurance','Running the baseline behaviour battery and Twin Pipeline before adaptive challenges.',68)
   behaviour_checks(self)
   import loop
   loop.run(self)
   from extensions import semantic_witness, training_attribution, calibrate
   semantic_witness(self);training_attribution(self);calibrate(self)
   rt=getattr(getattr(self,'ctx',None),'submitted_runtime',None)
   if rt and (self.model or {}).get('execution'):self.model['execution']['calls']=getattr(rt.worker,'calls',None)
   self.event('Decision','Evaluating evidence under the Assurance Contract.',96)
   self.finalize();self.progress=100;self.stage='Complete'
  except Exception as e:
   import traceback;traceback.print_exc();self.error=str(e);self.stage='Failed';self.progress=100
  finally:
   rt=getattr(getattr(self,'ctx',None),'submitted_runtime',None)
   if rt:rt.close()  # terminate the sandboxed worker with the assessment

 # ------------------------------------------------------------------ data assurance
 def data_checks(self,items):
  import forensics
  from sklearn.neighbors import NearestNeighbors
  policy=self.policy;fs=[];stats=[];hashes=collections.defaultdict(list)
  for n,item in enumerate(items):
   b=Path(item['path']).read_bytes();item['sha256']=digest(b);item['sha384']=digest(b,'sha384');hashes[item['sha256']].append(n)
   f,s=image_features(item['path']);fs.append(f);stats.append(s);item['stats']=s
   if n%100==0:self.progress_only('Baseline',15+int(5*n/max(1,len(items))))
  self.image_matrix=np.asarray(fs);self.stats=stats
  # Exact identity, conflicting duplicate labels, cross-split leakage and exact flooding.
  for indices in hashes.values():
   if len(indices)<2:continue
   cluster=[items[i]['id'] for i in indices]
   labels={tuple(sorted(a['label'] for a in items[i]['annotations'])) for i in indices}
   if len(labels)>1:
    for i in indices:self.finding('conflicting_duplicate_label','labels',items[i]['id'],'Identical image bytes carry different annotation class sets.','high',{'matches':cluster,'class_sets':[list(x) for x in labels]},source=items[i]['contributor'])
   cross=len(set(items[i]['split'] for i in indices))>1
   for i in indices[1:]:self.finding('split_leakage' if cross else 'exact_duplicate','split_integrity' if cross else 'duplication',items[i]['id'],f'Identical image bytes occur in {len(indices)} files'+(' across data splits.' if cross else '.'),'high' if cross else 'medium',{'cluster_size':len(indices),'sha256':items[i]['sha256'],'matches':cluster},source=items[i]['contributor'])
   if len(indices)>=10:self.finding('duplicate_flooding','duplication',items[indices[0]]['id'],f'{len(indices)} identical copies reduce effective dataset diversity.','high',{'cluster_size':len(indices)},source=items[indices[-1]]['contributor'])
  # Perceptual near identity; near-duplicate groups also stop repetition from manufacturing corroboration.
  keys=np.array([int(s['dhash'],16) for s in stats],dtype=np.uint64)
  bits=((keys[:,None]>>np.arange(64,dtype=np.uint64))&1).astype(np.float32)
  nn=NearestNeighbors(n_neighbors=min(6,len(items)),metric='hamming',algorithm='brute').fit(bits);dist,idx=nn.kneighbors(bits)
  group=list(range(len(items)))
  def root(i):
   while group[i]!=i:group[i]=group[group[i]];i=group[i]
   return i
  for indices in hashes.values():
   for i in indices[1:]:group[root(i)]=root(indices[0])
  for i in range(len(items)):
   matches=[int(j) for d,j in zip(dist[i],idx[i]) if j!=i and d*64<=policy['duplicate_distance'] and items[j]['sha256']!=items[i]['sha256']]
   for j in matches:group[root(j)]=root(i)
   if matches:self.finding('near_duplicate','duplication',items[i]['id'],f'Perceptual similarity matches {len(matches)} image(s) within {policy["duplicate_distance"]} hash bits.','medium',{'matches':[items[j]['id'] for j in matches],'distance_bits':[int(round(float(d)*64)) for d,j in zip(dist[i],idx[i]) if j in matches]},source=items[i]['contributor'])
  self.image_groups=[root(i) for i in range(len(items))]
  self.check('Cross-split identity','Completed','Exact byte identities compared across all parsed splits.','split_integrity')
  self.check('Exact and near identity','Completed',f'Byte hashes and perceptual comparisons computed; {len(set(self.image_groups))} distinct pictures among {len(items)} files.','duplication')
  texture=np.array([s['texture'] for s in stats]);med=float(np.median(texture));mad=float(np.median(abs(texture-med)))+1e-6
  for i,value in enumerate(texture):
   z=.6745*(float(value)-med)/mad
   if z>policy['texture_z']:self.finding('trigger_texture','poisoning',items[i]['id'],'Local texture energy is unusually concentrated. This can also reflect benign markings or compression.','medium',{'robust_z':round(z,3),'cell':stats[i]['texture_cell'],'corpus_median':med},source=items[i]['contributor'])
  self.event('Baseline','Mining compact patterns that recur across samples (§11.5).',21)
  self.patch_clusters=self.recurring_patch_checks(items)
  # Reference approval is decided before any reference-dependent method runs.
  registry=read_json(DATA/'trust-registry.json',{}).get(self.fixture,{})
  reference_identity=digest(canonical([(str(p.relative_to(self.root)),digest(p.read_bytes())) for p in sorted((self.root/'reference').rglob('*')) if p.is_file()]))
  refs=reference_items(self.root) if reference_identity==registry.get('reference_identity') else []
  self.reference_approved=bool(refs)
  if not refs:self.check('Reference approval','Unavailable','Reference identity is not approved independently of the submission.','distribution')
  objects=[];crops=[]
  for item in items:
   for a in item['annotations']:
    f,_=image_features(item['path'],a['bbox']);crops.append(f);objects.append({'image':item['id'],'path':item['path'],'label':a['label'],'box':a['bbox'],'source':item['contributor'],'sha':item['sha256']})
  matrix=np.asarray(crops);self.objects=objects;self.object_matrix=matrix
  encoder='Local visual descriptor';ref_objects=[];ref_matrix=None
  try:
   from models import encode_crops
   deep=encode_crops(objects,self)
   if deep is not None:
    matrix=deep;self.object_matrix=matrix;encoder='DINOv2'
    if refs:
     import embeddings
     ref_objects=[{'image':r['id'],'path':r['path'],'label':a['label'],'box':a['bbox'],'sha':digest(Path(r['path']).read_bytes())} for r in refs for a in r['annotations']]
     ref_matrix,_=embeddings.encode(ref_objects)
  except Exception as e:self.check('DINOv2 encoder','Unavailable',f'Local encoder could not run: {type(e).__name__}. Visual descriptor fallback is recorded.','labels')
  self.encoder=encoder;self.label_quality=None;self.subpopulation=None;self.ref_objects=ref_objects;self.ref_matrix=ref_matrix
  if len(objects)>2:self.label_checks(objects,matrix,encoder)
  self.event('Baseline','Screening class sub-populations and reference novelty.',50)
  if encoder=='DINOv2' and ref_matrix is not None:
   scores,abstained=forensics.robust_subpopulations(matrix,objects,ref_matrix,ref_objects,policy['robust_margin'])
   flagged=0
   for i,s in scores.items():
    if s['robust_distance']>s['threshold']:
     flagged+=1;self.finding('robust_subpopulation','poisoning',objects[i]['image'],f"Object lies outside the robust core of declared class '{s['class']}' beyond every approved-reference self-score. A planted sub-population or a rare valid example are competing explanations.",'medium',{**s},source=objects[i]['source'],group='DINOv2')
   self.subpopulation={'method':'Robust covariance (MCD after PCA), SPECTRE-inspired; threshold = max approved-reference self-score × margin','margin':policy['robust_margin'],'flagged':flagged,'abstained_classes':abstained,'scored':len(scores)}
   self.check('Robust sub-population screen','Completed' if not abstained else 'Limited',f'{len(scores)} objects scored, {flagged} beyond the reference-calibrated envelope; {len(abstained)} classes abstained for lack of approved references.','poisoning')
   distance,threshold=forensics.reference_novelty(matrix,ref_matrix,policy['ood_quantile'])
   worst={}
   for i,d in enumerate(distance):
    if d>threshold and d>worst.get(objects[i]['image'],(0,))[0]:worst[objects[i]['image']]=(float(d),i)
   for image,(d,i) in worst.items():self.finding('out_of_distribution','distribution',image,'Object is farther from every approved reference crop than the reference envelope allows. Valid novelty, a new sensor or a foreign insertion are competing explanations.','medium',{'distance':d,'reference_threshold':float(threshold),'method':'DINOv2 nearest approved-reference crop','declared':objects[i]['label']},source=objects[i]['source'],group='DINOv2')
   self.semantic_novelty={'threshold':float(threshold),'quantile':policy['ood_quantile'],'flagged_images':len(worst),'reference_objects':len(ref_objects)}
   self.check('Semantic reference novelty','Completed',f'{len(ref_objects)} approved reference crops; {len(worst)} submitted images outside the {policy["ood_quantile"]} reference envelope.','distribution')
  elif encoder=='DINOv2':
   for label in set(o['label'] for o in objects):
    ids=[i for i,o in enumerate(objects) if o['label']==label]
    if len(ids)<10:continue
    m=matrix[ids];center=np.median(m,axis=0);distance=np.linalg.norm(m-center,axis=1);median=np.median(distance);mad=np.median(abs(distance-median))+1e-6
    for i,dd in zip(ids,distance):
     z=.6745*(dd-median)/mad
     if z>5:self.finding('representation_outlier','poisoning',objects[i]['image'],'This object lies far from its declared class representation. Rare valid examples are an alternative explanation.','medium',{'robust_z':float(z),'class':label},source=objects[i]['source'],group=encoder)
   self.check('Robust sub-population screen','Unavailable','Approved reference embeddings are required to calibrate the robust screen; median-distance fallback used.','poisoning')
  self.check('Texture / representation','Completed','Local image statistics and class-conditional outliers; correlated features grouped.','poisoning')
  self.drift={'available':bool(refs),'reference_images':len(refs),'encoder':'Local visual descriptor','cause':'Unresolved'}
  if refs:
   rf=[];rstats=[]
   for item in refs:
    f,s=image_features(item['path']);rf.append(f);rstats.append(s)
   ref=np.asarray(rf);rnn=NearestNeighbors(n_neighbors=min(2,len(ref)),metric='cosine').fit(ref);cal=rnn.kneighbors(ref)[0][:,-1];threshold=max(float(np.quantile(cal,policy['ood_quantile'])),.05);distance=rnn.kneighbors(self.image_matrix,n_neighbors=1)[0].ravel()
   if encoder!='DINOv2':
    for i,d in enumerate(distance):
     if d>threshold:self.finding('out_of_distribution','distribution',items[i]['id'],'Image differs materially from its nearest approved reference. Drift or valid novelty may explain the difference.','medium',{'distance':float(d),'reference_threshold':threshold,'method':'descriptor'},source=items[i]['contributor'],group='local_descriptor')
   from sklearn.metrics.pairwise import rbf_kernel
   rng=np.random.default_rng(2026);x=self.image_matrix[rng.choice(len(items),min(200,len(items)),replace=False)];y=ref[rng.choice(len(ref),min(200,len(ref)),replace=False)];n=min(len(x),len(y));x=x[:n];y=y[:n];allv=np.vstack([x,y]);K=rbf_kernel(allv,gamma=4)
   def score(a,b):return float(K[np.ix_(a,a)].mean()+K[np.ix_(b,b)].mean()-2*K[np.ix_(a,b)].mean())
   stat=score(np.arange(n),np.arange(n,2*n));perms=[]
   for _ in range(99):perm=rng.permutation(2*n);perms.append(score(perm[:n],perm[n:]))
   p=(1+sum(v>=stat for v in perms))/100
   means={k:{'current':float(np.mean([s[k] for s in stats])),'reference':float(np.mean([s[k] for s in rstats]))} for k in ('brightness','blur','texture')}
   self.drift.update({'statistic':stat,'p_value':p,'window':n,'ood_images':int(sum(distance>threshold)),'threshold':threshold,'factors':means,'distances':[float(d) for d in distance[:300]],'semantic':getattr(self,'semantic_novelty',None),'limitation':'Permutation test, 99 permutations; descriptor-space shift does not establish cause or maliciousness.'})
   if p<=.05:self.finding('distribution_shift','distribution','dataset','Current and reference distributions differ under a kernel two-sample test; cause remains unresolved.','medium',{'mmd_squared':stat,'p_value':p,'sample_count':n},group='local_descriptor')
   self.check('Reference distribution','Completed',f'{len(refs)} references; distance screen and permutation MMD test.','distribution')
  else:self.check('Reference distribution','Unavailable','No approved reference set available.','distribution')
  sources=collections.Counter(i['contributor'] for i in items);self.sources=[]
  for source,total in sources.items():
   f=[f for f in self.findings if f['source']==source];affected=len(set(x['asset'] for x in f));self.sources.append({'source':source,'images':total,'affected':affected,'rate':affected/total,'findings':len(f),'classes':dict(collections.Counter(a['label'] for i in items if i['contributor']==source for a in i['annotations'])),'status':'Unavailable' if source=='unknown' else 'Measured'})
  self.check('Source aggregation','Completed' if 'unknown' not in sources else 'Limited','Counts and affected-image rates shown; no attacker attribution is inferred.','source_risk')

 def recurring_patch_checks(self,items):
  import forensics
  policy=self.policy;rows=forensics.mine_patches(items)
  clusters=forensics.recurring_patches(items,rows,self.image_groups,policy['patch_similarity'],policy['patch_min_images'])
  kept=[]
  for n,c in enumerate(clusters):
   top_source,top_count=max(c['sources'].items(),key=lambda x:x[1]);share=top_count/len(c['images'])
   placed=c['position_spread'] is not None and c['position_spread']<=.15
   concentrated=share>=.75
   c.update({'id':f'patch-{n+1}','top_source':top_source,'source_share':share,'position_consistent':placed,'source_concentrated':concentrated,'suspicious':placed or concentrated,'exemplar_png':forensics.patch_png(c['exemplar_rgb'])})
   if c['suspicious']:
    severity='high' if placed and concentrated else 'medium'
    why=('at a consistent position relative to the annotated object' if placed else '')+(' and ' if placed and concentrated else '')+(f'concentrated in {top_source} ({share:.0%})' if concentrated else '')
    for image in c['images']:
     self.finding('recurring_patch','poisoning',image,f'A compact high-gradient pattern recurs across {c["distinct_pictures"]} distinct pictures {why}. Insignia, watermarks and camouflage are benign alternatives.',severity,{'cluster':c['id'],'cluster_images':len(c['images']),'distinct_pictures':c['distinct_pictures'],'mean_similarity':round(c['mean_similarity'],4),'box_relative_position':c['box_relative_position'],'position_spread':c['position_spread'],'top_source':top_source,'source_share':round(share,3),'declared_labels':c['declared_labels']},source=next((i['contributor'] for i in items if i['id']==image),'unknown'),group='patch_texture')
   kept.append(c)
  suspicious=[c for c in kept if c['suspicious']]
  self.check('Recurring compact patterns','Completed',f'{len(rows)} corner-dense windows mined; {len(kept)} recurring clusters, {len(suspicious)} position-consistent or source-concentrated.','poisoning')
  return kept

 def label_checks(self,objects,matrix,encoder):
  import forensics
  policy=self.policy;k=policy['neighbours']
  if encoder=='DINOv2':
   import faiss
   faiss.omp_set_num_threads(1)
   index=faiss.IndexFlatIP(matrix.shape[1]);index.add(np.ascontiguousarray(matrix,dtype=np.float32));similarity,js=index.search(np.ascontiguousarray(matrix,dtype=np.float32),min(k+8,len(objects)));ds=1-similarity
  else:
   from sklearn.neighbors import NearestNeighbors
   knn=NearestNeighbors(n_neighbors=min(k+8,len(objects)),metric='cosine').fit(matrix);ds,js=knn.kneighbors(matrix)
  self.neighbours=(ds,js)
  votes=forensics.neighbour_votes(objects,ds,js,k);self.votes=votes
  classes=sorted(set(o['label'] for o in objects))
  cl=forensics.confident_learning(objects,votes,classes,policy['label_threshold'])
  if policy['label_method']=='confident_learning':
   for x in cl['issues']:
    obj=objects[x['index']];votes_i=votes[x['index']]
    if x['similarity']<.55:continue
    self.finding('label_disagreement','labels',obj['image'],f"Declared '{obj['label']}', but '{x['alternative']}' reaches {x['share']:.0%} of independent neighbour votes, above its per-class confident threshold {x['threshold']:.0%}. Label-quality evidence, not proof of intent.",'medium',{'declared':obj['label'],'alternative':x['alternative'],'votes':int(round(x['share']*len(votes_i))),'neighbours':len(votes_i),'similarity':round(x['similarity'],3),'class_threshold':x['threshold'],'method':'confident_learning','examples':[objects[j]['image'] for d,j in votes_i[:5]],'box':obj['box']},source=obj['source'],group=encoder)
  else:
   for i,obj in enumerate(objects):
    row=votes[i]
    if not row:continue
    counts=collections.Counter(objects[j]['label'] for d,j in row);alt,count=counts.most_common(1)[0];mean=float(np.mean([1-d for d,j in row]));ratio=count/len(row)
    if alt!=obj['label'] and ratio>=policy['label_threshold'] and mean>=0.55:
     self.finding('label_disagreement','labels',obj['image'],f"Declared '{obj['label']}', but {count}/{len(row)} independent image neighbours favour '{alt}'. This is label-quality evidence, not proof of malicious intent.",'medium',{'declared':obj['label'],'alternative':alt,'votes':count,'neighbours':len(row),'similarity':round(mean,3),'method':'neighbour_plurality','examples':[objects[j]['image'] for d,j in row[:5]],'box':obj['box']},source=obj['source'],group=encoder)
  self.label_quality={'method':policy['label_method'],'encoder':encoder,'confident_joint':cl['joint'],'classes':cl['classes'],'thresholds':cl['thresholds'],'contributor_pairs':forensics.contributor_pairs(objects,cl['issues'])[:40]}
  if encoder=='DINOv2':
   parent=list(range(len(objects)))
   def find(i):
    while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
    return i
   for i in range(len(objects)):
    for d,j in zip(ds[i],js[i]):
     if j!=i and d<=.015:parent[find(int(j))]=find(i)
   clusters=collections.defaultdict(list)
   for i in range(len(objects)):clusters[find(i)].append(i)
   for ids in clusters.values():
    images=set(objects[i]['image'] for i in ids)
    if len(images)>=10:
     by_source=collections.defaultdict(set)
     for i in ids:by_source[objects[i]['source']].add(objects[i]['image'])
     source,maximages=max(by_source.items(),key=lambda x:len(x[1]))
     self.finding('duplicate_flooding','duplication',objects[ids[0]]['image'],'A large, highly similar semantic neighbourhood concentrates repeated contribution content.','medium',{'cluster_images':len(images),'largest_source':source,'source_images':len(maximages),'similarity_threshold':.985,'examples':sorted(images)[:40]},source=source,group=encoder)
  self.check('Label neighbourhoods','Completed',f'{len(objects)} object crops; {encoder}; {policy["label_method"].replace("_"," ")}; exact-image duplicates excluded from votes.','labels')
  if encoder!='DINOv2':self.check('DINOv2 encoder','Unavailable','No local pretrained weights configured; descriptor fallback is not equivalent to a semantic backbone.','labels')

 def limitations(self):
  out=['Anomalies do not prove attack intent.','Negative conditional tests do not exclude all backdoors.']
  risk=getattr(self,'risk',{}) or {}
  out.append('Calibrated probabilities apply only to Attack Lab attack families in this operating context.' if risk.get('calibrated') else 'Raw scores are not calibrated compromise probabilities.')
  try:
   import keystore;hw=keystore.status()
  except Exception:hw={'available':False}
  execution=(getattr(self,'model',None) or {}).get('execution') or {}
  out.append(('Key custody: report co-signed by a Secure Enclave key (device-bound); the Ed25519 signature key is a file on disk.' if hw.get('available') else 'No hardware-backed key custody: no Secure Enclave available.')
   +(' Submitted model executed in an OS-sandboxed worker; no hardware attestation of execution.' if execution.get('isolation','').startswith('macOS') else ' No hardware attestation of execution.'))
  return out

 def finalize(self):
  self.claims=[]
  for id,label,domain in CLAIMS:
   fs=[f for f in self.findings if f['claim']==id];state=claim_state(self.findings,self.checks,id)
   applicable=not (domain=='model' and not list((self.root/'submission/models').glob('*'))) and not (domain=='records' and not (self.root/'submission/records/records.jsonl').exists())
   self.claims.append({'id':id,'label':label,'domain':domain,'state':state,'applicable':applicable,'findings':len(fs),'mandatory':id in self.policy['mandatory'] and applicable,'evidence':[f['id'] for f in fs]})
  if any(f['severity']=='critical' for f in self.findings):decision='Quarantine'
  elif self.findings or any(c['mandatory'] and c['state']!='Supported' for c in self.claims) or any(c['id']=='calibration' and c['state']=='Unresolved' for c in self.claims):decision='Review'
  else:decision='Accept'
  from lifecycle import snapshot as take_snapshot
  snapshot=take_snapshot(self.root,self.policy,self.fixture)
  result={'parent_run':getattr(self,'parent_run',None),'revalidated_claims':sorted(getattr(self,'affected',set())),'reused_claims':sorted(getattr(self,'reused',set())),'snapshot':snapshot,'risk':getattr(self,'risk',{}),'label_quality':getattr(self,'label_quality',None),'subpopulation':getattr(self,'subpopulation',None),'patch_clusters':[{k:v for k,v in c.items() if k not in ('exemplar_rgb','members')} for c in getattr(self,'patch_clusters',[])],'loop':getattr(self,'loop',None),'encoder':getattr(self,'encoder',None),'semantic_witness':getattr(self,'witness',{}),'id':self.id,'fixture':self.fixture,'name':LABELS.get(self.fixture) or (read_json(self.root/'manifest.json',{}) or {}).get('name',self.fixture),'created':self.started,'completed':now(),'decision':decision,'policy':self.policy,'format':self.format,'images':len(self.items),'objects':len(self.objects),'classes':self.classes,'findings':self.findings,'checks':self.checks,'claims':self.claims,'sources':self.sources,'drift':self.drift,'model':self.model,'records':getattr(self,'records',{}),'timeline':self.timeline,'evaluation':None,'capabilities':CAPABILITIES,'limitations':self.limitations(),'assets':[{'id':i['id'],'source':i['contributor'],'sha256':i['sha256'],'stats':i['stats'],'annotations':i['annotations']} for i in self.items]}
  result['finding_types']=dict(collections.Counter(f['type'] for f in self.findings));result['severity_counts']=dict(collections.Counter(f['severity'] for f in self.findings));result['report_digest']=digest(canonical(result),'sha384');result['report_signature']=base64.b64encode(key().sign(bytes.fromhex(result['report_digest']))).decode()
  hw=hardware_cosign(bytes.fromhex(result['report_digest']))
  if hw:result['hardware_signature']=hw
  atomic(STATE/'runs'/f'{self.id}.json',result);log_event('assessment',{'run':self.id,'decision':decision,'report_digest':result['report_digest'],'images':len(self.items),'findings':len(self.findings)});self.result=result

def verify_records(a):
 path=a.root/'submission/records/records.jsonl'
 if not path.exists():a.records={'total':0,'verified':0,'rows':[]};a.check('Inference records','Unavailable','No records supplied; record claims are not applicable.','provenance');return
 registry=read_json(DATA/'trust-registry.json',{}).get(a.fixture,{})
 keys={k['key_id']:k for k in registry.get('keys',[])};trusted=set(keys)
 trust=registry
 if not trusted:a.check('Edge-key trust','Unavailable','No independently approved edge-key registry; submitted public keys cannot approve themselves.','provenance')
 expected_models=set(d['model_id'] for d in trust.get('deployments',[]))
 clean=a.root/'suite/models/clean.safetensors'
 if clean.exists():expected_models.add(digest(clean.read_bytes()))
 seen=set();last={};rows=[]
 for lineno,line in enumerate(path.read_text().splitlines(),1):
  try:r=json.loads(line)
  except ValueError:
   a.finding('record_unparseable','provenance',f'line {lineno}','Inference envelope is not valid JSON.','critical');rows.append({'id':f'line-{lineno}','status':'Failed','issues':['Unparseable record']});continue
  required=('input','model','config','output','output_sha256','record_sha256','session_id','sequence','prev_record_sha256')
  if not isinstance(r,dict) or any(k not in r for k in required) or any(not isinstance(r.get(k),dict) for k in ('input','model','config','output')) or not isinstance(r.get('sequence'),int) or r.get('sequence',-1)<0 or not isinstance(r.get('session_id'),str):
   a.finding('record_unparseable','provenance',f'line {lineno}','Inference envelope lacks required typed bindings or freshness fields.','critical');rows.append({'id':f'line-{lineno}','status':'Failed','issues':['Invalid envelope schema']});continue
  try:canonical(r)
  except (ValueError,TypeError):
   a.finding('record_unparseable','provenance',f'line {lineno}','Inference envelope contains prohibited non-finite or non-canonical values.','critical');rows.append({'id':f'line-{lineno}','status':'Failed','issues':['Invalid canonical values']});continue
  ident=f"{r.get('session_id','unknown')}#{r.get('sequence','?')}";issues=[];body={k:v for k,v in r.items() if k not in ('signature','record_sha256','signer')};actual=digest(canonical(body));signer=r.get('signer')
  def fail(t,c,reason):
   issues.append(reason);a.finding(t,c,ident,reason,'critical',{'line':lineno,'session':r.get('session_id'),'sequence':r.get('sequence')})
  if actual!=r.get('record_sha256'):fail('record_altered','provenance','Canonical record digest differs from the sealed digest.')
  if not r.get('signature'):fail('record_unsigned','provenance','Record has no signature.')
  elif signer not in trusted:fail('untrusted_signer','provenance','Signer is not in the approved edge-key registry.')
  else:
   try:Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[signer]['public_key'])).verify(base64.b64decode(r['signature']),bytes.fromhex(r['record_sha256']))
   except Exception:fail('signature_invalid','provenance','Ed25519 verification failed for this record.')
  inp=r.get('input',{});ref=inp.get('ref')
  if not ref:fail('input_missing','provenance','Original input reference is missing from the signed binding.')
  if ref:
   try:ip=safe_path(path.parent,ref)
   except ValueError:ip=None
   if not ip or not ip.exists():fail('input_missing','provenance','Referenced original input is unavailable.')
   elif digest(ip.read_bytes())!=inp.get('sha256'):fail('input_substituted','provenance','Referenced input bytes no longer match the signed binding.')
  if digest(canonical(r.get('output',{})))!=r.get('output_sha256'):fail('output_altered','provenance','Prediction payload does not match its output digest.')
  model=r.get('model',{})
  if expected_models and model.get('model_id') not in expected_models:fail('model_substitution','provenance','Recorded model identity is not approved for this deployment.')
  cfg=r.get('config',{})
  for stage in ('preprocess','postprocess'):
   if cfg.get(stage+'_sha256') and digest(canonical(cfg.get(stage,{})))!=cfg[stage+'_sha256']:fail('config_mismatch','provenance',f'{stage.title()} digest differs from the recorded configuration.')
  deployments=trust.get('deployments',[])
  dep=next((d for d in deployments if d.get('label')==model.get('name')),None)
  if dep and any(dep.get(s+'_sha256') is not None and cfg.get(s+'_sha256')!=dep.get(s+'_sha256') for s in ('preprocess','postprocess')):fail('config_mismatch','provenance','Recorded processing configuration is not the approved deployment configuration.')
  session=r.get('session_id');seq=r.get('sequence');identity=(session,seq)
  if identity in seen:fail('record_replayed','replay','Session and sequence were already observed in this submitted history.')
  seen.add(identity)
  if session in last:
   prevseq,prevhash=last[session]
   if not isinstance(seq,int) or seq<=prevseq:fail('record_reordered','history','Sequence is stale or out of order.')
   elif seq!=prevseq+1:fail('record_gap','history','Sequence gap indicates missing history or delivery discontinuity.')
   if r.get('prev_record_sha256')!=prevhash:fail('chain_fork','history','Previous-record link does not match the observed predecessor.')
  last[session]=(seq,r.get('record_sha256'))
  rows.append({'id':ident,'status':'Failed' if issues else 'Verified','issues':issues,'signer':signer,'input':ref,'model':model.get('name'),'hash':r.get('record_sha256'),'signature':bool(r.get('signature')),'record':r})
 a.records={'total':len(rows),'verified':sum(r['status']=='Verified' for r in rows),'failed':sum(r['status']=='Failed' for r in rows),'rows':rows,'reproduction':None,'profile':'Canonical record-v1 + SHA-256 + Ed25519 over digest','limitation':'Fixture edge keys are evaluation keys. Missing suffix detection requires an independently retained checkpoint. Freshness is scoped to each supplied session history.'}
 for name,claim in [('Envelope and signature','provenance'),('Session replay checks','replay'),('Sequence / chain history','history')]:a.check(name,'Completed',f'{len(rows)} records inspected with explicitly trusted keys.',claim)
