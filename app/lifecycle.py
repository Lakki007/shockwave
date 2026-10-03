"""Dependency-based revalidation that retains verified unaffected evidence."""
import base64,copy
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import core
from provenance import report_verify

def snapshot(root,policy,fixture):
 out={}
 for domain,folders in {'data':['submission/coco','submission/yolo'],'model':['submission/models'],'pipeline':['submission/pipeline.json'],'reference':['reference','trust','suite/models']}.items():
  paths=[]
  for folder in folders:
   target=root/folder;paths.extend([target] if target.is_file() else target.rglob('*') if target.exists() else [])
  out[domain]=core.digest(core.canonical([(str(p.relative_to(root)),core.digest(p.read_bytes())) for p in sorted(set(paths)) if p.is_file()]))
 out['policy']=core.digest(core.canonical(policy));out['context']=core.digest(core.canonical({'context':policy['context'],'task':policy['task']}));out['keys']=core.digest(core.canonical(core.read_json(core.DATA/'trust-registry.json',{}).get(fixture,{})));return out

class Reassessment(core.Assessment):
 def __init__(self,previous,declared_changes,policy=None):
  pub=base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
  if not report_verify(previous,pub)['verified']:raise ValueError('Previous report does not verify under the trusted assessor key')
  super().__init__(previous['fixture'],{**previous['policy'],**(policy or {})},previous['format']);self.previous=previous;current=snapshot(self.root,self.policy,self.fixture);actual=[k for k,v in current.items() if previous.get('snapshot',{}).get(k)!=v];self.changes=sorted(set(actual+declared_changes));self.affected={c for change in self.changes for c in core.DEPENDENCIES.get(change,[])};self.reused={c[0] for c in core.CLAIMS}-self.affected;self.parent_run=previous['id']
 def finding(self,*args,**kwargs):
  claim=args[1] if len(args)>1 else kwargs.get('claim')
  if claim in self.affected:return super().finding(*args,**kwargs)
 def check(self,*args,**kwargs):
  claim=args[3] if len(args)>3 else kwargs.get('claim')
  if claim in self.affected:return super().check(*args,**kwargs)
 def run(self):
  try:
   prior=self.previous;self.event('Assurance delta',f'{len(self.affected)} claims invalidated by {", ".join(self.changes) or "no asset changes"}; verifying retained evidence.',5)
   self.findings=[{**copy.deepcopy(f),'reused_from':prior['id']} for f in prior['findings'] if f['claim'] in self.reused]
   # Fresh IDs keep the report ledger unambiguous after selective retention.
   for i,f in enumerate(self.findings,1):f['id']=f'f-{i:05}'
   self.checks=[{**copy.deepcopy(c),'reused_from':prior['id']} for c in prior['checks'] if c['claim'] in self.reused]
   self.items,self.classes,schema=core.inventory(self.fixture,self.format)
   if self.affected & {'data_schema','data_identity','duplication','split_integrity','labels','poisoning','source_risk','distribution'}:
    for x in schema:self.finding('invalid_annotation','data_schema',x['asset'],x['reason'],'high')
    self.check('Dataset schema','Completed',f'{len(self.items)} images parsed; {len(schema)} structural concerns.','data_schema');self.data_checks(self.items)
   else:
    old={x['id']:x for x in prior['assets']}
    for item in self.items:
     record=old[item['id']];item['sha256']=record['sha256'];item['stats']=record['stats'];item['sha384']=core.digest(Path(item['path']).read_bytes(),'sha384')
    self.objects=[{'image':x['id'],'path':x['path'],'label':an['label'],'box':an['bbox'],'source':x['contributor'],'sha':x['sha256']} for x in self.items for an in x['annotations']];self.sources=copy.deepcopy(prior['sources']);self.drift=copy.deepcopy(prior['drift']);self.event('Evidence reuse','Data identities unchanged. Retained data findings and source evidence remain bound to the verified parent report.',45)
   from models import analyse_models,behaviour_checks
   if self.affected & {'model_identity','safe_intake'}:self.model=analyse_models(self)
   else:self.model=copy.deepcopy(prior['model'])
   if self.affected & {'provenance','replay','history','reproduction'}:core.verify_records(self)
   else:self.records=copy.deepcopy(prior['records'])
   if self.affected & {'behaviour','backdoor','pipeline','reproduction'}:
    behaviour_checks(self)
    import loop
    loop.run(self)
   from extensions import semantic_witness,training_attribution,calibrate
   if 'poisoning' in self.affected:semantic_witness(self)
   if 'backdoor' in self.affected:training_attribution(self)
   calibrate(self);self.event('Decision','Revalidated affected claims and retained unaffected evidence with a parent-report linkage.',94);self.finalize();self.progress=100;self.stage='Complete'
  except Exception as e:
   import traceback;traceback.print_exc();self.error=str(e);self.progress=100;self.stage='Failed'
