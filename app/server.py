"""Local-only Shockwave workspace. No external service is required."""
import argparse, collections, io, json, mimetypes, os, threading, uuid, zipfile
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs
import core
JOBS={}

SUMMARIES={}

def summary(r):return {**{k:r.get(k) for k in ('id','name','fixture','created','completed','decision','images','objects','finding_types','severity_counts','format','report_digest','parent_run')},'loop_steps':len((r.get('loop') or {}).get('steps',[])),'engine':(r.get('policy') or {}).get('version')}

SHOWCASE={}

def showcase(summaries):
 """Latest Attack Lab run scored against its sealed key (read-only; no audit event)."""
 lab=next((r for r in summaries if r['fixture'].startswith('lab-') and r.get('engine')=='shockwave-1.1'),None)
 if not lab:return None
 if lab['id'] not in SHOWCASE:
  import forge
  r=core.read_json(core.safe_path(core.STATE/'runs',lab['id']+'.json'));s=forge.score(r) if r else None
  if not s:return None
  planted=sum(a['planted'] for a in s['attacks']);caught=sum(a['detected'] for a in s['attacks'])
  rec=s['records'];extra=[x for x in (s['model'].get('detected'),s['pipeline'].get('detected')) if x is not None]
  SHOWCASE[lab['id']]={'run':lab['id'],'fixture':lab['fixture'],'decision':lab['decision'],'planted_samples':planted,'caught_samples':caught,'records_tampered':len(rec),'records_caught':sum(x['detected'] for x in rec),'model':s['model'],'pipeline':s['pipeline'],'attacks':s['attack_summary'],'answer_key_intact':s['answer_key_intact'],'commitment':s['commitment'],'untouched_flagged':s['untouched_images_flagged'],'untouched':s['untouched_images'],'components_caught':sum(bool(x) for x in extra),'components':len(extra),'families':s['attacks']}
 return SHOWCASE[lab['id']]

def run_summaries():
 """Run summaries, re-read only when a sealed report file changes."""
 seen=set()
 for p in (core.STATE/'runs').glob('*.json'):
  seen.add(p);m=p.stat().st_mtime
  if SUMMARIES.get(p,(None,))[0]!=m:
   r=core.read_json(p)
   if r:SUMMARIES[p]=(m,summary(r))
 for p in list(SUMMARIES):
  if p not in seen:SUMMARIES.pop(p)
 return sorted((v[1] for v in SUMMARIES.values()),key=lambda r:r['completed'],reverse=True)

RANGES=[('neighbours',2,60),('duplicate_distance',0,16),('label_threshold',.5,1),('ood_quantile',.8,.999),('texture_z',1,12),('robust_margin',1,2),('patch_similarity',.8,.98),('patch_min_images',3,50),('challenge_budget',0,64),('trigger_steps',40,400),('numerical_tolerance',0,.2)]
CHOICES={'access':('white-box','grey-box','black-box'),'label_method':('neighbour_plurality','confident_learning'),'loop_mode':('exhaustive','decisive')}

def validate_policy(policy):
 if not isinstance(policy,dict) or set(policy)-set(core.POLICY):raise ValueError('Unknown contract field')
 for field,lo,hi in RANGES:
  if field in policy and (isinstance(policy[field],bool) or not isinstance(policy[field],(int,float)) or not lo<=policy[field]<=hi):raise ValueError('Contract threshold out of range: '+field)
 for field,options in CHOICES.items():
  if field in policy and policy[field] not in options:raise ValueError(f'Unsupported {field.replace("_"," ")}')
 if 'mandatory' in policy and (not isinstance(policy['mandatory'],list) or set(policy['mandatory'])-{c[0] for c in core.CLAIMS}):raise ValueError('Unknown mandatory claim')
 for field in ('task','context'):
  if field in policy and (not isinstance(policy[field],str) or len(policy[field])>200):raise ValueError(f'Invalid {field}')

def assess(body):
 fixture=body.get('fixture','synthetic'); core.safe_path(core.DATA/'fixtures',fixture)
 policy=body.get('policy',{})
 allowed=set(core.POLICY)
 if not isinstance(policy,dict) or set(policy)-allowed:raise ValueError('Unknown contract field')
 validate_policy(policy)
 if any(a.progress<100 for a in JOBS.values()):raise ValueError('An assessment is already active')
 if body.get('format','COCO') not in ('COCO','YOLO'):raise ValueError('Unsupported dataset format')
 a=core.Assessment(fixture,policy,body.get('format','COCO'));JOBS[a.id]=a;threading.Thread(target=a.run,daemon=True).start();return {'job':a.id}

def delta(body):
 r=core.read_json(core.STATE/'runs'/f"{body['run']}.json")
 if not r:raise ValueError('Unknown assessment')
 changes=body.get('changes',[])
 affected=set(c for change in changes for c in core.DEPENDENCIES.get(change,[]))
 out={'run':r['id'],'changes':changes,'affected_claims':sorted(affected),'claims':[{**c,'state':'Stale' if c['id'] in affected and c['applicable'] else c['state']} for c in r['claims']],'reason':'Changed dependencies invalidate the affected assurance claims; unaffected claims retain their evidence.','timestamp':core.now()}
 core.log_event('assurance_delta',{'run':r['id'],'changes':changes,'affected_claims':sorted(affected)});return out

FAMILIES={'trigger':{'trigger_texture','representation_outlier','robust_subpopulation','recurring_patch'},'label_flips':{'label_disagreement','conflicting_duplicate_label'},'exact_duplicates':{'exact_duplicate','split_leakage'},'near_duplicates':{'near_duplicate'},'flooding':{'duplicate_flooding','near_duplicate'},'ood':{'out_of_distribution'}}

def job_status(a,since=0):
 """Progress plus the live evidence feed after `since`; observational only."""
 feed=getattr(a,'feed',[]);out={'id':a.id,'kind':'forge' if a.id.startswith('lab-') else 'assessment','progress':a.progress,'stage':a.stage,'timeline':a.timeline[-40:],'error':a.error,'complete':bool(a.result),'cursor':len(feed),'feed':feed[since:since+400]}
 if out['kind']=='forge':out['result']=a.result
 else:
  fs=a.findings;out['counts']={'findings':len(fs),'critical':sum(f['severity']=='critical' for f in fs),'high':sum(f['severity']=='high' for f in fs),'checks':len(a.checks),'loop_steps':len(getattr(a,'loop',{}) and a.loop.get('steps',[]) or [])}
  out['claims']={c[0]:core.claim_state(fs,a.checks,c[0]) for c in core.CLAIMS}
 return out

def embedding_map(ident):
 """3-D PCA of the run's DINOv2 object embeddings, linked to concrete samples (§27)."""
 import numpy as np,embeddings
 r=core.read_json(core.safe_path(core.STATE/'runs',ident+'.json'))
 if not r:raise ValueError('Unknown assessment')
 cache=core.STATE/'maps'/f'{ident}.json'
 if cache.exists():return core.read_json(cache)
 if not embeddings.available():return {'available':False,'reason':'Local DINOv2 weights are not installed.'}
 items,_,_=core.inventory(r['fixture'],r['format']);by={a['id']:a for a in r['assets']}
 objects=[{'image':i['id'],'path':i['path'],'label':a['label'],'box':a['bbox'],'sha':by[i['id']]['sha256']} for i in items if i['id'] in by for a in i['annotations']]
 if len(objects)<4:return {'available':False,'reason':'Too few objects.'}
 M,_=embeddings.encode(objects);M=M-M.mean(0);_,sv,vt=np.linalg.svd(M,full_matrices=False);P=M@vt[:3].T;P/=np.abs(P).max(0)+1e-9
 rank={'critical':4,'high':3,'medium':2,'low':1};worst={};types={}
 for f in r['findings']:
  if rank.get(f['severity'],0)>worst.get(f['asset'],0):worst[f['asset']]=rank[f['severity']];types[f['asset']]=f['type']
 labels=sorted(set(o['label'] for o in objects));images=sorted(set(o['image'] for o in objects));ii={x:n for n,x in enumerate(images)}
 out={'available':True,'run':ident,'labels':labels,'images':images,'explained_variance':[float(x) for x in (sv[:3]**2/(sv**2).sum())],'types':sorted(set(types.values())),
      'points':[[round(float(p[0]),4),round(float(p[1]),4),round(float(p[2]),4),labels.index(o['label']),worst.get(o['image'],0),ii[o['image']],sorted(set(types.values())).index(types[o['image']]) if o['image'] in types else -1] for p,o in zip(P,objects)],
      'encoder':'DINOv2-S/14 CLS, PCA to 3 components','note':'A projection for exploration; distances in 3-D are not the detector distances.'}
 core.atomic(cache,out);return out

def evaluate(body):
 r=core.read_json(core.STATE/'runs'/f"{body['run']}.json")
 if not r:raise ValueError('Unknown assessment')
 if r['fixture'].startswith('lab-'):
  import forge
  lab=forge.score(r)
  if not lab:return {'available':False,'reason':'The sealed answer key for this Attack Lab package is unavailable.'}
  core.log_event('evaluation',{'run':r['id'],'attack_lab':r['fixture'],'answer_key_sha384':lab['commitment'],'answer_key_intact':lab['answer_key_intact']})
  return {'available':True,'run':r['id'],'lab':lab,'metrics':[],'reason':'Scored against the Attack Lab answer key that was sealed and committed to the audit log before assessment.'}
 root=core.DATA/'fixtures'/r['fixture'];truth=core.read_json(root/'ground_truth.json') or core.read_json(root/'suite/ground_truth.json')
 if not truth:return {'available':False,'reason':'No held-out scenario answer key supplied.'}
 # This endpoint is the only consumer of scenario truth; matching is image-level within declared families.
 def stems(value):
  if isinstance(value,dict):return set(value.get('stems',[]))
  if isinstance(value,list):return set(x.get('stem') if isinstance(x,dict) else x for x in value)
  return set()
 metrics=[];universe={Path(a['id']).stem for a in r['assets']}
 planted={name:stems(truth.get(name,[]))&universe for name in FAMILIES}
 for name,types in FAMILIES.items():
  expected=planted[name]
  if not expected:continue
  detected={Path(f['asset']).stem for f in r['findings'] if f['type'] in types and Path(f['asset']).stem in universe};tp=len(expected&detected);fp_set=detected-expected;fn=len(expected-detected)
  # A flag on a sample planted for another condition is a correct anomaly for the wrong family, not a false alarm on clean data.
  explained=fp_set&set().union(*[v for k,v in planted.items() if k!=name]);fp=len(fp_set)
  metrics.append({'family':name,'unit':'unique image stem','expected':len(expected),'detected':len(detected),'true_positive':tp,'false_positive':fp,'false_positive_other_planted':len(explained),'false_positive_unplanted':fp-len(explained),'false_negative':fn,'precision':tp/(tp+fp) if tp+fp else None,'precision_excluding_other_planted':tp/(tp+fp-len(explained)) if tp+fp-len(explained) else None,'recall':tp/len(expected),'matching_types':sorted(types),'misses':sorted(expected-detected)[:30]})
 result={'available':True,'run':r['id'],'metrics':metrics,'metrics_available':bool(metrics),'method':'Explicit image-stem and finding-family matching. One image is counted once per family; each family is a separate binary scenario condition.','reason':'These are fixture-specific scenario results. They do not establish operational attack probabilities or generalised accuracy.','scenario_inventory':{k:len(v) if isinstance(v,list) else len(v.get('stems',[])) if isinstance(v,dict) else v for k,v in truth.items()},'record_scenarios':truth.get('records',[]),'detected_types':r['finding_types']}
 core.log_event('evaluation',{'run':r['id'],'metrics':[{k:v for k,v in x.items() if k not in ('misses','matching_types')} for x in metrics]});return result

def curate(body):
 r=core.read_json(core.STATE/'runs'/f"{body['run']}.json")
 if not r:raise ValueError('Unknown assessment')
 ids=body.get('assets',[]);by={a['id']:a for a in r['assets']}
 if any(x not in by for x in ids):raise ValueError('Unknown image')
 plan={'id':'curation-'+uuid.uuid4().hex[:8],'run':r['id'],'excluded':ids,'retained':len(by)-len(ids),'classes_before':dict(collections.Counter(a['label'] for x in by.values() for a in x['annotations'])),'classes_after':dict(collections.Counter(a['label'] for x in by.values() if x['id'] not in ids for a in x['annotations'])),'note':'Non-destructive quarantine manifest. Reassessment of the curated dataset is required before acceptance.'}
 core.atomic(core.STATE/'curation'/f"{plan['id']}.json",plan);core.log_event('curation',plan);return plan

def upload(data):
 if len(data)>150*1024*1024:raise ValueError('Archive exceeds 150 MB intake limit')
 ident='submission-'+uuid.uuid4().hex[:8];root=core.DATA/'fixtures'/ident;root.mkdir(parents=True)
 try:
  with zipfile.ZipFile(io.BytesIO(data)) as z:
   infos=z.infolist()
   paths=[Path(i.filename).parts for i in infos if not i.is_dir()]
   wrapper=paths[0][0] if paths and all(len(x)>1 and x[0]==paths[0][0] for x in paths) and paths[0][0] not in ('submission','reference','trust','suite') else None
   if len(infos)>12000 or sum(i.file_size for i in infos)>700*1024*1024:raise ValueError('Archive exceeds decompression limits')
   for i in infos:
    if i.flag_bits&1 or ((i.external_attr>>16)&0o170000)==0o120000:raise ValueError('Encrypted archives and symbolic links are not supported')
    rel='/'.join(Path(i.filename).parts[1:]) if wrapper else i.filename
    if not rel:continue
    p=core.safe_path(root,rel)
    if '\\' in i.filename or i.filename.startswith('/') or i.file_size>200*1024*1024:raise ValueError('Unsafe archive entry')
    if i.is_dir():p.mkdir(parents=True,exist_ok=True);continue
    if p.name in ('ground_truth.json','README.md','README.txt','SHA256SUMS.txt') or p.suffix=='.key':continue
    payload=z.read(i)
    if p.name.endswith('key.json'):
     try:
      public=json.loads(payload);public.pop('private_key',None);payload=core.canonical(public)
     except ValueError:raise ValueError('Malformed key material')
    p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(payload)
  if not (root/'submission').exists():
   import shutil
   staging=root/'intake';staging.mkdir()
   for entry in list(root.iterdir()):
    if entry!=staging:shutil.move(str(entry),str(staging/entry.name))
   target=root/'submission'/('yolo' if (staging/'images').exists() and (staging/'labels').exists() else 'coco');target.parent.mkdir(parents=True,exist_ok=True);staging.rename(target)
  core.log_event('intake',{'fixture':ident,'archive_sha384':core.digest(data,'sha384'),'files':len(infos)})
  return {'fixture':ident,'name':'New submission','reason':'Imported into quarantine. Use submission/coco, submission/models, submission/records and reference/coco folders.'}
 except Exception:
  import shutil;shutil.rmtree(root,ignore_errors=True);raise

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def send(self,obj,status=200,ctype='application/json',filename=None):
  data=core.canonical(obj) if ctype=='application/json' else obj
  self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(data)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Cache-Control','no-store' if ctype=='application/json' else 'public,max-age=600');self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
  if filename:self.send_header('Content-Disposition',f'attachment; filename="{filename}"')
  self.end_headers();self.wfile.write(data)
 def do_GET(self):
  try:
   parsed=urlparse(self.path);path=unquote(parsed.path);q=parse_qs(parsed.query)
   if path=='/api/bootstrap':
    active=next((a.id for a in JOBS.values() if a.progress<100),None)
    summaries=run_summaries()
    return self.send({'showcase':showcase(summaries),'fixtures':core.fixtures(),'runs':summaries,'policy':core.POLICY,'claims':core.CLAIMS,'capabilities':core.CAPABILITIES,'dependencies':core.DEPENDENCIES,'ranges':{f:[lo,hi] for f,lo,hi in RANGES},'choices':{k:list(v) for k,v in CHOICES.items()},'active_job':active})
   if path=='/api/audit':return self.send(core.verify_audit())
   if path=='/api/regression':return self.send(core.read_json(core.STATE/'regression.json',[]))
   if path=='/api/inclusion':
    from provenance import inclusion
    return self.send(inclusion(int(q.get('sequence',['0'])[0])))
   if path.startswith('/api/jobs/'):
    a=JOBS.get(path.split('/')[-1])
    if not a:return self.send({'error':'Unknown job'},404)
    return self.send(job_status(a,int(q.get('since',['0'])[0] or 0)))
   if path=='/api/lab/options':
    import forge
    return self.send(forge.options())
   if path.startswith('/api/embedding/'):
    return self.send(embedding_map(path.split('/')[-1]))
   if path.startswith('/api/runs/'):
    ident=path.split('/')[-1];p=core.safe_path(core.STATE/'runs',ident+'.json');r=core.read_json(p)
    return self.send(r if r else {'error':'Unknown assessment'},200 if r else 404)
   if path.startswith('/api/export/'):
    ident=path.split('/')[-1];r=core.read_json(core.safe_path(core.STATE/'runs',ident+'.json'))
    if not r:raise ValueError('Unknown report')
    if q.get('format',[''])[0]=='bundle':
     out=io.BytesIO()
     with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
      z.writestr('assurance-report.json',core.canonical(r));z.writestr('audit.json',core.canonical(core.verify_audit()));z.writestr('coverage.json',core.canonical({'capabilities':r['capabilities'],'limitations':r['limitations']}));z.writestr('contract.json',core.canonical(r['policy']))
     return self.send(out.getvalue(),ctype='application/zip',filename=ident+'-assurance.zip')
    return self.send(core.canonical(r),ctype='application/octet-stream',filename=ident+'.json')
   if path=='/api/image':
    fixture=q.get('fixture',[''])[0];asset=q.get('asset',[''])[0];fmt=q.get('format',['COCO'])[0];base=core.safe_path(core.DATA/'fixtures',fixture)
    scope=q.get('scope',['submission'])[0]
    folder=base/('reference/coco' if scope=='reference' else 'submission/yolo/images' if fmt=='YOLO' else 'submission/coco');p=core.safe_path(folder,asset)
    if p.suffix.lower() not in ('.jpg','.jpeg','.png'):raise ValueError('Unsupported image')
    return self.send(p.read_bytes(),ctype=mimetypes.guess_type(p.name)[0] or 'image/jpeg')
   p=core.safe_path(core.ROOT/'app/static',path.lstrip('/') if path!='/' else 'index.html')
   if not p.is_file():return self.send({'error':'Not found'},404)
   return self.send(p.read_bytes(),ctype=mimetypes.guess_type(p.name)[0] or 'application/octet-stream')
  except (ValueError,KeyError,FileNotFoundError) as e:self.send({'error':str(e)},400)
 def do_POST(self):
  origin=self.headers.get('Origin');host=self.headers.get('Host')
  if urlparse('http://'+(host or '')).hostname not in ('localhost','127.0.0.1'):return self.send({'error':'Local host required'},403)
  if origin and urlparse(origin).netloc!=host:return self.send({'error':'Origin rejected'},403)
  try:
   length=int(self.headers.get('Content-Length',0))
   if length>150*1024*1024:return self.send({'error':'Request exceeds limit'},413)
   data=self.rfile.read(length);path=urlparse(self.path).path
   if path=='/api/upload':return self.send(upload(data))
   body=json.loads(data)
   if path=='/api/assess':return self.send(assess(body))
   if path=='/api/delta':return self.send(delta(body))
   if path=='/api/reassess':
    from lifecycle import Reassessment
    previous=core.read_json(core.safe_path(core.STATE/'runs',body['run']+'.json'))
    if not previous:raise ValueError('Unknown parent assessment')
    if any(a.progress<100 for a in JOBS.values()):raise ValueError('An assessment is already active')
    a=Reassessment(previous,body.get('changes',[]),body.get('policy'));JOBS[a.id]=a;threading.Thread(target=a.run,daemon=True).start();return self.send({'job':a.id})
   if path=='/api/evaluate':return self.send(evaluate(body))
   if path=='/api/lab/forge':
    import forge
    if any(a.progress<100 for a in JOBS.values()):raise ValueError('An assessment or forge is already active')
    job=forge.ForgeJob(body.get('spec',{}));JOBS[job.id]=job;threading.Thread(target=job.run,daemon=True).start();return self.send({'job':job.id,'spec':job.spec})
   if path=='/api/lab/delete':
    import forge
    if any(a.progress<100 for a in JOBS.values()):raise ValueError('Wait for the active job to finish')
    forge.delete(str(body.get('fixture','')));return self.send({'deleted':body.get('fixture')})
   if path=='/api/curate':return self.send(curate(body))
   if path=='/api/infer':
    from provenance import infer
    return self.send(infer(body))
   if path=='/api/receive':
    from provenance import receive
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    import base64
    pub=base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    return self.send(receive(body['record'],pub))
   if path=='/api/regression':
    r=core.read_json(core.safe_path(core.STATE/'runs',body['run']+'.json'))
    if not r or not body.get('reason','').strip():raise ValueError('A verified assessment and analyst validation reason are required')
    from provenance import report_verify
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    import base64
    pub=base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    if not report_verify(r,pub)['verified']:raise ValueError('Assurance report verification failed')
    index=int(body['test']);tests=r['model'].get('conditional',{}).get('tests',[])
    if index not in range(len(tests)):raise ValueError('Unknown measured condition')
    test=tests[index]
    if test['perturbation'] not in ('box_checker','corner_checker','illumination'):raise ValueError('Unsupported regression condition')
    entry={'id':'condition-'+uuid.uuid4().hex[:8],'created':core.now(),'source_report':r['report_digest'],'condition':test,'scope':body.get('scope',r['policy']['context']),'reason':body['reason'],'status':'Analyst validated','review_after':body.get('review_after','Before changing model/task/context')}
    entry['digest']=core.digest(core.canonical(entry),'sha384');library=core.read_json(core.STATE/'regression.json',[]);library.append(entry);core.atomic(core.STATE/'regression.json',library);core.log_event('condition_validated',entry);return self.send(entry)
   if path=='/api/review':
    if body.get('action') not in ('accept','review','quarantine'):raise ValueError('Unsupported analyst disposition')
    if not body.get('reason','').strip():raise ValueError('A disposition requires a reason')
    p=core.safe_path(core.STATE/'runs',body.get('run','')+'.json')
    if not p.exists():raise ValueError('Unknown assessment')
    return self.send(core.log_event('analyst_disposition',{'run':body['run'],'action':body['action'],'reason':body['reason'],'analyst':body.get('analyst','Local analyst'),'note':'Analyst disposition is separate from the computed recommendation.'}))
   self.send({'error':'Not found'},404)
  except (ValueError,KeyError,TypeError,FileNotFoundError) as e:self.send({'error':str(e)},400)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8765);args=p.parse_args();print(f'Shockwave ready at http://127.0.0.1:{args.port}',flush=True);ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
