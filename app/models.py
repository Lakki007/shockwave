"""Non-executing model intake and approved local inference adapters."""
import collections, hashlib, io, json, pickletools, threading, zipfile
from pathlib import Path
import numpy as np
from PIL import Image, ImageEnhance
import core

def inspect_model(path):
 p=Path(path);raw=p.read_bytes();out={'name':p.name,'format':p.suffix.lstrip('.'),'sha256':core.digest(raw),'size':len(raw),'status':'Review','reason':'No compatible execution adapter.','safe':False}
 try:
  if p.suffix in ('.pt','.pth','.torchscript'):
   if zipfile.is_zipfile(p):
    with zipfile.ZipFile(p) as z:
     infos=z.infolist()
     if sum(i.file_size for i in infos)>500_000_000 or any(i.file_size>20_000_000 and i.file_size/max(1,i.compress_size)>150 for i in infos):raise ValueError('Archive amplification / oversized tensor payload')
     if any('..' in Path(i.filename).parts or i.filename.startswith('/') for i in infos):raise ValueError('Archive path escape')
     pickles=[i for i in infos if i.filename.endswith('.pkl')]
     globals=[]
     for i in pickles:
      if i.file_size>5_000_000:raise ValueError('Serialized object exceeds inspection limit')
      for op,arg,pos in pickletools.genops(z.read(i)):
       if op.name in ('GLOBAL','STACK_GLOBAL'):globals.append(str(arg))
     out['globals']=globals[:100];out['torchscript']=any('/code/' in i.filename for i in infos)
     if any(any(x in g for x in ('posix','system','subprocess','eval','exec','Custom','Evil')) for g in globals):raise ValueError('Unsafe or custom serialized callable')
   else:
    globals=[str(arg) for op,arg,pos in pickletools.genops(raw) if op.name in ('GLOBAL','STACK_GLOBAL')];out['globals']=globals[:100]
   out.update(status='Review',reason='Static serialization inspected. Execution requires an approved TorchScript graph or architecture adapter; serialized Python is not loaded.')
  elif p.suffix=='.onnx':
   import onnx
   if len(raw)>200_000_000:raise ValueError('ONNX graph exceeds static inspection limit')
   m=onnx.load_model_from_string(raw);domains=set(n.domain for n in m.graph.node);out['domains']=sorted(domains);out['operators']=dict(collections.Counter(n.op_type for n in m.graph.node));out['nodes']=len(m.graph.node)
   if domains-set(('','ai.onnx')):raise ValueError('Custom execution domain in ONNX graph')
   def tensors(graph):
    yield from graph.initializer
    for node in graph.node:
     for attr in node.attribute:
      if attr.type==onnx.AttributeProto.GRAPH:yield from tensors(attr.g)
      elif attr.type==onnx.AttributeProto.GRAPHS:
       for g in attr.graphs:yield from tensors(g)
      elif attr.type==onnx.AttributeProto.TENSOR:yield attr.t
   for t in tensors(m.graph):
    if t.external_data:
     for d in t.external_data:
      if d.key=='location':core.safe_path(p.parent,d.value)
     raise ValueError('External tensor payload requires separate approved identity; execution blocked')
   onnx.checker.check_model(m)
   if any(n.op_type in ('Loop','Scan') for n in m.graph.node):raise ValueError('Unbounded control-flow graph requires dedicated execution isolation')
   out.update(status='Verified',reason='Standard ONNX graph passes structural, domain and external-path checks.',safe=True)
  elif p.suffix=='.safetensors':
   from safetensors import safe_open
   with safe_open(p,framework='np') as f:
    out['tensors']=len(list(f.keys()));out['metadata']=f.metadata() or {};out['shapes']={k:list(f.get_slice(k).get_shape()) for k in f.keys()}
   out.update(status='Verified',reason='Data-only tensor format; parsed without Python object deserialization.',safe=True)
  else:out.update(reason='Unsupported model serialization. Retained as an opaque artifact.')
 except Exception as e:out.update(status='Quarantine',reason=str(e),safe=False)
 return out

def tensor_diff(sub,ref):
 from safetensors import safe_open
 total=changed=0;num=den=0.;layers=[]
 with safe_open(sub,framework='np') as a,safe_open(ref,framework='np') as b:
  if set(a.keys())!=set(b.keys()):raise ValueError('Tensor names differ from the approved architecture')
  for k in a.keys():
   x=a.get_tensor(k).astype(np.float64);y=b.get_tensor(k).astype(np.float64)
   if x.shape!=y.shape:raise ValueError('Tensor shape mismatch')
   total+=1;different=not np.array_equal(x,y);changed+=different;d=float(np.sum((x-y)**2));n=float(np.sum(y*y));num+=d;den+=n
   layers.append({'name':k,'changed':different,'relative_l2':(d/(n+1e-12))**.5})
 return {'name':Path(sub).name,'tensors':total,'changed_tensors':changed,'relative_l2':(num/(den+1e-12))**.5,'layers':layers}

def analyse_models(a):
 rows=[];comp=[];refs=approved_models(a);approved_hashes={core.digest(p.read_bytes()) for p in refs};refweights=next((p for p in refs if p.suffix=='.safetensors'),None)
 for p in sorted((a.root/'submission/models').glob('*')):
  row=inspect_model(p);row['approved_identity']=row['sha256'] in approved_hashes;rows.append(row)
  if row['status']=='Quarantine':a.finding('unsafe_model','safe_intake',p.name,row['reason'],'critical',{'sha256':row['sha256'],'format':row['format']})
  elif not row['safe']:a.check('Model adapter: '+p.name,'Unavailable',row['reason'],'safe_intake')
  if approved_hashes and not row['approved_identity'] and row['safe']:a.finding('model_identity_changed','model_identity',p.name,'Submitted model bytes differ from the approved reference; an authorised new version is an alternative explanation.','high',{'submitted_digest':row['sha256'],'approved_digests':sorted(approved_hashes)})
  if refweights and p.suffix=='.safetensors' and row['safe'] and a.policy['access']=='white-box':
   try:
    w=tensor_diff(p,refweights);comp.append(w)
    if w['changed_tensors']:a.finding('weight_difference','model_identity',p.name,f"{w['changed_tensors']} of {w['tensors']} compatible tensors differ from the approved reference.",'high',{'relative_l2':w['relative_l2'],'layers':w['layers']})
   except ValueError as e:a.check('Weight comparison','Unavailable',str(e),'model_identity')
 if rows:a.check('Static model intake','Completed','Data-only tensors and graphs inspected; rejected model objects are never executed.','safe_intake')
 a.check('Approved identity','Completed' if refs else 'Unavailable',f'{len(refs)} explicitly approved model references.' if refs else 'No approved model identity registry supplied.','model_identity')
 return {'artifacts':rows,'weight_comparisons':comp,'behaviour':None,'twin':None}

def encode_crops(objects,a):
 import embeddings
 if not embeddings.available():return None
 a.event('Semantic embedding','Encoding object crops with the local DINOv2-S/14 encoder; unchanged crops reuse content-addressed vectors.',20)
 matrix,new=embeddings.encode(objects,lambda done,total:a.progress_only('Semantic embedding',min(47,20+int(27*done/max(1,total)))))
 a.check('DINOv2 encoder','Completed',f'{len(objects)} object embeddings; {new} newly encoded with DINOv2-S/14, {len(objects)-new} reused by image digest and box.','labels');return matrix

def tiny_adapter(weights):
 import torch
 from torch import nn
 from safetensors.torch import load_file
 class Tiny(nn.Module):
  def __init__(self):
   super().__init__();self.backbone=nn.Sequential(nn.Conv2d(3,16,3,2,1),nn.ReLU(),nn.Conv2d(16,32,3,2,1),nn.ReLU(),nn.Conv2d(32,32,3,2,1),nn.ReLU(),nn.Conv2d(32,32,3,1,1),nn.ReLU());self.heatmap=nn.Conv2d(32,1,1);self.size=nn.Conv2d(32,2,1);self.region=nn.Sequential(nn.Conv2d(3,16,3,padding=1),nn.ReLU(),nn.MaxPool2d(2),nn.Conv2d(16,32,3,padding=1),nn.ReLU(),nn.MaxPool2d(2),nn.Conv2d(32,64,3,padding=1),nn.ReLU(),nn.AdaptiveAvgPool2d(1),nn.Flatten());self.classifier=nn.Linear(64,8)
  def forward(self,x):
   from torch.nn import functional as F
   feat=self.backbone(x);heat=self.heatmap(feat).squeeze(1);sizes=self.size(feat).sigmoid();B,H,W=heat.shape;index=heat.flatten(1).argmax(1);ys=index//W;xs=index%W;b=torch.arange(B);box=torch.stack(((xs+.5)/W,(ys+.5)/H,sizes[b,0,ys,xs],sizes[b,1,ys,xs]),1);zero=torch.zeros_like(box[:,0]);theta=torch.stack((torch.stack((box[:,2],zero,box[:,0]*2-1),1),torch.stack((zero,box[:,3],box[:,1]*2-1),1)),1);grid=F.affine_grid(theta,(B,3,48,48),align_corners=False);crop=F.grid_sample(x,grid,align_corners=False);return self.classifier(self.region(crop)),box,heat.flatten(1).max(1).values.sigmoid()
 model=Tiny();model.load_state_dict(load_file(weights));return model.eval()

def input_array(path,size=256,pre=None):
 with Image.open(path) as im:
  im=im.convert('RGB').resize((size,size),Image.Resampling.BILINEAR);x=np.asarray(im,dtype=np.float32)/255
 if pre and pre.get('channel_order')=='BGR':x=x[:,:,::-1]
 return x.transpose(2,0,1)[None].copy()

class Runtime:
 """ONNX execution through the tiny-detector or a YOLO-family adapter (yolo.py).
 Approved, operator-provisioned graphs run in-process; submitted graphs run with sandboxed=True
 in a Seatbelt worker (sandbox.py) and are only reachable through raw tensor exchange."""
 def __init__(self,path,sandboxed=False,layout=None,names=None):
  self.isolation='in-process (approved, operator-provisioned graph)';self.worker=None
  if sandboxed:
   import sandbox
   self.worker=sandbox.SandboxedModel(path);inputs,outputs=self.worker.inputs,self.worker.outputs;self.isolation=self.worker.isolation;self.raw=self.worker
  else:
   import onnxruntime as ort
   ort.disable_telemetry_events();options=ort.SessionOptions();options.intra_op_num_threads=2;options.inter_op_num_threads=1;session=ort.InferenceSession(str(path),sess_options=options,providers=['CPUExecutionProvider'])
   inputs=[[i.name,i.shape] for i in session.get_inputs()];outputs=[[o.name,o.shape] for o in session.get_outputs()];name=inputs[0][0];self.raw=lambda x:session.run(None,{name:x})
  self.name=inputs[0][0];shape=inputs[0][1];self.size=shape[-1] if isinstance(shape[-1],int) else 256;self.detector=None;self.output_shapes=[o[1] for o in outputs]
  if len(outputs)==3:self.kind='tiny'
  else:
   import yolo
   self.kind=yolo.detect_layout(self.output_shapes,self.size,layout)
   if not self.kind:raise ValueError(f'No execution adapter matches output shapes {self.output_shapes}')
   self.detector=yolo.Detector(self.raw,self.kind,self.size,names)
 def prediction(self,x):
  if self.detector:return self.detector.prediction(x)
  logits,box,obj=self.raw(x);prob=np.exp(logits-logits.max(1,keepdims=True));prob/=prob.sum(1,keepdims=True);c=int(prob[0].argmax());return c,float(prob[0,c]*obj[0]),box[0].tolist()
 def probabilities(self,x):
  """Class distribution for each input in a batch (black-box score access)."""
  if self.detector:return self.detector.probabilities(x)
  logits=self.raw(x)[0];p=np.exp(logits-logits.max(1,keepdims=True));return p/p.sum(1,keepdims=True)
 def describe(self):
  return {'adapter':self.kind,'input_size':self.size,'output_shapes':self.output_shapes,'isolation':self.isolation,'calls':getattr(self.worker,'calls',None)}
 def close(self):
  if self.worker:self.worker.close()

def torch_prediction(model,x):
 import torch
 with torch.inference_mode():logits,box,obj=model(torch.from_numpy(x));prob=logits.softmax(1);c=int(prob[0].argmax());return c,float(prob[0,c]*obj[0]),box[0].tolist()

def tiny_crops(model,x):
 """The supported detector's own region crops; the classifier head only sees these."""
 import torch
 from torch.nn import functional as F
 with torch.no_grad():
  feat=model.backbone(x);heat=model.heatmap(feat).squeeze(1);sizes=model.size(feat).sigmoid();B,H,W=heat.shape;index=heat.flatten(1).argmax(1);ys=index//W;xs=index%W;b=torch.arange(B)
  box=torch.stack(((xs+.5)/W,(ys+.5)/H,sizes[b,0,ys,xs],sizes[b,1,ys,xs]),1);zero=torch.zeros_like(box[:,0])
  theta=torch.stack((torch.stack((box[:,2],zero,box[:,0]*2-1),1),torch.stack((zero,box[:,3],box[:,1]*2-1),1)),1)
  return F.grid_sample(x,F.affine_grid(theta,(B,3,48,48),align_corners=False),align_corners=False)

def output_envelope(pred,classes,width,height,cfg):
 c,score,box=pred
 if score<cfg.get('score_threshold',.25):return {'detections':[]}
 cx,cy,w,h=box;label=classes[c];mapping=cfg.get('class_map') or {};return {'detections':[{'class_name':mapping.get(label,label),'score':round(score,6),'bbox':[round((cx-w/2)*width,3),round((cy-h/2)*height,3),round(w*width,3),round(h*height,3)]}]}

class Context:
 """Access-aware execution context shared by the baseline and the Contrarian Loop.

 approved: ONNX runtime of the independently approved model (always the control).
 approved_torch: numerically validated white-box adapter of the approved weights, if any.
 submitted / submitted_probs: callable interfaces to the submitted model, if executable.
 submitted_torch: white-box adapter of submitted weights, only under white-box access.
 """
 def __init__(self,a,rt,names):
  self.a=a;self.approved=rt;self.names=names;self.size=rt.size;self.approved_torch=None;self.submitted=None;self.submitted_probs=None;self.submitted_torch=None;self.submitted_mode='unavailable'
  self.reference=core.reference_items(a.root) if getattr(a,'reference_approved',True) else []
  grouped=collections.defaultdict(list)
  for item in self.reference:grouped[item['annotations'][0]['label'] if item['annotations'] else 'unlabelled'].append(item)
  for k in grouped:grouped[k].sort(key=lambda x:core.digest(x['id'].encode()))
  self.by_class=dict(grouped);self._inputs={}
 def x(self,item_or_path):
  path=item_or_path['path'] if isinstance(item_or_path,dict) else item_or_path
  if path not in self._inputs:self._inputs[path]=input_array(path,self.size)
  return self._inputs[path]
 def class_name(self,c):return self.names[c] if 0<=c<len(self.names) else str(c)
 def capabilities(self):
  caps={'approved_exec'}
  if self.reference:caps.add('references')
  if self.approved_torch is not None:caps.add('approved_whitebox')
  if self.submitted:caps.add('submitted_exec')
  if self.submitted_probs:caps.add('probabilities')
  if self.submitted_torch is not None:caps.add('submitted_whitebox')
  return caps

def build_context(a):
 from safetensors import safe_open
 refs=[p for p in approved_models(a) if p.suffix=='.onnx'];ref=next((p for p in refs if inspect_model(p)['safe']),None)
 if not ref:return None
 rt=Runtime(ref);names=a.classes
 approved_weights=next((p for p in approved_models(a) if p.suffix=='.safetensors'),None)
 if approved_weights:
  with safe_open(approved_weights,framework='np') as f:
   meta=f.metadata() or {}
   if isinstance(meta.get('classes'),str) and meta['classes'].startswith('['):names=json.loads(meta['classes'])
 ctx=Context(a,rt,names)
 if approved_weights and rt.kind=='tiny':
  import torch
  model=tiny_adapter(approved_weights);x=input_array(a.items[0]['path'],rt.size);expected=rt.raw(x)
  with torch.inference_mode():actual=model(torch.from_numpy(x))
  error=max(float(np.max(np.abs(v.detach().numpy()-u))) for u,v in zip(expected,actual))
  if error>1e-4:raise ValueError(f'Architecture adapter disagrees with approved ONNX: {error}')
  ctx.approved_torch=model;ctx.adapter_error=error
 artifacts=a.model.get('artifacts',[])
 weights=next((a.root/'submission/models'/r['name'] for r in artifacts if r['format']=='safetensors' and r['safe']),None)
 onnx_model=next((a.root/'submission/models'/r['name'] for r in artifacts if r['format']=='onnx' and r['safe']),None)
 if weights and ctx.approved_torch is not None and a.policy['access']=='white-box':
  import torch
  tm=tiny_adapter(weights);ctx.submitted_torch=tm;ctx.submitted=lambda x:torch_prediction(tm,x)
  def probs(x):
   with torch.inference_mode():return tm(torch.from_numpy(x))[0].softmax(1).numpy()
  ctx.submitted_probs=probs;ctx.submitted_mode='white-box adapter (data-only weights, validated architecture)'
  a.check('White-box adapter','Completed',f'Data-only weights reconstructed in the approved architecture; approved ONNX agreement max error {ctx.adapter_error:.8f}.','behaviour')
 elif onnx_model:
  import sandbox
  layout=(core.read_json(a.root/'submission/pipeline.json',{}).get('adapter') or {}).get('layout')
  try:
   if not getattr(a,'sandbox_probe',None):a.sandbox_probe=sandbox.probe()
   if a.sandbox_probe.get('available') and not a.sandbox_probe.get('enforced'):raise sandbox.SandboxError('Sandbox self-test did not deny network, writes, package reads and exec: '+json.dumps(a.sandbox_probe))
   sub=Runtime(onnx_model,sandboxed=True,layout=layout,names=names)
  except (sandbox.SandboxError,ValueError) as e:
   a.check('Sandboxed execution','Unavailable',f'Submitted graph not executed: {e}','safe_intake');return ctx
  ctx.submitted_runtime=sub;ctx.submitted=sub.prediction;ctx.submitted_mode=f'black-box {sub.kind} adapter in sandboxed worker (labels and scores only)'
  if a.policy['access'] in ('black-box','grey-box','white-box'):ctx.submitted_probs=sub.probabilities
  a.model['execution']={**sub.describe(),'self_test':a.sandbox_probe,'limits':sandbox.LIMITS}
  a.check('Sandboxed execution','Completed',f'Submitted {sub.kind} graph runs in an isolated worker: {sub.isolation}. Self-test: network, file writes, package reads and exec denied.','safe_intake')
  if sub.kind!='tiny':a.check('Detector adapter','Completed',f'{sub.kind} output layout {sub.output_shapes} at {sub.size}px: letterbox preprocessing, decoding and class-aware NMS.','behaviour')
 return ctx

def behaviour_checks(a):
 """Baseline model and pipeline evidence. Adaptive follow-up belongs to the Contrarian Loop."""
 a.ctx=None
 try:ctx=build_context(a)
 except Exception as e:
  ctx=None;reason=f'Approved runtime adapter could not complete: {e}'
 else:reason='Compatible approved executable reference is unavailable.'
 if not ctx:
  for name,claim in [('Behavioural battery','behaviour'),('Conditional tests','backdoor'),('Twin pipeline','pipeline'),('Record re-execution','reproduction')]:a.check(name,'Unavailable',reason,claim)
  return
 a.ctx=ctx;rt=ctx.approved;names=ctx.names;budget=a.policy['challenge_budget']
 battery=[]
 for n in range(24):
  for label in sorted(ctx.by_class):
   if n<len(ctx.by_class[label]):battery.append(ctx.by_class[label][n])
   if len(battery)>=min(24,max(1,budget)):break
  if len(battery)>=min(24,max(1,budget)):break
 ctx.battery=battery
 finger=[];pairs=[];config=core.read_json(a.root/'submission/pipeline.json',{});changed=0;twin=[]
 for item in battery:
  x=ctx.x(item);p=rt.prediction(x);q=ctx.submitted(x) if ctx.submitted else None;finger.append(p);pairs.append({'input':item['id'],'reference_class':p[0],'submitted_class':q[0] if q else None,'reference_label':ctx.class_name(p[0]),'submitted_label':ctx.class_name(q[0]) if q else None,'reference_score':p[1],'submitted_score':q[1] if q else None})
  # Twin Pipeline: the same approved model and original input through both processing paths.
  pre=config.get('preprocess',{});x2=input_array(item['path'],rt.size,pre);p2=rt.prediction(x2);post=config.get('postprocess',{});mapping=post.get('class_map') or {};cl=ctx.class_name(p[0]);cl2=ctx.class_name(p2[0]);different=cl!=mapping.get(cl2,cl2) or abs(p[1]-p2[1])>a.policy['numerical_tolerance'] or post.get('score_threshold',.25)>.25 and p[1]<post['score_threshold'];changed+=different;twin.append({'input':item['id'],'authorised':cl,'submitted':mapping.get(cl2,cl2),'authorised_score':round(p[1],5),'submitted_score':round(p2[1],5),'different':bool(different)})
 if pairs and ctx.submitted:
  agreement=sum(p['reference_class']==p['submitted_class'] for p in pairs)/len(pairs);a.model['behaviour']={'samples':len(pairs),'agreement':agreement,'fingerprint':core.digest(core.canonical(finger)),'pairs':pairs,'mode':ctx.submitted_mode,'limitation':'Bounded clean reference battery. Agreement does not exclude trigger-conditional behaviour.'}
  if agreement<.95:a.finding('behaviour_difference','behaviour','model battery','Submitted and approved models disagree on the shared reference battery.','high',{'agreement':agreement,'samples':len(pairs),'pairs':pairs})
  a.check('Behavioural battery','Completed',f'{len(pairs)} identical reference inputs; agreement {agreement:.3f}; {ctx.submitted_mode}.','behaviour')
 else:a.check('Behavioural battery','Unavailable','No compatible submitted model execution adapter under this access level.','behaviour')
 a.model['twin']={'samples':len(twin),'changed':changed,'config':config,'comparisons':twin,'detail':'Same approved model and original reference inputs. Supports RGB/BGR, unit normalization, fixed-shape resize, score threshold and class-map comparison.'}
 if changed:a.finding('pipeline_difference','pipeline','submission/pipeline.json',f'{changed}/{len(twin)} same-model outputs differ under the submitted processing configuration.','high',{'comparisons':twin,'class_map':config.get('postprocess',{}).get('class_map')})
 a.check('Twin pipeline','Completed',f'{len(twin)} paired comparisons; {changed} output differences.','pipeline')
 if not ctx.submitted:a.check('Conditional tests','Unavailable','Submitted execution adapter required under the declared access level.','backdoor')
 reproduce_records(a,rt,names)

def reproduce_records(a,rt,names):
 rows=[r for r in a.records.get('rows',[]) if r['status']=='Verified' and r.get('record')];done=[];tol=a.policy['numerical_tolerance']
 for row in rows[:500]:
  r=row['record'];cfg=r['config'];pre=cfg.get('preprocess',{});resize=pre.get('resize',[rt.size,rt.size])
  if resize!=[rt.size,rt.size] or pre.get('normalize')!='unit' or pre.get('channel_order') not in ('RGB','BGR'):
   a.check('Record re-execution','Unavailable','Recorded preprocessing does not match the fixed-shape approved runtime adapter.','reproduction');return
  path=core.safe_path(a.root/'submission/records',r['input']['ref']);pred=rt.prediction(input_array(path,rt.size,pre));actual=output_envelope(pred,names,r['input']['width'],r['input']['height'],cfg['postprocess']);stored=r['output'];match=False;maxerr=None
  if len(actual['detections'])==len(stored.get('detections',[])):
   if not actual['detections']:match=True
   else:
    x=actual['detections'][0];y=stored['detections'][0];maxerr=max(abs(x['score']-y['score']),max(abs(i-j)/max(r['input']['width'],r['input']['height']) for i,j in zip(x['bbox'],y['bbox'])));match=x['class_name']==y['class_name'] and maxerr<=tol
  done.append({'record':row['id'],'matches':bool(match),'max_error':maxerr,'reexecuted':actual,'recorded':stored})
  if not match:a.finding('reexecution_mismatch','reproduction',row['id'],'Approved-model re-execution differs from the signed output under the declared adapter and numerical tolerance. A runtime or implementation mismatch remains possible.','high',{'tolerance':tol,'max_error':maxerr,'reexecuted':actual,'recorded':stored})
 a.records['reproduction']={'samples':len(done),'matches':sum(d['matches'] for d in done),'comparisons':done,'tolerance':tol}
 a.check('Record re-execution','Completed' if done else 'Unavailable',f'{len(done)} verified records re-executed; {sum(d["matches"] for d in done)} matched. Adapter and numerical tolerance are explicit.','reproduction')


def approved_models(a):
 registry=core.read_json(core.DATA/'trust-registry.json',{}).get(a.fixture,{})
 out=[]
 for entry in registry.get('approved_model_artifacts',[]):
  p=core.safe_path(a.root,entry['path'])
  if p.is_file() and core.digest(p.read_bytes())==entry['sha256']:out.append(p)
  else:a.check('Reference model binding','Failed','An approved model reference is absent or its bytes have changed.','model_identity')
 return out
