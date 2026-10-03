"""Optional checkpoint-bound TRAK execution for the supported detector's classifier."""
import json
from pathlib import Path
import numpy as np
import torch
import core
from models import tiny_adapter,input_array

def compute(a,cfg):
 from trak import TRAKer
 from trak.projectors import BasicProjector,ProjectionType
 if a.policy['access']!='white-box':raise ValueError('TRAK requires compatible white-box model access')
 paths=[]
 for entry in cfg.get('checkpoints',[]):
  p=core.safe_path(core.DATA/'attribution',entry['path'])
  if p.suffix!='.safetensors' or not p.exists() or core.digest(p.read_bytes())!=entry['sha256']:raise ValueError('Checkpoint must be data-only and independently hash-pinned')
  paths.append(p)
 if not paths:raise ValueError('No approved training checkpoints configured')
 if cfg.get('model_sha256') not in {x['sha256'] for x in a.model['artifacts']}:raise ValueError('Attribution configuration does not bind the submitted model')
 from safetensors import safe_open
 with safe_open(paths[0],framework='np') as f:classes=json.loads((f.metadata() or {})['classes'])
 class Classification(torch.nn.Module):
  def __init__(self,detector):super().__init__();self.detector=detector
  def forward(self,x):return self.detector(x)[0]
 model=Classification(tiny_adapter(paths[0]));by={x['id']:x for x in a.items};train_ids=cfg.get('training_assets',[]);target_ids=cfg.get('target_assets',[])
 if not train_ids or not target_ids:raise ValueError('Exact training membership and target assets are required')
 def batch(ident):
  if ident not in by:raise ValueError('Attribution asset not found')
  item=by[ident];labels=[an['label'] for an in item['annotations'] if an['label'] in classes]
  if len(set(labels))!=1:raise ValueError('Classification attribution adapter needs one unambiguous image label')
  return [torch.from_numpy(input_array(item['path'])),torch.tensor([classes.index(labels[0])])]
 dim=int(cfg.get('projection_dimension',128))
 if not 16<=dim<=2048:raise ValueError('Projection dimension outside declared resource limits')
 n=sum(p.numel() for p in model.parameters());projector=BasicProjector(grad_dim=n,proj_dim=dim,seed=2026,proj_type=ProjectionType.rademacher,device='cpu',dtype=torch.float32)
 workspace=core.STATE/'attribution'/a.id
 runner=TRAKer(model=model,task='image_classification',train_set_size=len(train_ids),save_dir=str(workspace),device='cpu',projector=projector,proj_dim=dim,use_half_precision=False,lambda_reg=.01,load_from_save_dir=True)
 checkpoints=[]
 for path in paths:
  checkpoint=Classification(tiny_adapter(path)).state_dict();checkpoints.append(checkpoint)
 for index,checkpoint in enumerate(checkpoints):
  runner.load_checkpoint(checkpoint,model_id=index)
  for ident in train_ids:runner.featurize(batch=batch(ident),num_samples=1)
 runner.finalize_features()
 # TRAK releases CPU projection storage after featurization; restore the same seeded block for scoring.
 if not projector.proj_matrix_available:projector.generate_sketch_matrix(projector.generator_states[0])
 for index,checkpoint in enumerate(checkpoints):
  runner.start_scoring_checkpoint(exp_name=a.id,checkpoint=checkpoint,model_id=index,num_targets=len(target_ids))
  for ident in target_ids:runner.score(batch=batch(ident),num_samples=1)
 values=np.asarray(runner.finalize_scores(exp_name=a.id));rows=[]
 for col,target in enumerate(target_ids):
  ranking=np.argsort(-values[:,col])[:20];rows.append({'target':target,'samples':[{'asset':train_ids[int(i)],'score':float(values[i,col])} for i in ranking]})
 return {'method':'TRAK / supported classifier output','model_sha256':cfg['model_sha256'],'checkpoint_digests':[core.digest(p.read_bytes()) for p in paths],'training_samples':len(train_ids),'targets':len(target_ids),'seed':2026,'projection_dimension':dim,'ranked_samples':rows,'limitation':'Conditional association, not causal proof of poisoning. Exact training membership and compatible checkpoints are required.'}
