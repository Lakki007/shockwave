import base64,copy,json,sys,tempfile,unittest,zipfile,io
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'.runtime'),str(ROOT/'app')]
import core,models,provenance,server
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

class AssuranceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.old=core.STATE;core.STATE=Path(self.tmp.name)
 def tearDown(self):core.STATE=self.old;self.tmp.cleanup()
 def pub(self):return base64.b64encode(core.key().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
 def test_canonical_rejects_nonfinite(self):
  self.assertEqual(core.canonical({'b':1,'a':2}),core.canonical({'a':2,'b':1}))
  with self.assertRaises(ValueError):core.canonical({'x':float('nan')})
 def test_path_escape_rejected(self):
  with self.assertRaises(ValueError):core.safe_path(core.STATE,'../secret')
 def test_audit_tamper_detected(self):
  core.log_event('intake',{'x':1});core.log_event('decision',{'x':2});self.assertTrue(core.verify_audit()['verified'])
  es=core.read_json(core.STATE/'audit.json');es[0]['body']['x']=9;core.atomic(core.STATE/'audit.json',es);self.assertFalse(core.verify_audit()['verified'])
 def test_historical_checkpoint_tamper_detected(self):
  core.log_event('a',{});core.log_event('b',{});history=core.read_json(core.STATE/'checkpoints.json');history[0]['root']='0'*64;core.atomic(core.STATE/'checkpoints.json',history);self.assertFalse(core.verify_audit()['verified'])
 def test_suffix_deletion_detected_by_checkpoint(self):
  for _ in range(4):core.log_event('a',{})
  events=core.read_json(core.STATE/'audit.json');core.atomic(core.STATE/'audit.json',events[:-1]);self.assertFalse(core.verify_audit()['verified'])
 def test_merkle_inclusion_for_odd_trees(self):
  for size in range(1,8):
   core.log_event('a',{})
   for i in range(size):self.assertTrue(provenance.inclusion_verify(provenance.inclusion(i)))
 def test_report_content_and_key_binding(self):
  report={'id':'test','decision':'Review'};report['report_digest']=core.digest(core.canonical(report),'sha384');report['report_signature']=base64.b64encode(core.key().sign(bytes.fromhex(report['report_digest']))).decode();self.assertTrue(provenance.report_verify(report,self.pub())['verified']);changed={**report,'decision':'Accept'};self.assertFalse(provenance.report_verify(changed,self.pub())['verified'])
 def test_coco_yolo_consistency(self):
  coco,classes,_=core.inventory('yolo');yolo,yclasses,_=core.inventory('yolo','YOLO');self.assertEqual(len(coco),len(yolo));self.assertEqual(sum(len(x['annotations']) for x in coco),sum(len(x['annotations']) for x in yolo));self.assertEqual(set(classes),set(yclasses))
 def test_unsafe_model_files_never_executed(self):
  folder=core.DATA/'fixtures/hostile/submission/models'
  for name in ('evil_pickle.pt','zip_bomb.pt','external_escape.onnx','pyop.onnx'):self.assertEqual(models.inspect_model(folder/name)['status'],'Quarantine')
  self.assertFalse(models.inspect_model(folder/'custom_layer.pt')['safe'])
 def test_safe_reference_is_hash_pinned(self):
  a=core.Assessment('hostile');self.assertEqual(len(models.approved_models(a)),2)
  with patch.object(core,'read_json',return_value={}):self.assertEqual(models.approved_models(a),[])
 def test_arbitrary_submission_key_does_not_self_approve(self):
  a=core.Assessment('hostile');a.items=[]
  original=core.read_json
  def registry(path,default=None):return {} if str(path).endswith('trust-registry.json') else original(path,default)
  with patch.object(core,'read_json',side_effect=registry):core.verify_records(a)
  self.assertTrue(any(f['type']=='untrusted_signer' for f in a.findings))
  self.assertTrue(any(c['name']=='Edge-key trust' and c['status']=='Unavailable' for c in a.checks))
 def receipt(self):
  body={'schema':'shockwave-inference-v1','session':'local-assessor','sequence':1,'nonce':'n1','previous':'0'*96,'input':{'sha384':'a'},'output':{}};raw=core.canonical(body);body['digest']=core.digest(raw,'sha384');body['signature']=base64.b64encode(core.key().sign(provenance.DOMAIN+raw)).decode();return body
 def test_receipt_replay_transaction(self):
  r=self.receipt();self.assertTrue(provenance.receive(r,self.pub())['verified']);self.assertFalse(provenance.receive(r,self.pub())['verified'])
 def test_receipt_alteration_rejected(self):
  r=self.receipt();r['input']['sha384']='substituted';self.assertFalse(provenance.receive(r,self.pub())['verified'])
 def test_receipt_sequence_gap_rejected(self):
  r=self.receipt();provenance.receive(r,self.pub());r2={'schema':'shockwave-inference-v1','session':'local-assessor','sequence':3,'nonce':'n2','previous':r['digest']};raw=core.canonical(r2);r2['digest']=core.digest(raw,'sha384');r2['signature']=base64.b64encode(core.key().sign(provenance.DOMAIN+raw)).decode();self.assertFalse(provenance.receive(r2,self.pub())['verified'])
 def test_independent_calibration_abstains(self):
  import extensions
  a=core.Assessment('hostile');a.items=[];a.drift={};extensions.calibrate(a);self.assertFalse(a.risk['calibrated']);self.assertTrue(a.risk['abstained'])
 def test_upload_path_traversal_rejected(self):
  out=io.BytesIO()
  with zipfile.ZipFile(out,'w') as z:z.writestr('../../outside.txt','x')
  with self.assertRaises(ValueError):server.upload(out.getvalue())
 def test_truth_never_read_by_detection(self):
  import inspect,extensions
  detection=inspect.getsource(core)+inspect.getsource(models)+inspect.getsource(extensions)
  self.assertNotIn('ground_truth.json',detection)
if __name__=='__main__':unittest.main()
