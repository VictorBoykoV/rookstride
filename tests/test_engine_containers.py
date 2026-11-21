import copy,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1];sys.path[:0]=[str(BASE/'server'),str(BASE/'single')]
import engine_containers as c
class Containers(unittest.TestCase):
 def setUp(self):
  self.op={'operation':'a'*32,'group':'awg','new_hash':'sha256:'+'b'*64,'candidate_image':'sha256:'+'b'*64,'target':'rookstride-awg:1','old_hashes':['sha256:'+'c'*64],'snapshot':{'services':[{'kind':'container','name':'rookstride-single-awg','configs':{},'instance':'owned','original_id':'old-id','binary':'sha256:'+'c'*64,'args':['--name','rookstride-single-awg']}]},'prior_images':{}}
  self.original={'Id':'old-id','Image':self.op['old_hashes'][0],'Config':{'Labels':{'io.rookstride.instance':'owned'}}};self.updated={'Id':'new-id','Image':self.op['new_hash'],'Config':{'Labels':{'io.rookstride.instance':'owned'}}}
 def test_unchanged_saved_listener_can_update(self):
  with patch.object(c,'inspect',side_effect=lambda n:self.original if n=='rookstride-single-awg' else None):c.same_identity(self.op,lambda _:None)
 def test_missing_listener_between_rename_and_create_can_resume(self):
  with patch.object(c,'inspect',side_effect=lambda n:None if n=='rookstride-single-awg' else self.original):c.same_identity(self.op,lambda _:None)
 def test_unknown_container_or_missing_original_refused(self):
  for current,prior in [(self.updated,None),({**self.updated,'Image':'other'},self.original),(None,None)]:
   with patch.object(c,'inspect',side_effect=lambda n:current if n=='rookstride-single-awg' else prior):
    with self.assertRaises(ValueError):c.same_identity(self.op,lambda _:None)
 def test_apply_retains_original_and_starts_only_replacement(self):
  calls=[]
  with patch.object(c,'inspect',side_effect=lambda n:self.original if n=='rookstride-single-awg' else None),patch.object(c.runtime,'command',side_effect=lambda args,**kwargs:calls.append(args)):
   c.mutate(self.op,False)
  self.assertIn(['docker','rename','rookstride-single-awg',c.backup(self.op)],calls)
  self.assertTrue(any(cmd[:2]==['docker','create'] and self.op['new_hash'] in cmd for cmd in calls))
  self.assertFalse(any(cmd[:2]==['docker','rm'] for cmd in calls))
 def test_rollback_restores_original_container_without_regenerating_identity(self):
  calls=[]
  with patch.object(c,'inspect',side_effect=lambda n:self.updated if n=='rookstride-single-awg' else self.original),patch.object(c.runtime,'command',side_effect=lambda args,**kwargs:calls.append(args)):
   c.mutate(self.op,True)
  self.assertIn(['docker','rename',c.backup(self.op),'rookstride-single-awg'],calls)
  self.assertFalse(any(cmd[:2]==['docker','create'] for cmd in calls))
 def test_shared_unreviewed_image_consumer_blocks_update(self):
  with patch.object(c.runtime,'command',return_value='rookstride-single-awg\nunrelated-service'):
   with self.assertRaisesRegex(ValueError,'unreviewed'):c.validate_consumers(self.op['snapshot']['services'])
 def test_bridge_uses_real_atomic_writer_and_restores_unit(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'bridge.service';text='ExecStart=/usr/bin/docker run '+self.op['old_hashes'][0]+'\n'
   self.op['snapshot']['services']=[{'kind':'bridge','name':'rookstride-pair-bridge','text':text,'path':str(path),'image_token':self.op['old_hashes'][0]}]
   with patch.object(c.runtime,'command'),patch.object(c.pair,'protected',side_effect=lambda p:Path(p)):
    c.mutate(self.op,False);self.assertIn(self.op['candidate_image'],path.read_text());self.assertEqual(0o644,path.stat().st_mode&0o777)
    c.mutate(self.op,True);self.assertEqual(text,path.read_text());self.assertEqual(0o644,path.stat().st_mode&0o777)
if __name__=='__main__':unittest.main()
