import sys,json,tempfile,hashlib,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import pair,pair_reset,reset
from types import SimpleNamespace
import os

BASE={'pair':'a'*32,'role':'entry','server':'vpn.example.net','exit_host':'exit.example.net'}
class PairResetTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  for d in ['own','state','release','amnezia/amneziawg','reviews']:(self.root/d).mkdir(parents=True)
  self.conf=self.root/'amnezia/amneziawg/awg-exit.conf';self.conf.write_text('owned tunnel')
  self.ike=self.root/'ipsec.conf';self.ike.write_text('conn ikev2-vpn\n')
  self.other=self.root/'unrelated';self.other.write_text('keep')
  self.m={'version':1,'plan':pair.plan(BASE),'jobs':{},'awg_hash':hashlib.sha256(self.conf.read_bytes()).hexdigest()}
  actual=Path
  def paths(value):
   return {'/etc/ipsec.conf':self.ike,'/etc/amnezia':self.root/'amnezia','/etc/amnezia/amneziawg/awg-exit.conf':self.conf}.get(str(value),actual(value))
  def protected(value):
   p=Path(value)
   if p.is_symlink():raise ValueError('Managed symbolic link')
   return p
  self.patches=[patch.multiple(pair,OWN=self.root/'own',STATE=self.root/'state',RELEASE=self.root/'release'),patch.object(pair,'load_manifest',side_effect=lambda:self.m),patch.object(pair,'protected',side_effect=protected),patch.object(pair_reset,'Path',side_effect=paths),patch.multiple(pair_reset,REVIEWS=self.root/'reviews',COMMON=(self.root/'amnezia',),ENTRY=(self.ike,),EXIT=())]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.tmp.cleanup()
 def request(self,r):return dict(BASE,token=r['token'],confirmation='DELETE PAIR')
 def test_wrong_role_and_unknown_owner_are_refused(self):
  for req in [dict(BASE,role='exit'),dict(BASE,pair='b'*32)]:
   with self.assertRaises(ValueError):pair_reset.plan(req)
 def test_extra_tunnels_and_additional_ike_are_preserved(self):
  extra=self.root/'amnezia/other.conf';extra.write_text('keep')
  with self.assertRaises(ValueError):pair_reset.plan(BASE)
  extra.unlink();self.ike.write_text('conn ikev2-vpn\nconn unrelated\n')
  with self.assertRaises(ValueError):pair_reset.plan(BASE)
  self.assertTrue(self.ike.exists())
 def test_confirmation_expiration_and_mutation_stop_before_commands(self):
  r=pair_reset.plan(BASE)
  with patch.object(reset,'execute') as commands:
   with self.assertRaises(ValueError):pair_reset.apply(dict(self.request(r),confirmation='yes'))
   with self.assertRaises(ValueError):pair_reset.apply(dict(self.request(r),token='bad'))
   self.ike.write_text('conn ikev2-vpn\n  leftid=changed.example.net\n')
   with self.assertRaises(ValueError):pair_reset.apply(self.request(r))
   self.ike.write_text('conn ikev2-vpn\n');record=json.loads(pair_reset.review_path(BASE).read_text());record['expires']=time.time()-1;pair_reset.review_path(BASE).write_text(json.dumps(record))
   with self.assertRaises(ValueError):pair_reset.apply(self.request(r))
   commands.assert_not_called()
 def test_active_job_and_changed_tunnel_are_refused(self):
  jid='b'*32;self.m['jobs']={'bootstrap':jid};p=self.root/'state'/jid;p.mkdir();(p/'status.json').write_text('{}')
  with patch.object(pair,'status',return_value={'state':'running'}):
   with self.assertRaises(ValueError):pair_reset.plan(BASE)
  self.m['jobs']={};self.conf.write_text('changed peer')
  with self.assertRaises(ValueError):pair_reset.plan(BASE)
 def test_stop_failure_keeps_owned_files_for_retry(self):
  r=pair_reset.plan(BASE)
  with patch.object(reset,'execute',return_value=0):
   with self.assertRaises(RuntimeError):pair_reset.apply(self.request(r))
  self.assertTrue(self.conf.exists());self.assertTrue(self.m['resetting'])
  self.assertFalse(pair_reset.plan(BASE)['already_fresh'])
 def test_reset_only_removes_owned_paths_and_dedicated_table(self):
  r=pair_reset.plan(BASE)
  def execute(args,check=True):return 1 if 'is-active' in args or '-L' in args or ('rule' in args and 'del' in args) else 0
  with patch.object(reset,'execute',side_effect=execute) as run:
   self.assertTrue(pair_reset.apply(self.request(r))['reset'])
   self.assertIn(['ip','route','flush','table','51831'],[c.args[0] for c in run.call_args_list])
   self.assertFalse(any(c.args[0][:3]==['ip','route','flush'] and c.args[0][-1]=='main' for c in run.call_args_list))
  self.assertFalse(self.conf.exists());self.assertEqual('keep',self.other.read_text())
 def test_already_fresh_node_has_a_reviewed_noop(self):
  self.m=None
  with patch.object(pair,'fresh') as fresh:
   r=pair_reset.plan(BASE)
   self.assertTrue(r['already_fresh'])
   with patch.object(reset,'execute') as run:self.assertTrue(pair_reset.apply(self.request(r))['reset']);run.assert_not_called()
   self.assertEqual(2,fresh.call_count)
 def test_service_owned_dns_state_is_removable_but_links_and_wrong_owners_are_not(self):
  d=self.root/'dns-state';d.mkdir();(d/'rules').write_text('owned data')
  with patch.object(pair_reset,'ADGUARD_STATE',d),patch.object(pair_reset.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid())):
   self.assertEqual(d,pair_reset.removal_path(d))
   (d/'link').symlink_to(self.other)
   with self.assertRaises(ValueError):pair_reset.removal_path(d)
   (d/'link').unlink()
  if os.getuid()!=0:
   with patch.object(pair_reset,'ADGUARD_STATE',d),patch.object(pair_reset.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid()+1)):
    with self.assertRaises(ValueError):pair_reset.removal_path(d)

if __name__=='__main__':unittest.main()
