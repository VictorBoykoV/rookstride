import copy,json,sys,tempfile,unittest,shutil,subprocess
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import maintenance as m,pair,lifecycle,engine_updates

class MaintenanceTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.own=self.root/'owned';self.own.mkdir();self.release=self.root/'release';self.source=self.root/'source'
  for root,text in ((self.release,'old'),(self.source,'new')):
   for folder in ('server','single','gateway','twohop'):
    (root/folder).mkdir(parents=True);(root/folder/'owned.py').write_text(text)
  self.manifest={'version':2,'bundle':pair.source_digest(self.release),'plan':{'pair':'a'*32,'role':'entry'},'configured':True,'activated':True,'configure_digest':'c'*64,'jobs':{}}
  self.patches=[patch.multiple(m,ROOT=self.root/'updates',SOURCE=self.source),patch.object(engine_updates,'ROOT',self.root/'runtimes'),patch.multiple(pair,RELEASE=self.release,OWN=self.own),patch.object(pair,'protected',side_effect=Path),patch.object(pair,'load_manifest',side_effect=lambda:copy.deepcopy(self.manifest)),patch.object(pair,'write_manifest',side_effect=self.store),patch.object(lifecycle,'inspect',return_value={'read_only':False}),patch.object(lifecycle,'records',return_value=[]),patch.object(lifecycle,'reanchor'),patch.object(lifecycle,'ROOT',self.root/'lifecycle'),patch('native_pair.command')]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def store(self,value):self.manifest=copy.deepcopy(value)
 def prepare(self):
  review=m.review();req=dict(review,action='prepare',operation='d'*32,confirmation='UPDATE HELPERS AND KEEP VPN USERS');m.prepare(req);return req
 def action(self,action):return m.transition({'action':action,'operation':'d'*32,'expected_exit_ip':'192.0.2.10'})
 def test_review_never_changes_running_installation(self):
  before=copy.deepcopy(self.manifest);self.assertTrue(m.review()['available']);self.assertEqual(before,self.manifest);self.assertFalse(m.ROOT.exists())
 def test_tampered_helper_and_stale_review_are_rejected(self):
  review=m.review();(self.release/'server/owned.py').write_text('tampered')
  with self.assertRaisesRegex(ValueError,'integrity'):m.review()
  (self.release/'server/owned.py').write_text('old');review['anchor']='wrong'
  with self.assertRaisesRegex(ValueError,'changed'):m.prepare(dict(review,operation='d'*32,confirmation='UPDATE HELPERS AND KEEP VPN USERS'))
  self.assertFalse(m.ROOT.exists())
 def test_prepare_idempotence_and_competing_review_denied(self):
  req=self.prepare();self.assertEqual(m.prepare(req),m.prepare(req))
  with self.assertRaisesRegex(ValueError,'review changed'):m.prepare(dict(req,anchor='different'))
  with self.assertRaisesRegex(ValueError,'existing helper'):m.prepare(dict(req,operation='e'*32))
 def test_update_retains_identity_and_quiesces_before_swap(self):
  old=copy.deepcopy(self.manifest);self.prepare();events=[]
  def route(mode):events.append((mode,pair.source_digest(self.release)))
  with patch.object(m,'routing',side_effect=route),patch.object(m,'verify',side_effect=lambda op:events.append(('verified',pair.source_digest(self.release)))):result=self.action('apply')
  self.assertEqual('verified',result['state']);self.assertEqual(old['bundle'],events[0][1]);self.assertEqual('quiesce',events[0][0]);self.assertEqual(self.manifest['bundle'],pair.source_digest(self.source));self.assertEqual(old['plan'],self.manifest['plan']);self.assertEqual(old['configure_digest'],self.manifest['configure_digest'])
 def test_failed_verification_leaves_guard_closed_and_rollback_retains_accounts(self):
  old=copy.deepcopy(self.manifest);self.prepare();user=self.own/'users.json';user.write_text('private account data')
  with patch.object(m,'routing') as route,patch.object(m,'verify',side_effect=ValueError('DNS failed')):
   with self.assertRaisesRegex(ValueError,'DNS'):self.action('apply')
   self.assertEqual('quiesce',route.call_args.args[0])
  with patch.object(m,'routing'),patch.object(m,'verify'):self.assertEqual('rolled-back',self.action('rollback')['state'])
  self.assertEqual(old['bundle'],self.manifest['bundle']);self.assertEqual('private account data',user.read_text())
 def test_death_between_helper_renames_reconciles_without_reinstallation(self):
  self.prepare();op=m.read(m.ROOT/('d'*32)/'journal.json');op['expected_exit_ip']='192.0.2.10';m.record(op,'applying','interrupted');self.release.rename(m.ROOT/('d'*32)/'previous')
  with patch.object(m,'routing'),patch.object(m,'verify'):self.assertEqual('verified',self.action('apply')['state'])
  self.assertEqual(pair.source_digest(self.release),pair.source_digest(self.source))
 def test_accept_requires_saved_client_confirmation(self):
  self.prepare()
  with patch.object(m,'routing'),patch.object(m,'verify'):self.action('apply')
  with self.assertRaisesRegex(ValueError,'saved client'):self.action('accept')
  self.assertEqual('accepted',m.transition(dict(action='accept',operation='d'*32,confirmation='CLIENT TRAFFIC VERIFIED'))['state'])
 def test_cancel_prepared_update_never_touches_the_working_route(self):
  old=copy.deepcopy(self.manifest);self.prepare()
  with patch.object(m,'routing') as route,patch.object(m,'verify') as verify:
   self.assertEqual('cancelled',self.action('rollback')['state']);route.assert_not_called();verify.assert_not_called()
  self.assertEqual(old,self.manifest);self.assertEqual('cancelled',self.action('rollback')['state'])
 def test_status_of_unstarted_member_does_not_create_an_operation(self):
  self.assertEqual('not-started',self.action('status')['state']);self.assertFalse(m.ROOT.exists())
 def test_stale_prepared_review_cannot_replace_another_deployment(self):
  self.prepare();old_digest=pair.source_digest(self.release);self.manifest['plan']['pair']='b'*32
  with patch.object(m,'routing') as route, self.assertRaisesRegex(ValueError,'identity changed'):self.action('apply')
  route.assert_not_called();self.assertEqual('b'*32,self.manifest['plan']['pair']);self.assertEqual(old_digest,pair.source_digest(self.release))
  self.assertEqual('prepared',self.action('status')['state'])
  with patch.object(m,'routing') as route:result=self.action('rollback')
  route.assert_not_called();self.assertEqual('cancelled',result['state']);self.assertEqual('b'*32,self.manifest['plan']['pair'])
  self.assertEqual(old_digest,pair.source_digest(self.release))
  reviewed=m.review();request=dict(reviewed,action='prepare',operation='e'*32,confirmation='UPDATE HELPERS AND KEEP VPN USERS')
  self.assertEqual('prepared',m.prepare(request)['state'])
 def test_interrupted_update_cannot_rollback_over_new_identity(self):
  self.prepare();op=m.read(m.ROOT/('d'*32)/'journal.json');m.record(op,'applying','interrupted')
  self.manifest['configure_digest']='f'*64;before=copy.deepcopy(self.manifest)
  with patch.object(m,'routing') as route, self.assertRaisesRegex(ValueError,'identity changed'):self.action('rollback')
  route.assert_not_called();self.assertEqual(before,self.manifest)
 def test_reset_or_third_helper_revision_requires_new_review(self):
  self.prepare();self.manifest['resetting']=True
  with patch.object(m,'routing') as route,self.assertRaisesRegex(ValueError,'reset'):self.action('apply')
  route.assert_not_called();self.manifest.pop('resetting');self.manifest['bundle']='e'*64
  with patch.object(m,'routing') as route,self.assertRaisesRegex(ValueError,'revision changed'):self.action('apply')
  route.assert_not_called()
 def test_legitimate_service_or_topology_change_invalidates_old_review(self):
  self.prepare();self.manifest['unit_hashes']={'new-guard':'c'*64}
  with patch.object(m,'routing') as route,self.assertRaisesRegex(ValueError,'service or lifecycle revision changed'):self.action('apply')
  route.assert_not_called();self.manifest.pop('unit_hashes')
  m.write(lifecycle.ROOT/'inventory.json',{'revision':2,'anchor':'known'})
  with patch.object(m,'routing') as route,self.assertRaisesRegex(ValueError,'service or lifecycle revision changed'):self.action('apply')
  route.assert_not_called()
 def test_update_retains_complete_new_adapters_in_release_and_lifecycle_runtime(self):
  project=Path(__file__).resolve().parents[1]
  for folder in ('server','single'):shutil.copytree(project/folder,self.source/folder,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
  old_runtime=lifecycle.ROOT/'runtime';(old_runtime/'server').mkdir(parents=True);(old_runtime/'server/previous.py').write_text('previous helper runtime')
  self.prepare()
  with patch.object(m,'routing'),patch.object(m,'verify'):self.action('apply')
  for root in (self.release,lifecycle.ROOT/'runtime'):
   for name in ('recovery_adapters.py','recovery_ike.py','lifecycle_transport.py','engine_updates.py','engine_lifecycle.py','engine_packages.py','engine_containers.py'):
    self.assertEqual((project/'server'/name).read_bytes(),(root/'server'/name).read_bytes())
   script='import sys;sys.path[:0]='+repr([str(root/'server'),str(root/'single')])+';import recovery,recovery_adapters,recovery_ike,lifecycle_transport,entry_migration,engine_updates;from rookstride import engine_guard;import user_updates'
   subprocess.run([sys.executable,'-I','-c',script],check=True,capture_output=True)
  with patch.object(m,'routing'),patch.object(m,'verify'):self.action('rollback')
  self.assertEqual('previous helper runtime',(old_runtime/'server/previous.py').read_text())
 def test_new_helper_does_not_activate_forwarding_before_verification(self):
  self.prepare();events=[]
  def route(mode):events.append((mode,self.manifest.get('activated')))
  def verify(op):events.append(('verify',self.manifest.get('activated')))
  with patch.object(m,'routing',side_effect=route),patch.object(m,'verify',side_effect=verify):self.action('apply')
  self.assertEqual(('refresh',False),events[-2]);self.assertEqual(('verify',False),events[-1])
 def test_pending_runtime_refuses_helper_apply_without_directory_or_route_change(self):
  self.prepare();before=pair.source_digest(self.release);journal=engine_updates.ROOT/('a'*32)/'journal.json'
  for state in ('preparing','prepared','prepare-failed','applying','apply-failed','verified','rolling-back','rollback-failed'):
   m.write(journal,{'state':state})
   with self.subTest(state=state),patch.object(m,'routing') as route:
    with self.assertRaisesRegex(ValueError,'reviewed runtime'):self.action('apply')
    route.assert_not_called();self.assertEqual(before,pair.source_digest(self.release));self.assertEqual('prepared',self.action('status')['state'])
  # An unapplied helper can always be discarded to resolve a stale conflict.
  with patch.object(m,'routing') as route:self.assertEqual('cancelled',self.action('rollback')['state']);route.assert_not_called()
 def test_pending_runtime_refuses_applied_helper_rollback_and_accept(self):
  self.prepare()
  with patch.object(m,'routing'),patch.object(m,'verify'):self.action('apply')
  before=pair.source_digest(self.release);m.write(engine_updates.ROOT/('a'*32)/'journal.json',{'state':'verified'})
  for action in ('rollback','accept'):
   with self.subTest(action=action),patch.object(m,'routing') as route:
    with self.assertRaisesRegex(ValueError,'reviewed runtime'):m.transition({'action':action,'operation':'d'*32,'confirmation':'CLIENT TRAFFIC VERIFIED'})
    route.assert_not_called();self.assertEqual(before,pair.source_digest(self.release))
  m.write(engine_updates.ROOT/('a'*32)/'journal.json',{'state':'accepted'})
  self.assertEqual('accepted',m.transition({'action':'accept','operation':'d'*32,'confirmation':'CLIENT TRAFFIC VERIFIED'})['state'])
 def test_pending_helper_blocks_runtime_preparation_and_every_adapter_resume(self):
  self.prepare();journal=m.ROOT/('d'*32)/'journal.json';original=m.read(journal)
  for state in ('prepared','applying','verified','rolling-back'):
   m.write(journal,dict(original,state=state))
   for group in engine_updates.GROUPS:
    with self.subTest(state=state,group=group):
     with self.assertRaisesRegex(ValueError,'reviewed helper'):engine_updates.snapshot(group)
     with self.assertRaisesRegex(ValueError,'reviewed helper'):engine_updates.same_identity({'group':group})
  # Closing an unapplied helper removes the conflict without touching either
  # runtime or installed helper; terminal journals stay as history.
  m.write(journal,original);self.action('rollback');m.ensure_no_pending_update()
  for state in m.TERMINAL:
   m.write(journal,dict(original,state=state));m.ensure_no_pending_update()

if __name__=='__main__':unittest.main()
