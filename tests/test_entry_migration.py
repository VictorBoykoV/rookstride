import copy,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import pair,lifecycle,entry_migration,recovery,native_pair,native_routing
from test_owner_recovery import snapshot
class EntryMigrationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.snapshot=snapshot();self.m=dict(version=2,plan=self.snapshot['plan'],bundle='c'*64,configure_digest='d'*64,configured=True,activated=True,jobs={})
  self.patches=[patch.multiple(lifecycle,ROOT=self.root,ACTIVE=self.root/'active.json'),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',side_effect=lambda:copy.deepcopy(self.m)),patch.object(recovery,'export',side_effect=lambda:copy.deepcopy(self.snapshot))]
  for p in self.patches:p.start()
  self.req=dict(action='prepare',operation='e'*32,deployment='a'*32,expected_revision=1,candidate='new.example.net',candidate_fingerprint='SHA256:'+'A'*43,endpoint_transfer=False,confirmation='REPLACE ENTRY AND PRESERVE VPN IDENTITY')
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def action(self,action,**extra):return entry_migration.dispatch(dict(action=action,operation='e'*32,deployment='a'*32,**extra))
 def test_prepare_keeps_original_route_unchanged_and_pins_exact_review(self):
  with patch.object(native_routing,'apply') as routing:
   first=entry_migration.prepare(self.req);self.assertEqual('entry-prepared',first['state']);self.assertEqual(first,entry_migration.prepare(self.req));routing.assert_not_called()
  with self.assertRaisesRegex(ValueError,'review changed'):entry_migration.prepare(dict(self.req,candidate='other.example.net'))
 def test_literal_ip_requires_reviewed_address_transfer(self):
  self.m['plan']['server']='192.0.2.7'
  with self.assertRaisesRegex(ValueError,'literal IP'):entry_migration.prepare(self.req)
  self.assertEqual('entry-prepared',entry_migration.prepare(dict(self.req,endpoint_transfer=True))['state'])
 def test_fixed_address_can_move_only_with_explicit_updated_client_mode(self):
  self.m['plan']['server']='192.0.2.7'
  op=entry_migration.prepare(dict(self.req,new_address=True));self.assertTrue(op['client_update_required']);self.assertEqual('new.example.net',op['endpoint'])
  self.action('candidate-ready')
  with patch.object(native_routing,'apply') as routing:
   with self.assertRaisesRegex(ValueError,'Verify endpoint'):self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED')
   routing.assert_not_called();self.assertEqual('accepted',self.action('commit',confirmation='NEW ENDPOINT CLIENT VERIFIED')['state'])
 def test_logical_endpoint_revision_does_not_rewrite_pair_recipe(self):
  before=copy.deepcopy(self.m);request={'action':'record-revision','deployment':'a'*32,'operation':'e'*32,'revision':2,'entry_endpoint':'new.example.net'}
  entry_migration.dispatch(request);entry_migration.dispatch(request)
  self.assertEqual(before,self.m);self.assertEqual('new.example.net',lifecycle.inspect()['plan']['server'])
  with self.assertRaisesRegex(ValueError,'endpoint changed'):entry_migration.dispatch(dict(request,entry_endpoint='another.example.net'))
 def test_account_changes_after_staging_do_not_silently_discard_new_users(self):
  entry_migration.prepare(self.req);self.action('candidate-ready');self.snapshot['state']['users'][0]['enabled']=False
  with patch.object(native_routing,'apply') as routing:
   with self.assertRaisesRegex(ValueError,'users or identity changed'):self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED')
   routing.assert_not_called()
 def test_new_entry_activation_is_separate_from_old_entry_retirement(self):
  entry_migration.prepare(self.req)
  with self.assertRaisesRegex(ValueError,'Stage'):self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED')
  self.action('candidate-ready')
  with patch.object(native_routing,'apply') as routing:
   with self.assertRaisesRegex(ValueError,'Verify endpoint'):self.action('commit')
   self.assertEqual('accepted',self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED')['state']);routing.assert_called_once_with('quiesce');self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED');routing.assert_called_once()
 def test_accepted_commit_replay_does_not_revalidate_retired_user_database(self):
  entry_migration.prepare(self.req);self.action('candidate-ready')
  with patch.object(native_routing,'apply') as routing:
   result=self.action('commit',confirmation='ENDPOINT AND SAVED CLIENT VERIFIED');self.snapshot['state']['users'][0]['enabled']=False
   self.assertEqual('accepted',self.action('commit')['state']);routing.assert_called_once_with('quiesce')
 def test_candidate_route_is_rechecked_on_pinned_member_before_old_entry_commit(self):
  request=dict(action='verify-candidate',deployment='a'*32,expected_exit_ip='192.0.2.9',filtering_enabled=False)
  with patch.object(lifecycle,'route_override',return_value=None),patch.object(native_pair,'verify') as verify:
   self.assertTrue(entry_migration.dispatch(request)['verified']);verify.assert_called_once_with(self.m['plan'],{'expected_exit_ip':'192.0.2.9','filtering_enabled':False},True)
  with patch.object(native_pair,'verify',side_effect=ValueError('candidate route failed')):
   with self.assertRaisesRegex(ValueError,'candidate route failed'):entry_migration.dispatch(request)
 def test_rollback_verifies_current_accepted_exit_and_dns_not_original_recipe(self):
  entry_migration.prepare(self.req);self.action('candidate-ready');plan=dict(self.m['plan'],exit_host='replacement.example.net');transport={'dns':{'address':'10.253.0.1','dns_port':53}}
  with patch.object(lifecycle,'route_override',return_value={'operation':'f'*32}),patch.object(recovery,'effective_topology',return_value=(plan,transport)),patch.object(lifecycle,'verify_route') as verify,patch.object(native_pair,'verify') as obsolete,patch.object(pair,'write_manifest'),patch.object(native_routing,'apply') as routing:
   self.action('rollback',confirmation='ORIGINAL ENDPOINT RESTORED',expected_exit_ip='192.0.2.9',filtering_enabled=False)
   obsolete.assert_not_called();self.assertEqual('replacement.example.net',verify.call_args.args[0]['plan']['exit_host']);self.assertEqual([('refresh',),('activate',)],[call.args for call in routing.call_args_list])
 def test_failed_rollback_never_claims_original_route_restored(self):
  entry_migration.prepare(self.req);self.action('candidate-ready')
  with patch.object(native_pair,'verify',side_effect=ValueError('exit unreachable')):
   with self.assertRaises(ValueError):self.action('rollback',confirmation='ORIGINAL ENDPOINT RESTORED',expected_exit_ip='192.0.2.9')
  self.assertEqual('awaiting-endpoint-switch',self.action('status')['state'])
if __name__=='__main__':unittest.main()
