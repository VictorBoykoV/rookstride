"""Runtime transactions bind identity/configuration, retain rollback and keep routes closed."""
import copy,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE/'server'));sys.path.insert(0,str(BASE/'single'))
import engine_updates as engine

class EngineUpdates(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.patchers=[patch.object(engine,'ROOT',self.root/'updates'),patch.object(engine.pair,'protected',side_effect=lambda p:Path(p))]
  for p in self.patchers:p.start()
  self.op={'operation':'a'*32,'group':'xray','state':'prepared','candidate':'v-fixture','old_hashes':['old'],'new_hash':'new','target':'/opt/rookstride-single/bin/xray','created':1,
   'snapshot':{'machine':'server-generation','pair':{},'states':{'xray':'users-hash'},'services':[{'name':'rookstride-single-xray','text':'ExecStart=/opt/rookstride-single/bin/xray run -config /owned/config\n','argv':['/opt/rookstride-single/bin/xray','run','-config','/owned/config'],'configs':{'/owned/config':'same-config'},'binary':'old'}]}}
 def tearDown(self):
  for p in reversed(self.patchers):p.stop()
  self.temp.cleanup()
 def test_identity_account_and_config_changes_prevent_apply(self):
  for key in ('machine','pair','states'):
   snap=copy.deepcopy(self.op['snapshot']);snap[key]='changed'
   with patch.object(engine,'snapshot',return_value=snap):
    with self.assertRaisesRegex(ValueError,'changed after review'):engine.same_identity(self.op)
  snap=copy.deepcopy(self.op['snapshot']);snap['services'][0]['configs']={'/owned/config':'edited'}
  with patch.object(engine,'snapshot',return_value=snap):
   with self.assertRaisesRegex(ValueError,'configuration changed'):engine.same_identity(self.op)
 def test_only_recorded_old_or_new_engine_files_can_resume(self):
  for identity,allowed in [('old',True),('new',True),('unknown',False)]:
   snap=copy.deepcopy(self.op['snapshot']);snap['services'][0]['binary']=identity
   with patch.object(engine,'snapshot',return_value=snap):
    if allowed:engine.same_identity(self.op)
    else:
     with self.assertRaisesRegex(ValueError,'outside this operation'):engine.same_identity(self.op)
 def test_apply_requires_review_and_journals_before_launch(self):
  with patch.object(engine,'load',return_value=self.op),patch.object(engine,'same_identity'),patch.object(engine,'launch') as launch:
   with self.assertRaisesRegex(ValueError,'Review'):engine.transition({'action':'apply','operation':'a'*32})
   launch.assert_not_called()
   result=engine.transition({'action':'apply','operation':'a'*32,'confirmation':'RESTART REVIEWED VPN RUNTIMES'})
   self.assertEqual('applying',result['state']);record=json.loads((engine.ROOT/('a'*32)/'journal.json').read_text());self.assertEqual('apply',record['direction']);launch.assert_called_once()
 def test_unapplied_cancel_never_touches_runtime(self):
  with patch.object(engine,'load',return_value=self.op),patch.object(engine,'restart') as restart,patch.object(engine,'quiesce') as guard:
   self.assertEqual('cancelled',engine.transition({'action':'cancel','operation':'a'*32})['state'])
   restart.assert_not_called();guard.assert_not_called()
 def test_accept_requires_client_confirmation_and_unchanged_identity(self):
  self.op['state']='verified'
  with patch.object(engine,'load',return_value=self.op),patch.object(engine,'same_identity') as verify:
   with self.assertRaisesRegex(ValueError,'saved client'):engine.transition({'action':'accept','operation':'a'*32})
   self.assertEqual('accepted',engine.transition({'action':'accept','operation':'a'*32,'confirmation':'SAVED CLIENT TRAFFIC VERIFIED'})['state']);verify.assert_called_once()
 def test_lost_worker_is_reported_then_reconciled_without_replaying(self):
  self.op.update(state='applying',direction='apply')
  with patch.object(engine,'load',side_effect=lambda _:copy.deepcopy(self.op)),patch.object(engine.subprocess,'run',return_value=SimpleNamespace(returncode=3)),patch.object(engine,'launch') as launch:
   report=engine.status(self.op);self.assertEqual('apply-failed',report['state']);self.assertFalse((engine.ROOT/('a'*32)/'journal.json').exists());launch.assert_not_called()
   engine.status(self.op,True);self.assertTrue((engine.ROOT/('a'*32)/'journal.json').exists());launch.assert_not_called()
 def test_completed_worker_race_returns_latest_state(self):
  stale=copy.deepcopy(self.op);stale.update(state='applying',direction='apply');new=copy.deepcopy(self.op);new['state']='verified'
  with patch.object(engine,'load',return_value=new),patch.object(engine.subprocess,'run',return_value=SimpleNamespace(returncode=3)):
   self.assertEqual('verified',engine.status(stale)['state'])
 def test_candidate_integrity_failure_does_not_restart_or_open_forwarding(self):
  self.op['candidate_file']=str(self.root/'candidate');self.op['snapshot']['services']=[]
  with patch.object(engine,'same_identity'),patch.object(engine,'quiesce') as guard,patch.object(engine,'sha',return_value='tampered'),patch.object(engine,'restart') as restart,patch.object(engine,'verify') as verify:
   with self.assertRaisesRegex(ValueError,'Staged runtime changed'):engine.mutate(self.op,False)
   guard.assert_called_once();restart.assert_not_called();verify.assert_not_called()
 def test_rollback_checks_retained_executable_before_replacing_current(self):
  self.op['previous_binaries']={self.op['target']:{'backup':str(self.root/'old'),'sha256':'old'}}
  with patch.object(engine,'same_identity'),patch.object(engine,'quiesce'),patch.object(engine,'sha',return_value='tampered'),patch.object(engine,'copy_binary') as swap:
   with self.assertRaisesRegex(ValueError,'Retained runtime integrity'):engine.mutate(self.op,True)
   swap.assert_not_called()
 def test_pair_reopens_only_after_actual_expected_exit_and_dns_verification(self):
  manifest={'plan':{'pair':'b'*32,'role':'entry'}};req={'action':'verify-pair','deployment':'b'*32,'expected_exit_ip':'192.0.2.42','filtering_enabled':False}
  with patch.object(engine.pair,'load_manifest',return_value=manifest),patch.object(engine.native_pair,'verify') as verify:
   result=engine.pair_guard(req);verify.assert_called_once_with(manifest['plan'],{'expected_exit_ip':'192.0.2.42','filtering_enabled':False},True);self.assertEqual('active',result['forwarding'])
  with patch.object(engine.pair,'load_manifest',return_value=manifest),patch.object(engine.native_pair,'verify',side_effect=ValueError('Wrong exit')):
   with self.assertRaisesRegex(ValueError,'Wrong exit'):engine.pair_guard(req)
 def test_actual_unit_parser_rejects_other_paths_and_multiple_commands(self):
  state=self.root/'state';state.mkdir();config=state/'config.json';config.write_text('{}');opt=self.root/'opt';(opt/'bin').mkdir(parents=True);binary=opt/'bin/xray';binary.write_bytes(b'fixture executable');units=self.root/'units';units.mkdir();path=units/'rookstride-single-xray.service'
  with patch.object(engine,'UNIT',units),patch.object(engine.runtime,'ROOT',opt),patch.object(engine.runtime,'STATE',state):
   path.write_text('Description=Rookstride Xray VPN\nExecStart='+str(binary)+' run -config '+str(config)+'\n')
   result=engine.unit('rookstride-single-xray','xray');self.assertEqual(str(binary),result['argv'][0]);self.assertEqual(1,len(result['configs']))
   path.write_text(path.read_text()+'ExecStart=/bin/sh -c true\n')
   with self.assertRaises(ValueError):engine.unit('rookstride-single-xray','xray')
 def test_user_mutations_refuse_pending_runtime_rollback(self):
  import user_updates
  path=engine.ROOT/('a'*32)/'journal.json';path.parent.mkdir(parents=True)
  for state,blocked in [('preparing',False),('prepared',False),('verified',True),('applying',True),('apply-failed',True),('rolling-back',True),('rolled-back',False),('accepted',False)]:
   path.write_text(json.dumps({'state':state}))
   if blocked:
    with self.assertRaisesRegex(ValueError,'Finish or roll back'):user_updates.ensure_no_runtime_update(engine.ROOT)
   else:user_updates.ensure_no_runtime_update(engine.ROOT)
 def test_destructive_reuse_requires_closing_even_unapplied_review(self):
  import user_updates
  path=engine.ROOT/('a'*32)/'journal.json';path.parent.mkdir(parents=True)
  for state in ('preparing','prepared','prepare-failed','verified'):
   path.write_text(json.dumps({'state':state}))
   with self.assertRaisesRegex(ValueError,'Finish or roll back'):user_updates.ensure_no_runtime_update(engine.ROOT,destructive=True)
  path.write_text(json.dumps({'state':'abandoned'}));user_updates.ensure_no_runtime_update(engine.ROOT,destructive=True)
 def test_abandon_closes_only_record_and_keeps_running_engine_untouched(self):
  self.op['state']='apply-failed'
  with patch.object(engine,'load',return_value=self.op),patch.object(engine,'restart') as restart,patch.object(engine,'quiesce') as guard:
   with self.assertRaisesRegex(ValueError,'Review abandoning'):engine.transition({'action':'abandon','operation':'a'*32})
   self.assertEqual('abandoned',engine.transition({'action':'abandon','operation':'a'*32,'confirmation':'ABANDON ENGINE ROLLBACK'})['state']);restart.assert_not_called();guard.assert_not_called()
 def test_another_consumers_old_binary_is_not_this_services_rollback_identity(self):
  self.op['old_hashes']=['old','other-old'];snap=copy.deepcopy(self.op['snapshot']);snap['services'][0]['binary']='other-old'
  with patch.object(engine,'snapshot',return_value=snap):
   with self.assertRaisesRegex(ValueError,'outside this operation'):engine.same_identity(self.op)
 def test_missing_original_version_marker_is_removed_on_rollback(self):
  opt=self.root/'opt';(opt/'bin').mkdir(parents=True);marker=opt/'bin/version';marker.write_text(engine.runtime.PINS['xray']['version']);self.op.update(old_version=None,previous_binaries={})
  with patch.object(engine.runtime,'ROOT',opt),patch.object(engine,'same_identity'),patch.object(engine,'quiesce'),patch.object(engine,'restart'),patch.object(engine,'verify'):
   engine.mutate(self.op,True)
  self.assertFalse(marker.exists())
 def test_restart_writes_a_real_owned_unit_with_readable_service_mode(self):
  service=self.op['snapshot']['services'][0];path=self.root/'rookstride-single-xray.service';service['path']=str(path)
  with patch.object(engine.runtime,'command') as command,patch.object(engine.pair,'load_manifest',return_value=None),patch.object(engine.engine_lifecycle,'update'):
   engine.restart(self.op,False)
  self.assertEqual(service['text'],path.read_text());self.assertEqual(0o644,path.stat().st_mode&0o777);self.assertEqual(['systemctl','restart',service['name']],command.call_args.args[0])
 def test_ike_exit_filter_policy_reads_its_classic_adguard(self):
  import recovery
  manifest={'plan':{'role':'exit','exit_protocol':'ikev2'}}
  with patch.object(recovery.pair,'load_manifest',return_value=manifest),patch.object(recovery.recovery_ike,'filter_api',return_value={'protection_enabled':False}) as classic,patch.object(engine.filtering,'api',side_effect=AssertionError('Native DNS is not installed')):
   self.assertEqual({'enabled':False},engine.dispatch({'action':'filter-policy'}));classic.assert_called_once_with('dns_info',None)
 def test_native_exit_filter_policy_keeps_shared_adguard_dispatch(self):
  import recovery
  manifest={'plan':{'role':'exit','exit_protocol':'awg'}}
  with patch.object(recovery.pair,'load_manifest',return_value=manifest),patch.object(recovery.recovery_ike,'filter_api',side_effect=AssertionError('Classic DNS is not installed')),patch.object(engine.filtering,'api',return_value={'protection_enabled':True}) as shared:
   self.assertEqual({'enabled':True},engine.dispatch({'action':'filter-policy'}));shared.assert_called_once_with('dns_info',None)
if __name__=='__main__':unittest.main()
