import base64,copy,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import pair,lifecycle,native_pair,native_routing
KEY=base64.b64encode(bytes(range(32))).decode()
def material(host):return {'protocol':'awg','endpoint':host,'dns':{'address':'10.253.0.1','dns_port':5354},'profile':{'content':'[Interface]\nPrivateKey = '+KEY+'\nAddress = 10.67.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = '+KEY+'\nPresharedKey = '+KEY+'\nEndpoint = '+host+':443\nAllowedIPs = 0.0.0.0/0, ::/0\n'}}
class LifecycleTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.own=self.root/'pair';self.own.mkdir()
  self.units=self.root/'units';self.units.mkdir()
  self.p=pair.plan(dict(pair='a'*32,role='entry',server='entry.example.net',exit_host='old.example.net',engine='native-v2',entry_protocol='awg',exit_protocol='awg'))
  self.m=dict(version=2,plan=self.p,bundle='b'*64,configure_digest='c'*64,configured=True,verified=True,activated=True,bridge_ip='10.67.0.2',jobs={})
  (self.own/'transport.json').write_text(json.dumps(material('old.example.net')))
  self.patches=[patch.multiple(lifecycle,ROOT=self.root/'lifecycle',ACTIVE=self.root/'lifecycle'/'active.json'),patch.object(pair,'OWN',self.own),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',side_effect=lambda:copy.deepcopy(self.m)),patch.object(native_pair,'UNIT',self.units),patch.object(lifecycle,'command',return_value='')]
  for p in self.patches:p.start()
  self.req=dict(action='prepare-exit',operation='d'*32,deployment='a'*32,expected_revision=1,exit_host='new.example.net',transport=material('new.example.net'),expected_exit_ip='192.0.2.4',confirmation='REPLACE EXIT AND KEEP ENTRY USERS')
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def action(self,action,**kwargs):return lifecycle.transition(dict(action=action,operation='d'*32,deployment='a'*32,**kwargs))
 def staged(self):
  lifecycle.prepare(self.req)
  def stage(op):
   op['bridge_ip']='10.67.0.3';content=lifecycle.candidate_unit(op);(self.units/('rookstride-lifecycle-'+op['operation']+'.service')).write_text(content);op['service_sha256']=hashlib.sha256(content.encode()).hexdigest()
  with patch.object(lifecycle,'stage',side_effect=stage),patch.object(lifecycle,'verify_route'):self.action('stage')
 def test_adoption_is_read_only_and_has_a_stable_logical_identity(self):
  before=list(self.root.rglob('*'));a=lifecycle.inspect();b=lifecycle.inspect()
  self.assertEqual(a,b);self.assertEqual('a'*32,a['deployment']);self.assertEqual(1,a['revision']);self.assertEqual(before,list(self.root.rglob('*')));self.assertFalse(a['read_only'])
 def test_adoption_never_reconciles_or_writes_an_interrupted_job(self):
  state=self.root/'jobs';status=state/('f'*32)/'status.json';status.parent.mkdir(parents=True);status.write_text(json.dumps({'state':'running','job':'f'*32}));before=status.read_bytes();self.m['jobs']={'bootstrap':'f'*32}
  with patch.object(pair,'STATE',state),patch.object(pair,'status',side_effect=AssertionError('Read-only adoption must not reconcile a job')):self.assertTrue(lifecycle.inspect()['read_only'])
  self.assertEqual(before,status.read_bytes())
 def test_awg_exit_can_be_replaced_behind_every_native_entry_without_touching_listener(self):
  for entry in ('ikev2','awg','openvpn','xray','xhttp','hysteria2','outline','shadowsocks','trusttunnel','naive'):
   self.m['plan'].update(entry_protocol=entry,exit_protocol='awg')
   self.assertIn('replace-exit-awg',lifecycle.inspect()['capabilities'])
   operation=entry.encode().hex().ljust(32,'0')[:32]
   with patch.object(native_pair.runtime,'save') as listener,patch.object(native_routing,'apply') as routing:
    value=lifecycle.prepare(dict(self.req,operation=operation));self.assertEqual('prepared',value['state']);listener.assert_not_called();routing.assert_not_called()
   journal=lifecycle.ROOT/'operations'/operation/'journal.json';op=json.loads(journal.read_text());op['state']='cancelled';lifecycle.write(journal,op)
 def test_unknown_or_changed_owned_installation_is_read_only(self):
  self.m['file_hashes']={str(self.root/'missing'):'x'}
  self.assertTrue(lifecycle.inspect()['read_only'])
  with self.assertRaisesRegex(ValueError,'inspection-only'):lifecycle.prepare(self.req)
 def test_prepare_is_idempotent_but_request_changes_and_competing_operations_are_denied(self):
  first=lifecycle.prepare(self.req);again=lifecycle.prepare(self.req);self.assertEqual(first,again)
  with self.assertRaisesRegex(ValueError,'parameters changed'):lifecycle.prepare(dict(self.req,expected_exit_ip='192.0.2.6'))
  with self.assertRaisesRegex(ValueError,'recorded operation'):lifecycle.prepare(dict(self.req,operation='e'*32))
  self.assertFalse(lifecycle.ACTIVE.exists());self.assertEqual(self.m['plan'],self.p)
 def test_revision_dns_and_profile_executable_tampering_are_rejected_before_stage(self):
  bad=material('new.example.net');bad['dns']['address']='10.254.0.1'
  for changes in ({'expected_revision':2},{'transport':bad},{'confirmation':'yes'}):
   with self.assertRaises(ValueError):lifecycle.prepare(dict(self.req,**changes))
  bad=material('new.example.net');bad['profile']['content']+='PostUp = evil\n'
  with self.assertRaises(ValueError):lifecycle.prepare(dict(self.req,transport=bad))
  self.assertFalse(lifecycle.ROOT.exists())
 def test_failed_candidate_probe_never_changes_live_route(self):
  lifecycle.prepare(self.req)
  with patch.object(lifecycle,'stage'),patch.object(lifecycle,'verify_route',side_effect=ValueError('wrong exit')),patch.object(native_routing,'apply') as route:
   with self.assertRaisesRegex(ValueError,'wrong exit'):self.action('stage')
   route.assert_not_called();self.assertFalse(lifecycle.ACTIVE.exists());self.assertEqual('staging',self.action('status')['state'])
 def test_cutover_closes_before_switch_and_keeps_recipe_and_clients_unchanged(self):
  self.staged();calls=[]
  with patch.object(lifecycle,'candidate_route'),patch.object(lifecycle,'verify_route',side_effect=lambda op,source:calls.append(('verify',source))),patch.object(native_routing,'apply',side_effect=lambda action:calls.append(('route',action))):result=self.action('cutover')
  self.assertEqual('active',result['state']);self.assertEqual(2,lifecycle.inspect()['revision']);self.assertEqual('new.example.net',lifecycle.inspect()['exit_host']);self.assertEqual('old.example.net',self.m['plan']['exit_host']);self.assertEqual('c'*64,self.m['configure_digest']);self.assertEqual('old.example.net',json.loads((self.own/'transport.json').read_text())['endpoint'])
  self.assertEqual([('verify',lifecycle.PROBE),('route','quiesce'),('route','refresh'),('verify',self.p['test_ip']),('route','activate')],calls)
 def test_interrupted_cutover_reconciles_selected_revision_without_reinstalling(self):
  self.staged()
  with patch.object(lifecycle,'candidate_route'),patch.object(lifecycle,'verify_route',side_effect=[None,ValueError('failed live probe')]),patch.object(native_routing,'apply') as route:
   with self.assertRaises(ValueError):self.action('cutover')
   self.assertEqual('quiesce',route.call_args.args[0]);self.assertNotIn('activate',[v.args[0] for v in route.call_args_list])
  self.assertEqual('cutting-over',self.action('status')['state'])
  with patch.object(lifecycle,'candidate_route'),patch.object(lifecycle,'verify_route'),patch.object(lifecycle,'stage') as stage,patch.object(native_routing,'apply'):
   self.assertEqual('active',self.action('cutover')['state']);stage.assert_not_called()
 def test_rollback_verifies_old_exit_before_forwarding_and_can_resume(self):
  self.staged()
  with patch.object(lifecycle,'candidate_route'),patch.object(lifecycle,'verify_route'),patch.object(native_routing,'apply'):self.action('cutover')
  with patch.object(lifecycle,'verify_route',side_effect=ValueError('old exit lost')),patch.object(native_routing,'apply') as route:
   with self.assertRaises(ValueError):self.action('rollback',previous_exit_ip='192.0.2.3')
   self.assertNotIn('activate',[v.args[0] for v in route.call_args_list]);self.assertEqual('rolling-back',self.action('status')['state'])
  with patch.object(lifecycle,'verify_route'),patch.object(native_routing,'apply'):
   self.assertEqual('rolled-back',self.action('rollback',previous_exit_ip='192.0.2.3')['state'])
  self.assertFalse(lifecycle.ACTIVE.exists());self.assertEqual(1,lifecycle.inspect()['revision'])
 def test_corrupt_route_anchor_or_interface_is_never_adopted(self):
  lifecycle.write(lifecycle.ACTIVE,dict(schema=1,deployment='a'*32,anchor='bad',route={}))
  with self.assertRaisesRegex(ValueError,'no longer matches'):lifecycle.route_override(self.m)
  lifecycle.write(lifecycle.ACTIVE,dict(schema=1,deployment='a'*32,anchor=lifecycle.anchor(self.m),route=dict(interface='eth0')))
  with self.assertRaisesRegex(ValueError,'interface'):lifecycle.route_override(self.m)
 def test_accept_requires_explicit_independent_client_verification(self):
  self.staged()
  with patch.object(lifecycle,'candidate_route'),patch.object(lifecycle,'verify_route'),patch.object(native_routing,'apply'):self.action('cutover')
  with self.assertRaisesRegex(ValueError,'independent'):self.action('accept')
  self.assertEqual('accepted',self.action('accept',confirmation='CLIENT TRAFFIC VERIFIED')['state'])
  with self.assertRaisesRegex(ValueError,'new reviewed'):self.action('rollback',previous_exit_ip='192.0.2.3')
 def test_staging_waits_for_exact_address_and_up_state_before_adding_routes(self):
  from types import SimpleNamespace
  lifecycle.prepare(self.req);op,_,_=lifecycle.load_operation(dict(operation='d'*32,deployment='a'*32));units=self.units;calls=[]
  states=[{'flags':['UP'],'addr_info':[]},{'flags':[],'addr_info':[{'local':'10.67.0.2'}]},{'flags':['UP'],'addr_info':[{'local':'10.67.0.2'}]}]
  def link(args,**kwargs):calls.append('link');return SimpleNamespace(returncode=0,stdout=json.dumps([states.pop(0)]))
  with patch.object(lifecycle,'enable_runtime'),patch.object(native_pair,'UNIT',units),patch.object(lifecycle,'command'),patch.object(lifecycle.subprocess,'run',side_effect=link),patch.object(lifecycle.time,'sleep'),patch.object(lifecycle,'candidate_route',side_effect=lambda op:calls.append('route')):
   lifecycle.stage(op)
  self.assertEqual(['link','link','link','route'],calls);self.assertEqual('10.67.0.2',op['bridge_ip'])
 def test_rollback_retires_only_after_old_route_verified_and_rechecks_terminal_replay(self):
  self.staged();events=[]
  with patch.object(lifecycle,'verify_route',side_effect=lambda *args:events.append('verified')),patch.object(native_routing,'apply',side_effect=lambda action:events.append(action)),patch.object(lifecycle,'command',side_effect=lambda args:events.append(tuple(args))):
   result=self.action('rollback',previous_exit_ip='192.0.2.3')
  self.assertTrue(result['candidate_retired']);self.assertEqual('verified',events[-3]);self.assertEqual('activate',events[-2]);self.assertEqual(('systemctl','disable','--now','rookstride-lifecycle-'+'d'*32),events[-1])
  with patch.object(lifecycle,'command') as stop,patch.object(native_routing,'apply') as route,patch.object(lifecycle,'verify_route') as verify:
   self.assertTrue(self.action('rollback')['candidate_retired']);stop.assert_called_once_with(['systemctl','disable','--now','rookstride-lifecycle-'+'d'*32]);route.assert_not_called();verify.assert_not_called()
  self.assertTrue((self.units/('rookstride-lifecycle-'+'d'*32+'.service')).is_file());self.assertTrue((lifecycle.ROOT/'operations'/('d'*32)/'journal.json').is_file())
 def test_retirement_refuses_active_referenced_changed_and_missing_service(self):
  self.staged();op,_,_=lifecycle.load_operation(dict(operation='d'*32,deployment='a'*32));path=self.units/('rookstride-lifecycle-'+'d'*32+'.service');original=path.read_text()
  with patch.object(lifecycle,'command') as stop:
   lifecycle.write(lifecycle.ACTIVE,{'operation':op['operation']})
   with self.assertRaisesRegex(ValueError,'selected'):lifecycle.retire_candidate(op)
   lifecycle.ACTIVE.unlink();other={**op,'operation':'e'*32,'state':'accepted','previous':{'operation':op['operation']}};journal=lifecycle.ROOT/'operations'/('e'*32)/'journal.json';lifecycle.write(journal,other)
   with self.assertRaisesRegex(ValueError,'retains'):lifecycle.retire_candidate(op)
   journal.unlink();path.write_text(original+'# changed\n')
   with self.assertRaisesRegex(ValueError,'ownership'):lifecycle.retire_candidate(op)
   path.unlink()
   with self.assertRaisesRegex(ValueError,'ownership'):lifecycle.retire_candidate(op)
   stop.assert_not_called()
 def test_failed_retirement_keeps_resumable_journal_without_reopening_bad_route(self):
  self.staged()
  with patch.object(lifecycle,'verify_route'),patch.object(native_routing,'apply'),patch.object(lifecycle,'command',side_effect=RuntimeError('service stop interrupted')):
   with self.assertRaisesRegex(RuntimeError,'interrupted'):self.action('rollback',previous_exit_ip='192.0.2.3')
  self.assertEqual('rolling-back',self.action('status')['state']);self.assertFalse(lifecycle.ACTIVE.exists())
  with patch.object(lifecycle,'verify_route'),patch.object(native_routing,'apply'):
   self.assertTrue(self.action('rollback',previous_exit_ip='192.0.2.3')['candidate_retired'])

class SharedManagementLockTests(unittest.TestCase):
 def test_owner_snapshot_waits_for_the_current_administrator_mutation(self):
  import threading,fcntl
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);started=threading.Event();acquired=threading.Event();errors=[]
   with patch.multiple(lifecycle,MANAGEMENT_LOCK=root/'management',LOCK=root/'lifecycle'),patch.object(pair,'LOCK',root/'pair'):
    def snapshot():
     try:
      started.set()
      with lifecycle.management_lock():acquired.set()
     except Exception as error:errors.append(error)
    with (root/'management').open('a') as owner:
     fcntl.flock(owner,fcntl.LOCK_EX);thread=threading.Thread(target=snapshot);thread.start();self.assertTrue(started.wait(1));self.assertFalse(acquired.wait(.1));fcntl.flock(owner,fcntl.LOCK_UN)
    thread.join(2);self.assertFalse(thread.is_alive());self.assertTrue(acquired.is_set());self.assertFalse(errors)

if __name__=='__main__':unittest.main()
