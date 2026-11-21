import base64,contextlib,copy,json,secrets,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import pair,native_pair,lifecycle,recovery
KEY=base64.b64encode(bytes(range(32))).decode()
PUBLIC=base64.b64encode(recovery.adapters.derived_public(bytes(range(32)))).decode()
def snapshot(role='entry'):
 p=pair.plan(dict(pair='a'*32,role=role,server='vpn.example.net',exit_host='exit.example.net',engine='native-v2',entry_protocol='awg',exit_protocol='awg',vpn_port=51820))
 user=dict(login='phone',enabled=True,created=1,private=KEY,public=PUBLIC,psk=KEY,address='10.66.0.2' if role=='entry' else '10.67.0.2',ipv6='fd42:670::2')
 state=dict(protocol='awg',server=p['server'] if role=='entry' else p['exit_host'],port=p['vpn_port'] if role=='entry' else p['tunnel_port'],owner='rookstride-single-v1',instance='b'*32,initialLogin='phone',private=KEY,public=PUBLIC,parameters=native_pair.model.awg_parameters(),users=[user])
 bridge=copy.deepcopy(state);bridge.update(server=p['exit_host'],port=p['tunnel_port']);bridge['users'][0].update(address='10.67.0.2')
 transport={'protocol':'awg','endpoint':p['exit_host'],'profile':native_pair.runtime.profile(bridge,'phone'),'dns':{'address':'10.253.0.1','dns_port':5354}}
 if role=='entry':state.update(pair='a'*32,pair_dns=transport['dns'])
 return dict(schema=1,purpose='rookstride-owner-recovery-node',deployment='a'*32,role=role,plan=p,state=state,initial_user={'login':'phone','password':'password-fixture'},transport=transport if role=='entry' else None,filter_policy={'enabled':True,'level':'standard'})
def archive():
 nodes={role:snapshot(role) for role in ('entry','exit')}
 nodes['entry']['transport']['profile']=native_pair.runtime.profile(nodes['exit']['state'],'phone')
 return dict(schema=1,purpose='rookstride-owner-recovery',deployment='a'*32,nodes=nodes)
class OwnerRecoveryTests(unittest.TestCase):
 def test_complete_native_parameters_and_client_addresses_are_required(self):
  value=snapshot();recovery.validate(value)
  for mutate in (lambda s:s['state']['parameters'].pop('HeaderProtectionKey'),lambda s:s['state']['users'][0].update(address='192.0.2.1'),lambda s:s.update(grants={'owner':'resurrect'}),lambda s:s['state']['parameters'].update(Jc='1\nPostUp = arbitrary')):
   bad=copy.deepcopy(value);mutate(bad)
   with self.assertRaises(ValueError):recovery.validate(bad)
 def test_bootstrap_metadata_is_required_before_rehearsal_succeeds(self):
  for mutate in (lambda s:s.pop('initial_user'),lambda s:s['initial_user'].pop('password'),lambda s:s['initial_user'].update(login='another'),lambda s:s['initial_user'].update(password='bad\nvalue')):
   value=snapshot();mutate(value)
   with self.assertRaises(ValueError):recovery.dispatch(dict(action='rehearse',snapshot=value))
 def test_pair_rehearsal_checks_complete_bridge_and_target_contract_before_mutation(self):
  value=archive();plans={role:copy.deepcopy(value['nodes'][role]['plan']) for role in ('entry','exit')}
  with patch.object(native_pair.runtime,'save') as save,patch.object(native_pair,'command') as command:
   self.assertEqual(2,recovery.validate_pair(value,plans)['readiness_schema'])
   for field,replacement in (('server','new-entry.example.net'),('exit_host','new-exit.example.net'),('tunnel_port',8443),('vpn_port',51821)):
    changed=copy.deepcopy(plans);changed['entry'][field]=replacement
    with self.assertRaisesRegex(ValueError,'planned deployment'):recovery.validate_pair(value,changed)
   for field in ('private','psk'):
    changed=copy.deepcopy(value);changed['nodes']['exit']['state']['users'][0][field]=base64.b64encode(b'x'*32).decode()
    with self.assertRaisesRegex(ValueError,'identity|bridge credentials'):recovery.validate_pair(changed,plans)
   changed=copy.deepcopy(value);changed['nodes']['exit']['state']['public']=base64.b64encode(b'x'*32).decode()
   with self.assertRaisesRegex(ValueError,'identity|bridge credentials'):recovery.validate_pair(changed,plans)
   changed=copy.deepcopy(value);changed['nodes']['exit']['state']['users'][0]['enabled']=False
   with self.assertRaisesRegex(ValueError,'enabled exit bridge'):recovery.validate_pair(changed,plans)
   save.assert_not_called();command.assert_not_called()
 def test_cross_member_topology_mismatch_and_active_exit_migration_are_refused(self):
  value=archive();plans={role:copy.deepcopy(value['nodes'][role]['plan']) for role in ('entry','exit')}
  changed=copy.deepcopy(value);changed['nodes']['exit']['state']['server']='replacement.example.net';changed['nodes']['exit']['plan']['exit_host']='replacement.example.net';changed_plans=copy.deepcopy(plans);changed_plans['exit']['exit_host']='replacement.example.net'
  with self.assertRaisesRegex(ValueError,'one compatible pair'):recovery.validate_pair(changed,changed_plans)
  with patch.object(pair,'load_manifest',return_value=dict(plan=plans['entry'])),patch.object(lifecycle,'route_override',return_value={'operation':'e'*32,'route':{'exit_host':'replacement.example.net'}}):
   with self.assertRaisesRegex(ValueError,'accepted exit replacement'):recovery.rehearse_pair(dict(archive=value,plans=plans))
 def test_restore_keeps_exact_saved_profile_and_uses_new_counter_generation(self):
  value=snapshot();old=native_pair.runtime.profile(value['state'],'phone')['content'];current=copy.deepcopy(value['state']);current['instance']='c'*32;current['private']=base64.b64encode(b'x'*32).decode();saved=[]
  m=dict(version=2,plan=value['plan'])
  with tempfile.TemporaryDirectory() as directory,patch.object(lifecycle,'ROOT',Path(directory)),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',return_value=m),patch.object(pair,'RELEASE',Path(__file__).resolve().parents[1]),patch.object(pair,'OWN',Path(directory)/'owned'),patch.object(native_pair.runtime,'load',side_effect=lambda _:saved[-1] if saved else current),patch.object(native_pair.runtime,'check_container',return_value={'owned':True}),patch.object(native_pair,'command') as command,patch.object(native_pair.runtime,'save',side_effect=lambda v:saved.append(copy.deepcopy(v))),patch.object(native_pair.runtime,'apply_config') as apply,patch.object(native_pair.runtime,'health',return_value={'running':True}):
   req=dict(action='restore',snapshot=value,confirmation='RESTORE REVIEWED VPN IDENTITY');result=recovery.restore(req);self.assertEqual(old,native_pair.runtime.profile(saved[-1],'phone')['content']);self.assertEqual('c'*32,result['usage_generation']);self.assertEqual(['docker','rm','-f','rookstride-single-awg'],command.call_args.args[0]);apply.assert_called_once()
   replay=recovery.restore(req);self.assertEqual(result,replay);apply.assert_called_once()
   with patch.object(native_pair.runtime,'health',return_value={'running':False}):
    with self.assertRaisesRegex(ValueError,'not running'):recovery.restore(req)
   saved[-1]['users'][0]['enabled']=False
   with self.assertRaisesRegex(ValueError,'identity changed after completion'):recovery.restore(req)
   apply.assert_called_once()
 def test_restore_denies_foreign_deployment_existing_accounts_and_endpoint_changes(self):
  value=snapshot();current=copy.deepcopy(value['state']);current['users']*=2
  with tempfile.TemporaryDirectory() as directory,patch.object(lifecycle,'ROOT',Path(directory)),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',return_value=dict(version=2,plan=value['plan'])),patch.object(native_pair.runtime,'load',return_value=current),patch.object(native_pair.runtime,'save') as save:
   with self.assertRaisesRegex(ValueError,'existing user'):recovery.restore(dict(snapshot=value,confirmation='RESTORE REVIEWED VPN IDENTITY'))
   value['plan']['server']='other.example.net'
   with self.assertRaises(ValueError):recovery.restore(dict(snapshot=value,confirmation='RESTORE REVIEWED VPN IDENTITY'))
   save.assert_not_called()
 def test_restore_rejects_active_one_account_nodes_before_any_mutation(self):
  for role,flag in (('entry','activated'),('exit','configured')):
   value=snapshot(role);current=copy.deepcopy(value['state']);current['instance']='c'*32
   for same_generation in (False,True):
    manifest=dict(version=2,plan=value['plan']);manifest[flag]=not same_generation
    if same_generation:current['instance']=value['state']['instance']
    with tempfile.TemporaryDirectory() as directory,patch.object(lifecycle,'ROOT',Path(directory)),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',return_value=manifest),patch.object(native_pair.runtime,'load',return_value=current),patch.object(native_pair.runtime,'save') as save,patch.object(native_pair,'command') as command:
     with self.assertRaisesRegex(ValueError,'fresh replacement'):recovery.restore(dict(snapshot=value,confirmation='RESTORE REVIEWED VPN IDENTITY'))
     save.assert_not_called();command.assert_not_called()
 def test_restore_rejects_changed_exit_endpoint_or_port(self):
  value=snapshot('exit');current=copy.deepcopy(value['state'])
  for field,replacement in (('exit_host','new-exit.example.net'),('tunnel_port',8443)):
   target=copy.deepcopy(value['plan']);target[field]=replacement
   with patch.object(pair,'load_manifest',return_value=dict(version=2,plan=target)),patch.object(native_pair.runtime,'load',return_value=current),patch.object(native_pair.runtime,'save') as save:
    with self.assertRaisesRegex(ValueError,'endpoint or protocol'):recovery.restore(dict(snapshot=value,confirmation='RESTORE REVIEWED VPN IDENTITY'))
    save.assert_not_called()

 def test_delegated_account_provenance_is_excluded_without_losing_vpn_keys(self):
  value=snapshot();state=copy.deepcopy(value['state']);state['users'][0]['administration_account_id']='admin-issued-fixture';m=dict(version=2,plan=value['plan'],bundle='c'*64,configure_digest='d'*64)
  with tempfile.TemporaryDirectory() as directory:
   own=Path(directory);(own/'initial-user.json').write_text(json.dumps(value['initial_user']));(own/'transport.json').write_text(json.dumps(value['transport']))
   with patch.object(pair,'OWN',own),patch.object(pair,'load_manifest',return_value=m),patch.object(native_pair.runtime,'load',return_value=state):archive=recovery.export()
  self.assertNotIn('administration_account_id',archive['state']['users'][0]);self.assertEqual(state['users'][0]['private'],archive['state']['users'][0]['private']);self.assertIn('administration_account_id',state['users'][0])
  archive['state']['users'][0]['administration_account_id']='restore-old-authority'
  with self.assertRaises(ValueError):recovery.validate(archive)

 def test_empty_adguard_whitelist_is_returned_as_null(self):
  standard=native_pair.filtering.FILTERS['standard'][1]
  with patch.object(recovery,'filtering_api',side_effect=[{'filters':[{'enabled':True,'url':standard}],'user_rules':None,'whitelist_filters':None},{'protection_enabled':True}]):self.assertEqual({'level':'standard','enabled':True},recovery.filter_policy())

 def test_custom_filtering_is_not_silently_lost(self):
  standard=native_pair.filtering.FILTERS['standard'][1]
  for filters in ([],[{'enabled':True,'url':'https://example.net/custom.txt'}]):
   with patch.object(recovery,'filtering_api',side_effect=[{'filters':filters},{'protection_enabled':True}]):
    with self.assertRaises(ValueError):recovery.filter_policy()
  with patch.object(recovery,'filtering_api',side_effect=[{'filters':[{'enabled':True,'url':standard}]},{'protection_enabled':False}]):self.assertEqual({'level':'standard','enabled':False},recovery.filter_policy())
class MigrationBridgeIdentityTests(unittest.TestCase):
 def setUp(self):
  patcher=patch.object(pair,'RELEASE',Path(__file__).resolve().parents[1]);patcher.start();self.addCleanup(patcher.stop)
 def test_worker_bridge_uses_durable_recipe_on_creation_and_interrupted_reapply(self):
  import routes
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);release=root/'owned-release';(release/'single').mkdir(parents=True)
   for name in ('runtime.py','run.py'):(release/'single'/name).write_text('# owned test recipe\n')
   path=root/'state.json';value={'protocol':'hysteria2','instance':'b'*32,'server':'exit.example.net','port':443,'users':[{'login':'initial','enabled':True,'password':'original'}]};path.write_text(json.dumps(value))
   plan=pair.plan(dict(pair='a'*32,role='exit',engine='native-v2',entry_protocol='awg',exit_protocol='hysteria2',server='entry.example.net',exit_host='exit.example.net'))
   def load(*args):return json.loads(path.read_text())
   def save(state):path.write_text(json.dumps(state))
   units=[]
   def apply(state):
    self.assertEqual(str(release/'single/runtime.py'),native_pair.runtime.__file__)
    routes.write_unit(state,native_pair.runtime,Path('/owned/worker'),['run','/owned/worker.json'])
    if len(units)==1:raise RuntimeError('interrupted listener restart')
   temporary='/tmp/rookstride-upload/package/single/runtime.py';temporary_helper=Path(temporary).with_name('run.py')
   with patch.object(pair,'RELEASE',release),patch.object(lifecycle,'ROOT',root/'lifecycle'),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',return_value=dict(version=2,plan=plan)),patch.object(native_pair.runtime,'__file__',temporary),patch.object(native_pair.runtime,'HELPER',temporary_helper),patch.object(native_pair.runtime,'load',side_effect=load),patch.object(native_pair.runtime,'save',side_effect=save),patch.object(native_pair.runtime,'apply_config',side_effect=apply) as applied,patch.object(native_pair.runtime,'atomic',side_effect=lambda path,text,mode:units.append(text)),patch.object(native_pair.runtime,'command',return_value=''),patch.object(native_pair.runtime,'profile',side_effect=lambda state,login:{'login':login}),patch.object(native_pair.filtering,'load',return_value={'address':'10.253.0.1','dns_port':5354}):
    req={'deployment':'a'*32,'operation':'e'*32};journal=root/'lifecycle/entry-bridges'/('e'*32+'.json')
    with self.assertRaisesRegex(RuntimeError,'interrupted'):recovery.entry_bridge(req)
    original=load();self.assertEqual(2,len(original['users']));self.assertEqual('creating',json.loads(journal.read_text())['state'])
    self.assertEqual(temporary,native_pair.runtime.__file__);self.assertEqual(temporary_helper,native_pair.runtime.HELPER)
    result=recovery.entry_bridge(req);self.assertEqual(original,load());self.assertEqual('ready',json.loads(journal.read_text())['state'])
    self.assertEqual(result,recovery.entry_bridge(req));self.assertEqual(2,applied.call_count)
    self.assertEqual(temporary,native_pair.runtime.__file__);self.assertEqual(temporary_helper,native_pair.runtime.HELPER)
    for unit in units:self.assertIn('ExecStartPre=/usr/bin/python3 '+str(release/'single/run.py')+' local-guard hysteria2\n',unit);self.assertIn('PrivateTmp=true',unit);self.assertNotIn('/tmp/rookstride-upload',unit)
 def test_interrupted_bridge_apply_resumes_existing_identity_without_new_keys(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=root/'state.json';value=snapshot('exit')['state'];path.write_text(json.dumps(value));plan=snapshot('exit')['plan']
   def load(protocol):return json.loads(path.read_text())
   def save(state):path.write_text(json.dumps(state))
   with patch.object(lifecycle,'ROOT',root/'lifecycle'),patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'load_manifest',return_value=dict(version=2,plan=plan)),patch.object(native_pair.runtime,'load',side_effect=load),patch.object(native_pair.runtime,'save',side_effect=save),patch.object(native_pair.runtime,'awg_key',side_effect=lambda *args:base64.b64encode(secrets.token_bytes(32)).decode()) as keys,patch.object(native_pair.runtime,'apply_config',side_effect=[RuntimeError('interrupted listener apply'),{'update':'live'}]) as apply,patch.object(native_pair.runtime,'profile',side_effect=lambda state,login:{'login':login}),patch.object(native_pair.filtering,'load',return_value={'address':'10.253.0.1','dns_port':5354}):
    req={'deployment':'a'*32,'operation':'e'*32}
    with self.assertRaisesRegex(RuntimeError,'interrupted'):recovery.entry_bridge(req)
    original=load('awg');count=keys.call_count;self.assertEqual(2,len(original['users']))
    result=recovery.entry_bridge(req);self.assertEqual(original,load('awg'));self.assertEqual(count,keys.call_count);self.assertEqual(2,apply.call_count)
    self.assertEqual(result,recovery.entry_bridge(req));self.assertEqual(2,apply.call_count)
 def test_every_exit_mode_uses_distinct_idempotent_operation_account(self):
  variants=[(p,'profile') for p in native_pair.model.PROTOCOLS]+[(p,'password') for p in ('openvpn','hysteria2','trusttunnel','naive')]+[('ikev2','password')]
  for protocol,mode in variants:
   with self.subTest(protocol=protocol,mode=mode),tempfile.TemporaryDirectory() as directory,contextlib.ExitStack() as stack:
    root=Path(directory);path=root/'state.json';initial={'login':'initial','enabled':True,'address':'10.67.0.2','password':'original','private':'original-key'}
    value={'protocol':protocol,'access_mode':mode,'instance':'b'*32,'owner':'rookstride-single-v1','server':'exit.example.net','port':443,'metrics_port':25000,'users':[initial]};path.write_text(json.dumps(value));network=root/'network.env';network.write_text('DNS_IP=10.253.0.1\n')
    plan=pair.plan(dict(pair='a'*32,role='exit',engine='native-v2',entry_protocol='awg',exit_protocol=protocol,server='entry.example.net',exit_host='exit.example.net'))
    def load(*args):return json.loads(path.read_text())
    def save(state):path.write_text(json.dumps(state))
    def ike_add(req):
     state=load();recovery.recovery_ike.admin.vpn_password(req['password']);state['users'].append({'login':req['login'],'password':req['password'],'enabled':True});save(state)
    for target,name,replacement in ((lifecycle,'ROOT',root/'lifecycle'),(pair,'protected',lambda p:Path(p)),(pair,'load_manifest',lambda:dict(version=2,plan=plan)),(native_pair.runtime,'load',load),(native_pair.runtime,'save',save),(native_pair.runtime,'apply_config',lambda state:{'update':'live'}),(native_pair.runtime,'awg_key',lambda *args:base64.b64encode(secrets.token_bytes(32)).decode()),(native_pair.runtime,'command',lambda *args,**kwargs:''),(native_pair.runtime,'check_container',lambda state:None),(native_pair.runtime,'profile',lambda state,login:{'login':login}),(native_pair.filtering,'load',lambda:{'address':'10.253.0.1','dns_port':5354}),(recovery.recovery_ike,'state',lambda plan:load()),(recovery.recovery_ike.admin,'update_user',ike_add),(recovery.recovery_ike,'profile',lambda state,login,data:{'login':login}),(recovery.adapters,'files',lambda state:{}),(recovery.adapters,'decode_files',lambda state,files:{}),(native_pair,'IKE_NETWORK',network)):
     stack.enter_context(patch.object(target,name,replacement))
    req={'deployment':'a'*32,'operation':'c'*32};first=recovery.entry_bridge(req);first_state=load();again=recovery.entry_bridge(req)
    self.assertEqual(first,again);self.assertEqual(first_state,load());self.assertEqual('migration-'+'c'*16,first['profile']['login']);self.assertEqual(2,len(load()['users']))
    second=recovery.entry_bridge({**req,'operation':'d'*32});users=load()['users'];self.assertEqual(3,len(users));self.assertEqual(initial,users[0]);self.assertNotEqual(first['profile']['login'],second['profile']['login'])
    if protocol=='awg':self.assertNotEqual(users[1]['private'],users[2]['private']);self.assertNotEqual(users[1]['address'],users[2]['address'])
    elif protocol in ('xray','xhttp'):self.assertNotEqual(users[1]['uuid'],users[2]['uuid'])
    elif mode=='password' or protocol not in ('openvpn',):self.assertNotEqual(users[1].get('password_hash',users[1].get('password')),users[2].get('password_hash',users[2].get('password')))
    state=load();state['instance']='new-instance';save(state)
    with self.assertRaisesRegex(ValueError,'changed'):recovery.entry_bridge(req)

if __name__=='__main__':unittest.main()
