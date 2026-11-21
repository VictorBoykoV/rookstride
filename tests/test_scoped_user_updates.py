"""Delegated user edits use current grants and account-generation ownership."""
import copy,hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_scoped_access as fixtures
a=fixtures.a
Effects=fixtures.Effects
class UpdateEffects(Effects):
 def execute(self,obj,op,params):
  if op!='users.update':return super().execute(obj,op,params)
  self.calls.append((obj['id'],op,dict(params)));user=self.users.get(obj['id'],{}).get(params['login'])
  if not user or params.get('expected_account_id') and user.get('administration_account_id')!=params['expected_account_id']:raise a.Denied('Account was replaced')
  user.update({key:params[key] for key in ('password','person','device') if key in params});return {'updated':True,'login':params['login']}
class ScopedUserUpdatesTest(unittest.TestCase):
 setUpClass=classmethod(fixtures.ScopedAccessTest.setUpClass.__func__)
 tearDown=fixtures.ScopedAccessTest.tearDown
 call=fixtures.ScopedAccessTest.call;invite=fixtures.ScopedAccessTest.invite;proof=fixtures.ScopedAccessTest.proof;enroll=fixtures.ScopedAccessTest.enroll;mutate=fixtures.ScopedAccessTest.mutate
 def setUp(self):
  fixtures.ScopedAccessTest.setUp(self);self.effects=UpdateEffects();self.db.system=self.effects
 def test_owned_user_can_change_password_and_labels_without_losing_grant_identity(self):
  _,admin=self.enroll();self.mutate(admin['account'],login='alice',password='before');key=self.effects.users[self.obj['id']]['alice']['administration_account_id']
  result=self.mutate(admin['account'],'users.update',login='alice',password='after',person='Alice',device='Laptop')
  self.assertTrue(result['updated']);user=self.effects.users[self.obj['id']]['alice'];self.assertEqual('after',user['password']);self.assertEqual('Laptop',user['device']);self.assertEqual(key,user['administration_account_id'])
 def test_viewer_and_forged_generation_or_protocol_cannot_edit(self):
  _,admin=self.enroll('viewer',{'kind':'protocol','id':self.obj['id'],'users':'all'})
  with self.assertRaises(a.Denied):self.mutate(admin['account'],'users.update',login='alice',person='Oops')
  _,manager=self.enroll(key=self.key2);self.mutate(manager['account'],login='alice',password='before')
  for fields in ({'administration_account_id':'forged'},{'expected_account_id':'forged'},{'protocol':'openvpn'},{'command':'id'},{'new_login':'takeover'}):
   with self.assertRaises(a.Denied):self.mutate(manager['account'],'users.update',login='alice',**fields)
 def test_own_scope_denies_preexisting_and_replaced_login(self):
  self.effects.users[self.obj['id']]={'existing':{'password':'untouched'}};_,admin=self.enroll()
  with self.assertRaises(a.Denied):self.mutate(admin['account'],'users.update',login='existing',password='changed')
  self.mutate(admin['account'],login='alice',password='before');self.effects.users[self.obj['id']]['alice']['administration_account_id']='new-owner-generation'
  with self.assertRaises(a.Denied):self.mutate(admin['account'],'users.update',login='alice',password='changed')
  self.assertEqual('before',self.effects.users[self.obj['id']]['alice']['password'])
 def test_current_revoked_role_denies_existing_session_update(self):
  _,admin=self.enroll();self.mutate(admin['account'],login='alice',password='before')
  self.call('grants.update',grant_id=admin['grant_id'],role='viewer',scope={'kind':'protocol','id':self.obj['id'],'users':'own'},expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.mutate(admin['account'],'users.update',login='alice',password='changed')
  self.assertEqual('before',self.effects.users[self.obj['id']]['alice']['password'])
 def test_revision_and_duplicate_operation_do_not_replay_password_mutation(self):
  _,admin=self.enroll();self.mutate(admin['account'],login='alice',password='before');request={'schema':1,'operation':'users.update','object_id':self.obj['id'],'parameters':{'login':'alice','password':'after'},'expected_revision':self.db.revision(),'operation_id':'update-once'}
  self.db.request(admin['account'],request);before=len(self.effects.calls)
  with self.assertRaises(a.Denied):self.db.request(admin['account'],request)
  self.assertEqual(before,len(self.effects.calls));self.assertEqual('after',self.effects.users[self.obj['id']]['alice']['password'])
 def test_failed_original_blank_label_request_keeps_digest_and_cannot_be_replayed(self):
  _,admin=self.enroll();parameters={'login':'legacy','password':'','person':'Legacy','device':''}
  request={'schema':1,'operation':'users.create','object_id':self.obj['id'],'parameters':parameters,'expected_revision':self.db.revision(),'operation_id':'failed-legacy-create'};original=copy.deepcopy(request)
  with patch.object(self.effects,'execute',side_effect=ValueError('Prior adapter failure')) as execute:
   with self.assertRaises(ValueError):self.db.request(admin['account'],request)
   row=self.db.db.execute('SELECT digest,state FROM operations WHERE id=?',('failed-legacy-create',)).fetchone()
   self.assertEqual(hashlib.sha256(a.canonical({'op':'users.create','obj':self.obj,'parameters':parameters}).encode()).hexdigest(),row['digest']);self.assertEqual('running',row['state'])
   with self.assertRaisesRegex(a.Denied,'not replayed'):self.db.request(admin['account'],request)
   changed={**request,'parameters':{key:value for key,value in parameters.items() if key!='device'}}
   with self.assertRaisesRegex(a.Denied,'another request'):self.db.request(admin['account'],changed)
   self.assertEqual(1,execute.call_count);self.assertEqual(original,request)

 def test_current_peer_authentication_mode_is_identity_matched_and_not_cached_between_requests(self):
  peer,effects,obj,link=fixtures.ScopedAccessTest.setup_peer(self)
  with patch.object(a,'installed_access_mode',side_effect=lambda value:'password' if value['server_id']==obj['server_id'] else 'profile'):
   objects=self.call('capabilities')['objects'];self.assertEqual('password',next(o for o in objects if o['id']==obj['id'])['access_mode'])
  self.effects.fail_peer=True
  objects=self.call('capabilities')['objects'];self.assertEqual('unknown',next(o for o in objects if o['id']==obj['id'])['access_mode'])
  self.effects.fail_peer=False
  for response in ({'server_id':obj['server_id'],'objects':[obj]}, {'server_id':obj['server_id'],'objects':[obj],'descriptions':[{**obj,'instance':'replacement','access_mode':'password'}]}, {'server_id':obj['server_id'],'objects':[],'descriptions':[{**obj,'access_mode':'password'}]}):
   with patch.object(self.effects,'peer',return_value=response):
    objects=self.call('capabilities')['objects'];self.assertEqual('unknown',next(o for o in objects if o['id']==obj['id'])['access_mode'])

class InstalledAuthenticationModeTest(unittest.TestCase):
 def test_all_native_protocol_modes_are_derived_from_current_owned_state(self):
  password_protocols=('openvpn','hysteria2','trusttunnel','naive')
  with tempfile.TemporaryDirectory() as directory,patch.object(a,'SINGLE_STATE',Path(directory)):
   for protocol in ('awg','openvpn','xray','xhttp','hysteria2','trusttunnel','naive','shadowsocks','outline'):
    obj={'protocol':protocol,'instance':'installed','server_id':'server','deployment_id':'deployment'};folder=Path(directory)/protocol;folder.mkdir();path=folder/'state.json';base={'owner':'rookstride-single-v1','protocol':protocol,'instance':'installed'}
    for mode in ('password','profile',None,'unrecognized'):
     state={**base,**({'access_mode':mode} if mode is not None else {})};path.write_text(json.dumps(state))
     expected='password' if mode=='password' and protocol in password_protocols else 'profile' if mode in ('profile',None) else 'unknown'
     self.assertEqual(expected,a.installed_access_mode(obj),(protocol,mode))
    for changed in ({'owner':'foreign'},{'instance':'replaced'},{'protocol':'other'}):
     path.write_text(json.dumps({**base,'access_mode':'password',**changed}));self.assertEqual('unknown',a.installed_access_mode(obj))
    path.write_text('[]');self.assertEqual('unknown',a.installed_access_mode(obj));path.unlink();self.assertEqual('unknown',a.installed_access_mode(obj))
 def test_ikev2_requires_current_installed_instance(self):
  obj={'protocol':'ikev2','instance':'certificate-first','server_id':'server','deployment_id':'deployment'}
  with patch.object(a,'discover',return_value=[obj]):self.assertEqual('password',a.installed_access_mode(obj))
  for live in ([],[{**obj,'instance':'new-certificate'}]):
   with patch.object(a,'discover',return_value=live):self.assertEqual('unknown',a.installed_access_mode(obj))

class OptionalCreateLabelsTest(unittest.TestCase):
 """Exercise the actual forced-command adapter and protocol label validator."""
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name)
  self.single=Path(__file__).resolve().parents[1]/'single'
  (self.folder/'state.json').write_text(json.dumps({'protocol':'awg','instance':'owned-instance','users':[]}))
  # The actual runtime persists the user and checks labels. Only external key
  # generation and listener mutation are replaced in this file-backed fixture.
  (self.folder/'run.py').write_text('''import json,sys
from pathlib import Path
sys.path.insert(0,SINGLE)
import runtime
folder=Path(__file__).parent
runtime.load=lambda protocol:json.loads((folder/'state.json').read_text())
runtime.save=lambda state:(folder/'state.json').write_text(json.dumps(state))
runtime.awg_key=lambda *args:'fixture-key'
runtime.apply_config=lambda state:{'listener_restarted':False,'update':'live'}
def action(request):
 (folder/'received.json').write_text(json.dumps(request))
 state=runtime.load(request['protocol'])
 if request['action']=='edit-user':return runtime.edit_user(state,request)
 return runtime.add_user(state,request.get('login'),password=request.get('password'),person=request.get('person'),device=request.get('device'))
'''.replace('SINGLE',repr(str(self.single))))
  self.code=a.ADAPTER_RUNNER.replace('/run/rookstride-management.lock',str(self.folder/'manage.lock')).replace('/run/rookstride-single.lock',str(self.folder/'single.lock'))
 def tearDown(self):self.temp.cleanup()
 def invoke(self,parameters,action='add-user'):
  request={'action':action,'protocol':self.state()['protocol'],'expected_instance':'owned-instance',**parameters};before=copy.deepcopy(request)
  process=subprocess.run([sys.executable,'-I','-c',self.code,str(self.folder/'run.py'),'single'],input=json.dumps(request).encode(),capture_output=True,timeout=10)
  self.assertEqual(before,request)
  return json.loads(process.stdout)
 def state(self):return json.loads((self.folder/'state.json').read_text())
 def test_legacy_blank_labels_create_user_and_generation_with_real_runtime(self):
  result=self.invoke({'login':'new-phone','password':'','person':'New phone','device':''})
  self.assertTrue(result['ok'],result);user=self.state()['users'][0]
  self.assertEqual('New phone',user['person']);self.assertNotIn('device',user)
  self.assertEqual(result['result']['_created_account_id'],user['administration_account_id'])
  request=json.loads((self.folder/'received.json').read_text());self.assertEqual('',request['password']);self.assertNotIn('device',request)
  result=self.invoke({'login':'another-phone','person':'','device':''})
  self.assertTrue(result['ok'],result);self.assertNotIn('person',self.state()['users'][1]);self.assertNotIn('device',self.state()['users'][1])
 def test_invalid_types_controls_and_login_still_fail_without_creating_user(self):
  for parameters in ({'login':''},{'login':'bad name'},{'login':'valid','person':[]},{'login':'valid','device':False},{'login':'valid','device':0},{'login':'valid','person':'\n'},{'login':'valid','device':'\t'}):
   with self.subTest(parameters=parameters):
    result=self.invoke(parameters);self.assertFalse(result['ok'],result);self.assertEqual([],self.state()['users'])
 def test_only_exact_empty_string_is_normalized_and_edit_validation_unchanged(self):
  result=self.invoke({'login':'spaces','person':' ','device':' Laptop '});self.assertTrue(result['ok'],result)
  self.assertEqual(' ',self.state()['users'][0]['person']);self.assertEqual(' Laptop ',self.state()['users'][0]['device'])
  result=self.invoke({'login':'spaces','person':'','device':''},'edit-user');self.assertFalse(result['ok'],result)
  self.assertEqual(' ',self.state()['users'][0]['person']);self.assertEqual(' Laptop ',self.state()['users'][0]['device'])
 def test_partial_edit_through_real_adapter_keeps_omitted_label_and_issued_generation(self):
  created=self.invoke({'login':'partial','person':'Before','device':'Tablet'});self.assertTrue(created['ok'],created)
  account_id=created['result']['_created_account_id']
  result=self.invoke({'login':'partial','person':'After','expected_account_id':account_id},'edit-user');self.assertTrue(result['ok'],result)
  user=self.state()['users'][0];self.assertEqual('After',user['person']);self.assertEqual('Tablet',user['device']);self.assertEqual(account_id,user['administration_account_id'])
 def test_chosen_password_for_profile_installation_is_rejected_before_creation(self):
  for value in ('chosen-password',None,123):
   result=self.invoke({'login':'ignored-password','password':value});self.assertFalse(result['ok'],result);self.assertEqual([],self.state()['users'])
  for protocol in ('awg','openvpn','xray','xhttp','hysteria2','trusttunnel','naive','shadowsocks','outline'):
   state=self.state();state['protocol']=protocol;state['access_mode']='profile';(self.folder/'state.json').write_text(json.dumps(state))
   result=self.invoke({'login':'ignored-password','password':'chosen-password'});self.assertFalse(result['ok'],(protocol,result));self.assertEqual([],self.state()['users'])
 def test_real_password_mode_retains_chosen_password_and_its_validation(self):
  for protocol in ('openvpn','hysteria2','trusttunnel','naive'):
   state={'protocol':protocol,'access_mode':'password','instance':'owned-instance','users':[]};(self.folder/'state.json').write_text(json.dumps(state))
   result=self.invoke({'login':'family.name','password':'chosen-password'});self.assertTrue(result['ok'],(protocol,result))
   user=self.state()['users'][0]
   if protocol=='openvpn':self.assertTrue(user['password_hash'].startswith('pbkdf2-sha256$'));self.assertNotIn('password',user)
   else:self.assertEqual('chosen-password',user['password'])
   before=copy.deepcopy(self.state());result=self.invoke({'login':'bad-password','password':'bad\npassword'});self.assertFalse(result['ok'],result);self.assertEqual(before,self.state())
if __name__=='__main__':unittest.main()
