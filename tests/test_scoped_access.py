"""Authorization/enrollment execution tests, including concurrency and paired state.
OS/SSH effects are isolated here; real forced-command acceptance is a separate gate.
"""
import base64,concurrent.futures,importlib.util,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scoped_access',ROOT/'server/scoped_access.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class Effects:
 def __init__(self):self.accounts={};self.revoked=[];self.users={};self.calls=[];self.peers={};self.fail_peer=False;self.fail_account=False
 def account(self,name,key,expires=None):
  if self.fail_account:raise OSError('interrupted provisioning')
  self.accounts[name]=key
 def revoke(self,name):self.revoked.append(name)
 def execute(self,obj,op,params):
  self.calls.append((obj['id'],op,dict(params)));users=self.users.setdefault(obj['id'],{})
  if op=='users.list':return {'users':[{'login':x,'_account_id':v.get('administration_account_id')} for x,v in users.items()]}
  login=params['login']
  if op=='users.create':
   if login in users:raise ValueError('exists')
   users[login]={**params,'administration_account_id':a.token()};return {'login':login,'_created_account_id':users[login]['administration_account_id']}
  if params.get('expected_account_id') and users.get(login,{}).get('administration_account_id')!=params['expected_account_id']:raise a.Denied('Account was replaced')
  if op=='users.revoke':users.pop(login);return {'removed':True}
  if op=='users.profile':return {'profile':users[login]}
  raise ValueError('unknown')
 def peer(self,peer,req):
  if self.fail_peer:raise OSError('unreachable')
  return self.peers[peer['server_id']].request(peer['account'],req)

class ScopedAccessTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.key1=a.make_key();cls.key2=a.make_key()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.effects=Effects();self.now=2000000000
  self.db=a.Access(Path(self.temp.name)/'main',self.effects,lambda:self.now)
  self.obj={'kind':'protocol','id':'vpn-first','server_id':'server-first','deployment_id':'deployment','protocol':'awg','instance':'instance-first'}
  self.obj2={**self.obj,'id':'vpn-second','instance':'instance-second'}
  self.db.initialize('server-first','deployment',{'host':'192.0.2.1','port':22,'fingerprint':'SHA256:'+'a'*43,'host_key':self.key1[1]},[self.obj,self.obj2])
  self.keys=patch.object(a,'make_key',return_value=self.key1);self.keys.start()
 def tearDown(self):self.keys.stop();self.db.db.close();self.temp.cleanup()
 def call(self,op,account='@owner',**params):return self.db.request(account,{'schema':1,'operation':op,**params})
 def invite(self,role='user_manager',scope=None):
  return self.call('invitations.create',role=role,scope=scope or {'kind':'protocol','id':self.obj['id'],'users':'own'},ttl_seconds=3600,expected_revision=self.db.revision())['invitation']
 def proof(self,invite,key=None):
  key=key or self.key1;stored=self.db.get('invitation',invite['invitation_id'])
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'key';path.write_text(key[0]);signature=a.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(path)],a.proof_message(stored,key[1]))
  return {'public_key':key[1],'signature':base64.b64encode(signature).decode()}
 def enroll(self,role='user_manager',scope=None,key=None):
  invite=self.invite(role,scope);r=self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite,key));return invite,r
 def mutate(self,account,op='users.create',obj=None,**parameters):
  return self.call(op,account,object_id=(obj or self.obj)['id'],parameters=parameters,expected_revision=self.db.revision(),operation_id=a.token('op-'))
 def test_empty_truncated_and_nonaffirmative_device_proof_is_denied(self):
  invite=self.invite();stored=self.db.get('invitation',invite['invitation_id']);proof=self.proof(invite)
  for signature in ('',base64.b64encode(b'x'*383).decode(),base64.b64encode(b'x'*385).decode()):
   with patch.object(a,'run') as run:
    with self.assertRaises(a.Denied):a.verify_proof(stored,proof['public_key'],signature)
    run.assert_not_called()
  for stdout in (b'',b'Error configuring OpenSSL\n',b'Verification failure\n'):
   with patch.object(a,'run',side_effect=[b'fake-public-key',stdout]):
    with self.assertRaises(a.Denied):a.verify_proof(stored,proof['public_key'],proof['signature'])
  self.assertTrue(self.call('enrollment.accept',invite['bootstrap']['account'],**proof)['enrolled'])
 def test_automatic_device_proof_enrollment_and_idempotent_resume(self):
  invite,r=self.enroll();again=self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite))
  self.assertEqual(r['device_id'],again['device_id']);self.assertEqual(1,len(self.db.all('device')))
  self.assertEqual('user_manager',self.call('capabilities',r['account'])['role'])
 def test_bootstrap_has_no_operational_authority(self):
  invite=self.invite()
  for op in ('capabilities','access.list','users.create','peers.prepare','invitations.create'):
   with self.assertRaises(a.Denied):self.call(op,invite['bootstrap']['account'])
 def test_role_and_actor_in_client_json_never_grant_authority(self):
  _,r=self.enroll('viewer')
  with self.assertRaises(a.Denied):self.call('invitations.create',r['account'],actor='@owner',role='owner',scope={'kind':'server','id':'server-first'})
 def test_wrong_device_signature_rejected(self):
  invite=self.invite();proof=self.proof(invite);proof['public_key']=self.key2[1]
  with self.assertRaises(a.Denied):self.call('enrollment.accept',invite['bootstrap']['account'],**proof)
  self.assertIsNone(self.db.get('invitation',invite['invitation_id'])['claimed_device'])
 def test_editing_invitation_role_does_not_change_server_role(self):
  invite=self.invite('viewer');invite['role']='owner';r=self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite))
  self.assertEqual('viewer',r['role'])
 def test_consumed_invitation_rejects_another_valid_device(self):
  invite,_=self.enroll()
  with self.assertRaises(a.Denied):self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite,self.key2))
 def test_expiry_checked_on_existing_bootstrap_session(self):
  invite=self.invite();self.call('enrollment.challenge',invite['bootstrap']['account']);self.now+=3601
  with self.assertRaises(a.Denied):self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite))
 def test_real_account_file_has_openssh89_local_expiry_in_utc_and_other_timezones(self):
  from types import SimpleNamespace
  import pwd
  account='rsb'+'1'*20;root=Path(self.temp.name)/'accounts';home=root/account;expires=2000000000
  original=os.environ.get('TZ')
  try:
   for zone in ('UTC0','UTC-3','UTC+5'):
    with self.subTest(zone=zone):
     os.environ['TZ']=zone;time.tzset()
     effective='\n'.join(['forcecommand /usr/bin/sudo -n '+a.HELPER,'disableforwarding yes','permittty no','permituserrc no','passwordauthentication no','authenticationmethods publickey','authorizedkeysfile '+str(root)+'/%u/authorized_keys'])
     with patch.object(a,'ACCOUNTS',root),patch.object(pwd,'getpwnam',return_value=SimpleNamespace(pw_dir=str(home),pw_shell='/bin/sh')),patch.object(a,'run',return_value=effective.encode()),patch.object(a.os,'chown'):
      a.System().account(account,self.key1[1],expires)
     line=(home/'authorized_keys').read_text();stamp=__import__('re').search(r'expiry-time="([^"]+)"',line)[1]
     self.assertRegex(stamp,r'^\d{14}$');self.assertEqual(expires,int(time.mktime(time.strptime(stamp,'%Y%m%d%H%M%S'))))
     self.assertTrue(line.startswith('restrict,command="/usr/bin/sudo -n '+a.HELPER+'",'));self.assertTrue(line.endswith(self.key1[1]+'\n'))
  finally:
   if original is None:os.environ.pop('TZ',None)
   else:os.environ['TZ']=original
   time.tzset()
 def test_invitation_revocation_checked_on_existing_session(self):
  invite=self.invite();self.call('invitations.revoke',invitation_id=invite['invitation_id'],expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.call('enrollment.challenge',invite['bootstrap']['account'])
 def test_cross_instance_and_forged_parameters_denied(self):
  _,r=self.enroll()
  with self.assertRaises(a.Denied):self.mutate(r['account'],obj=self.obj2,login='alice')
  with self.assertRaises(a.Denied):self.mutate(r['account'],login='alice',protocol='openvpn')
  with self.assertRaises(a.Denied):self.mutate(r['account'],login='alice',command='id')
  self.assertFalse(self.effects.calls)
 def test_current_role_used_without_reenrollment_or_vpn_rewrite(self):
  _,r=self.enroll();self.mutate(r['account'],login='alice',password='same-old-password');saved=dict(self.effects.users)
  self.call('grants.update',grant_id=r['grant_id'],role='viewer',scope={'kind':'protocol','id':self.obj['id'],'users':'own'},expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.mutate(r['account'],login='bob')
  self.assertEqual(saved,self.effects.users)
 def test_device_revocation_applies_to_open_session_and_vpn_unchanged(self):
  _,r=self.enroll();self.mutate(r['account'],login='alice',password='retained');self.call('devices.revoke',device_id=r['device_id'],expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.call('capabilities',r['account'])
  self.assertIn('alice',self.effects.users[self.obj['id']]);self.assertIn(r['account'],self.effects.revoked)
 def test_own_issued_user_enforcement_and_no_existing_account_takeover(self):
  self.effects.users[self.obj['id']]={'existing':{'password':'external-client'}};_,r=self.enroll()
  self.assertEqual([],self.call('users.list',r['account'],object_id=self.obj['id'])['users'])
  for op in ('users.revoke','users.profile'):
   with self.assertRaises(a.Denied):self.mutate(r['account'],op,login='existing')
  self.mutate(r['account'],login='alice',password='new')
  self.assertEqual([{'login':'alice'}],self.call('users.list',r['account'],object_id=self.obj['id'])['users'])
 def test_viewer_cannot_export_secrets_or_mutate(self):
  _,r=self.enroll('viewer',{'kind':'protocol','id':self.obj['id'],'users':'all'})
  for op in ('users.create','users.revoke','users.profile'):
   with self.assertRaises(a.Denied):self.mutate(r['account'],op,login='alice')
 def test_owner_cannot_invite_root_authority(self):
  with self.assertRaises(a.Denied):self.invite('owner')
 def test_mutation_conflict_and_duplicate_are_safe(self):
  _,r=self.enroll();req={'schema':1,'operation':'users.create','object_id':self.obj['id'],'parameters':{'login':'alice'},'expected_revision':self.db.revision(),'operation_id':'operation-one'}
  self.db.request(r['account'],req)
  with self.assertRaises(a.Denied):self.db.request(r['account'],req)
  self.assertEqual(1,len(self.effects.calls))
 def test_durable_claim_resumes_after_account_creation_failure(self):
  invite=self.invite();self.effects.fail_account=True
  with self.assertRaises(OSError):self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite))
  self.assertIsNotNone(self.db.get('invitation',invite['invitation_id'])['claimed_device']);self.effects.fail_account=False
  with self.assertRaises(a.Denied):self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite,self.key2))
  self.assertTrue(self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite))['enrolled'])
 def test_atomic_two_device_race_has_only_one_winner(self):
  invite=self.invite();proofs=[self.proof(invite,self.key1),self.proof(invite,self.key2)]
  def attempt(proof):
   db=a.Access(Path(self.temp.name)/'main',self.effects,lambda:self.now)
   try:return db.request(invite['bootstrap']['account'],{'schema':1,'operation':'enrollment.accept',**proof}).get('device_id')
   except a.Denied:return None
   finally:db.db.close()
  with concurrent.futures.ThreadPoolExecutor(2) as pool:winners=list(pool.map(attempt,proofs))
  self.assertEqual(1,sum(w is not None for w in winners));self.assertEqual(1,len(self.db.all('device')))
 def test_restart_prone_protocol_requires_explicit_review(self):
  self.obj['protocol']='hysteria2';self.db.put('object',self.obj['id'],self.obj);_,r=self.enroll()
  caps=self.call('capabilities',r['account']);self.assertEqual('restart-review',caps['objects'][0]['user_updates']['create'])
  with self.assertRaises(a.Denied):self.mutate(r['account'],login='alice')
  self.assertFalse(self.effects.calls)
  self.call('users.create',r['account'],object_id=self.obj['id'],parameters={'login':'alice'},expected_revision=self.db.revision(),operation_id='reviewed-operation',acknowledge_restart=True)
  self.assertEqual(1,len(self.effects.calls))
 def test_infrastructure_inventory_remains_scoped(self):
  self.enroll('viewer',{'kind':'protocol','id':self.obj2['id'],'users':'all'})
  _,r=self.enroll('infrastructure',key=self.key2)
  snapshot=self.call('access.list',r['account']);self.assertEqual([self.obj['id']],[o['id'] for o in snapshot['objects']]);self.assertEqual(1,len(snapshot['devices']))
 def test_disabled_authority_blocks_every_current_device_but_keeps_owner_recovery(self):
  _,r=self.enroll();config=self.db.get('meta','config');config['disabled']=True;self.db.put('meta','config',config)
  with self.assertRaises(a.Denied):self.call('capabilities',r['account'])
  self.assertEqual('owner',self.call('capabilities')['role'])
 def test_sharing_cleanup_cannot_be_requested_by_delegates(self):
  _,r=self.enroll('infrastructure')
  for op in ('module.removal-plan','module.remove'):
   with self.assertRaises(a.Denied):self.call(op,r['account'],confirmation='REMOVE ADMINISTRATION')
 def test_public_authorized_key_mode_survives_private_process_umask(self):
  path=Path(self.temp.name)/'authorized_keys';previous=__import__('os').umask(0o077)
  try:a.System().atomic(path,'test-key',0o644)
  finally:__import__('os').umask(previous)
  self.assertEqual(0o644,path.stat().st_mode & 0o777)
 def test_instance_is_rechecked_after_acquiring_actual_protocol_lock(self):
  import fcntl,sys
  folder=Path(self.temp.name)/'adapter';folder.mkdir();state=folder/'instance';state.write_text('old-instance');marker=folder/'mutated'
  (folder/'run.py').write_text("from pathlib import Path\nfrom types import SimpleNamespace\nruntime=SimpleNamespace(load=lambda protocol:{'instance':Path(__file__).with_name('instance').read_text()})\ndef action(req):\n Path(__file__).with_name('mutated').write_text('executed')\n return {'done':True}\n")
  shared=folder/'management.lock';single=folder/'single.lock';code=a.ADAPTER_RUNNER.replace('/run/rookstride-management.lock',str(shared)).replace('/run/rookstride-single.lock',str(single))
  with shared.open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX)
   process=subprocess.Popen([sys.executable,'-I','-c',code,str(folder/'run.py'),'single'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   request={'action':'status','protocol':'awg','expected_instance':'old-instance'};process.stdin.write(json.dumps(request).encode());process.stdin.close();process.stdin=None
   state.write_text('replacement-instance');fcntl.flock(lock,fcntl.LOCK_UN)
   output,error=process.communicate(timeout=10)
  self.assertEqual(1,process.returncode);self.assertIn('identity changed',json.loads(output)['error']);self.assertFalse(marker.exists())
  request['expected_instance']='replacement-instance';result=subprocess.run([sys.executable,'-I','-c',code,str(folder/'run.py'),'single'],input=json.dumps(request).encode(),capture_output=True,timeout=10)
  self.assertEqual(0,result.returncode);self.assertTrue(marker.exists())
 def test_reused_login_is_not_still_owned_by_original_issuer(self):
  _,r=self.enroll();self.mutate(r['account'],login='alice')
  self.effects.users[self.obj['id']]['alice']={'password':'replacement-external-account'}
  self.assertEqual([],self.call('users.list',r['account'],object_id=self.obj['id'])['users'])
  for op in ('users.profile','users.revoke'):
   with self.assertRaises(a.Denied):self.mutate(r['account'],op,login='alice')
  self.assertIn('alice',self.effects.users[self.obj['id']])
 def test_real_adapter_generation_rejects_same_login_recreated_outside_dispatcher(self):
  import sys
  folder=Path(self.temp.name)/'generation';folder.mkdir();state=folder/'state.json';state.write_text(json.dumps({'instance':'same-instance','users':[]}))
  (folder/'run.py').write_text("import json\nfrom pathlib import Path\nfrom types import SimpleNamespace\nstate=Path(__file__).with_name('state.json')\nruntime=SimpleNamespace(load=lambda protocol:json.loads(state.read_text()),save=lambda value:state.write_text(json.dumps(value)))\ndef action(req):\n value=runtime.load('awg')\n if req['action']=='add-user':\n  value['users'].append({'login':req['login'],'public':'native-public-key'})\n  runtime.save(value)\n  return {'login':req['login']}\n return {'profile':'profile-secret'}\n")
  code=a.ADAPTER_RUNNER.replace('/run/rookstride-management.lock',str(folder/'management.lock')).replace('/run/rookstride-single.lock',str(folder/'single.lock'))
  def invoke(req):return subprocess.run([sys.executable,'-I','-c',code,str(folder/'run.py'),'single'],input=json.dumps(req).encode(),capture_output=True,timeout=10)
  request={'action':'add-user','protocol':'awg','expected_instance':'same-instance','login':'alice'};created=invoke(request);self.assertEqual(0,created.returncode)
  generation=json.loads(created.stdout)['result']['_created_account_id'];self.assertEqual(generation,json.loads(state.read_text())['users'][0]['administration_account_id'])
  state.write_text(json.dumps({'instance':'same-instance','users':[{'login':'alice','public':'different-native-key'}]}))
  result=invoke({**request,'action':'profile','expected_account_id':generation});self.assertEqual(1,result.returncode);self.assertNotIn('profile-secret',result.stdout.decode());self.assertIn('replaced',json.loads(result.stdout)['error'])
 def test_coexisting_openvpn_requires_exact_reviewed_pair_and_instance(self):
  manifest={'version':2,'activated':True,'plan':{'pair':'pair-one','role':'entry','entry_protocol':'awg','exit_protocol':'awg','client_pool':'10.66.0.0/24'}}
  obj={**self.obj,'protocol':'openvpn'};state={'owner':'rookstride-single-v1','protocol':'openvpn','instance':obj['instance'],'coexist_pair':'pair-one'}
  self.assertEqual('coexist',a.pair_protocol_mode(manifest,obj,state))
  for modified in ({**state,'coexist_pair':'another-pair'},{**state,'instance':'replacement-instance'},{**state,'owner':'foreign'}):
   with self.assertRaises(a.Denied):a.pair_protocol_mode(manifest,obj,modified)
  for modified in ({**manifest,'activated':False},{**manifest,'resetting':True},{**manifest,'version':1}):
   with self.assertRaises(a.Denied):a.pair_protocol_mode(modified,obj,state)
 def test_subprocess_output_is_bounded_during_streaming(self):
  import sys
  with self.assertRaisesRegex(ValueError,'too large'):a.run([sys.executable,'-c','import sys;sys.stdout.write("x"*1000000)'],limit=1024)
  self.assertEqual(b'input',a.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'input',limit=1024))
 def test_oversized_operation_names_do_not_fill_audit_storage(self):
  with self.assertRaises(ValueError):self.call('x'*65000)
  self.assertEqual(0,self.db.db.execute('SELECT COUNT(*) FROM audit').fetchone()[0])
 def test_secret_payloads_absent_from_audit(self):
  _,r=self.enroll();self.mutate(r['account'],login='alice',password='never-record-me')
  audit=self.call('audit.read');self.assertNotIn('never-record-me',json.dumps(audit));self.assertNotIn('PRIVATE KEY',json.dumps(audit))
 def test_unknown_account_and_unsupported_upload_denied(self):
  with self.assertRaises(a.Denied):self.call('capabilities','rsd'+'0'*20)
  _,r=self.enroll()
  for op in ('shell','install','upload','os.reinstall','route.replace'):
   with self.assertRaises(a.Denied):self.call(op,r['account'],payload='malicious')
 def setup_peer(self):
  effects=Effects();peer=a.Access(Path(self.temp.name)/'peer',effects,lambda:self.now);self.addCleanup(peer.db.close)
  obj={**self.obj,'id':'vpn-peer','server_id':'server-peer','instance':'peer-instance'}
  peer.initialize('server-peer','deployment',{'host':'192.0.2.2','port':22,'host_key':self.key1[1]},[obj])
  link=peer.request('@owner',{'schema':1,'operation':'peers.prepare','authority_id':'server-first','scope':{'kind':'deployment','id':'deployment','users':'all'},'expected_revision':peer.revision()})['link']
  self.effects.peers['server-peer']=peer
  self.call('peers.link',link=link,expected_revision=self.db.revision());return peer,effects,obj,link
 def test_pair_claim_same_key_partial_sync_resumes_and_proxy_enforces(self):
  peer,effects,obj,_=self.setup_peer();self.effects.fail_peer=True
  invite,r=self.enroll('user_manager',{'kind':'deployment','id':'deployment','users':'own'})
  self.assertEqual(['server-peer'],r['pending_peers']);self.effects.fail_peer=False
  resumed=self.call('enrollment.resume',r['account']);self.assertEqual(['server-peer'],resumed['completed_peers'])
  self.assertEqual(self.key1[1],peer.get('peer_device',r['device_id'])['public_key'])
  with self.assertRaises(a.Denied):self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite,self.key2))
  self.mutate(r['account'],obj=obj,login='paired-user')
  self.assertIn('paired-user',effects.users[obj['id']])
  self.call('devices.revoke',device_id=r['device_id'],expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.mutate(r['account'],obj=obj,login='after-revocation')
  self.assertNotIn('after-revocation',effects.users[obj['id']])
 def test_peer_rejects_direct_recipient_and_wrong_authority(self):
  peer,_,_,link=self.setup_peer();_,r=self.enroll()
  with self.assertRaises(a.Denied):peer.request(r['account'],{'schema':1,'operation':'capabilities'})
  with self.assertRaises(a.Denied):peer.request(link['account'],{'schema':1,'operation':'peer.inspect','authority_id':'forged'})
  with self.assertRaises(a.Denied):peer.request(link['account'],{'schema':1,'operation':'grants.update','authority_id':'server-first'})
 def test_pair_scope_denial_and_authority_outage_are_fail_closed(self):
  _,effects,obj,_=self.setup_peer();_,r=self.enroll()
  with self.assertRaises(a.Denied):self.mutate(r['account'],obj=obj,login='wrong-scope')
  self.assertFalse(effects.calls)
  _,r2=self.enroll('user_manager',{'kind':'deployment','id':'deployment','users':'all'},self.key2);self.effects.fail_peer=True
  with self.assertRaises(OSError):self.mutate(r2['account'],obj=obj,login='no-authority')
  self.assertFalse(effects.calls)

if __name__=='__main__':unittest.main()
