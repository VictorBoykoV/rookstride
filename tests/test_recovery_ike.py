"""Parsed EAP and certificate recovery excludes daemon configuration and grants."""
import copy,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_recovery_adapters as fixtures
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import recovery_ike as ike,recovery_adapters as adapters,pair,recovery,lifecycle,native_pair
class IkeRecoveryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):fixtures.NativeRecoveryAdaptersTests.setUpClass()
 @classmethod
 def tearDownClass(cls):fixtures.NativeRecoveryAdaptersTests.tearDownClass()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.secrets=self.root/'ipsec.secrets';self.metadata=self.root/'users';self.metadata.mkdir();self.own=self.root/'owned';self.own.mkdir();self.identity={key:self.root/key for key in fixtures.NativeRecoveryAdaptersTests.tls}
  for key,path in self.identity.items():path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(fixtures.NativeRecoveryAdaptersTests.tls[key])
  self.secrets.write_text('exit.example.net : RSA single-vps-server-key.pem\nbridge : EAP "fixture-password"\n')
  (self.metadata/'users.json').write_text(json.dumps({'bridge':{'person':'Reader','device':'Tablet','administration_account_id':'not-restored'}}))
  self.plan=pair.plan(dict(pair='a'*32,role='exit',engine='native-v2',entry_protocol='awg',exit_protocol='ikev2',server='entry.example.net',exit_host='exit.example.net',tunnel_port=500))
  (self.own/'initial-user.json').write_text(json.dumps({'login':'bridge','password':'fixture-password'}))
  paths=[self.secrets,*[p for k,p in self.identity.items() if k!='tls/ca.key']];(self.own/'ike-files.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p)+'\n' for p in paths))
  self.patches=[patch.object(pair,'protected',side_effect=lambda p:Path(p)),patch.object(pair,'OWN',self.own),patch.multiple(ike.admin,SECRETS=self.secrets,STATE=self.metadata),patch.object(ike,'FILES',self.identity),patch.multiple(ike.ike_public,CERT=self.identity['tls/server.pem'],KEY=self.identity['tls/server.key']),patch.object(ike.ike_public,'status',return_value=None)]
  for value in self.patches:value.start()
 def tearDown(self):
  for value in reversed(self.patches):value.stop()
  self.temp.cleanup()
 def test_private_ike_snapshot_retains_eap_credentials_and_pinned_server_certificate(self):
  state=ike.state(self.plan);identity=adapters.files(state);adapters.validate(state,'exit',identity);profile=adapters.client_profile(state,'bridge',identity)
  self.assertEqual('fixture-password',profile['password']);self.assertEqual('exit.example.net',profile['identity']);self.assertNotIn('administration_account_id',state['users'][0]);self.assertEqual(32,len(state['instance']))
 def test_restore_rebuilds_only_eap_records_and_updates_only_reviewed_data_hashes(self):
  state=ike.state(self.plan);state['users'][0]['password']='quote" and slash\\ and dollar$';data=adapters.decode_files(state,adapters.files(state));before=self.own.joinpath('ike-files.sha256').read_text()
  with patch.object(ike.native_pair,'command') as commands:ike.restore(state,data)
  self.assertEqual(state['users'][0]['password'],ike.accounts()[0]['password']);self.assertNotIn('administration_account_id',(self.metadata/'users.json').read_text());self.assertNotEqual(before,(self.own/'ike-files.sha256').read_text());self.assertEqual(['ipsec','rereadall'],commands.call_args_list[0].args[0])
 def test_unknown_secret_directive_is_not_restored_or_executed(self):
  state=ike.state(self.plan);data=adapters.decode_files(state,adapters.files(state));self.secrets.write_text('include /outside/secrets\n');before=self.secrets.read_text()
  with patch.object(ike.native_pair,'command') as commands:
   with self.assertRaisesRegex(ValueError,'unrecognized'):ike.restore(state,data)
   commands.assert_not_called()
  self.assertEqual(before,self.secrets.read_text())
 def test_unverified_public_identity_does_not_export_private_server_keys(self):
  with patch.object(ike.ike_public,'status',return_value={'aliases':[]}):state=ike.state(self.plan)
  self.assertEqual('password',state['access_mode']);self.assertEqual({},adapters.files(state));adapters.validate(state,'exit',{})
 def test_interrupted_bridge_secret_write_reloads_same_identity_before_ready(self):
  network=self.root/'network.env';network.write_text('DNS_IP=10.253.0.1\n')
  req={'deployment':'a'*32,'operation':'d'*32};login='migration-'+'d'*16;journal=self.root/'lifecycle'/'entry-bridges'/('d'*32+'.json')
  with patch.object(pair,'load_manifest',return_value={'version':2,'plan':self.plan}),patch.object(lifecycle,'ROOT',self.root/'lifecycle'),patch.object(native_pair,'IKE_NETWORK',network),patch.object(ike.admin,'PAIR_ROOT',self.own),patch.object(ike.admin,'update_user',wraps=ike.admin.update_user) as create,patch.object(ike.admin,'run',side_effect=[KeyboardInterrupt('killed before daemon reload'),RuntimeError('daemon unavailable'),None]) as reload:
   # A process death bypasses update_user's ordinary Exception rollback after
   # its real atomic secret write; the durable journal must remain creating.
   with self.assertRaises(KeyboardInterrupt):recovery.entry_bridge(req)
   secret_bytes=self.secrets.read_bytes();user=next(u for u in ike.accounts() if u['login']==login)
   self.assertEqual('creating',json.loads(journal.read_text())['state']);self.assertNotIn(login,ike.admin.catalog())
   with self.assertRaisesRegex(RuntimeError,'unavailable'):recovery.entry_bridge(req)
   self.assertEqual(secret_bytes,self.secrets.read_bytes());self.assertEqual('creating',json.loads(journal.read_text())['state'])
   result=recovery.entry_bridge(req)
   self.assertEqual(user['password'],result['profile']['password']);self.assertEqual(login,result['profile']['login']);self.assertEqual(secret_bytes,self.secrets.read_bytes())
   self.assertEqual('ready',json.loads(journal.read_text())['state']);self.assertEqual(1,create.call_count)
   self.assertEqual([['ipsec','rereadsecrets']]*3,[call.args[0] for call in reload.call_args_list])
   self.assertEqual(result,recovery.entry_bridge(req));self.assertEqual(3,reload.call_count)
if __name__=='__main__':unittest.main()
