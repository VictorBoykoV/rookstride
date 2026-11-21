"""Real native export shapes and cryptographic identity checks before any restore."""
import base64,copy,hashlib,json,subprocess,sys,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import recovery_adapters as adapters,recovery,native_pair,pair
from test_owner_recovery import snapshot,archive,KEY,PUBLIC

def state(protocol,role='exit',public=False):
 value=dict(protocol=protocol,server='exit.example.net' if role=='exit' else 'vpn.example.net',port=443,initialLogin='bridge',instance='b'*32,owner='rookstride-single-v1',users=[dict(login='bridge',enabled=True,created=1)])
 if role=='entry':value.update(pair='a'*32,pair_dns={'address':'10.253.0.1','dns_port':53})
 if protocol=='awg':value.update(private=KEY,public=PUBLIC,parameters=native_pair.model.awg_parameters());value['users'][0].update(private=KEY,public=PUBLIC,psk=KEY,address='10.67.0.2' if role=='exit' else '10.66.0.2',ipv6='fd42:670::2')
 elif protocol in ('xray','xhttp'):
  value.update(private=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),public=base64.urlsafe_b64encode(adapters.derived_public(bytes(range(32)))).decode().rstrip('='),shortId='f'*16,sni='www.example.org');value['users'][0]['uuid']=str(uuid.UUID(int=42))
  if protocol=='xhttp':value['path']='/'+('f'*48)
 elif protocol=='openvpn':
  if public:value['users'][0]['password_hash']=native_pair.runtime.access.hash_password('fixture-password-123');value.update(access_mode='password',tls_name=value['server'])
 else:
  value.update(tls_name=value['server'],tls_mode='private-authority-pinned-through-ssh');value['users'][0]['password']='fixture-password-123'
  if protocol in ('outline','shadowsocks'):value['users'][0]['path']='/'+('e'*48)
  if protocol=='hysteria2':value['obfs']='fixture-obfuscation-123'
  if public:value.update(access_mode='password',tls_mode='public-authority')
 return value

def encoded(data):return {name:dict(content=base64.b64encode(content).decode(),sha256=hashlib.sha256(content).hexdigest()) for name,content in data.items()}

class NativeRecoveryAdaptersTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();root=Path(cls.temp.name)
  def run(args):subprocess.run(['openssl',*args],cwd=root,capture_output=True,check=True)
  run(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=Fixture CA','-keyout','ca.key','-out','ca.pem'])
  run(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=server','-keyout','server.key','-out','server.csr'])
  (root/'extensions').write_text('basicConstraints=CA:FALSE\nsubjectAltName=DNS:exit.example.net\nextendedKeyUsage=serverAuth\n')
  run(['x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','2','-extfile','extensions','-out','server.pem'])
  cls.tls={name:(root/name.split('/')[-1]).read_bytes() for name in ('tls/ca.pem','tls/ca.key','tls/server.pem','tls/server.key')}
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def openvpn_identity(self):
  root=Path(self.temp.name)
  def run(args):return subprocess.run(['openssl',*args],cwd=root,capture_output=True,check=True).stdout
  run(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=bridge','-keyout','bridge.key','-out','bridge.csr'])
  run(['x509','-req','-in','bridge.csr','-CA','ca.pem','-CAkey','ca.key','-CAserial','ca.srl','-days','2','-out','bridge.pem'])
  rows=[]
  for name in ('server','bridge'):
   serial=run(['x509','-in',name+'.pem','-noout','-serial']).decode().strip().split('=')[1]
   rows.append('V\t491231235959Z\t\t'+serial+'\tunknown\t/CN='+name+'\n')
  (root/'index.txt').write_text(''.join(rows));(root/'index.txt.attr').write_text('unique_subject = no\n');(root/'serial').write_text('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n')
  (root/'ca.conf').write_text('[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index.txt\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\nserial=serial\ndefault_days=2\ndefault_crl_days=2\ndefault_md=sha256\npolicy=subject\n[subject]\ncommonName=supplied\n')
  run(['ca','-config','ca.conf','-gencrl','-out','crl.pem'])
  mapping={'runtime/pki/ca.crt':'ca.pem','runtime/pki/private/ca.key':'ca.key','runtime/pki/issued/server.crt':'server.pem','runtime/pki/private/server.key':'server.key','runtime/pki/issued/bridge.crt':'bridge.pem','runtime/pki/private/bridge.key':'bridge.key','runtime/pki/crl.pem':'crl.pem','runtime/pki/index.txt':'index.txt','runtime/pki/index.txt.attr':'index.txt.attr','runtime/pki/serial':'serial'}
  data={name:(root/source).read_bytes() for name,source in mapping.items()};data['runtime/tls-crypt.key']=('-----BEGIN OpenVPN Static key V1-----\n'+('a'*32+'\n')*16+'-----END OpenVPN Static key V1-----\n').encode()
  return data
 def test_openvpn_identity_keeps_authority_accounts_and_native_profile_without_invented_files(self):
  value=state('openvpn');data=self.openvpn_identity();identity=encoded(data)
  self.assertNotIn('runtime/pki/crlnumber',identity);adapters.validate(value,'exit',identity)
  profile=adapters.client_profile(value,'bridge',identity)
  p=pair.plan(dict(pair='a'*32,role='entry',engine='native-v2',entry_protocol='awg',exit_protocol='openvpn',server='entry.example.net',exit_host='exit.example.net',tunnel_port=443))
  native_pair.validate_material(p,{'protocol':'openvpn','endpoint':'exit.example.net','profile':{'content':profile},'dns':{'address':'10.253.0.1','dns_port':53}})
  # EasyRSA's optional human-readable certificate preamble is not profile data.
  data['runtime/pki/issued/bridge.crt']=b'Certificate:\n    Data:\n'+data['runtime/pki/issued/bridge.crt']
  self.assertEqual(profile,adapters.client_profile(value,'bridge',encoded(data)))
  bad=copy.deepcopy(data);bad['runtime/pki/issued/bridge.crt']=data['runtime/pki/issued/server.crt'];bad['runtime/pki/private/bridge.key']=data['runtime/pki/private/server.key']
  with self.assertRaisesRegex(ValueError,'account identity'):adapters.validate(value,'exit',encoded(bad))
 def test_enabled_openvpn_user_with_revoked_certificate_cannot_pass_rehearsal(self):
  value=state('openvpn');data=self.openvpn_identity();root=Path(self.temp.name)
  for command in (['ca','-config','ca.conf','-revoke','bridge.pem'],['ca','-config','ca.conf','-gencrl','-out','crl.pem']):subprocess.run(['openssl',*command],cwd=root,check=True,capture_output=True)
  data['runtime/pki/crl.pem']=(root/'crl.pem').read_bytes();data['runtime/pki/index.txt']=(root/'index.txt').read_bytes()
  with self.assertRaisesRegex(ValueError,'did not verify'):adapters.validate(value,'exit',encoded(data))
  value['users'][0]['enabled']=False;adapters.validate(value,'exit',encoded(data))
 def test_real_worker_exports_retain_account_and_ca(self):
  for protocol in adapters.WORKERS:
   with self.subTest(protocol=protocol):
    value=state(protocol);identity=encoded(self.tls);adapters.validate(value,'exit',identity)
    profile=adapters.client_profile(value,'bridge',identity)
    self.assertEqual(value['users'][0]['password'],profile['password']);self.assertEqual(self.tls['tls/ca.pem'].decode(),profile['certificate'])
    import routes
    routes.validate_profile(profile)
 def test_key_protocols_use_their_real_native_profile_not_json_assumptions(self):
  for protocol in ('awg','xray','xhttp'):
   value=state(protocol);adapters.validate(value,'exit',{});profile=adapters.client_profile(value,'bridge',{})
   self.assertTrue(profile.startswith('[Interface]' if protocol=='awg' else 'vless://'))
 def test_unknown_authority_files_paths_and_executable_fields_are_rejected(self):
  value=state('trusttunnel');identity=encoded(self.tls)
  for path in ('../../etc/ssh/sshd_config','tls/start.sh','tls/extra.pem'):
   bad=copy.deepcopy(identity);bad[path]=next(iter(identity.values()))
   with self.assertRaisesRegex(ValueError,'unexpected'):adapters.validate(value,'exit',bad)
  for where in ('state','user'):
   bad=copy.deepcopy(value);(bad if where=='state' else bad['users'][0])['command']='arbitrary'
   with self.assertRaisesRegex(ValueError,'Unexpected'):adapters.validate(bad,'exit',identity)
 def test_certificate_key_chain_and_digest_are_actually_checked(self):
  value=state('hysteria2');bad=copy.deepcopy(self.tls);bad['tls/server.key']=bad['tls/ca.key']
  with self.assertRaisesRegex(ValueError,'do not match'):adapters.validate(value,'exit',encoded(bad))
  bad=encoded(self.tls);bad['tls/server.pem']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'checksum'):adapters.validate(value,'exit',bad)
 def test_valid_private_certificate_for_another_endpoint_is_rejected(self):
  for endpoint in ('another.example.net','192.0.2.99'):
   for protocol in ('hysteria2','trusttunnel','naive','ikev2'):
    value=state(protocol);value['server']=endpoint
    if protocol!='ikev2':value['tls_name']=endpoint
    else:value['users'][0]['password']='fixture-password';value.pop('tls_name',None);value.pop('tls_mode',None)
    with self.assertRaisesRegex(ValueError,'did not verify'):adapters.validate(value,'exit',encoded(self.tls))
 def test_silent_successful_crypto_process_cannot_confirm_identity(self):
  from types import SimpleNamespace
  with patch.object(adapters.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'')):
   with self.assertRaisesRegex(ValueError,'do not match'):adapters.validate(state('hysteria2'),'exit',encoded(self.tls))
 def test_new_install_runtime_fields_and_counter_generation_survive_restore(self):
  old=state('shadowsocks');old['users'][0].update(private_port=25000,administration_account_id='old-grant');old.update(metrics_port=25001,metrics_token='old-token',filtering='old-filter')
  clean=adapters.clean_state(old);self.assertNotIn('private_port',clean['users'][0]);self.assertNotIn('administration_account_id',clean['users'][0]);self.assertNotIn('metrics_token',clean)
  new=copy.deepcopy(old);new.update(instance='c'*32,metrics_port=26001,metrics_token='new-token',filtering='new-filter')
  with patch('routes.port',return_value=27000):restored=adapters.restore_state({'state':clean},new)
  self.assertEqual('c'*32,restored['instance']);self.assertEqual('new-token',restored['metrics_token']);self.assertEqual(27000,restored['users'][0]['private_port']);self.assertEqual(clean['users'][0]['password'],restored['users'][0]['password'])
 def test_public_signin_uses_new_issuer_material_not_stale_private_leaf(self):
  for protocol in ('openvpn','hysteria2','trusttunnel','naive'):
   value=state(protocol,public=True);self.assertEqual([],adapters.names(value));adapters.validate(value,'exit',{})
 def test_actual_password_openvpn_hash_roundtrips_without_rehashing(self):
  value=state('openvpn',public=True);original=value['users'][0]['password_hash']
  self.assertTrue(native_pair.runtime.access.verify('fixture-password-123',original))
  adapters.validate(value,'exit',{})
  current=copy.deepcopy(value);current['instance']='c'*32
  restored=adapters.restore_state({'state':adapters.clean_state(value)},current)
  self.assertEqual(original,restored['users'][0]['password_hash'])
  self.assertTrue(native_pair.runtime.access.verify('fixture-password-123',restored['users'][0]['password_hash']))
  for invalid in ('$2b$12$'+'a'*53,original.replace('310000','1'),original[:-1],original.upper()):
   broken=copy.deepcopy(value);broken['users'][0]['password_hash']=invalid
   with self.assertRaisesRegex(ValueError,'password hash'):adapters.validate(broken,'exit',{})
 def test_mismatched_native_private_keys_are_rejected_without_restoring(self):
  for protocol in ('awg','xray','xhttp'):
   for user in (False,True) if protocol=='awg' else (False,):
    value=state(protocol);target=value['users'][0] if user else value
    target['private']=base64.b64encode(b'z'*32).decode() if protocol=='awg' else base64.urlsafe_b64encode(b'z'*32).decode().rstrip('=')
    with patch.object(native_pair.runtime,'save') as save,patch.object(native_pair,'command') as command:
     with self.assertRaisesRegex(ValueError,'identity'):adapters.validate(value,'exit',{})
     save.assert_not_called();command.assert_not_called()
 def test_duplicate_client_keys_or_uuid_are_refused(self):
  for protocol in ('awg','xray','xhttp'):
   value=state(protocol);duplicate=copy.deepcopy(value['users'][0]);duplicate['login']='another';value['users'].append(duplicate)
   with self.assertRaisesRegex(ValueError,'[Dd]uplicate'):adapters.validate(value,'exit',{})
 def test_cross_protocol_pair_rehearsal_compares_actual_exit_user_identity(self):
  for protocol in ('xray','xhttp','trusttunnel','hysteria2','outline','shadowsocks','naive'):
   value=archive();exit=value['nodes']['exit'];es=state(protocol);identity=encoded(self.tls) if protocol in adapters.WORKERS else {}
   for role,node in value['nodes'].items():
    node['schema']=2;node['adapter']=node['state']['protocol']+'-identity-v1';node['identity_files']={};node['plan']['exit_protocol']=protocol
   exit.update(state=es,adapter=protocol+'-identity-v1',identity_files=identity,initial_user={'login':'bridge','password':'fixture-password-123'})
   content=adapters.client_profile(es,'bridge',identity);content=json.dumps(content) if isinstance(content,dict) else content
   value['nodes']['entry']['transport']={'protocol':protocol,'endpoint':es['server'],'profile':{'format':protocol,'content':content},'dns':{'address':'10.253.0.1','dns_port':5354}}
   plans={role:node['plan'] for role,node in value['nodes'].items()}
   with self.subTest(protocol=protocol):self.assertTrue(recovery.validate_pair(value,plans)['verified'])
   es['users'][0]['uuid' if protocol in ('xray','xhttp') else 'password']=str(uuid.UUID(int=43)) if protocol in ('xray','xhttp') else 'another-password'
   with self.assertRaisesRegex(ValueError,'bridge credentials'):recovery.validate_pair(value,plans)
if __name__=='__main__':unittest.main()
