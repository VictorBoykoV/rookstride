"""Password means wire authentication; rebuilding a server never pins a new leaf."""
import contextlib,importlib.util,json,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import access,model,routes,runtime,public_tls
spec=importlib.util.spec_from_file_location('openvpn_auth',Path(__file__).resolve().parents[1]/'single/openvpn-password.py');verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
class ReusableSignIn(unittest.TestCase):
 def test_reported_policy_distinguishes_recommendations_from_wire_limits(self):
  p=access.policy();self.assertTrue(p['advisory']);self.assertEqual(1,p['minimum']);self.assertEqual(127,p['maximum_utf8_bytes']);self.assertEqual(8,p['recommended_minimum']);self.assertEqual(15,p['generated_length'])
 def test_capabilities_do_not_mislabel_keys_as_usernames(self):
  for protocol in model.PROTOCOLS:
   req=dict(protocol=protocol,server='vpn.example.net',login='family.user',password='onlyletters',access_mode='password')
   if protocol in access.PASSWORD_PROTOCOLS:self.assertEqual(model.validate(req)['password'],'onlyletters')
   else:
    with self.assertRaises(ValueError):model.validate(req)
 def test_reusable_usernames_keep_the_existing_ike_64_character_contract(self):
  from rookstride import admin
  for value in ('family.user','a'*64,'@family','-guest','..'):
   self.assertEqual(access.login(value),admin.username(value))
  with self.assertRaises(ValueError):access.login('a'*65)
 def test_same_rules_for_every_reusable_method(self):
  for protocol in ('hysteria2','trusttunnel','naive','openvpn'):
   for password in ('1','short','a'*64,'abcdefgh','12345678','Ab@12345','quotes"\\!!','a space !','😀abcdefg'):
    self.assertEqual(model.validate(dict(protocol=protocol,server='vpn.example.net',login='a.b@c',password=password,access_mode='password'))['password'],password)
   for password in ('','1'*128,'😀'*32,'1234567\n','1234567\0','1234567\u2028'):
    with self.assertRaises(ValueError):model.validate(dict(protocol=protocol,server='vpn.example.net',login='a',password=password,access_mode='password'))
 def test_hashes_are_salted_and_plain_password_cannot_be_recovered_from_user_inventory(self):
  one=access.hash_password('onlyletters');two=access.hash_password('onlyletters')
  self.assertNotEqual(one,two);self.assertNotIn('onlyletters',one);self.assertTrue(access.verify('onlyletters',one));self.assertFalse(access.verify('wrongletters',one));self.assertFalse(access.verify('onlyletters','pbkdf2-sha256$999999999$bad$bad'))
 def test_real_authenticator_rejects_removed_users_and_wrong_password_and_allows_recreation(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Path(folder);accounts=f/'accounts';request=f/'request';request.write_text('family.user\nlettersOnly\n')
   accounts.write_text(json.dumps({'family.user':access.hash_password('lettersOnly')}));self.assertTrue(verifier.authenticate(request,accounts))
   request.write_text('family.user\nwrongSecret\n');self.assertFalse(verifier.authenticate(request,accounts))
   request.write_text('family.user\nlettersOnly\n');accounts.write_text('{}');self.assertFalse(verifier.authenticate(request,accounts))
   accounts.write_text(json.dumps({'family.user':access.hash_password('lettersOnly')}));self.assertTrue(verifier.authenticate(request,accounts))
 def test_openvpn_password_template_needs_no_device_key_or_changing_leaf(self):
  state=dict(server='vpn.example.net',port=1194,tls_name='vpn.example.net')
  one=model.openvpn_password_client(state,'TRUSTED ROOT');two=model.openvpn_password_client(dict(state,instance='new',leaf='new',users=[]),'TRUSTED ROOT')
  self.assertEqual(one,two);self.assertIn('verify-x509-name vpn.example.net name',one);self.assertIn('auth-user-pass\n',one)
  for value in ('<key>','<cert>','tls-crypt','insecure','ignore-unknown-option'):self.assertNotIn(value,one)
 def test_openvpn_wire_verifier_is_explicit_and_keeps_reused_login_sessions(self):
  text=model.openvpn_password_server(dict(server='vpn.example.net',port=1194))
  for directive in ('verify-client-cert none','username-as-common-name','duplicate-cn','auth-user-pass-verify /usr/local/bin/rookstride-openvpn-password via-file'):self.assertIn(directive,text)
 def test_hysteria_password_is_a_real_user_password_pair_not_an_account_label(self):
  public=dict(protocol='hysteria2',access_mode='password');user=dict(login='family.user',password='lettersOnly')
  self.assertEqual(access.wire_password(public,user),'family.user:lettersOnly');self.assertEqual(access.wire_password(dict(protocol='hysteria2'),user),'lettersOnly')
 def test_ip_tls_name_is_stable_and_domains_remain_the_entered_domain(self):
  self.assertEqual(public_tls.tls_name('8.8.8.8'),'8-8-8-8.sslip.io');self.assertEqual(public_tls.tls_name('VPN.Example-Company.org'),'vpn.example-company.org')
  for value in ('10.0.0.1','127.0.0.1','192.0.2.1','::1','vpn.invalid','x.local','a;rm.com'):
   with self.assertRaises(ValueError):public_tls.identity(value)
 def test_public_cache_never_accepts_unowned_directories(self):
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder)/'tls';base.mkdir()
   with patch.object(public_tls,'BASE',base),patch.object(public_tls,'owned',side_effect=lambda p:p),patch.object(public_tls,'run',return_value=Mock(returncode=1)):
    with self.assertRaises(ValueError):public_tls.initialize()
    base.rmdir();public_tls.initialize();self.assertIsNotNone(public_tls.fingerprint());public_tls.cleanup(public_tls.fingerprint());self.assertFalse(base.exists())
 def test_failed_acme_does_not_return_a_private_fallback_as_password_ready(self):
  with tempfile.TemporaryDirectory() as folder:
   with patch.multiple(public_tls,BASE=Path(folder)/'cache',LOCK=Path(folder)/'lock'),patch.object(public_tls,'owned',side_effect=lambda p:p),patch.object(public_tls,'client',return_value=Path('/certbot')),patch.object(public_tls,'material',side_effect=OSError()),patch.object(public_tls,'http_challenge',contextlib.nullcontext),patch.object(public_tls,'run',side_effect=subprocess.CalledProcessError(1,'certbot')):
    with self.assertRaisesRegex(ValueError,'public VPN address'):public_tls.ensure('8.8.8.8')
 def test_existing_verified_cached_identity_does_not_reissue_for_each_user(self):
  material={'renew_after':time.time()+50000,'sha256':'known'}
  with tempfile.TemporaryDirectory() as folder:
   with patch.multiple(public_tls,BASE=Path(folder)/'cache',LOCK=Path(folder)/'lock'),patch.object(public_tls,'owned',side_effect=lambda p:p),patch.object(public_tls,'material',return_value=material),patch.object(public_tls,'client') as client:
    self.assertEqual(public_tls.ensure('8.8.8.8'),material);client.assert_not_called()
 def test_password_changes_use_hashes_and_disconnect_revoked_openvpn_sessions(self):
  state=dict(protocol='openvpn',access_mode='password',users=[dict(login='family.user',password_hash=access.hash_password('firstPass'))])
  with patch.object(runtime,'save'),patch.object(runtime,'apply_config'),patch.object(runtime,'disconnect_password_user') as kill:
   runtime.edit_user(state,dict(login='family.user',password='secondPass'));self.assertTrue(access.verify('secondPass',state['users'][0]['password_hash']));self.assertNotIn('password',state['users'][0]);kill.assert_called_once_with(state,'family.user')
   runtime.remove_user(state,'family.user');self.assertEqual(state['users'],[])

class CrossModuleContracts(unittest.TestCase):
 def test_certificate_client_pins_cannot_drift_between_ike_and_other_password_routes(self):
  import ike_public
  self.assertEqual(ike_public.CERTBOT_VERSION,public_tls.CERTBOT_VERSION)
 def test_trust_credentials_encode_astral_passwords_as_valid_toml_unicode(self):
  import routes
  secret='😀abcdefg';quoted=routes.toml_quote(secret)
  self.assertIn(secret,quoted);self.assertNotIn('\\ud83d',quoted.lower());self.assertEqual(json.loads(quoted),secret)
 def test_local_naive_verification_preserves_tls_identity_without_public_ip_hairpin(self):
  import routes
  profile=dict(protocol='naive',server='192.0.2.10',server_name='vpn.family-domain.org',port=9443,login='family.user',password='lettersOnly',certificate='TRUSTED ROOT')
  with patch.object(routes,'validate_profile'):
   value=routes.client_config(profile,1080,server='127.0.0.1')['box']['outbounds']
  self.assertEqual(value[0]['tls']['server_name'],'vpn.family-domain.org');self.assertEqual(value[1]['server'],'127.0.0.1');self.assertEqual(value[1]['server_port'],9443)
 def test_public_ike_alias_profile_uses_address_bound_automatic_ca_validation(self):
  from rookstride import admin
  import ssl
  with patch.object(admin,'user_inventory',return_value=[dict(login='family.user')]),patch.object(admin.ike_public,'status',return_value=dict(identity='vpn.family-domain.org',aliases=[])),patch.object(Path,'read_text',return_value=' leftid=@vpn.family-domain.org\n leftcert=server.pem\n'),patch.object(ssl,'PEM_cert_to_DER_cert',return_value=b'fake'):
   value=admin.profile(dict(login='family.user'));self.assertEqual(value['remote']['addr'],'vpn.family-domain.org');self.assertNotIn('cert',value['remote']);self.assertNotIn('id',value['remote'])
