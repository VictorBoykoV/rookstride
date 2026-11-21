import contextlib,importlib.util,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch,Mock
spec=importlib.util.spec_from_file_location('ike_public',Path(__file__).resolve().parents[1]/'server/ike_public.py')
certs=importlib.util.module_from_spec(spec);spec.loader.exec_module(certs)

class PublicCertificateTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.base=self.root/'owned';self.base.mkdir()
  self.cert=self.root/'server.pem';self.cert.write_bytes(b'old certificate');self.key=self.root/'private.pem';self.key.write_bytes(b'old private key');self.issuers=tuple(self.root/('issuer-'+str(i)+'.pem') for i in range(4));self.marker=self.base/'public.json'
  self.paths=patch.multiple(certs,BASE=self.base,MARKER=self.marker,CERT=self.cert,KEY=self.key,ISSUERS=self.issuers,ACME=self.base/'acme',VENV=self.base/'venv',UNIT=self.root/'renew.service',TIMER=self.root/'renew.timer');self.paths.start()
 def tearDown(self):self.paths.stop();self.temp.cleanup()
 def material(self):return (b'new certificate',b'new private key',['issuer\n'],time.time()+500000)
 def test_only_public_addresses_and_real_hostnames_are_eligible(self):
  for value in ('127.0.0.1','192.0.2.1','198.51.100.1','10.0.0.1','169.254.1.2','::1','vpn.example.net','x.example.org','x.test','x.local','a;id','a\nb.com','-a.com','a..com',''):
   self.assertFalse(certs.eligible(value),value)
  self.assertTrue(certs.eligible('8.8.8.8'));self.assertTrue(certs.eligible('vpn.example-company.org'))
 def test_issuance_for_ip_selects_short_lived_profile_and_no_domain_prompt(self):
  with patch.object(certs,'client',return_value=Path('/owned/certbot')),patch.object(certs,'challenge_port',contextlib.nullcontext),patch.object(certs,'run') as run:
   certs.obtain('8.8.8.8');args=run.call_args.args[0];self.assertIn('--ip-address',args);self.assertIn('shortlived',args);self.assertNotIn('-d',args);self.assertIn('--non-interactive',args)
 def test_renewal_is_scoped_to_our_certificate_name(self):
  with patch.object(certs,'client',return_value=Path('/owned/certbot')),patch.object(certs,'challenge_port',contextlib.nullcontext),patch.object(certs,'run') as run:
   certs.obtain('8.8.8.8',True);args=run.call_args.args[0];self.assertEqual(args[args.index('--cert-name')+1],'rookstride-ike')
 def test_failed_material_verification_never_changes_identity(self):
  with patch.object(certs,'material',side_effect=ValueError('untrusted chain')),patch.object(certs,'run') as run:
   with self.assertRaises(ValueError):certs.activate(self.base,'8.8.8.8')
   run.assert_not_called()
  self.assertEqual(self.cert.read_bytes(),b'old certificate');self.assertFalse(self.marker.exists())
 def test_failed_reload_rolls_back_all_certificate_files(self):
  def command(args,**kw):
   if args==['ipsec','reload'] and kw.get('check',True):raise RuntimeError('reload failed')
   return Mock(returncode=0)
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run',side_effect=command):
   with self.assertRaises(RuntimeError):certs.activate(self.base,'8.8.8.8')
  self.assertEqual(self.cert.read_bytes(),b'old certificate');self.assertEqual(self.key.read_bytes(),b'old private key');self.assertFalse(self.marker.exists());self.assertFalse(self.issuers[0].exists())
 def test_renewed_leaf_keeps_the_installation_identity(self):
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run'):
   first=certs.activate(self.base,'8.8.8.8');self.assertEqual(certs.status(),first)
  next_material=(b'renewed certificate',b'renewed key',['next issuer\n'],time.time()+500000)
  with patch.object(certs,'material',return_value=next_material),patch.object(certs,'run'):
   second=certs.activate(self.base,'8.8.8.8')
  self.assertEqual(first['instance'],second['instance']);self.assertNotEqual(first['certificate_sha256'],second['certificate_sha256']);self.assertEqual(self.key.stat().st_mode&0o777,0o600)
 def test_external_certificate_change_does_not_claim_public_trust(self):
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run'):certs.activate(self.base,'8.8.8.8')
  self.cert.write_bytes(b'other server identity');self.assertIsNone(certs.status())
 def test_an_unowned_issuer_or_symlink_is_refused(self):
  self.issuers[0].write_text('not ours')
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run'):
   with self.assertRaises(ValueError):certs.activate(self.base,'8.8.8.8')
  self.issuers[0].unlink();self.issuers[0].symlink_to(self.cert)
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run'):
   with self.assertRaises(ValueError):certs.activate(self.base,'8.8.8.8')
 def test_renewal_setup_failure_precedes_identity_activation(self):
  with patch.object(certs,'identity',return_value='8.8.8.8'),patch.object(certs,'obtain',return_value=self.base),patch.object(certs,'timer',side_effect=RuntimeError('not enabled')),patch.object(certs,'activate') as activate:
   with self.assertRaises(RuntimeError):certs.enable()
   activate.assert_not_called()
 def test_failure_after_new_timer_start_removes_the_timer(self):
  with patch.object(certs,'identity',return_value='8.8.8.8'),patch.object(certs,'obtain',return_value=self.base),patch.object(certs,'timer'),patch.object(certs,'activate',side_effect=RuntimeError('bad material')),patch.object(certs,'run') as run:
   with self.assertRaises(RuntimeError):certs.enable()
   self.assertIn(unittest.mock.call(['systemctl','disable','--now','renew.timer'],check=False),run.call_args_list)
 def test_invalid_or_linked_marker_does_not_disable_certificate_validation(self):
  for value in ([],{},None,{'version':1}):self.marker.write_text(json.dumps(value));self.assertIsNone(certs.status())
  self.marker.unlink();self.marker.symlink_to(self.cert);self.assertIsNone(certs.status())
 def test_renewal_unit_never_silently_replaces_an_unrelated_unit(self):
  certs.UNIT.write_text('Description=another service')
  with patch.object(certs,'run') as run:
   with self.assertRaises(ValueError):certs.timer()
   run.assert_not_called()

if __name__=='__main__':unittest.main()

class PublicProfileTests(unittest.TestCase):
 def setUp(self):
  import sys
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
  from rookstride import admin
  self.admin=admin;self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.config=self.root/'config';self.config.write_text('conn ikev2-vpn\n leftid=8.8.8.8\n leftcert=server.pem\n');self.cert=self.root/'server.pem';self.cert.write_text('fixture certificate')
 def tearDown(self):self.temp.cleanup()
 def profile(self,public):
  def local(path):
   if str(path)=='/etc/ipsec.conf':return self.config
   if str(path)=='/etc/ipsec.d/certs':return self.root
   if str(path)=='/etc/rookstride-pair/manifest.json':return self.root/'no-pair'
   return Path(path)
  with patch.object(self.admin,'Path',side_effect=local),patch.object(self.admin,'user_inventory',return_value=[{'login':'alice'}]),patch.object(self.admin.ssl,'PEM_cert_to_DER_cert',return_value=b'fixture DER'),patch.object(self.admin.ike_public,'status',return_value=public):return self.admin.profile({'login':'alice'})
 def test_public_ca_export_does_not_pin_a_renewable_leaf(self):
  profile=self.profile({'identity':'8.8.8.8'});self.assertEqual(profile['type'],'ikev2-eap');self.assertEqual(profile['local'],{'eap_id':'alice'});self.assertNotIn('cert',profile['remote']);self.assertNotIn('p12',profile['local']);self.assertNotIn('id',profile['remote'])
 def test_private_or_different_identity_still_exports_its_certificate(self):
  for public in (None,{'identity':'vpn.other-domain.org'}):self.assertIn('cert',self.profile(public)['remote'])
 def test_unexpected_ciphertext_or_password_is_not_added_to_profile(self):
  profile=self.profile(None);self.assertNotIn('shared_secret',profile['local']);self.assertEqual(profile['mtu'],1280)

class FreshDeploymentCertificateTests(unittest.TestCase):
 def setUp(self):
  import sys
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
  import deploy
  self.deploy=deploy;self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.ident='a'*32;self.job=self.root/self.ident;self.job.mkdir();self.paths=patch.object(deploy,'JOBS',self.root);self.paths.start()
 def tearDown(self):self.paths.stop();self.temp.cleanup()
 def execute(self,mode='install',address='8.8.8.8',failure=False):
  import subprocess
  self.job.joinpath('config.json').write_text(json.dumps({'mode':mode,'server':address,'login':'fixture-user','password':'Sample123','statistics':True}))
  calls=[]
  def run(args,**kw):
   calls.append(args)
   if failure and args[-1]=='enable':raise subprocess.CalledProcessError(1,args)
   return subprocess.CompletedProcess(args,0,stdout='',stderr='')
  def public(log,aliases=()):
   calls.append(['public-certificate','enable'])
   if failure:raise subprocess.CalledProcessError(1,['public-certificate'])
  with patch.object(self.deploy.subprocess,'run',side_effect=run),patch.object(self.deploy,'public_certificate',side_effect=public):self.deploy.execute(self.ident)
  self.assertFalse(self.job.joinpath('config.json').exists());self.assertFalse(self.job.joinpath('vpn-password').exists())
  return calls,json.loads(self.job.joinpath('status.json').read_text())
 def test_fresh_public_address_prepares_public_sign_in_automatically(self):
  calls,state=self.execute();self.assertEqual(state['state'],'complete');self.assertTrue(state['public_certificate']);self.assertTrue(any(args[-1]=='enable' for args in calls))
 def test_unavailable_public_validation_keeps_secure_profile_setup_available(self):
  calls,state=self.execute(failure=True);self.assertEqual(state['state'],'complete');self.assertFalse(state['public_certificate']);self.assertIn('Secure pinned-profile',self.job.joinpath('install.log').read_text())
 def test_management_enrollment_does_not_rotate_existing_server_identity(self):
  calls,state=self.execute(mode='enroll');self.assertEqual(state['state'],'complete');self.assertFalse(state['public_certificate']);self.assertEqual(len(calls),1)
 def test_documentation_and_private_addresses_do_not_contact_a_public_ca(self):
  for address in ('vpn.example.net','192.0.2.10'):
   calls,state=self.execute(address=address);self.assertEqual(len(calls),3);self.assertFalse(state['public_certificate'])
 def test_filter_verification_failure_is_actionable_and_never_runs_management_or_acme(self):
  import subprocess
  self.job.joinpath('config.json').write_text(json.dumps({'mode':'install','server':'8.8.8.8','login':'fixture-user','password':'Sample123','statistics':True}))
  phases=[];original=self.deploy.state
  def state(job,value):phases.append(value['phase']);original(job,value)
  def run(args,**kw):
   if args[-1].endswith('/verify.sh'):
    return subprocess.CompletedProcess(args,1,stdout='',stderr='private server detail\nThe ad-block list did not finish downloading. Check server HTTPS access; the existing VPN setup has been retained.')
   self.assertEqual(kw['env']['ROOKSTRIDE_VERIFY_SEPARATELY'],'YES')
   return subprocess.CompletedProcess(args,0,stdout='',stderr='')
  with patch.object(self.deploy.subprocess,'run',side_effect=run) as commands,patch.object(self.deploy,'state',side_effect=state),patch.object(self.deploy,'public_certificate') as public:
   self.deploy.execute(self.ident)
  value=json.loads(self.job.joinpath('status.json').read_text())
  self.assertEqual('failed',value['state']);self.assertIn('Ad blocking did not finish',value['phase'])
  self.assertNotIn('private server detail',value['phase']);self.assertIn('private server detail',self.job.joinpath('install.log').read_text())
  self.assertIn('Checking VPN, DNS and ad blocking',phases);self.assertEqual(2,commands.call_count);public.assert_not_called()
  self.assertFalse(self.job.joinpath('config.json').exists());self.assertFalse(self.job.joinpath('vpn-password').exists())
 def test_verification_timeout_is_not_reported_as_success_or_reinstallation(self):
  import subprocess
  self.job.joinpath('config.json').write_text(json.dumps({'mode':'install','server':'8.8.8.8','login':'fixture-user','password':'Sample123','statistics':True}))
  def run(args,**kw):
   if args[-1].endswith('/verify.sh'):raise subprocess.TimeoutExpired(args,360)
   return subprocess.CompletedProcess(args,0,stdout='',stderr='')
  with patch.object(self.deploy.subprocess,'run',side_effect=run) as commands,patch.object(self.deploy,'public_certificate') as public:self.deploy.execute(self.ident)
  value=json.loads(self.job.joinpath('status.json').read_text())
  self.assertEqual('failed',value['state']);self.assertIn('checks timed out',value['phase']);self.assertEqual(2,commands.call_count);public.assert_not_called()

class CertificateWorkerTimeoutTests(unittest.TestCase):
 def test_timeout_stops_the_complete_acme_process_group(self):
  import sys,subprocess,signal
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
  import deploy
  worker=Mock(pid=12345);worker.wait.side_effect=[subprocess.TimeoutExpired('fixture',1200),0]
  with patch.object(deploy.subprocess,'Popen',return_value=worker) as start,patch.object(deploy.os,'killpg') as stop:
   with self.assertRaises(subprocess.TimeoutExpired):deploy.public_certificate(Mock())
   self.assertTrue(start.call_args.kwargs['start_new_session']);stop.assert_called_once_with(12345,signal.SIGTERM)

class CertificateAliasTests(unittest.TestCase):
 setUp=PublicCertificateTests.setUp
 tearDown=PublicCertificateTests.tearDown
 material=PublicCertificateTests.material
 def test_alias_input_is_bounded_normalized_and_never_a_command(self):
  self.assertEqual(['vpn.family-domain.org'],certs.aliases(['VPN.FAMILY-DOMAIN.ORG','vpn.family-domain.org']))
  for value in (["bad;command"],["8.8.8.8"],["x\ny.org"],['a'+str(i)+'.family-domain.org' for i in range(6)]):
   with self.assertRaises(ValueError):certs.aliases(value)
 def test_one_certificate_can_request_the_ip_and_saved_hostname(self):
  with patch.object(certs,'client',return_value=Path('/owned/certbot')),patch.object(certs,'challenge_port',contextlib.nullcontext),patch.object(certs,'run') as run:
   certs.obtain('8.8.8.8',names=['vpn.family-domain.org']);args=run.call_args.args[0];self.assertIn('--ip-address',args);self.assertIn('shortlived',args);self.assertIn('--expand',args);self.assertIn('vpn.family-domain.org',args);self.assertEqual(args[args.index('--preferred-chain')+1],'ISRG Root X1')
 def test_expanding_names_does_not_replace_the_installation_identity(self):
  with patch.object(certs,'material',return_value=self.material()),patch.object(certs,'run'):first=certs.activate(self.base,'8.8.8.8')
  with patch.object(certs,'material',return_value=(b'expanded certificate',b'expanded key',['issuer\n'],time.time()+500000)),patch.object(certs,'run'):next=certs.activate(self.base,'8.8.8.8',['vpn.family-domain.org'])
  self.assertEqual(first['instance'],next['instance']);self.assertEqual(['vpn.family-domain.org'],certs.status()['aliases'])
 def test_enable_preserves_previously_verified_hostname_names(self):
  with patch.object(certs,'status',return_value={'aliases':['vpn.family-domain.org']}),patch.object(certs,'identity',return_value='8.8.8.8'),patch.object(certs,'obtain',return_value=self.base) as obtain,patch.object(certs,'timer'),patch.object(certs,'activate',return_value={}):certs.enable()
  obtain.assert_called_once_with('8.8.8.8',names=['vpn.family-domain.org'])
