"""Protocol boundaries and server-content inspection, independent of live providers."""
import base64,copy,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import model,inspect_server,runtime
spec=importlib.util.spec_from_file_location('single_port_api',ROOT/'single/run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
class SingleProtocolTests(unittest.TestCase):
 def test_coexist_inventory_hint_requires_matching_owned_pair(self):
  state={'protocol':'openvpn','owner':'rookstride-single-v1','coexist_pair':'a'*32}
  with tempfile.TemporaryDirectory() as d:
   manifest=Path(d)/'manifest.json';value={'version':2,'plan':{'pair':'a'*32,'role':'entry','entry_protocol':'awg','client_pool':'10.66.0.0/24'}}
   manifest.write_text(json.dumps(value));manifest.chmod(0o600)
   self.assertEqual('a'*32,runtime.coexist_pair(state,manifest))
   for field,wrong in [('pair','b'*32),('role','exit'),('entry_protocol','ikev2'),('client_pool','10.68.0.0/24')]:
    changed=json.loads(json.dumps(value));changed['plan'][field]=wrong;manifest.write_text(json.dumps(changed));self.assertEqual('',runtime.coexist_pair(state,manifest))
   manifest.write_text(json.dumps(value));manifest.chmod(0o666);self.assertEqual('',runtime.coexist_pair(state,manifest))
   manifest.unlink();self.assertEqual('',runtime.coexist_pair(state,manifest))
 def test_coexist_read_hint_does_not_claim_other_protocols(self):
  self.assertEqual('',runtime.coexist_pair({'protocol':'awg','owner':'rookstride-single-v1','coexist_pair':'a'*32}))
  self.assertEqual('',runtime.coexist_pair({'protocol':'openvpn','owner':'foreign','coexist_pair':'a'*32}))
 def test_classic_openvpn_certificate_add_preserves_running_listener(self):
  for running in (True,False):
   state=dict(protocol='openvpn',instance='fixture',users=[],server='vpn.example.test')
   with tempfile.TemporaryDirectory() as directory,patch.object(runtime,'directory',return_value=Path(directory)),patch.object(runtime,'save'),patch.object(runtime,'command') as command,patch.object(runtime,'check_container',return_value={'State':{'Running':running}}),patch.object(runtime,'apply_config') as apply:
    runtime.add_user(state,'newcert')
    self.assertEqual(1,len(state['users']));self.assertEqual('newcert',state['users'][0]['login'])
    self.assertEqual(['add','newcert'],command.call_args.args[0][-2:])
    if running:apply.assert_not_called()
    else:apply.assert_called_once_with(state)
 def test_edit_account_metadata_does_not_replace_keys_or_restart_a_protocol(self):
  for protocol in model.PROTOCOLS:
   state=dict(protocol=protocol,users=[dict(login='phone',private='private-key-fixture',uuid='uuid-fixture',psk='psk-fixture')])
   with patch.object(runtime,'save') as save,patch.object(runtime,'command') as command,patch.object(runtime,'apply_config') as apply:
    self.assertTrue(runtime.edit_user(state,dict(login='phone',person='Alex',device='Tablet'))['edited']);save.assert_called_once();command.assert_not_called();apply.assert_not_called()
   self.assertEqual(state['users'][0]['private'],'private-key-fixture');self.assertEqual(state['users'][0]['device'],'Tablet')
   for req in (dict(login='missing',person='Alex',device='Phone'),dict(login='phone',person='Alex',device='bad\nlabel')):
    with patch.object(runtime,'save') as save:
     with self.assertRaises(ValueError):runtime.edit_user(state,req)
     save.assert_not_called()
 def test_delegated_awg_empty_device_rejects_before_any_account_side_effect(self):
  state=dict(protocol='awg',users=[])
  with patch.object(runtime,'awg_key') as key,patch.object(runtime,'save') as save,patch.object(runtime,'apply_config') as apply:
   with self.assertRaisesRegex(ValueError,'1–80 printable'):
    runtime.add_user(state,'family-user',password='',person='family-user',device='')
   key.assert_not_called();save.assert_not_called();apply.assert_not_called();self.assertEqual([],state['users'])
 def test_partial_metadata_edits_keep_omitted_fields_and_account_generation(self):
  for protocol in model.PROTOCOLS:
   state=dict(protocol=protocol,users=[dict(login='phone',person='Before',device='Tablet',administration_account_id='owned-generation',private='retained-key')])
   with tempfile.TemporaryDirectory() as folder,patch.object(runtime,'directory',return_value=Path(folder)),patch.object(runtime,'apply_config') as apply:
    runtime.save(state);runtime.edit_user(state,dict(login='phone',person='After'))
    user=json.loads((Path(folder)/'state.json').read_text())['users'][0]
    self.assertEqual('After',user['person']);self.assertEqual('Tablet',user['device']);self.assertEqual('owned-generation',user['administration_account_id']);self.assertEqual('retained-key',user['private']);apply.assert_not_called()
 def test_empty_metadata_patch_does_not_write_or_restart(self):
  state=dict(protocol='awg',users=[dict(login='phone',administration_account_id='owned-generation')]);before=copy.deepcopy(state)
  with patch.object(runtime,'save') as save,patch.object(runtime,'apply_config') as apply:
   self.assertFalse(runtime.edit_user(state,dict(login='phone'))['edited']);save.assert_not_called();apply.assert_not_called();self.assertEqual(before,state)
 def test_combined_password_and_labels_persist_together_for_each_password_method(self):
  for protocol in ('openvpn','hysteria2','trusttunnel','naive'):
   state=dict(protocol=protocol,access_mode='password',users=[dict(login='phone',person='Before',device='Tablet',administration_account_id='owned-generation')])
   secret=' 1 chosen secret '
   with tempfile.TemporaryDirectory() as folder,patch.object(runtime,'directory',return_value=Path(folder)),patch.object(runtime,'apply_config',return_value={'listener_restarted':False}) as apply,patch.object(runtime,'disconnect_password_user',return_value={'listener_restarted':False}) as disconnect:
    runtime.edit_user(state,dict(login='phone',password=secret,person='After'))
    user=json.loads((Path(folder)/'state.json').read_text())['users'][0]
    self.assertEqual('After',user['person']);self.assertEqual('Tablet',user['device']);self.assertEqual('owned-generation',user['administration_account_id']);apply.assert_called_once_with(state)
    if protocol=='openvpn':self.assertTrue(runtime.access.verify(secret,user['password_hash']));self.assertNotIn('password',user);disconnect.assert_called_once_with(state,'phone')
    else:self.assertEqual(secret,user['password']);disconnect.assert_not_called()
 def test_invalid_combined_patch_never_changes_memory_or_saved_identity(self):
  for protocol in model.PROTOCOLS:
   state=dict(protocol=protocol,access_mode='password' if protocol in runtime.access.PASSWORD_PROTOCOLS else 'profile',users=[dict(login='phone',person='Before',device='Tablet',administration_account_id='owned-generation')])
   for fields in ({'person':'After','device':''},{'person':'After','password':''},{'person':'bad\nlabel','password':'new secret'},{'person':None},{'device':False}):
    before=copy.deepcopy(state)
    with patch.object(runtime,'save') as save,patch.object(runtime,'apply_config') as apply:
     with self.assertRaises(ValueError):runtime.edit_user(state,dict(login='phone',**fields))
     self.assertEqual(before,state);save.assert_not_called();apply.assert_not_called()
 def test_delegated_awg_omitted_optional_device_creates_only_the_requested_account(self):
  state=dict(protocol='awg',users=[])
  with patch.object(runtime,'awg_key',side_effect=['private-fixture','psk-fixture','public-fixture']),patch.object(runtime,'save') as save,patch.object(runtime,'apply_config') as apply:
   runtime.add_user(state,'family-user',apply=False,person='family-user')
   save.assert_called_once_with(state);apply.assert_not_called()
  self.assertEqual(1,len(state['users']));self.assertEqual('family-user',state['users'][0]['login']);self.assertEqual('family-user',state['users'][0]['person']);self.assertNotIn('device',state['users'][0])
 def test_automatic_ports_prefer_defaults_and_respect_transport_and_ssh(self):
  for protocol,settings in model.PROTOCOLS.items():
   default=settings['port'];self.assertEqual(model.free_port(protocol,[],22),default)
   other='tcp' if settings['transport']=='udp' else 'udp'
   self.assertEqual(model.free_port(protocol,[dict(port=default,transport=other)],22),default)
   busy=[dict(port=default,transport=settings['transport'])]
   selected=model.free_port(protocol,busy,22);self.assertNotEqual(selected,default)
   self.assertNotEqual(model.free_port(protocol,busy,selected),selected)
 def test_automatic_port_fallback_and_exhaustion_are_bounded(self):
  busy=[dict(port=p,transport='tcp') for p in (443,8443,9443,20000)]
  self.assertEqual(model.free_port('xray',busy,20001),20002)
  with self.assertRaises(ValueError):model.free_port('xray',[dict(port=p,transport='tcp') for p in range(1,65536)],22)
 def test_plan_uses_auto_only_when_port_is_omitted(self):
  inventory=dict(compatible_os=True,os='Ubuntu 24.04',ports=[dict(port=443,transport='tcp')])
  with tempfile.TemporaryDirectory() as d,patch.object(api,'inspect',return_value=inventory),patch.object(runtime,'directory',return_value=Path(d)):
   request=dict(protocol='xray',server='vpn.example.net');self.assertEqual(api.plan(request)['port'],8443);self.assertNotIn('port',request)
   with self.assertRaises(ValueError):api.plan(dict(request,port=443))
   self.assertEqual(api.plan(dict(request,port=9443))['port'],9443)
   self.assertEqual(api.plan(dict(request,sshPort=8443))['port'],9443)
   for port in (None,True,'443',0,65536):
    with self.assertRaises(ValueError):api.plan(dict(request,port=port))
   for port in (None,True,'22',0,65536):
    with self.assertRaises(ValueError):api.plan(dict(request,sshPort=port))
 def test_detached_job_and_review_persist_the_same_automatic_port(self):
  from types import SimpleNamespace
  inventory=dict(compatible_os=True,os='Ubuntu 24.04',ports=[dict(port=443,transport='tcp')])
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   with patch.object(api,'inspect',return_value=inventory),patch.object(runtime,'ROOT',root/'opt'),patch.object(runtime,'STATE',root/'state'),patch.object(runtime,'directory',return_value=root/'vpn'),patch.object(api.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
    started=api.start(dict(protocol='xray',server='vpn.example.net'))
    request=json.loads((root/'state/jobs'/started['job']/'request.json').read_text());self.assertEqual(request['port'],8443);self.assertEqual(request['port'],started['plan']['port'])
 def test_request_values_cannot_become_shell_or_configuration_lines(self):
  for host in ('x;reboot','x\nListenPort=22','-option','a..example','http://example.com'):
   with self.assertRaises(ValueError):model.validate({'protocol':'xray','server':host})
  for login in ('a b','../root','a\nfoo','$(id)'):
   with self.assertRaises(ValueError):model.label(login)
  for port in (True,0,65536,22,'443'):
   with self.assertRaises(ValueError):model.validate({'protocol':'awg','server':'vpn.example.net','port':port})
 def test_awg31_export_preserves_header_protection_on_both_ends(self):
  parameters=model.awg_parameters();self.assertEqual(len(base64.b64decode(parameters['HeaderProtectionKey'])),32)
  state=dict(private='server-private',public='server-public',parameters=parameters,users=[],server='vpn.example.net',port=51820)
  user=dict(private='client-private',public='client-public',psk='test-psk',address='10.67.0.2',ipv6='fd42:670::2')
  state['users']=[user];server=model.awg_server(state);client=model.awg_client(state,user)
  self.assertNotIn('client-private',server);self.assertNotIn('server-private',client)
  for key,value in parameters.items():self.assertIn(key+' = '+value,server);self.assertIn(key+' = '+value,client)
  self.assertIn('MTU = 1280',client);self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0',client)
 def test_awg_export_name_fits_native_android_limit_and_separates_servers(self):
  user=dict(login='this-phone-with-a-long-device-name',private='client-private',public='client-public',psk='psk',address='10.67.0.2',ipv6='fd42:670::2')
  state=dict(protocol='awg',private='server-private',public='server-public',parameters=model.awg_parameters(),users=[user],server='vpn.example.net',port=51820)
  name=runtime.profile(state,user['login'])['name'];self.assertLessEqual(len(Path(name).stem),15);self.assertRegex(name,r'^rook-[a-f0-9]{10}\.conf$')
  state['public']='another-server-public';self.assertNotEqual(runtime.profile(state,user['login'])['name'],name)
 def test_xray_profile_does_not_distribute_server_private_key(self):
  state=dict(server='vpn.example.net',port=443,sni='www.cloudflare.com',private='server-private',public='public',shortId='0123456789abcdef',users=[dict(uuid='test-uuid',login='phone')])
  uri=model.xray_uri(state,state['users'][0]);self.assertNotIn('server-private',uri);self.assertIn('security=reality',uri)
  config=model.xray_server(state);self.assertEqual(config['inbounds'][0]['streamSettings']['realitySettings']['serverNames'],['www.cloudflare.com'])
  state['users'][0]['enabled']=False;self.assertEqual(model.xray_server(state)['inbounds'][0]['settings']['clients'],[])
 def test_xray_pinned_cli_public_key_label_and_key_lengths(self):
  private=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=');public=base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip('=')
  self.assertEqual(runtime.xray_keys('PrivateKey: '+private+'\nPassword (PublicKey): '+public+'\nHash32: ignored'),(private,public))
  for output in ('PrivateKey: invalid\nPassword (PublicKey): '+public,'PrivateKey: '+private+'\nHash32: '+public):
   with self.assertRaises(ValueError):runtime.xray_keys(output)
 def test_openvpn_export_requires_server_certificate_identity_and_ipv6_block(self):
  text=model.openvpn_client({'server':'vpn.example.net','port':1194},{},'ca','cert','key','tls')
  for expected in ('remote-cert-tls server','verify-x509-name server name','block-ipv6','<tls-crypt>','<key>'):
   self.assertIn(expected,text)
  self.assertNotIn('auth-user-pass',text)
 def root(self,path,ports=''):
  (path/'etc').mkdir();(path/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04"\n')
  (path/'run/systemd/system').mkdir(parents=True)
  for command in ('python3','apt-get','dpkg','systemctl'):
   p=path/'usr/bin'/command;p.parent.mkdir(parents=True,exist_ok=True);p.touch()
  (path/'proc/net').mkdir(parents=True)
  for name in ('tcp','udp'):(path/'proc/net'/name).write_text('header\n'+(ports if name=='udp' else ''))
 def test_nonempty_server_and_system_resolver_are_not_blanket_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.root(root,'0: 3500007F:0035 00000000:0000 07\n');(root/'var/www').mkdir(parents=True);(root/'var/www/index.html').write_text('existing website')
   value=inspect_server.inspect(root);self.assertTrue(value['ikev2_ready']);self.assertFalse(value['os_reinstall']);self.assertTrue((root/'var/www/index.html').exists())
 def test_existing_vpn_and_public_dns_conflicts_require_review(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.root(root,'0: 00000000:01F4 00000000:0000 07\n');self.assertFalse(inspect_server.inspect(root)['ikev2_ready'])
   (root/'proc/net/udp').write_text('header\n0: 00000000:0035 00000000:0000 07\n');self.assertFalse(inspect_server.inspect(root)['ikev2_ready'])
   (root/'proc/net/udp').write_text('header\n');(root/'etc/ipsec.conf').write_text('other VPN');self.assertFalse(inspect_server.inspect(root)['ikev2_ready'])
 def test_all_loopback_resolvers_including_ubuntu_proxy_and_ipv6_allow_reinstall(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.root(root,'0: 3600007F:0035 00000000:0000 07\n1: 0201007F:0035 00000000:0000 07\n')
   (root/'proc/net/udp6').write_text('header\n0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07\n')
   value=inspect_server.inspect(root);self.assertTrue(value['ikev2_ready']);self.assertEqual([],value['ikev2_conflicts'])
   self.assertEqual({'127.0.0.54','127.0.1.2','::1'},{v['address'] for v in value['ports']})
   self.assertTrue(all(v['loopback'] for v in value['ports']))
 def test_conflicts_identify_the_actual_blocker_without_deleting_unowned_files(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);self.root(root,'0: 00000000:0035 00000000:0000 07\n');config=root/'etc/ipsec.conf';config.write_text('unrelated VPN')
   value=inspect_server.inspect(root);self.assertFalse(value['ikev2_ready'])
   self.assertIn('DNS port 53 is in use on 0.0.0.0',value['ikev2_conflicts']);self.assertIn('Existing configuration: /etc/ipsec.conf',value['ikev2_conflicts'])
   self.assertEqual('unrelated VPN',config.read_text())
 def test_missing_port_inventory_cannot_be_treated_as_free(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):inspect_server.listeners(Path(d))
 def test_reality_target_is_automatic_only_when_not_explicit_and_requires_a_live_tls_check(self):
  state=model.validate({'protocol':'xray','server':'vpn.example.net'})
  self.assertTrue(state['sni_auto'])
  with patch('runtime.reality_target_ready',side_effect=lambda host:host=='www.cloudflare.com') as check:
   self.assertEqual('www.cloudflare.com',runtime.choose_reality_target(state));self.assertEqual(1,check.call_count)
  explicit=model.validate({'protocol':'xray','server':'vpn.example.net','sni':'custom.example.net'})
  self.assertFalse(explicit['sni_auto'])
  with patch('runtime.reality_target_ready',return_value=False) as check:
   with self.assertRaisesRegex(ValueError,'compatible REALITY'):runtime.choose_reality_target(explicit)
   check.assert_called_once_with('custom.example.net')
 def test_real_vless_check_falls_back_when_tls_preflight_was_insufficient(self):
  state=dict(sni='www.microsoft.com',sni_auto=True)
  with patch.object(runtime,'reality_client_ready',side_effect=[False,True]) as client,patch.object(runtime,'reality_target_ready',return_value=True) as tls,patch.object(runtime,'apply_config') as apply,patch.object(runtime,'save') as save:
   runtime.verify_reality_route(state,lambda *args:None)
   self.assertEqual('www.cloudflare.com',state['sni']);self.assertEqual(2,client.call_count);tls.assert_called_once_with('www.cloudflare.com');save.assert_called_once_with(state);apply.assert_called_once_with(state)
 def test_explicit_target_cannot_succeed_on_tls_alone_or_silently_change(self):
  state=dict(sni='www.example.net',sni_auto=False)
  with patch.object(runtime,'reality_client_ready',return_value=False),patch.object(runtime,'reality_target_ready') as tls,patch.object(runtime,'apply_config') as apply:
   with self.assertRaisesRegex(ValueError,'encrypted VPN connection check failed'):runtime.verify_reality_route(state,lambda *args:None)
   self.assertEqual('www.example.net',state['sni']);tls.assert_not_called();apply.assert_not_called()
 def test_successful_existing_target_never_rotates_credentials_or_configuration(self):
  state=dict(sni='www.cloudflare.com',sni_auto=True,public='public-fixture',users=[dict(uuid='device-fixture')])
  before=json.dumps(state,sort_keys=True)
  with patch.object(runtime,'reality_client_ready',return_value=True),patch.object(runtime,'apply_config') as apply:
   runtime.verify_reality_route(state,lambda *args:None);apply.assert_not_called();self.assertEqual(before,json.dumps(state,sort_keys=True))
 def test_xhttp_rejects_intermittent_outer_handshake_before_completion(self):
  with patch.object(runtime,'reality_session_ready',side_effect=[True,False,True]) as check:
   self.assertFalse(runtime.reality_client_ready({'protocol':'xhttp'}));self.assertEqual(2,check.call_count)
  with patch.object(runtime,'reality_session_ready',return_value=True) as check:
   self.assertTrue(runtime.reality_client_ready({'protocol':'xhttp'}));self.assertEqual(3,check.call_count)
  self.assertEqual('www.apple.com',runtime.reality_targets({'protocol':'xhttp'})[0])
  self.assertEqual(runtime.REALITY_TARGETS,runtime.reality_targets({'protocol':'xray'}))
 def test_rejected_socks_connection_has_no_direct_https_fallback(self):
  with patch.object(runtime.socket,'create_connection') as connect,patch.object(runtime.ssl,'create_default_context') as tls:
   connect.return_value.__enter__.return_value.recv.side_effect=[b'\x05\x00',b'\x05\x01\x00\x01']
   self.assertFalse(runtime.socks_https_ready(18081,'example.com'));connect.assert_called_once_with(('127.0.0.1',18081),timeout=8);tls.assert_not_called()
 def test_missing_container_and_unavailable_docker_have_different_reset_outcomes(self):
  from types import SimpleNamespace
  state={'protocol':'awg','instance':'owned-instance'}
  with patch('runtime.subprocess.run',return_value=SimpleNamespace(returncode=1,stderr='Error: no such container: rookstride-single-awg',stdout='')):
   self.assertIsNone(runtime.check_container(state))
  with patch('runtime.subprocess.run',return_value=SimpleNamespace(returncode=1,stderr='Cannot connect to Docker: no such file or directory',stdout='')):
   with self.assertRaises(ValueError):runtime.check_container(state)
  value=[{'Config':{'Labels':{'io.rookstride.instance':'someone-else'}}}]
  with patch('runtime.subprocess.run',return_value=SimpleNamespace(returncode=0,stderr='',stdout=json.dumps(value))):
   with self.assertRaises(ValueError):runtime.check_container(state)
 def test_partial_state_can_be_removed_before_docker_was_installed(self):
  with patch('runtime.subprocess.run',side_effect=FileNotFoundError()),patch.object(Path,'exists',return_value=False):
   self.assertIsNone(runtime.check_container({'protocol':'awg','instance':'owned'}))
 def test_missing_docker_never_ignores_an_existing_container_store(self):
  with patch('runtime.subprocess.run',side_effect=FileNotFoundError()),patch.object(Path,'exists',return_value=True):
   with self.assertRaisesRegex(ValueError,'container data remains'):runtime.check_container({'protocol':'openvpn','instance':'owned'})
 def test_running_awg_container_is_not_enough_without_configured_port_and_peers(self):
  state={'protocol':'awg','users':[{'login':'phone','public':'public-key','address':'10.67.0.2'}]}
  for port,peers,expected in [('40288','',False),('51820','',False),('51820','public-key',True)]:
   with patch('runtime.check_container',return_value={'State':{'Running':True}}),patch('runtime.command',side_effect=[port,peers,'']):
    self.assertEqual(runtime.health(state)['running'],expected)
 def test_health_does_not_include_private_connection_material(self):
  state={'protocol':'xray','private':'do-not-return','users':[{'login':'phone','private':'peer-private','uuid':'peer-secret'}]}
  with patch('runtime.subprocess.run') as run:
   run.return_value.returncode=0;value=runtime.health(state)
  self.assertNotIn('do-not-return',json.dumps(value));self.assertNotIn('peer-secret',json.dumps(value));self.assertFalse(value['monitoring_available'])
if __name__=='__main__':unittest.main()
