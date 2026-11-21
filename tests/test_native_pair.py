import struct,base64,importlib.util,json,sys,tempfile,unittest,io
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import pair,native_pair,native_pair_reset
import native_routing
from types import SimpleNamespace
KEY=base64.b64encode(bytes(range(32))).decode()
BASE=dict(pair='a'*32,role='entry',server='entry.example.net',exit_host='exit.example.net',entry_protocol='awg',exit_protocol='awg',vpn_port=51820)
def material():
 return {'protocol':'awg','endpoint':'exit.example.net','dns':{'address':'10.253.0.1','dns_port':5354},'profile':{'content':'[Interface]\nPrivateKey = '+KEY+'\nAddress = 10.67.0.2/32\nMTU = 1280\nDNS = 1.1.1.1\n[Peer]\nPublicKey = '+KEY+'\nPresharedKey = '+KEY+'\nEndpoint = exit.example.net:443\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'}}
class NativePairSafety(unittest.TestCase):
 def test_a_resumed_success_does_not_keep_an_old_failure_in_its_status(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);pair.job_state(root,state='failed',error='TimeoutError',detail='old fixture failure');pair.job_state(root,state='running',phase='resuming');self.assertNotIn('error',json.loads((root/'status.json').read_text()));pair.job_state(root,state='complete',phase='done');result=json.loads((root/'status.json').read_text());self.assertEqual('complete',result['state']);self.assertNotIn('detail',result)
 def test_exit_generates_independent_bridge_credentials_and_reserves_the_shared_ike_name(self):
  p=pair.plan(dict(BASE,role='exit',exit_protocol='ikev2'));user=pair.initial_user(p,{})
  self.assertEqual('bridge-'+p['pair'][:12],user['login']);self.assertEqual(15,len(user['password']));pair.vpn_password(user['password']);self.assertFalse(user['statistics'])
  entry=pair.plan(dict(BASE,entry_protocol='ikev2',exit_protocol='ikev2'))
  with self.assertRaisesRegex(ValueError,'reserved'):pair.initial_user(entry,{'login':user['login'],'password':'phone-pass123'})
 def test_phone_user_edit_cannot_shadow_the_shared_daemons_bridge_secret(self):
  from rookstride import admin
  with tempfile.TemporaryDirectory() as directory,patch.object(admin,'PAIR_ROOT',Path(directory)):
   root=Path(directory);(root/'manifest.json').write_text(json.dumps({'version':2,'plan':{'role':'entry','entry_protocol':'ikev2','exit_protocol':'ikev2'}}));(root/'transport.json').write_text(json.dumps({'profile':{'login':'bridge-reserved'}}))
   for remove in (False,True):
    with self.assertRaisesRegex(ValueError,'reserved'):admin.update_user({'login':'bridge-reserved','password':'phone-pass123'},remove=remove)
 def test_reloaded_ike_connection_is_explicitly_initiated(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);sock=root/'vici';sock.touch();m={'version':2,'plan':pair.plan(dict(BASE,exit_protocol='ikev2'))}
   with patch.object(pair,'load_manifest',return_value=m),patch.multiple(native_pair,IKE_SOCKET=sock,IKE_CREDENTIALS=root),patch.object(native_routing,'run',return_value=SimpleNamespace(returncode=0)) as run:
    native_routing.apply('ike-load');self.assertEqual(2,run.call_count);self.assertIn('--load-all',run.call_args_list[0].args[0]);self.assertIn('--initiate',run.call_args_list[1].args[0]);self.assertIn('route-exit',run.call_args_list[1].args[0])
 def test_dns_checks_accept_both_real_filter_response_formats_and_reject_bad_packets(self):
  question=b'\7example\3com\0\0\1\0\1'
  def reply(code,address=None,tx=42):
   return struct.pack('!HHHHHH',tx,0x8180|code,1,int(address is not None),0,0)+question+(b'\xc0\x0c'+struct.pack('!HHIH',1,1,10,4)+bytes(address) if address is not None else b'')
  self.assertEqual((3,[]),native_pair.dns_answer(reply(3),42))
  self.assertEqual((0,['0.0.0.0']),native_pair.dns_answer(reply(0,[0,0,0,0]),42))
  self.assertEqual((0,['192.0.2.1']),native_pair.dns_answer(reply(0,[192,0,2,1]),42))
  for bad in [reply(0,[1,2,3,4],43),reply(0,[1,2,3,4])[:-1],b'bad']:
   with self.assertRaises(ValueError):native_pair.dns_answer(bad,42)
 def test_ike_exit_health_uses_the_enrolled_administrator_interface(self):
  p=pair.plan(dict(BASE,role='exit',exit_protocol='ikev2'))
  with patch('rookstride.admin.health',return_value={'services':{'strongswan-starter':True}}) as health:
   result=native_pair.dispatch({'command':'health'},{'plan':p,'version':2})
   self.assertTrue(result['services']['strongswan-starter']);health.assert_called_once_with()
 def test_boot_guard_does_not_activate_docker_before_its_own_dependency_finishes(self):
  with patch.object(native_routing.shutil,'which',return_value='/usr/bin/docker'),patch.object(native_routing,'run',return_value=SimpleNamespace(returncode=3)) as run:
   native_routing.container_route(pair.plan(BASE));self.assertEqual(['systemctl','is-active','--quiet','docker'],run.call_args.args[0]);self.assertEqual(1,run.call_count)
 def test_changed_service_cannot_be_adopted_by_a_familiar_description(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(native_pair,'UNIT',Path(folder)),patch.object(pair,'protected',side_effect=lambda x:x),patch.object(pair,'load_manifest',return_value={'unit_hashes':{}}),patch.object(pair,'write_manifest') as write:
   unit=Path(folder)/'rookstride-pair-bridge.service';unit.write_text('[Unit]\nDescription=Rookstride owned AWG exit connection\n[Service]\nExecStop=/bin/false\n')
   with self.assertRaises(ValueError):native_pair.unit('rookstride-pair-bridge','[Unit]\nDescription=Rookstride reviewed service\n')
   self.assertIn('ExecStop=/bin/false',unit.read_text());write.assert_not_called()
 def test_partial_entry_without_a_created_vpn_can_still_be_reviewed_for_cleanup(self):
  p=pair.plan(BASE);m={'plan':p,'version':2,'jobs':{},'unit_hashes':{}}
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)
   with patch.multiple(pair,OWN=root/'own',STATE=root/'state',RELEASE=root/'release'),patch.object(pair,'require_owner',return_value=m),patch.object(pair,'protected',side_effect=lambda x:x),patch.object(native_pair,'UNIT',root/'units'),patch.object(native_pair.runtime,'directory',return_value=root/'missing-vpn'):
    result=native_pair_reset.inspect(BASE);self.assertFalse(result['child_exists']);self.assertEqual(['awg'],result['protocols'])
 def test_kernel_rule_network_prefix_forms_are_idempotent_but_other_rules_are_not_adopted(self):
  for rule in [{'priority':100,'src':'10.66.0.0','srclen':24,'table':'51831'},{'priority':100,'src':'10.66.0.0/24','table':51831}]:
   with patch.object(native_routing,'run',return_value=SimpleNamespace(stdout=json.dumps([rule]))) as run:
    native_routing.rule(100,'10.66.0.0/24',51831);self.assertEqual(1,run.call_count)
  for extra in [{'srclen':16},{'table':254},{'fwmark':42}]:
   row=dict(priority=100,src='10.66.0.0',srclen=24,table=51831);row.update(extra)
   with patch.object(native_routing,'run',return_value=SimpleNamespace(stdout=json.dumps([row]))):
    with self.assertRaises(ValueError):native_routing.rule(100,'10.66.0.0/24',51831)
 def test_supported_routes_are_explicit_and_keep_separate_address_pools(self):
  self.assertEqual('10.66.0.0/24',pair.plan(BASE)['client_pool'])
  self.assertEqual('10.250.0.0/16',pair.plan(dict(pair='a'*32,role='entry',server='a.example.net',exit_host='b.example.net'))['client_pool'])
  for entry in ('awg','ikev2'):
   for exit in ('awg','ikev2','openvpn','xray'):
    plan=pair.plan(dict(BASE,entry_protocol=entry,exit_protocol=exit));self.assertEqual(entry,plan['entry_protocol']);self.assertEqual((entry,exit)!=('ikev2','awg'),pair.native_plan(plan))
    self.assertEqual('10.66.0.0/24' if pair.native_plan(plan) else '10.250.0.0/16',plan['client_pool'])
  for entry,exit in [('socks','awg'),('openvpn','socks'),('awg','socks'),('$(id)','awg')]:
   with self.assertRaises(ValueError):pair.plan(dict(BASE,entry_protocol=entry,exit_protocol=exit))
 def test_openvpn_bridge_never_accepts_scripts_external_paths_or_pushed_default_routes(self):
  p=pair.plan(dict(BASE,exit_protocol='openvpn'));blob='-----BEGIN CERTIFICATE-----\n'+('a'*600)+'\n-----END CERTIFICATE-----'
  profile={'content':native_pair.model.openvpn_client({'server':p['exit_host'],'port':p['tunnel_port']},{},blob,blob,blob,blob)}
  rendered=native_pair.openvpn_profile(p,profile)
  self.assertIn('route-nopull\nroute-noexec\n',rendered);self.assertIn('dev awg-exit\n',rendered);self.assertNotRegex(rendered,r'(?m)^redirect-gateway\b');self.assertIn('dev-type tun\n',rendered)
  for injected in ['up /tmp/untrusted\n','config /tmp/other\n','<ca>\nextra\n</ca>\n','remote other.example.net 1194\n']:
   with self.assertRaises(ValueError):native_pair.openvpn_profile(p,{'content':profile['content']+injected})
 def test_xray_bridge_pins_exit_and_reality_keys_and_rejects_ambiguous_options(self):
  p=pair.plan(dict(BASE,exit_protocol='xray'));state={'server':p['exit_host'],'port':p['tunnel_port'],'sni':'www.example.net','public':'A'*43,'shortId':'0123456789abcdef'};user={'uuid':'12345678-1234-1234-1234-123456789abc','login':'bridge'}
  profile={'content':native_pair.model.xray_uri(state,user)};out=native_pair.xray_outbound(p,profile);self.assertEqual(p['exit_host'],out['settings']['vnext'][0]['address']);self.assertEqual('exit',out['tag'])
  for content in [profile['content'].replace('exit.example.net','other.example.net'),profile['content'].replace('security=reality','security=none'),profile['content'].replace('&sni=','&sni=other.example.net&sni='),profile['content'].replace('vless://','http://')]:
   with self.assertRaises(ValueError):native_pair.xray_outbound(p,{'content':content})
 def test_shared_ike_bridge_is_not_reported_or_billed_as_a_phone_user(self):
  from rookstride.vici import connections
  sa={'uniqueid':'9','remote-id':'exit.example.net','state':'ESTABLISHED','child-sas':{'route-exit':{'state':'INSTALLED','bytes-in':'1000','bytes-out':'2000'}}}
  self.assertEqual([],connections([{'route-exit':sa}]))
  phone=dict(sa,**{'remote-eap-id':'this-phone','remote-vips':['10.66.0.2']})
  result=connections([{'route-exit':sa,'ikev2-vpn':phone}]);self.assertEqual(1,len(result));self.assertEqual('this-phone',result[0]['user']);self.assertEqual(1000,result[0]['upload'])
 def test_resumed_ike_exit_checks_ownership_and_dns_then_still_enrolls_management(self):
  p=pair.plan(dict(BASE,role='exit',exit_protocol='ikev2'))
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);marker=root/'network.env';marker.write_text('owned');(root/'ike-files.sha256').write_text('fixture')
   with patch.object(pair,'OWN',root),patch.object(native_pair,'IKE_NETWORK',marker),patch.object(native_pair,'initial',return_value={'login':'bridge','password':'password123'}),patch.object(native_pair,'command') as command,patch.object(pair,'run') as run,patch.object(pair,'job_state'):
    self.assertTrue(native_pair.bootstrap(p,root,io.StringIO()));command.assert_called_once_with(['sha256sum','--check','--status',str(root/'ike-files.sha256')]);self.assertEqual(['verify.sh','enroll.sh'],[Path(c.args[0][1]).name for c in run.call_args_list])
    (root/'ike-files.sha256').unlink();run.reset_mock()
    with self.assertRaisesRegex(ValueError,'ownership record'):native_pair.bootstrap(p,root,io.StringIO())
    run.assert_not_called()
 def test_partial_ike_reset_review_remains_valid_after_its_child_creates_management_state(self):
  p=pair.plan(dict(BASE,role='exit',exit_protocol='ikev2'));m={'plan':p,'version':2,'jobs':{},'unit_hashes':{}}
  reset=native_pair_reset.ike_reset
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);marker=root/'network.env';marker.write_text('owned');config=root/'ipsec.conf';config.write_text('conn ikev2-vpn\n');secret=root/'ipsec.secrets';secret.write_text('fixture');state=root/'management'
   with patch.multiple(pair,OWN=root/'own',STATE=root/'jobs',RELEASE=root/'release'),patch.object(pair,'require_owner',return_value=m),patch.object(pair,'protected',side_effect=lambda x:Path(x)),patch.multiple(native_pair,UNIT=root/'units',IKE_SHARED=root/'shared',IKE_DROP=root/'drop'),patch.multiple(reset,MARKER=marker,CONFIG=config,SECRETS=secret,STATE=state,PATHS=(marker,config,secret,state)),patch.object(native_pair_reset,'REVIEWS',root/'reviews'):
    result=native_pair_reset.plan(dict(BASE,role='exit',exit_protocol='ikev2'));self.assertTrue(state.is_dir());record=json.loads(native_pair_reset.path(p).read_text());self.assertEqual(native_pair_reset.inspect(p),record['review']);self.assertIn(str(state),reset.inspect()['files'])
 def test_bridge_profile_is_bound_to_exit_protocol_endpoint_and_private_dns(self):
  p=pair.plan(BASE);native_pair.validate_material(p,material())
  for changes in [{'protocol':'ikev2'},{'endpoint':'other.example.net'},{'dns':{'address':'1.1.1.1','dns_port':53}},{'dns':{'address':'10.253.0.1','dns_port':True}}]:
   with self.assertRaises(ValueError):native_pair.validate_material(p,dict(material(),**changes))
 def test_extra_peer_duplicate_endpoint_and_executable_profile_directives_are_rejected(self):
  for extra in ['PostUp = touch /tmp/unowned\n','Table = auto\n','[Peer]\nPublicKey = '+KEY+'\n','Endpoint = other.example.net:443\n']:
   value=material();value['profile']['content']+=extra
   with self.assertRaises(ValueError):native_pair.validate_material(pair.plan(BASE),value)
  value=material();value['profile']['content']=value['profile']['content'].replace('0.0.0.0/0, ::/0','10.0.0.0/8')
  with self.assertRaises(ValueError):native_pair.validate_material(pair.plan(BASE),value)
 def test_ike_exit_requires_an_exact_identity_and_valid_pinned_certificate(self):
  p=pair.plan(dict(BASE,exit_protocol='ikev2'));value={'protocol':'ikev2','endpoint':'exit.example.net','dns':{'address':'10.254.0.1','dns_port':53},'profile':{'server':'exit.example.net','identity':'exit.example.net','certificate':base64.b64encode(b'x'*1024).decode(),'login':'route-bridge','password':'password8'}}
  native_pair.validate_material(p,value)
  for key,item in [('identity','other.example.net'),('login','user\nsecret=bad'),('password',''),('certificate','not a certificate')]:
   changed=json.loads(json.dumps(value));changed['profile'][key]=item
   with self.assertRaises(ValueError):native_pair.validate_material(p,changed)
 def test_exit_does_not_accept_another_profile(self):
  p=pair.plan(dict(BASE,role='exit'));native_pair.validate_material(p,None)
  with self.assertRaises(ValueError):native_pair.validate_material(p,material())
 def test_activation_requires_both_egress_and_ad_dns_success(self):
  p=pair.plan(BASE);m={'plan':p,'version':2,'verified':False};value=material()
  with tempfile.TemporaryDirectory() as folder,patch.object(pair,'OWN',Path(folder)),patch.object(pair,'require_owner',return_value=m),patch.object(pair,'write_manifest') as write,patch.object(native_pair,'network') as network,patch.object(native_pair,'command',return_value='192.0.2.44') as probe,patch.object(native_pair,'dns_check',side_effect=ValueError('DNS unavailable')):
   (Path(folder)/'transport.json').write_text(json.dumps(value))
   with self.assertRaises(ValueError):native_pair.verify(p,{'expected_exit_ip':'192.0.2.44'},activate=True)
   self.assertIn('--interface',probe.call_args.args[0]);self.assertIn(p['test_ip'],probe.call_args.args[0]);self.assertIn('X25519',probe.call_args.args[0]);self.assertFalse(m['verified']);write.assert_not_called();self.assertNotIn('activate',[c.args[0] for c in network.call_args_list])
 def test_wrong_exit_never_opens_forwarding_or_checks_dns(self):
  p=pair.plan(BASE)
  with tempfile.TemporaryDirectory() as folder,patch.object(pair,'OWN',Path(folder)),patch.object(native_pair,'network') as network,patch.object(native_pair,'command',return_value='192.0.2.99'),patch.object(native_pair,'dns_check') as dns:
   (Path(folder)/'transport.json').write_text(json.dumps(material()))
   with self.assertRaises(ValueError):native_pair.verify(p,{'expected_exit_ip':'192.0.2.44'},activate=True)
   dns.assert_not_called();self.assertEqual(['refresh'],[c.args[0] for c in network.call_args_list])

class AdGuardStartupReadiness(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  spec=importlib.util.spec_from_file_location('gateway_adguard_ready',Path(__file__).resolve().parents[1]/'gateway/scripts/prepare-adguard.py');cls.ready=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.ready)
 def test_loaded_filter_does_not_change_preferences_or_trigger_download(self):
  calls=[]
  def call(endpoint,data=None):calls.append((endpoint,data));return {'enabled':True,'filters':[{'enabled':True,'rules_count':100}]}
  self.ready.ensure(call);self.assertEqual([('filtering/status',None)],calls)
 def test_failed_initial_download_can_recover_without_resetting_dns_or_credentials(self):
  refreshes=[]
  def call(endpoint,data=None):
   if endpoint=='filtering/status':return {'enabled':True,'filters':[{'enabled':True,'rules_count':100 if len(refreshes)>1 else 0}]}
   refreshes.append(data)
   if len(refreshes)==1:raise OSError('fixture network unavailable')
   return {}
  self.ready.ensure(call,clock=lambda:0,sleep=lambda _:None);self.assertEqual([{'whitelist':False,'force':True}]*2,refreshes)
 def test_missing_or_disabled_filter_is_never_silently_enabled(self):
  for status in ({'enabled':False,'filters':[{'enabled':True,'rules_count':0}]},{'enabled':True,'filters':[]}):
   calls=[]
   def call(endpoint,data=None):calls.append(endpoint);return status
   with self.assertRaisesRegex(ValueError,'enabled filter'):self.ready.ensure(call)
   self.assertEqual(['filtering/status'],calls)
 def test_async_download_can_finish_after_the_third_refresh_without_a_fourth_request(self):
  status_reads=0;refreshes=[]
  def call(endpoint,data=None):
   nonlocal status_reads
   if endpoint=='filtering/refresh':refreshes.append(data);return {}
   status_reads+=1;return {'enabled':True,'filters':[{'enabled':True,'rules_count':100 if status_reads>=26 else 0}]}
  self.ready.ensure(call,clock=lambda:0,sleep=lambda _:None);self.assertEqual(3,len(refreshes));self.assertEqual(26,status_reads)
 def test_failed_downloads_have_a_fixed_retry_bound(self):
  calls=[]
  def call(endpoint,data=None):
   calls.append(endpoint)
   if endpoint=='filtering/refresh':raise OSError('offline fixture')
   return {'enabled':True,'filters':[{'enabled':True,'rules_count':0}]}
  with self.assertRaisesRegex(ValueError,'did not finish downloading'):self.ready.ensure(call,clock=lambda:0,sleep=lambda _:None)
  self.assertEqual(3,calls.count('filtering/refresh'))
 def test_first_filter_can_arrive_after_two_minutes_without_restarting_setup(self):
  elapsed=[0];refreshes=[]
  def call(endpoint,data=None):
   if endpoint=='filtering/refresh':refreshes.append(data);return {}
   return {'enabled':True,'filters':[{'enabled':True,'rules_count':188167 if elapsed[0]>=138 else 0}]}
  def sleep(seconds):elapsed[0]+=seconds
  self.ready.ensure(call,clock=lambda:elapsed[0],sleep=sleep)
  self.assertEqual(138,elapsed[0]);self.assertEqual(3,len(refreshes))
 def test_offline_download_stops_at_the_real_deadline_without_disabling_filtering(self):
  elapsed=[0];calls=[]
  def call(endpoint,data=None):
   calls.append(endpoint)
   if endpoint=='filtering/refresh':raise OSError('offline fixture')
   return {'enabled':True,'filters':[{'enabled':True,'rules_count':0}]}
  def sleep(seconds):elapsed[0]+=seconds
  with self.assertRaisesRegex(ValueError,'existing VPN setup has been retained'):
   self.ready.ensure(call,clock=lambda:elapsed[0],sleep=sleep)
  self.assertEqual(240,elapsed[0]);self.assertEqual(3,calls.count('filtering/refresh'))
  self.assertEqual({'filtering/status','filtering/refresh'},set(calls))

if __name__=='__main__':unittest.main()

class NewEntrySafety(unittest.TestCase):
 def test_all_sixteen_protocol_choices_are_explicit_with_distinct_reserved_pools(self):
  for entry in ('awg','ikev2','openvpn','xray'):
   for exit in ('awg','ikev2','openvpn','xray'):
    p=pair.plan(dict(BASE,entry_protocol=entry,exit_protocol=exit));self.assertEqual((entry,exit)!=('ikev2','awg'),pair.native_plan(p))
  for bad in ('socks','wireguard',';id'):
   with self.assertRaises(ValueError):pair.plan(dict(BASE,entry_protocol=bad))
 def test_openvpn_pair_uses_the_guarded_pool_without_changing_single_server_pool(self):
  model=native_pair.model
  self.assertIn('server 10.66.0.0 ',model.openvpn_server({'pair_dns':{'address':'10.10.0.1'}}));self.assertIn('server 10.68.0.0 ',model.openvpn_server())
 def test_xray_pair_has_no_unbound_freedom_or_local_dns_bypass(self):
  state={'port':443,'users':[{'uuid':'00000000-0000-4000-8000-000000000001','login':'fixture'}],'sni':'www.example.net','private':'fixture','shortId':'abcd','pair_dns':{'address':'10.254.0.1','dns_port':53}}
  cfg=native_pair.model.xray_server(state);self.assertEqual('blackhole',cfg['outbounds'][0]['protocol'])
  for outbound in cfg['outbounds']:
   if outbound['protocol']!='blackhole':self.assertEqual('10.66.0.1',outbound['sendThrough'])
  self.assertNotIn('local://',json.dumps(cfg));self.assertEqual('pair-resolver',cfg['dns']['tag']);self.assertEqual('pair-resolver',cfg['routing']['rules'][0]['inboundTag'][0]);self.assertIn('redirect',cfg['outbounds'][2]['settings'])
 def test_proxy_output_is_rejected_while_quiesced_and_is_scoped_to_the_bridge(self):
  p=pair.plan(dict(BASE,entry_protocol='xray'));m={'version':2,'plan':p,'activated':True,'verified':True}
  with patch.object(pair,'load_manifest',return_value=m),patch.object(pair,'write_manifest'),patch.object(native_routing,'guard'),patch.object(native_routing,'routes'),patch.object(native_routing,'chain'),patch.object(native_routing,'jump'),patch.object(native_routing,'run'),patch.object(native_routing,'ipt') as ipt:
   native_routing.apply('quiesce');calls=[c.args for c in ipt.call_args_list if native_routing.OUTPUT in c.args];self.assertIn(('filter','-A',native_routing.OUTPUT,'-s',p['client_pool'],'-j','REJECT'),calls);self.assertFalse(any('ACCEPT' in c for c in calls));self.assertFalse(m['activated'])
 def test_proxy_admin_exception_is_only_local_ssh_even_during_outage(self):
  p=pair.plan(dict(BASE,entry_protocol='xray'));m={'version':2,'plan':p,'activated':True,'verified':True}
  with patch.object(pair,'load_manifest',return_value=m),patch.object(pair,'write_manifest'),patch.object(native_routing,'guard'),patch.object(native_routing,'routes'),patch.object(native_routing,'chain'),patch.object(native_routing,'jump') as jump,patch.object(native_routing,'run'),patch.object(native_routing,'ssh_ports',return_value=[2222]),patch.object(native_routing,'ipt') as ipt:
   native_routing.apply('quiesce')
   allows=[c.args for c in ipt.call_args_list if native_routing.ADMIN in c.args and 'ACCEPT' in c.args]
   self.assertEqual([('filter','-A',native_routing.ADMIN,'-s',p['client_pool'],'-m','addrtype','--dst-type','LOCAL','-p','tcp','--dport','2222','-j','ACCEPT')],allows)
   jumps=[c.args for c in jump.call_args_list];self.assertGreater(jumps.index(('filter','OUTPUT',native_routing.ADMIN)),jumps.index(('filter','OUTPUT',native_routing.OUTPUT_GUARD)))

class EntryLifecycle(unittest.TestCase):
 def test_xray_marker_never_stops_the_parent_service_synchronously(self):
  p=pair.plan(dict(BASE,entry_protocol='xray',exit_protocol='openvpn'));m={'plan':p,'version':2,'configured':False,'jobs':{}}
  value={'dns':{'address':'10.253.0.1','dns_port':5354}};units=[]
  with tempfile.TemporaryDirectory() as d,patch.object(pair,'require_owner',return_value=m),patch.object(pair,'OWN',Path(d)),patch.object(pair,'atomic'),patch.object(pair,'write_manifest'),patch.object(native_pair,'validate_material'),patch.object(native_pair,'packet_bridge',return_value='10.68.0.2'),patch.object(native_pair,'initial',return_value={'login':'phone'}),patch.object(native_pair.runtime,'directory',return_value=Path(d)/'missing'),patch.object(native_pair.runtime,'install'),patch.object(native_pair,'unit',side_effect=lambda name,text:units.append((name,text))),patch.object(native_pair,'command'),patch.object(native_pair,'network'):
   native_pair.configure(p,{'transport':value},Path(d),None)
  entry=dict(units)['rookstride-pair-entry'];self.assertIn('PartOf=rookstride-single-xray.service',entry);self.assertIn('ExecStop=/usr/bin/true',entry);self.assertNotIn('ExecStop=/usr/bin/systemctl stop',entry)
