"""Private DNS, TLS renewal, export and protocol-boundary regression checks."""
import copy,datetime,json,ssl,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
import routes,model,runtime
class RouteMethods(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.change=patch.object(runtime,'STATE',self.folder);self.change.start()
  self.state=dict(protocol='naive',server='192.0.2.15',instance='a'*32,owner='rookstride-single-v1',users=[],port=443,metrics_port=24000,metrics_token='b'*64)
 def tearDown(self):self.change.stop();self.temp.cleanup()
 def authority(self):
  runtime.directory('naive').mkdir();routes.tls_material(self.state,runtime)
  return (runtime.directory('naive')/'tls/ca.pem').read_text()
 def test_private_tls_uses_short_leaf_and_keeps_active_generation_on_renewal_failure(self):
  authority=self.authority();cert,key=routes.tls_paths(self.state,runtime);first=cert.read_bytes();root=cert.parent.parent/'ca.pem'
  self.assertEqual(0,subprocess.run(['openssl','verify','-CAfile',str(root),str(cert)],capture_output=True).returncode)
  self.assertFalse(routes.tls_material(self.state,runtime));self.assertEqual(first,cert.read_bytes())
  old_generation=self.state['tls_leaf'];original=runtime.command
  def failing(args,*a,**kw):
   if args[:2]==['openssl','x509']:raise ValueError('simulated signing failure')
   return original(args,*a,**kw)
  with patch('routes.subprocess.run',return_value=type('Result',(),{'returncode':1})()),patch.object(runtime,'command',side_effect=failing):
   with self.assertRaises(ValueError):routes.tls_material(self.state,runtime)
  self.assertEqual(old_generation,self.state['tls_leaf']);self.assertEqual(first,cert.read_bytes());self.assertEqual(authority,root.read_text())
 def test_new_profiles_cannot_inject_engine_options_or_change_verified_identity(self):
  certificate=self.authority()
  profile=dict(schema=1,protocol='naive',server='192.0.2.15',server_name='192.0.2.15',port=443,login='phone',password='12345678',certificate=certificate)
  routes.validate_profile(profile)
  for change in ({'insecure':True},{'server_name':'attacker.invalid'},{'port':True},{'certificate':'not a certificate'},{'password':'short'}):
   with self.assertRaises(ValueError):routes.validate_profile(dict(profile,**change))
  trust=dict(profile,protocol='trusttunnel',server_name='vpn-'+'a'*32+'.internal');routes.validate_profile(trust)
  with self.assertRaises(ValueError):routes.validate_profile(dict(trust,server_name='vpn-attacker.internal'))
 def test_client_dns_is_tunneled_and_chromium_has_only_an_endpoint_transport(self):
  certificate=self.authority();base=dict(schema=1,server='192.0.2.15',server_name='192.0.2.15',port=443,login='phone',password='12345678',certificate=certificate)
  for protocol in routes.PROTOCOLS:
   p=dict(base,protocol=protocol)
   if protocol in ('outline','shadowsocks'):p.update(method='chacha20-ietf-poly1305',path='/'+'a'*48)
   if protocol=='hysteria2':p['obfs']='a'*32
   config=routes.client_config(p,10800,protect_path='@private-protector')['box']
   self.assertEqual('vpn',config['dns']['servers'][0]['detour']);self.assertEqual('vpn',config['route']['final']);self.assertNotIn('insecure',json.dumps(config))
   if protocol=='naive':
    self.assertEqual('transport',config['outbounds'][0]['detour']);self.assertEqual('endpoint-only',config['outbounds'][1]['type']);self.assertEqual('@private-protector',config['outbounds'][1]['protect_path'])
   else:self.assertEqual('@private-protector',config['outbounds'][0]['protect_path'])
 def test_naive_verification_can_use_only_the_advertised_endpoint_after_loopback(self):
  self.authority()
  self.state['users']=[dict(login='phone',password='fixture-password')]
  with patch.object(routes,'worker',return_value=Path('/verified/rook-routes')), \
       patch.object(routes.socket,'socket') as reserve, \
       patch.object(routes.socket,'create_connection'), \
       patch.object(routes.subprocess,'Popen') as start, \
       patch.object(routes,'client_config',wraps=routes.client_config) as configure, \
       patch.object(runtime,'socks_https_ready',side_effect=[False,False,True]):
   reserve.return_value.__enter__.return_value.getsockname.return_value=('127.0.0.1',19000)
   start.return_value.poll.return_value=None
   routes.verify_connection(self.state,runtime)
   self.assertEqual([call.kwargs['server'] for call in configure.call_args_list],
                    ['127.0.0.1',self.state['server']])
   self.assertEqual(2,start.return_value.terminate.call_count)
 def test_manual_passwords_survive_export_validation_and_encrypted_outbound_creation(self):
  certificate=self.authority()
  for protocol in ('hysteria2','trusttunnel','naive'):
   for secret in ('1','Our family chooses a longer private passphrase 2026!'):
    profile=dict(schema=1,protocol=protocol,server='192.0.2.15',server_name='192-0-2-15.sslip.io',port=443,login='1',password=secret,certificate=certificate,access_mode='password')
    routes.validate_profile(profile);out=routes.client_config(profile,10800)['box']['outbounds'][0]
    self.assertEqual('1:'+secret if protocol=='hysteria2' else secret,out['password'])
   for secret in ('','a'*128,'with\ncontrol'):
    with self.assertRaises(ValueError):routes.validate_profile(dict(profile,password=secret))
 def test_entry_dns_and_internet_sockets_share_the_guarded_source(self):
  cfg=routes.route_policy(dict(self.state,pair_dns=True),dict(address='10.254.42.1',dns_port=15353))
  self.assertEqual('10.66.0.1',cfg['outbounds'][0]['inet4_bind_address']);self.assertEqual('10.66.0.1',cfg['dns']['servers'][0]['inet4_bind_address'])
  rules=cfg['route']['rules'];self.assertEqual('route-options',rules[0]['action']);self.assertEqual('10.254.42.1',rules[0]['override_address']);self.assertEqual(15353,rules[1]['port']);self.assertIn(dict(ip_version=6,action='reject'),rules);self.assertEqual(dict(ip_is_private=True,action='reject'),rules[-1]);self.assertEqual(dict(action='resolve',server='private-dns',strategy='ipv4_only'),rules[-2])
 def test_hysteria_outer_packet_budget_preserves_existing_access_and_private_dns(self):
  self.state.update(protocol='hysteria2',obfs='documentation-obfuscation',users=[dict(login='phone',password='existing-access')])
  before=copy.deepcopy(self.state)
  with patch('filtering.load',return_value=dict(address='10.253.0.1',dns_port=5354)):
   cfg=routes.configuration(self.state,runtime)['box']
  incoming=cfg['inbounds'][0]
  # QUIC's 1200 minimum still fits IPv6 + UDP + the eight-byte Salamander salt.
  self.assertGreaterEqual(incoming['initial_packet_size'],1200)
  self.assertLessEqual(incoming['initial_packet_size']+40+8+8,1280)
  self.assertTrue(incoming['disable_path_mtu_discovery'])
  self.assertEqual(before,self.state);self.assertEqual(before['users'][0]['password'],incoming['users'][0]['password']);self.assertEqual(443,incoming['listen_port'])
  self.assertEqual('10.253.0.1',cfg['route']['rules'][0]['override_address']);self.assertEqual(5354,cfg['route']['rules'][0]['override_port']);self.assertEqual('internet',cfg['route']['final'])
 def test_hysteria_bridge_adapts_only_to_an_observed_small_endpoint_route(self):
  certificate=self.authority();profile=dict(schema=1,protocol='hysteria2',server='192.0.2.15',server_name='192.0.2.15',port=443,login='phone',password='existing-access',obfs='documentation-obfuscation',certificate=certificate)
  before=copy.deepcopy(profile);route=dict(dst=profile['server'],dev='fixture0')
  def config(rows,interface_mtu='1500',value=profile,listen=0):
   result=subprocess.CompletedProcess([],0,json.dumps(rows),'')
   def read_mtu(path):
    self.assertEqual(Path('/sys/class/net/fixture0/mtu'),path)
    if isinstance(interface_mtu,Exception):raise interface_mtu
    return interface_mtu+'\n'
   with patch('routes.subprocess.run',return_value=result) as lookup,patch.object(Path,'read_text',read_mtu):
    output=routes.client_config(value,listen,protect_path='@private-protector')['box']
   if listen:self.assertEqual(0,lookup.call_count)
   else:lookup.assert_called_once_with(['ip','-j','-4','route','get',profile['server']],capture_output=True,text=True,timeout=2)
   return output
  normal=config([route]);small=config([route],'1280')
  options=dict(initial_packet_size=1200,disable_path_mtu_discovery=True,disable_chrome_parrot=True)
  expected=copy.deepcopy(normal);expected['outbounds'][0].update(options)
  self.assertEqual(expected,small)
  # Chrome's preset would force 1250 despite initial_packet_size: all three
  # options are necessary, with QUIC >=1200 and the complete IPv4 wire budget.
  out=small['outbounds'][0];self.assertGreaterEqual(out['initial_packet_size'],1200);self.assertLessEqual(out['initial_packet_size']+20+8+8,1280)
  self.assertEqual(before,profile);self.assertEqual('existing-access',out['password']);self.assertEqual(normal['dns'],small['dns']);self.assertEqual(normal['route'],small['route'])
  for metrics,interface_mtu in (({'mtu':1280},'1500'),([{'mtu':1280}],'1500'),({'mtu':1500},'1280'),({'mtu':1280},OSError('no sysfs observation'))):
   with self.subTest(metrics=metrics,interface_mtu=str(interface_mtu)):self.assertEqual(small,config([dict(route,metrics=metrics)],interface_mtu))
  for rows,mtu in (([route],'1286'),([route],'1500'),([route],OSError('unknown interface')),([dict(route,metrics={'mtu':True})],'1280'),([dict(route,dev='../escape')],'1280'),([dict(route,type='blackhole')],'1280'),([route,route],'1280'),([], '1280')):
   with self.subTest(rows=rows,mtu=str(mtu)):self.assertEqual(normal,config(rows,mtu))
  with patch('routes.subprocess.run',side_effect=subprocess.TimeoutExpired('ip',2)):
   self.assertEqual(normal,routes.client_config(profile,0,protect_path='@private-protector')['box'])
  socks=config([route],'1280',listen=10800);self.assertEqual(normal['outbounds'],socks['outbounds'])
  password=dict(profile,access_mode='password',login='1',password='1',server_name='192-0-2-15.sslip.io');password.pop('obfs')
  self.assertNotIn('disable_chrome_parrot',config([route],'1280',password)['outbounds'][0])
  password_out=config([route],'1277',password)['outbounds'][0]
  self.assertEqual('1:1',password_out['password']);self.assertTrue(password_out['disable_chrome_parrot'])
  self.assertEqual(password['server_name'],password_out['tls']['server_name']);self.assertEqual([certificate],password_out['tls']['certificate'])
  with self.assertRaisesRegex(ValueError,'below the QUIC minimum'):config([route],'1235')
 def test_xhttp_has_no_vision_flow_and_keeps_statistics_private(self):
  state=dict(protocol='xhttp',port=443,path='/'+'a'*48,sni='www.example.com',private='private-fixture',shortId='a'*16,metrics_port=24000,users=[dict(uuid='fixture',login='phone')])
  config=model.xray_server(state);stream=config['inbounds'][0]['streamSettings'];self.assertEqual('xhttp',stream['network']);self.assertNotIn('flow',config['inbounds'][0]['settings']['clients'][0]);self.assertEqual('127.0.0.1',config['inbounds'][1]['listen']);self.assertEqual(['StatsService','HandlerService'],config['api']['services'])
if __name__=='__main__':unittest.main()
