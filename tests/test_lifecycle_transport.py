"""Candidate service isolation and native parser contracts, without network effects."""
import copy,json,sys,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
import test_recovery_adapters as fixtures
state=fixtures.state;encoded=fixtures.encoded
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import lifecycle_transport as transport,lifecycle,native_pair,pair,recovery_adapters
class LifecycleTransportTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):fixtures.NativeRecoveryAdaptersTests.setUpClass()
 @classmethod
 def tearDownClass(cls):fixtures.NativeRecoveryAdaptersTests.tearDownClass()
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.protected=patch.object(pair,'protected',side_effect=lambda p:Path(p));self.protected.start()
 def tearDown(self):self.protected.stop();self.temp.cleanup()
 def operation(self,protocol):
  es=state(protocol);identity=encoded(fixtures.NativeRecoveryAdaptersTests.tls) if protocol in recovery_adapters.WORKERS|{'ikev2'} else {}
  if protocol=='openvpn':identity=encoded(fixtures.NativeRecoveryAdaptersTests().openvpn_identity())
  if protocol=='ikev2':es['users'][0]['password']='fixture-secret'
  content=recovery_adapters.client_profile(es,'bridge',identity)
  p=pair.plan(dict(pair='a'*32,role='entry',engine='native-v2',entry_protocol='awg',exit_protocol=protocol,server='entry.example.net',exit_host='exit.example.net',tunnel_port=500 if protocol=='ikev2' else 443))
  material={'protocol':protocol,'endpoint':p['exit_host'],'profile':content if protocol=='ikev2' else {'format':protocol,'content':json.dumps(content) if isinstance(content,dict) else content},'dns':{'address':'10.253.0.1','dns_port':53}}
  native_pair.validate_material(p,material)
  return dict(operation='e'*32,plan=p,interface='rsx'+'e'*10,transport=material)
 def test_real_worker_and_reality_outbounds_bind_only_the_candidate_tunnel(self):
  for protocol in ('xray','xhttp','hysteria2','outline','shadowsocks','trusttunnel','naive'):
   op=self.operation(protocol);folder=self.root/protocol;folder.mkdir();(folder/'bin').mkdir();(folder/'bin/xray').write_bytes(b'fixture runtime')
   with patch.object(transport,'directory',return_value=folder),patch.object(transport,'reserve_vip'),patch.object(native_pair.runtime,'ROOT',folder),patch('routes.worker',return_value=Path('/owned/pinned/rook-routes')),patch.object(native_pair,'command',return_value=json.dumps({'schema':1,'tun_gvisor':True})),patch('routes.socket.getaddrinfo',return_value=[(2,1,6,'',('192.0.2.20',443))]):
    unit=transport.prepare(op)
   self.assertNotIn('awg-exit',unit);self.assertNotIn('rookstride-pair-bridge',unit);self.assertNotIn('ip route',unit)
   config=json.loads((folder/('client.json' if protocol in ('xray','xhttp') else 'worker.json')).read_text());inbound=(config['inbounds'] if 'inbounds' in config else config['box']['inbounds'])[0]
   self.assertEqual(op['interface'],inbound['settings']['name'] if protocol in ('xray','xhttp') else inbound['interface_name'])
   if protocol not in ('xray','xhttp'):self.assertFalse(inbound['auto_route']);self.assertEqual('/owned/pinned/rook-routes',op['worker_binary'])
   else:self.assertEqual(str(folder/'xray'),op['xray_binary']);self.assertEqual(b'fixture runtime',(folder/'xray').read_bytes());self.assertNotEqual(str(folder/'bin/xray'),op['xray_binary'])
 def test_ike_candidate_has_unique_named_connection_if_id_and_exact_certificate_pin(self):
  op=self.operation('ikev2');folder=self.root/'ike';folder.mkdir()
  with patch.object(transport,'directory',return_value=self.root),patch.object(transport,'ike_folder',return_value=folder),patch.object(pair,'load_manifest',return_value={'plan':op['plan']}),patch.object(native_pair.ike_packages,'install'),patch.object(native_pair,'command'):
   unit=transport.prepare(op)
  config=(folder/'swanctl.conf').read_text();self.assertIn('rsx-'+op['operation'],config);self.assertNotIn('route-exit {',config);self.assertIn('if_id_in = '+str(transport.if_id(op)),config);self.assertNotIn('if_id_in = 42',config)
  self.assertIn('certs = '+str(folder/'exit.pem'),config);self.assertIn('PartOf=rookstride-pair-bridge.service',unit);self.assertIn('--ike rsx-',unit)
 def test_candidate_address_uses_whole_identity_and_rejects_existing_interface(self):
  first=dict(operation='e'*32,interface='rsxeeeeeeeeee');second=dict(operation='e'+'f'*31,interface='rsxefffffffff')
  self.assertNotEqual(transport.fixed_vip(first),transport.fixed_vip(second))
  result=SimpleNamespace(stdout=json.dumps([{'ifname':'other-tunnel','addr_info':[{'local':transport.fixed_vip(first)}]}]))
  with patch.object(transport.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(ValueError,'already assigned'):transport.reserve_vip(first)
  result.stdout=json.dumps([{'ifname':first['interface'],'addr_info':[{'local':transport.fixed_vip(first)}]}])
  with patch.object(transport.subprocess,'run',return_value=result):transport.reserve_vip(first)
 def test_openvpn_staging_reuses_immutable_installed_image_without_build(self):
  op=self.operation('openvpn');folder=self.root/'openvpn';folder.mkdir();image='sha256:'+'a'*64
  with patch.object(transport,'directory',return_value=folder),patch.object(native_pair,'command',return_value=image) as command,patch.object(native_pair,'openvpn_profile',return_value='dev '+native_pair.INTERFACE+'\nclient\n'):
   unit=transport.prepare(op)
  command.assert_called_once_with(['docker','image','inspect','--format','{{.Id}}','rookstride-openvpn:1']);self.assertIn(image,unit);self.assertNotIn('rookstride-openvpn:1',unit)
  self.assertEqual('dev '+op['interface']+'\nclient\n',(folder/'client.ovpn').read_text())
 def test_configuration_retry_refuses_changed_staged_profile(self):
  path=self.root/'config';transport.write_owned(path,'exact');transport.write_owned(path,'exact')
  with self.assertRaisesRegex(ValueError,'configuration changed'):transport.write_owned(path,'changed')
  self.assertEqual('exact',path.read_text())
if __name__=='__main__':unittest.main()
