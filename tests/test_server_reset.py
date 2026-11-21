"""All-protocol review must change when accounts/installations change; partial retry is explicit."""
import importlib.util,json,shutil,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import model,runtime,reset_server
spec=importlib.util.spec_from_file_location('multi_api',ROOT/'single/run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
class ServerReset(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.state=self.root/'state';self.state.mkdir()
  self.patches=[patch.object(runtime,'STATE',self.state),patch.object(reset_server,'PAIR',self.root/'pair'),patch.object(reset_server.ike,'MARKER',self.root/'ike-marker'),patch.object(runtime,'check_container',return_value=None)]
  for p in self.patches:p.start()
  for protocol in model.PROTOCOLS:runtime.save(dict(protocol=protocol,owner='rookstride-single-v1',instance=protocol,users=[],port=model.PROTOCOLS[protocol]['port']))
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def review(self):return reset_server.plan(lambda p:dict(token=p+'-review'))
 def request(self,plan):return dict(token=plan['token'],confirmation='DELETE ALL VPNS')
 def test_bad_confirmation_expiry_and_changed_accounts_precede_any_removal(self):
  plan=self.review();remove=lambda req:shutil.rmtree(runtime.directory(req['protocol']))
  with self.assertRaises(ValueError):reset_server.apply(dict(self.request(plan),confirmation='yes'),remove)
  state=runtime.load('awg');state['users'].append(dict(login='another-device'));runtime.save(state)
  with self.assertRaises(ValueError):reset_server.apply(self.request(plan),remove)
  self.assertTrue(runtime.directory('awg').exists());plan=self.review();record=json.loads((self.state/'reset-server.json').read_text());record['expires']=time.time()-1;(self.state/'reset-server.json').write_text(json.dumps(record))
  with self.assertRaises(ValueError):reset_server.apply(self.request(plan),remove)
 def test_partial_removal_requires_a_fresh_review_for_the_remaining_protocols(self):
  plan=self.review();calls=[]
  def remove(req):
   calls.append(req['protocol'])
   if req['protocol']=='openvpn':raise RuntimeError('simulated service stop failure')
   shutil.rmtree(runtime.directory(req['protocol']))
  with self.assertRaisesRegex(ValueError,'after removing awg'):reset_server.apply(self.request(plan),remove)
  self.assertEqual(calls,sorted(p for p in model.PROTOCOLS if p<='openvpn'));self.assertTrue(runtime.directory('xray').exists())
  with self.assertRaises(ValueError):reset_server.apply(self.request(plan),remove)
  plan=self.review();result=reset_server.apply(self.request(plan),lambda req:shutil.rmtree(runtime.directory(req['protocol'])))
  self.assertEqual(set(result['removed_protocols']),{p for p in model.PROTOCOLS if p>='openvpn'});self.assertFalse(result['os_reinstall'])
 def test_empty_removal_can_be_repeated_and_does_not_touch_unrelated_data(self):
  for protocol in model.PROTOCOLS:shutil.rmtree(runtime.directory(protocol))
  sentinel=self.root/'unrelated-application';sentinel.write_text('keep')
  for _ in range(2):
   review=self.review();self.assertTrue(review['already_empty']);self.assertEqual([],review['protocols'])
   with patch.object(reset_server.filtering,'reset_apply') as filters:
    result=reset_server.apply(self.request(review),lambda req:self.fail('Nothing should be removed'))
   filters.assert_not_called();self.assertTrue(result['already_empty']);self.assertFalse(result['os_reinstall']);self.assertEqual('keep',sentinel.read_text())
 def test_empty_review_does_not_authorize_a_vpn_created_afterwards(self):
  for protocol in model.PROTOCOLS:shutil.rmtree(runtime.directory(protocol))
  review=self.review();runtime.save(dict(protocol='xhttp',owner='rookstride-single-v1',instance='new',users=[],port=443))
  with self.assertRaisesRegex(ValueError,'server changed'):reset_server.apply(self.request(review),lambda req:self.fail('Changed inventory was removed'))
 def test_pair_and_unowned_adapter_states_are_rejected(self):
  (self.root/'pair').mkdir()
  with self.assertRaises(ValueError):self.review()
  (self.root/'pair').rmdir();state=runtime.load('awg');state['owner']='someone-else';runtime.save(state)
  with self.assertRaises(ValueError):self.review()
 def test_an_inactive_owned_protocol_still_reserves_its_port(self):
  runtime.save(dict(protocol='xray',owner='rookstride-single-v1',instance='owned',users=[],port=1194))
  shutil.rmtree(runtime.directory('openvpn'))
  with patch.object(api,'inspect',return_value=dict(compatible_os=True,os='Ubuntu 24.04',ports=[])):
   self.assertNotEqual(api.plan(dict(protocol='openvpn',server='vpn.example.net'))['port'],1194)
   with self.assertRaises(ValueError):api.plan(dict(protocol='openvpn',server='vpn.example.net',port=1194))
 def test_failed_runtime_preparation_leaves_an_owned_resettable_checkpoint(self):
  shutil.rmtree(runtime.directory('awg'))
  state=dict(protocol='awg',owner='rookstride-single-v1',instance='owned',initialLogin='device',port=51820)
  with patch.object(runtime.filtering,'prepare_binary',return_value=b'fixture binary'),patch.object(runtime,'docker_ready',side_effect=ValueError('preparation failed')):
   with self.assertRaises(ValueError):runtime.install(state,lambda stage,phase:None)
  self.assertEqual(runtime.load('awg')['users'],[]);self.assertIn('awg',reset_server.inventory())
