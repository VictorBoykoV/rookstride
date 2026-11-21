import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import model,runtime,xray_users
class XrayLiveUsersTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name);(self.path/'runtime').mkdir()
  self.state=dict(protocol='xray',users=[dict(login='existing',uuid='old-key')],port=443,sni='www.example.test',private='private-fixture',shortId='abcd',metrics_port=24000)
  (self.path/'runtime/server.json').write_text(json.dumps(model.xray_server(self.state)))
  self.directory=patch.object(runtime,'directory',return_value=self.path);self.directory.start();self.saving=patch.object(runtime,'save');self.saving.start()
 def tearDown(self):self.directory.stop();self.saving.stop();self.temp.cleanup()
 def test_hot_add_verifies_runtime_and_keeps_existing_key_without_restart(self):
  self.state['users'].append(dict(login='new-user',uuid='new-key'))
  with patch.object(runtime,'command',side_effect=['Added 1 user(s) in total.',json.dumps({'users':[{'email':'new-user'}]})]) as command:
   self.assertTrue(xray_users.add(self.state,self.state['users'][-1],runtime))
   self.assertEqual(['adu','inbounduser'],[call.args[0][2] for call in command.call_args_list]);self.assertNotIn('pending_user_update',self.state)
  final=json.loads((self.path/'runtime/server.json').read_text());self.assertEqual('old-key',final['inbounds'][0]['settings']['clients'][0]['id'])
 def test_zero_exit_zero_added_never_counts_as_success_or_restarts(self):
  self.state['users'].append(dict(login='new-user',uuid='new-key'))
  with patch.object(runtime,'command',return_value='Added 0 user(s) in total.') as command:
   with self.assertRaises(ValueError):xray_users.add(self.state,self.state['users'][-1],runtime)
   self.assertEqual(1,command.call_count);self.assertIn('pending_user_update',self.state)
 def test_missing_runtime_identity_after_cli_receipt_is_rejected(self):
  self.state['users'].append(dict(login='new-user',uuid='new-key'))
  with patch.object(runtime,'command',side_effect=['Added 1 user(s) in total.','{"users":[]}']):
   with self.assertRaises(ValueError):xray_users.add(self.state,self.state['users'][-1],runtime)
 def test_legacy_api_and_other_config_changes_do_not_attempt_hot_mutation(self):
  self.state['users'].append(dict(login='new-user',uuid='new-key'));old=json.loads((self.path/'runtime/server.json').read_text());old['api']['services']=['StatsService'];(self.path/'runtime/server.json').write_text(json.dumps(old))
  with patch.object(runtime,'command') as command:self.assertFalse(xray_users.add(self.state,self.state['users'][-1],runtime));command.assert_not_called()
  old['api']['services'].append('HandlerService');(self.path/'runtime/server.json').write_text(json.dumps(old));self.state['port']=8443
  with patch.object(runtime,'command') as command:self.assertFalse(xray_users.add(self.state,self.state['users'][-1],runtime));command.assert_not_called()
 def test_xhttp_uses_the_same_user_api_without_vision_flow(self):
  self.state.update(protocol='xhttp',path='/fixture');(self.path/'runtime/server.json').write_text(json.dumps(model.xray_server(self.state)));self.state['users'].append(dict(login='new-user',uuid='new-key'))
  with patch.object(runtime,'command',side_effect=['Added 1 user(s) in total.','{"users":[{"email":"new-user"}]}']):self.assertTrue(xray_users.add(self.state,self.state['users'][-1],runtime))
  self.assertNotIn('flow',json.loads((self.path/'runtime/server.json').read_text())['inbounds'][0]['settings']['clients'][1])
if __name__=='__main__':unittest.main()
