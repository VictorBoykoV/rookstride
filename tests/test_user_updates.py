"""Account change contracts and targeted session control, without a live provider."""
import json,os,socket,sys,tempfile,threading,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
import user_updates,runtime,model

class AccountUpdates(unittest.TestCase):
 def test_each_method_has_separate_add_revoke_and_metadata_impact(self):
  for method in model.PROTOCOLS:
   result=user_updates.impact({'protocol':method})
   self.assertEqual('live',result['metadata']);self.assertIn(result['add'],('live','restart','live-or-restart'))
   self.assertIn(result['revoke'],('live','restart','targeted-or-restart'))
   self.assertEqual('not-applicable',result['password'])
  self.assertEqual('live-or-restart',user_updates.impact({'protocol':'xray'})['add'])
  self.assertEqual('restart',user_updates.impact({'protocol':'xray'})['revoke'])
  self.assertEqual('targeted-or-restart',user_updates.impact({'protocol':'openvpn','access_mode':'password'})['password'])
 def test_merge_preserves_any_actual_restart(self):
  self.assertEqual({},user_updates.merge(None,None))
  self.assertFalse(user_updates.merge(user_updates.result(),None)['listener_restarted'])
  self.assertTrue(user_updates.merge(user_updates.result(True),user_updates.result())['listener_restarted'])
 def test_certificate_server_exposes_only_root_local_socket(self):
  config=model.openvpn_server({'protocol':'openvpn'})
  self.assertIn('management /vpn/management.sock unix',config)
  self.assertNotIn('management 0.0.0.0',config)
 def test_live_certificate_revoke_does_not_apply_or_restart_listener(self):
  state={'protocol':'openvpn','users':[{'login':'keep'},{'login':'remove'}]}
  with tempfile.TemporaryDirectory() as directory,patch.object(runtime,'directory',return_value=Path(directory)),patch.object(runtime,'save'),patch.object(runtime,'command') as command,patch.object(runtime,'check_container',return_value={'State':{'Running':True}}),patch.object(runtime,'apply_config') as apply,patch.object(user_updates,'terminate',return_value=user_updates.result()) as terminate:
   result=runtime.remove_user(state,'remove')
   self.assertFalse(result['listener_restarted']);self.assertEqual('live',result['update']);apply.assert_not_called()
   self.assertEqual('keep',state['users'][0]['login']);terminate.assert_called_once()
   self.assertEqual(['revoke','remove'],command.call_args.args[0][-2:])
 def test_targeted_failure_falls_back_to_explicit_restart(self):
  with patch.object(user_updates,'terminate',side_effect=OSError('fragment unavailable')),patch.object(runtime,'command') as command:
   value=runtime.disconnect_password_user({'protocol':'openvpn'},'remove')
   self.assertTrue(value['listener_restarted']);self.assertEqual('restart',value['update'])
   command.assert_called_once_with(['docker','restart','rookstride-single-openvpn'])
 def test_management_reads_fragmented_lines_and_keeps_common_name_exact(self):
  with tempfile.TemporaryDirectory() as directory:
   folder=Path(directory)/'runtime';folder.mkdir();(folder/'server.conf').write_text('management /vpn/management.sock unix\n')
   path=folder/'management.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
   listener.bind(str(path));listener.listen();received=[]
   def server():
    client,_=listener.accept()
    with client:
     client.sendall(b'>INFO:OpenVPN ');client.sendall(b'Management\n')
     received.append(client.recv(128));client.sendall(b'>STATE:ignored\nSUCC');client.sendall(b'ESS: common name killed\n')
   thread=threading.Thread(target=server);thread.start()
   try:
    with patch.object(runtime,'directory',return_value=Path(directory)):
     result=user_updates.terminate({'protocol':'openvpn'},'chosen-client',runtime)
    self.assertFalse(result['listener_restarted']);thread.join(3);self.assertFalse(thread.is_alive())
    self.assertEqual([b'kill chosen-client\n'],received)
   finally:listener.close()
 def test_missing_management_and_invalid_login_fail_before_socket_connection(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(runtime,'directory',return_value=Path(directory)),patch.object(user_updates.socket,'socket') as socket_factory:
   for login in ('bad\nkill other','bad space','../bad'):
    with self.assertRaises(ValueError):user_updates.terminate({'protocol':'openvpn'},login,runtime)
   with self.assertRaises(OSError):user_updates.terminate({'protocol':'openvpn'},'fine',runtime)
   socket_factory.assert_not_called()
 def test_bounded_response_rejects_unconfirmed_and_oversized_output(self):
  control=Mock();control.recv.side_effect=[b'a'*4096]*16
  with self.assertRaisesRegex(OSError,'limit'):user_updates._line(control,b'',user_updates.time.monotonic()+3,0)
  control=Mock();control.recv.return_value=b''
  with self.assertRaisesRegex(OSError,'ended'):user_updates._line(control,b'',user_updates.time.monotonic()+3,0)

class RetainedImageRemoval(unittest.TestCase):
 def fixture(self,root,state='accepted'):
  path=root/('a'*32)/'journal.json';path.parent.mkdir();path.write_text(json.dumps({'operation':'a'*32,'group':'awg','state':state,'snapshot':{'services':[{'kind':'container','name':'rookstride-single-awg','original_id':'exact-original'}]}}))
 def test_managed_reset_removes_only_exact_stopped_retained_container(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);self.fixture(root);command=Mock();response=SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':'exact-original','State':{'Running':False}}]))
   with patch('subprocess.run',return_value=response):user_updates.remove_retained_containers('awg',command,root)
   command.assert_called_once_with(['docker','rm','rookstride-prior-'+'a'*32+'-awg'])
 def test_active_or_replaced_backup_refused_before_remove(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);self.fixture(root);command=Mock()
   for ident,running in [('different-container',False),('exact-original',True)]:
    response=SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':ident,'State':{'Running':running}}]))
    with patch('subprocess.run',return_value=response):
     with self.assertRaisesRegex(ValueError,'changed'):user_updates.remove_retained_containers('awg',command,root)
   command.assert_not_called()
 def test_pending_review_blocks_removal_before_docker_inspection(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);self.fixture(root,'prepared')
   with patch('subprocess.run') as inspect:
    with self.assertRaises(ValueError):user_updates.remove_retained_containers('awg',Mock(),root)
    inspect.assert_not_called()

if __name__=='__main__':unittest.main()
