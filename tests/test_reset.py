import importlib.util
import json
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('gateway_reset',Path(__file__).resolve().parents[1]/'server/reset.py')
reset=importlib.util.module_from_spec(spec);spec.loader.exec_module(reset)

class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.marker=self.root/'network.env';self.marker.write_text('DNS_IP=10.254.0.1\n')
        self.config=self.root/'ipsec.conf';self.config.write_text('conn ikev2-vpn\n  leftid=vpn.example.net\n')
        self.state=self.root/'state';self.state.mkdir()
        self.unrelated=self.root/'other-project';self.unrelated.write_text('keep this')
        self.paths=patch.multiple(reset,MARKER=self.marker,CONFIG=self.config,STATE=self.state,PATHS=(self.marker,self.config,self.state))
        self.paths.start()
    def tearDown(self):self.paths.stop();self.tmp.cleanup()
    def request(self,p):return {'mode':'apply','token':p['token'],'confirmation':'DELETE VPN'}
    def test_unknown_or_additional_vpn_is_refused(self):
        self.marker.unlink()
        with self.assertRaises(ValueError):reset.plan()
        self.marker.write_text('marker')
        self.config.write_text('conn ikev2-vpn\nconn other-project\n')
        with self.assertRaises(ValueError):reset.plan()
        self.assertTrue(self.unrelated.exists())
    def test_confirmation_and_expiration_checked_before_service_changes(self):
        p=reset.plan()
        with patch.object(reset,'execute') as run:
            with self.assertRaises(ValueError):reset.apply(dict(self.request(p),confirmation='yes'))
            with self.assertRaises(ValueError):reset.apply(dict(self.request(p),token='wrong'))
            record=json.loads((self.state/'reset-plan.json').read_text());record['expires']=time.time()-1
            (self.state/'reset-plan.json').write_text(json.dumps(record))
            with self.assertRaises(ValueError):reset.apply(self.request(p))
            run.assert_not_called()
        self.assertTrue(self.config.exists())
    def test_configuration_change_requires_new_review(self):
        p=reset.plan();self.config.write_text('conn ikev2-vpn\n  leftid=changed.example.net\n')
        with patch.object(reset,'execute') as run:
            with self.assertRaises(ValueError):reset.apply(self.request(p))
            run.assert_not_called()
    def test_service_stop_failure_preserves_files(self):
        p=reset.plan()
        with patch.object(reset,'execute',return_value=0):
            with self.assertRaises(RuntimeError):reset.apply(self.request(p))
        self.assertTrue(self.config.exists());self.assertTrue(self.marker.exists())
    def test_running_installation_is_refused(self):
        p=reset.plan();job=self.state/'jobs/job';job.mkdir(parents=True)
        (job/'status.json').write_text('{"state":"running"}')
        with patch.object(reset,'execute') as run:
            with self.assertRaises(ValueError):reset.apply(self.request(p))
            run.assert_not_called()
    def test_reset_preserves_unrelated_files_and_base_firewall(self):
        p=reset.plan()
        def run(args,check=True):
            if 'is-active' in args or '-C' in args:return 1
            return 0
        with patch.object(reset,'execute',side_effect=run) as commands:
            self.assertTrue(reset.apply(self.request(p))['reset'])
            for call in commands.call_args_list:
                args=call.args[0]
                if '-F' in args or '-X' in args:self.assertTrue(args[-1].startswith('SINGLEVPN_'))
        self.assertFalse(self.config.exists());self.assertFalse(self.state.exists())
        self.assertEqual(self.unrelated.read_text(),'keep this')
    def test_symlinked_managed_path_is_refused(self):
        self.config.unlink();self.config.symlink_to(self.unrelated)
        with self.assertRaises(ValueError):reset.plan()
        self.assertTrue(self.unrelated.exists())
    def test_closed_unix_socket_is_removed_after_services_stop(self):
        stale=self.root/'charon.vici'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(stale))
        self.assertTrue(stale.is_socket())
        with patch.object(reset,'PATHS',(self.marker,self.config,self.state,stale)):
            p=reset.plan()
            def run(args,check=True):
                if 'is-active' in args or '-C' in args:return 1
                return 0
            with patch.object(reset,'execute',side_effect=run):reset.apply(self.request(p))
        self.assertFalse(stale.exists())

if __name__=='__main__':unittest.main()
