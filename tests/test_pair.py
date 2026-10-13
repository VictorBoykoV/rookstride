"""Pair validation, ownership, feature/config safety and interrupted-job behavior."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('pair',Path(__file__).resolve().parents[1]/'server/pair.py')
pair=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair)
KEY=base64.b64encode(bytes(range(32))).decode()
SHARED={'psk':KEY,'header_key':KEY,'headers':[101,102,103,104]}
BASE={'pair':'a'*32,'role':'entry','server':'vpn.example.net','exit_host':'exit.example.net'}

class PairValidation(unittest.TestCase):
    def test_both_roles_and_nonstandard_ports_are_validated(self):
        for role in ['entry','exit']:
            p=pair.plan(dict(BASE,role=role,vpn_port=15500,tunnel_port=1443))
            self.assertEqual(role,p['role']);self.assertEqual(15500,p['vpn_port'])
        for field,value in [('vpn_port',True),('tunnel_port',0),('route_table',2**31),('role','other'),('exit_host','host; id'),('server','-bad'),('pair','../x')]:
            with self.assertRaises(ValueError):pair.plan(dict(BASE,**{field:value}))
    def test_overlapping_ranges_and_network_endpoints_are_refused(self):
        for changes in [{'client_pool':'10.253.0.0/24'},{'test_ip':'10.250.0.8'},{'entry_address':'10.253.0.0/30'},{'exit_address':'10.253.0.2/30'},{'entry_address':'fd00::2/64'},{'client_pool':'10.250.0.7/16'}]:
            with self.assertRaises(ValueError):pair.plan(dict(BASE,**changes))
    def test_invalid_peer_material_never_renders_a_config(self):
        for value in ['not base64',KEY+'\n',base64.b64encode(b'x'*31).decode()]:
            with self.assertRaises(ValueError):pair.key(value)
        for changes in [{'headers':[1,1,2,3]},{'headers':[True,2,3,4]},{'psk':'bad'},{'extra':'unrecognized'}]:
            with self.assertRaises(ValueError):pair.validate_shared(dict(SHARED,**changes))
    def test_roles_do_not_mix_client_allowed_ips_and_backhaul_default(self):
        entry=pair.config_text(pair.plan(BASE),{'private_key':KEY},KEY,SHARED)
        exit=pair.config_text(pair.plan(dict(BASE,role='exit')),{'private_key':KEY},KEY,SHARED)
        self.assertIn('AllowedIPs = 0.0.0.0/0',entry)
        self.assertNotIn('AllowedIPs = 0.0.0.0/0',exit)
        self.assertIn('10.250.0.0/16',exit);self.assertIn('10.249.255.254/32',exit)
        self.assertIn('Endpoint = exit.example.net:443',entry);self.assertNotIn('Endpoint =',exit)
        self.assertIn('MTU = 1280',entry);self.assertIn('HeaderProtectionKey',exit)
    def test_material_response_never_returns_a_node_private_key(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'material.json').write_text(json.dumps({'private_key':'must-stay-on-node','public_key':KEY,'shared':SHARED}))
            with patch.object(pair,'OWN',root),patch.object(pair,'load_manifest',return_value={'plan':pair.plan(BASE)}):
                result=pair.dispatch({'command':'material','pair':'a'*32})
                self.assertNotIn('private_key',result);self.assertNotIn('must-stay-on-node',json.dumps(result))
    def test_wrong_pair_owner_and_changed_plan_are_refused(self):
        with patch.object(pair,'load_manifest',return_value={'plan':pair.plan(BASE)}):
            with self.assertRaises(ValueError):pair.require_owner(pair.plan(dict(BASE,pair='b'*32)))
            with self.assertRaises(ValueError):pair.require_owner(pair.plan(dict(BASE,exit_host='replacement.example.net')))
    def test_activating_systemd_oneshot_is_not_misreported_as_interrupted(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d);job=state/('b'*32);job.mkdir()
            (job/'status.json').write_text(json.dumps({'state':'running','updated':0,'job':'b'*32}))
            with patch.object(pair,'STATE',state),patch.object(pair,'command_output',return_value='activating'):
                self.assertEqual('running',pair.status('b'*32)['state'])
            with patch.object(pair,'STATE',state),patch.object(pair,'command_output',return_value='failed'):
                self.assertEqual('paused',pair.status('b'*32)['state'])
    def test_completed_jobs_do_not_query_or_restart_systemd(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d);job=state/('b'*32);job.mkdir()
            (job/'status.json').write_text(json.dumps({'state':'complete','updated':0,'job':'b'*32}))
            with patch.object(pair,'STATE',state),patch.object(pair,'command_output',side_effect=AssertionError('unexpected command')):
                self.assertEqual('complete',pair.status('b'*32)['state'])
    def test_source_digest_changes_with_backend_and_skips_only_python_cache(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for folder in ['server','gateway','twohop']:(root/folder).mkdir()
            f=root/'twohop/entry.sh';f.write_text('blocked')
            a=pair.source_digest(root);f.write_text('active');self.assertNotEqual(a,pair.source_digest(root))
            a=pair.source_digest(root);cache=root/'server/__pycache__';cache.mkdir();(cache/'job.pyc').write_bytes(b'cache')
            self.assertEqual(a,pair.source_digest(root))
            (root/'server/link').symlink_to(f)
            with self.assertRaises(ValueError):pair.source_digest(root)


class PairRecovery(unittest.TestCase):
    def test_unknown_partial_ike_configuration_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);conf=root/'ipsec.conf';conf.write_text('config setup\n\nconn unrelated\n  auto=start\n')
            actual_path=Path
            with patch.object(pair,'OWN',root),patch.object(pair,'Path',side_effect=lambda value:conf if value=='/etc/ipsec.conf' else actual_path(value)):
                with self.assertRaises(ValueError):pair.check_partial_ike()
                conf.write_text('# Package sample\nconfig setup\n#conn sample\n')
                pair.check_partial_ike()
    def test_partial_ike_checkpoint_must_validate(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);checkpoint=root/'ike-files.sha256';checkpoint.write_text('private checkpoint')
            with patch.object(pair,'OWN',root),patch.object(pair,'run') as run:
                pair.check_partial_ike();run.assert_called_once_with(['sha256sum','--check','--status',str(checkpoint)])
    def test_vendor_hashes_match_every_shipped_file(self):
        root=Path(__file__).resolve().parents[1]/'twohop';meta=json.loads((root/'SOURCE.json').read_text())
        import hashlib
        for name,digest in meta['files'].items():self.assertEqual(digest,hashlib.sha256((root/name).read_bytes()).hexdigest(),name)

    def test_transient_systemd_query_failure_does_not_abort_or_pause_job(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            state=Path(d);job=state/('b'*32);job.mkdir()
            (job/'status.json').write_text(json.dumps({'state':'running','updated':0,'job':'b'*32}))
            for error in [subprocess.CalledProcessError(1,['systemctl']),subprocess.TimeoutExpired(['systemctl'],30)]:
                with patch.object(pair,'STATE',state),patch.object(pair,'command_output',side_effect=error):
                    status=pair.status('b'*32)
                    self.assertEqual('running',status['state']);self.assertTrue(status['status_unavailable'])

class CanonicalDigest(unittest.TestCase):
    def test_path_component_order_does_not_change_phone_server_digest(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for folder in ['server/rookstride','twohop','gateway']:(root/folder).mkdir(parents=True)
            (root/'server/rookstride/a.py').write_text('nested')
            (root/'server/rookstride-service').write_text('sibling')
            expected=hashlib.sha256(b'server/rookstride-servicesiblingserver/rookstride/a.pynested').hexdigest()
            self.assertEqual(expected,pair.source_digest(root))

if __name__=='__main__':unittest.main()
