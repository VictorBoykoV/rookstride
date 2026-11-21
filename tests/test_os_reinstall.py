"""OS replacement is distinct from VPN reset and cannot infer authorization."""
import importlib.util,tempfile,json,shutil,subprocess,unittest,io
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('os_reinstall',ROOT/'reinstall/run.py');osr=importlib.util.module_from_spec(spec);spec.loader.exec_module(osr)
class OsReinstall(unittest.TestCase):
 def test_failed_or_oversized_download_never_poison_the_verified_cache(self):
  with tempfile.TemporaryDirectory() as d:
   target=Path(d)/'verified-image';target.write_bytes(b'previous verified bytes')
   with patch.object(osr.urllib.request,'urlopen',return_value=io.BytesIO(b'too large')):
    with self.assertRaisesRegex(ValueError,'size'):osr.download('https://example.invalid/image',target,2)
   self.assertEqual(b'previous verified bytes',target.read_bytes());self.assertFalse(target.with_name(target.name+'.download').exists())
   with patch.object(osr.urllib.request,'urlopen',return_value=io.BytesIO(b'ok')):osr.download('https://example.invalid/image',target,2)
   self.assertEqual(b'ok',target.read_bytes())
 def test_changed_vendor_source_is_rejected_before_preparation(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);shutil.copytree(ROOT/'reinstall',p/'adapter');f=p/'adapter/vendor/trans.sh';f.write_text(f.read_text()+'\n# changed\n')
   with self.assertRaisesRegex(ValueError,'integrity'):osr.patched_vendor(p,dict(job='a'*32,version='24.04'),'https://cloud-images.ubuntu.com/image.img','b'*64)
 def test_review_expiry_confirmation_and_machine_changes_cannot_start_a_wipe(self):
  with tempfile.TemporaryDirectory() as d,patch.object(osr,'BASE',Path(d)),patch.object(osr,'call') as call:
   p=Path(d);base=dict(token='reviewed',job='a'*32,version='24.04',scope={'machine':'first'},expires=10**12);(p/'plan.json').write_text(json.dumps(base))
   for req,current in [({'token':'other','confirmation':osr.CONFIRM},{'machine':'first'}),({'token':'reviewed','confirmation':'DELETE VPN'},{'machine':'first'}),({'token':'reviewed','confirmation':osr.CONFIRM},{'machine':'replacement'})]:
    with patch.object(osr,'inspect',return_value=current),self.assertRaises(ValueError):osr.start(req)
   base['expires']=0;(p/'plan.json').write_text(json.dumps(base))
   with self.assertRaises(ValueError):osr.start({'token':'reviewed','confirmation':osr.CONFIRM})
   call.assert_not_called();self.assertFalse((p/('a'*32)).exists())
 def test_status_identifiers_cannot_escape_job_storage(self):
  for value in ('../etc','a;id','',None):
   with self.assertRaises((ValueError,TypeError)):osr.read_status(value)
 def test_background_start_failure_removes_the_password_and_records_no_reboot(self):
  with tempfile.TemporaryDirectory() as d,patch.object(osr,'BASE',Path(d)):
   p=Path(d);job='a'*32;scope=dict(machine='fixture',ssh_port=22)
   (p/'plan.json').write_text(json.dumps(dict(token='reviewed',job=job,version='24.04',scope=scope,expires=10**12,fingerprint='fixture-pin')))
   planned=p/('planned-'+job);planned.mkdir()
   for name in ('ssh_host_ecdsa_key','ssh_host_ecdsa_key.pub'):(planned/name).write_text('disposable fixture')
   with patch.object(osr,'secure_base'),patch.object(osr,'inspect',return_value=scope),patch.object(osr,'call',side_effect=ValueError('Background service unavailable')) as command:
    with self.assertRaises(ValueError):osr.start(dict(token='reviewed',confirmation=osr.CONFIRM,password='temporary-secret'))
   self.assertFalse((p/job/'password').exists());self.assertEqual('failed',osr.read_status(job)['state'])
   self.assertEqual(1,command.call_count);self.assertEqual('systemd-run',command.call_args.args[0][0])
   self.assertNotIn('temporary-secret',json.dumps(command.call_args.args));self.assertNotIn('reboot',command.call_args.args[0])
 def test_unverified_ubuntu_signature_cannot_prepare_boot_or_reboot(self):
  with tempfile.TemporaryDirectory() as d,patch.object(osr,'BASE',Path(d)):
   p=Path(d);job='a'*32;folder=p/job;folder.mkdir()
   (folder/'request.json').write_text(json.dumps(dict(job=job,version='24.04',scope=dict(arch='x86_64'))))
   (folder/'status.json').write_text(json.dumps(dict(job=job,state='preparing',stage=0)))
   (folder/'password').write_text('temporary-secret')
   def command(args,**kw):
    if args[0]=='gpgv':raise ValueError('Ubuntu signature verification failed')
   with patch.object(osr,'call',side_effect=command) as calls,patch.object(osr.urllib.request,'urlopen',return_value=io.BytesIO(b'<a href="release-20260101/">')),patch.object(osr,'download'),patch.object(osr,'prepare_boot') as boot,patch.object(osr,'patched_vendor') as vendor:
    osr.worker(job)
   self.assertEqual('failed',osr.read_status(job)['state']);self.assertFalse((folder/'password').exists())
   boot.assert_not_called();vendor.assert_not_called();self.assertFalse(any('reboot' in c.args[0] for c in calls.call_args_list))
 def test_future_versions_are_not_silently_added_to_the_destructive_image_selector(self):
  with patch.object(osr,'inspect') as inspect:
   with self.assertRaises(ValueError):osr.plan(dict(version='28.04'))
   inspect.assert_not_called()
 def test_patches_are_deterministic_and_provision_a_future_identity_without_secret_arguments(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);shutil.copytree(ROOT/'reinstall',p/'adapter')
   for name in ('ssh_host_ecdsa_key','ssh_host_ecdsa_key.pub'):(p/name).write_text('test fixture')
   vendor,configs=osr.patched_vendor(p,dict(job='a'*32,version='24.04'),'https://cloud-images.ubuntu.com/image.img','b'*64)
   script=(vendor/'rook-reinstall.sh').read_text();boot=(vendor/'trans.sh').read_text()
   self.assertIn('password=$(cat "$2")',script);self.assertNotIn('echo "Password: $password',script)
   self.assertIn('Acquire::Retries=3',boot);self.assertNotIn('AllowUnauthenticated',boot);self.assertNotIn('Verify-Peer=false',boot);self.assertIn('chattr +C $swapfile 2>/dev/null || true',boot)
   self.assertIn('b'*64+'  $qcow_file',boot);self.assertIn('/configs/rook/ssh_host_ecdsa_key',boot)
   self.assertNotIn('reinstall/main',script.splitlines()[8]);self.assertEqual('a'*32,json.loads((configs/'result.json').read_text())['job'])
