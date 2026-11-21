"""Release eligibility is capability-based; evidence is not an allowlist."""
import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'single'))
import ubuntu_support
import runtime,ssl
from unittest.mock import patch,Mock

class UbuntuSupportTests(unittest.TestCase):
 def fixture(self,root,version,identity='ubuntu'):
  (root/'etc').mkdir(exist_ok=True)
  (root/'etc/os-release').write_text('ID='+identity+'\nVERSION_ID="'+version+'"\n')
  (root/'run/systemd/system').mkdir(parents=True,exist_ok=True)
  for name in ubuntu_support.REQUIRED:
   path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.touch()
 def test_lts_point_interim_and_future_releases_are_assessed(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   for release in ('22.04','22.04.5','24.04','26.04','26.10','28.04'):
    self.fixture(root,release);value=ubuntu_support.assess(root)
    self.assertTrue(value['eligible'],value)
    self.assertIn('prerequisites only',value['assessment'])
   self.assertFalse(ubuntu_support.assess(root)['release_matrix'])
 def test_other_distributions_old_and_invalid_versions_are_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   for identity,version in [('debian','13'),('ubuntu','20.04'),('ubuntu','rolling'),('ubuntu','26.04;reboot')]:
    self.fixture(root,version,identity);self.assertFalse(ubuntu_support.assess(root)['eligible'])
 def test_missing_package_manager_or_systemd_is_actionable(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);self.fixture(root,'26.04')
   (root/'usr/bin/apt-get').unlink()
   self.assertIn('Required server component is missing: apt-get',ubuntu_support.assess(root)['errors'])
   (root/'run/systemd/system').rmdir()
   self.assertIn('A running systemd VPS is required',ubuntu_support.assess(root)['errors'])
 def test_ikev2_and_native_recipes_use_identical_eligibility(self):
  self.assertEqual((ROOT/'single/ubuntu_support.py').read_bytes(),(ROOT/'gateway/scripts/ubuntu_support.py').read_bytes())
 def test_reference_probe_keeps_certificate_and_hostname_verification(self):
  context=runtime.probe_tls_context()
  self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
  self.assertTrue(context.check_hostname)
  self.assertGreaterEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
 def test_new_groups_are_selected_only_where_the_new_ec_api_is_available(self):
  for version in ((1,1,1),(3,0,2),(3,5,5),(4,0,3)):
   context=Mock()
   with patch.object(runtime.ssl,'OPENSSL_VERSION_INFO',version),patch.object(runtime.ssl,'create_default_context',return_value=context):
    self.assertIs(runtime.probe_tls_context(),context)
   if version>=(3,5):context.set_ecdh_curve.assert_called_once_with('X25519')
   else:context.set_ecdh_curve.assert_not_called()

if __name__=='__main__':unittest.main()
