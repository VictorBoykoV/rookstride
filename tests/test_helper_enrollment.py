"""Durable service references must survive disposal of the app's SSH upload."""
import importlib.util,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'));import runtime
spec=importlib.util.spec_from_file_location('enrollment_api',ROOT/'single/run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
class HelperEnrollment(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.upload=self.root/'upload';shutil.copytree(ROOT/'single',self.upload/'single',ignore=shutil.ignore_patterns('__pycache__'));(self.upload/'server').mkdir()
  for name in api.SERVER_HELPERS:shutil.copy2(ROOT/'server'/name,self.upload/'server'/name)
  self.patches=[patch.object(api,'__file__',str(self.upload/'single/run.py')),patch.object(api,'PAIR_SOURCE',self.root/'pair/single'),patch.object(api,'PAIR_MANIFEST',self.root/'pair/manifest.json'),patch.object(runtime,'ROOT',self.root/'installed'),patch.object(runtime,'STATE',self.root/'state'),patch.object(runtime,'HELPER',None)]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def test_service_helper_survives_the_temporary_upload(self):
  expected=api.digest(self.upload/'single');release=api.prepare_helper();helper=runtime.helper_path();self.assertEqual(expected,release.parent.name);self.assertEqual(release/'run.py',helper);self.assertEqual(release.parent.resolve(),(runtime.ROOT/'current').resolve());shutil.rmtree(self.upload);self.assertTrue(helper.is_file());self.assertEqual(expected,api.digest(release))
  subprocess.run([sys.executable,'-I','-c','import sys;sys.path.insert(0,sys.argv[1]);import reset_server',str(release)],check=True,capture_output=True)
 def test_reset_dependency_participates_in_identity_and_integrity(self):
  release=api.prepare_helper();previous=api.digest(self.upload/'single');source=self.upload/'server/ike_packages.py';source.write_text(source.read_text()+'\n# changed dependency\n');self.assertNotEqual(previous,api.digest(self.upload/'single'))
  source.write_bytes((ROOT/'server/ike_packages.py').read_bytes());(release.parent/'server/ike_packages.py').write_text('changed by another actor')
  with self.assertRaisesRegex(ValueError,'integrity changed'):api.prepare_helper()
 def test_changed_enrolled_source_is_never_overwritten(self):
  release=api.prepare_helper();(release/'model.py').write_text('changed by another actor')
  with self.assertRaisesRegex(ValueError,'integrity changed'):api.prepare_helper()
  self.assertEqual('changed by another actor',(release/'model.py').read_text())
 def test_interrupted_copy_does_not_publish_a_partial_release(self):
  with patch.object(api.shutil,'copytree',side_effect=OSError('simulated storage failure')):
   with self.assertRaises(OSError):api.prepare_helper()
  self.assertEqual([],list((runtime.ROOT/'releases').iterdir()));self.assertTrue(api.prepare_helper().is_dir())
 def test_pair_updates_require_the_exact_enrolled_pair_source(self):
  api.PAIR_MANIFEST.parent.mkdir();api.PAIR_MANIFEST.write_text('{}')
  with self.assertRaisesRegex(ValueError,'another installer version'):api.prepare_helper()
  self.assertFalse(runtime.ROOT.exists());shutil.copytree(self.upload/'single',api.PAIR_SOURCE);shutil.copytree(self.upload/'server',api.PAIR_SOURCE.parent/'server');self.assertEqual(api.PAIR_SOURCE,api.prepare_helper());self.assertFalse(runtime.ROOT.exists())
 def test_read_only_inspection_does_not_enroll_or_upgrade_helpers(self):
  runtime.STATE.mkdir()
  with patch.object(api,'inspect',return_value={}),patch.object(api.filtering,'inspect',return_value={}),patch.object(api,'prepare_helper') as enrolled:
   api.action({'action':'inspect'});enrolled.assert_not_called()
if __name__=='__main__':unittest.main()
