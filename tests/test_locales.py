"""Exercise the catalog compiler's stale-review and unsafe-edit rejection boundary."""
import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class LocaleContractTests(unittest.TestCase):
 def setUp(self):
  self.stage=tempfile.TemporaryDirectory(prefix='rookstride-locale-');self.root=Path(self.stage.name)
  (self.root/'scripts').mkdir();shutil.copyfile(ROOT/'scripts/compile-locales.py',self.root/'scripts/compile-locales.py');shutil.copytree(ROOT/'i18n',self.root/'i18n')
  (self.root/'android/overlay/assets').mkdir(parents=True);(self.root/'android/overlay/java/org/strongswan/android/rookstride').mkdir(parents=True);(self.root/'android/overlay/res/xml').mkdir(parents=True)
 def tearDown(self):self.stage.cleanup()
 def run_compiler(self):return subprocess.run(['python3',str(self.root/'scripts/compile-locales.py')],capture_output=True,text=True)
 def change(self,file,key,value):
  path=self.root/'i18n'/file;data=json.loads(path.read_text());data[key]=value;path.write_text(json.dumps(data,ensure_ascii=False))
 def test_reviewed_catalogs_generate_all_locale_resources(self):
  result=self.run_compiler();self.assertEqual(result.returncode,0,result.stderr)
  for tag,qualifier in [('en','values'),('ru','values-ru'),('fa','values-fa'),('ar','values-ar'),('zh-Hans','values-b+zh+Hans')]:
   self.assertTrue((self.root/'android/overlay/res'/qualifier/'rookstride_strings.xml').is_file());page=(self.root/'android/overlay/assets'/('guide-'+tag+'.html')).read_text();self.assertIn('lang="'+tag+'"',page);self.assertNotIn('<script',page)
 def test_source_change_invalidates_every_translation_review(self):
  self.change('en.json','home.intro','Changed meaning for the source.');result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('stale review',result.stderr)
 def test_translation_edit_requires_new_review(self):
  self.change('ru.json','home.intro','Другая формулировка.');result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('unreviewed catalog edit',result.stderr)
 def test_missing_placeholder_is_refused_before_generation(self):
  self.change('fa.json','app.progress_summary','Bad {recipe}');result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('placeholders',result.stderr)
 def test_localized_deletion_phrase_is_refused(self):
  data=json.loads((self.root/'i18n/en.json').read_text());key=next(k for k,v in data.items() if 'DELETE PAIR' in v)
  self.change('ar.json',key,'A phrase without the required confirmation.');result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('confirmation phrase',result.stderr)
 def test_english_plural_change_invalidates_translation_review(self):
  path=self.root/'i18n/plurals-en.json';data=json.loads(path.read_text());data['checkpoints_remaining']['other']='%1$d stages left';path.write_text(json.dumps(data));result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('stale English plural review',result.stderr)
 def test_plural_edit_requires_review(self):
  path=self.root/'i18n/plurals-ru.json';data=json.loads(path.read_text());data['checkpoints_remaining']['one']='%1$d changed';path.write_text(json.dumps(data));result=self.run_compiler();self.assertNotEqual(result.returncode,0);self.assertIn('unreviewed plural edit',result.stderr)
if __name__=='__main__':unittest.main()
