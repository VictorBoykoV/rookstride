import html
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('license_page',Path(__file__).resolve().parents[1]/'scripts/license_page.py')
page=importlib.util.module_from_spec(spec);spec.loader.exec_module(page)

class GroupedLicensing(unittest.TestCase):
    def fixture(self,root):
        for name in ('LICENSE','NOTICE.md','gateway/LICENSE','twohop/LICENSE','licenses/strongSwan-COPYING','licenses/JSch-LICENSE.txt'):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('Full notice '+name+'\nCopyright <example>')
        for folder in ('sources','route-sources'):
            p=root/'.tools/native-engines'/folder/'manifest.json';p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text(json.dumps(dict(go_license='Go full license',modules=[dict(module='github.com/owner/component@1',licenses=[dict(path='LICENSE',text='Shared full text')]),dict(module='github.com/second/component@2',licenses=[dict(path='NOTICE',text='Shared full text')])],extra_licenses=[dict(path='tools/license',text='Tool full notice')])) )
    def test_every_full_notice_and_attribution_remains_available(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);output=html.unescape(page.render(root))
            for record in page.records(root):
                self.assertIn(record['text'],output);self.assertIn(record['owner'],output)
            self.assertEqual(1,output.count('<pre>Shared full text</pre>'))
    def test_four_collapsed_groups_and_no_active_content(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);output=page.render(root)
            self.assertEqual(4,output.count('data-license-group='));self.assertNotRegex(output,r'<details\b[^>]*\sopen(?:\s|=|>)')
            self.assertNotIn('<script',output);self.assertNotIn('<iframe',output);self.assertIn('&lt;example&gt;',output)
            self.assertIn('IKEv2 · strongSwan',output)

if __name__=='__main__':unittest.main()
