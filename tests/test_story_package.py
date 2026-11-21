"""The app story edition must replace stale worlds and keep art/text paired."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_stories',ROOT/'scripts/prepare-stories.py')
package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)


class StoryPackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'persia';self.source.mkdir()
        (self.source/'art').mkdir()
        self.data={'schema':1,'world':{'id':'persia','title':'Persia','subtitle':'Through Iran','seriesTitle':'Rook travels','description':'A story.','cast':[{'id':'rook','name':'Rook','description':'A helpful traveler.'}]},'chapters':[]}
        for c in range(1,3):
            chapter={'id':f'chapter-{c}','number':c,'title':'A chapter','summary':'A summary','lesson':'A lesson','cliffhanger':'What next?','pages':[]}
            for p in range(1,11):
                image=f'art/ch{c:02d}-p{p:02d}.webp';(self.source/image).write_bytes(b'RIFF0000WEBP')
                chapter['pages'].append({'number':p,'image':image,'panels':[{'id':f'c{c}-p{p}-f{f}','scene':'A scene','narration':'Rook listens.','dialogue':[],'alt':'Rook listens to a friend.'} for f in range(1,7)]})
            self.data['chapters'].append(chapter)
        self.write()

    def write(self):
        (self.source/'catalog.json').write_text(json.dumps(self.data))

    def test_replacing_bundle_removes_historical_worlds_and_contains_only_optimized_art(self):
        destination=self.root/'packed';(destination/'worlds/old').mkdir(parents=True)
        (destination/'worlds/old/voice.js').write_text('historical')
        (self.source/'master.png').write_bytes(b'not a runtime asset')
        self.assertEqual((2,20),package.pack(self.source,ROOT/'stories/reader',destination))
        self.assertEqual(24,len([p for p in destination.rglob('*') if p.is_file()]))
        self.assertFalse((destination/'worlds').exists())
        self.assertFalse((destination/'master.png').exists())
        self.assertEqual(self.data,json.loads((destination/'catalog.json').read_text()))

    def test_audit_rejects_residual_runtime_files(self):
        destination=self.root/'packed'
        package.pack(self.source,ROOT/'stories/reader',destination)
        (destination/'voice.js').write_text('stale audio runtime')
        with self.assertRaisesRegex(AssertionError,'current 24-file edition'):
            package.audit_packed(self.source,ROOT/'stories/reader',destination)

    def test_audit_rejects_caption_bytes_that_differ_from_canonical_source(self):
        destination=self.root/'packed'
        package.pack(self.source,ROOT/'stories/reader',destination)
        changed=copy.deepcopy(self.data);changed['chapters'][0]['pages'][0]['panels'][0]['narration']='A stale caption.'
        (destination/'catalog.json').write_text(json.dumps(changed))
        with self.assertRaisesRegex(AssertionError,'Packed story differs: catalog.json'):
            package.audit_packed(self.source,ROOT/'stories/reader',destination)

    def test_symlink_cannot_pull_unreviewed_art_from_outside_source(self):
        image=self.source/'art/ch01-p01.webp';image.unlink()
        outside=self.root/'outside.webp';outside.write_bytes(b'RIFF0000WEBP')
        image.symlink_to(outside)
        with self.assertRaisesRegex(AssertionError,'escape the source tree'):package.validate(self.source)

    def test_missing_caption_is_rejected_before_copy(self):
        panel=self.data['chapters'][0]['pages'][0]['panels'][0]
        panel['narration']='';panel['dialogue']=[];self.write()
        with self.assertRaisesRegex(AssertionError,'readable story text'):package.validate(self.source)

    def test_duplicate_panel_identity_and_asset_traversal_are_rejected(self):
        original=copy.deepcopy(self.data)
        self.data['chapters'][0]['pages'][0]['panels'][1]['id']=self.data['chapters'][0]['pages'][0]['panels'][0]['id'];self.write()
        with self.assertRaises(AssertionError):package.validate(self.source)
        self.data=original;self.data['chapters'][0]['pages'][0]['image']='../private.webp';self.write()
        with self.assertRaisesRegex(AssertionError,'unambiguous'):package.validate(self.source)
