#!/usr/bin/env python3
"""Audit the signed release, native alignment and embedded installer without a device."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('apk',type=Path)
parser.add_argument('--sdk',type=Path,default=Path(os.environ.get('ROOKSTRIDE_SDK',ROOT/'.tools/sdk')))
parser.add_argument('--ndk',type=Path)
parser.add_argument('--build-tools',default='35.0.0')
args=parser.parse_args()
ndk=args.ndk or args.sdk/'ndk/27.3.13750724'
host='darwin-x86_64' if sys.platform=='darwin' else 'linux-x86_64'
reader=ndk/'toolchains/llvm/prebuilt'/host/'bin/llvm-readelf'
tools=args.sdk/'build-tools'/args.build_tools

def output(*command):
    return subprocess.check_output([str(p) for p in command],text=True,stderr=subprocess.STDOUT)

output(tools/'zipalign','-c','-P','16','4',args.apk)
signature=output(tools/'apksigner','verify','--print-certs',args.apk)
signer=re.search(r'Signer #1 certificate SHA-256 digest: ([0-9a-f]+)',signature)
assert signer,'Missing signing certificate'
manifest=output(tools/'aapt2','dump','badging',args.apk)
release=json.loads((ROOT/'release.json').read_text())
assert "name='io.rookstride.android'" in manifest
assert "versionName='"+release['name']+"'" in manifest
assert "versionCode='"+str(release['code'])+"'" in manifest
assert "minSdkVersion:'26'" in manifest and "targetSdkVersion:'36'" in manifest
assert 'application-debuggable' not in manifest,'Release must not be debuggable'
with tempfile.TemporaryDirectory(prefix='rookstride-apk-') as stage,zipfile.ZipFile(args.apk) as apk:
    expected_assets={'assets/guide-en-full.html','assets/guide-en.html','assets/guide-ru.html','assets/guide-fa.html','assets/guide-ar.html','assets/guide-zh-Hans.html','assets/guide.html','assets/licenses.html','assets/gateway_bundle.zip','assets/gateway_bundle.sha256','assets/dexopt/baseline.prof','assets/dexopt/baseline.profm'}
    assert all(not name.startswith('assets/') or name.startswith('assets/stories/') or name in expected_assets for name in apk.namelist()),'Unexpected packaged asset; review before publication'
    libraries=[n for n in apk.namelist() if n.startswith('lib/') and n.endswith('.so')]
    assert {n.split('/')[1] for n in libraries}=={'arm64-v8a','armeabi-v7a','x86_64'}
    for name in libraries:
        path=Path(stage)/name.replace('/','-');path.write_bytes(apk.read(name))
        headers=output(reader,'--program-headers','--wide',path).splitlines()
        loads=[line.split() for line in headers if line.strip().startswith('LOAD ')]
        relro=[line.split() for line in headers if line.strip().startswith('GNU_RELRO ')]
        assert loads and all(int(row[-1],16)>=16384 for row in loads),'LOAD alignment: '+name
        assert all((int(row[2],16)+int(row[5],16))%16384==0 for row in relro),'RELRO alignment: '+name
    with zipfile.ZipFile(io.BytesIO(apk.read('assets/gateway_bundle.zip'))) as bundle:
        for folder in ('gateway','server','twohop'):
            for path in (ROOT/folder).rglob('*'):
                if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pyc','.log'):
                    assert bundle.read(path.relative_to(ROOT).as_posix())==path.read_bytes(),'Embedded source differs: '+str(path.relative_to(ROOT))
    import importlib.util
    spec=importlib.util.spec_from_file_location('audit_pair',ROOT/'server/pair.py');pair_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair_module)
    assert apk.read('assets/gateway_bundle.sha256').decode().strip()==pair_module.source_digest(ROOT),'Installer identity differs'
    assert apk.read('assets/guide.html')==(ROOT/'android/overlay/assets/guide.html').read_bytes()
    for name in ('guide-en-full.html','guide-en.html','guide-ru.html','guide-fa.html','guide-ar.html','guide-zh-Hans.html'):
        assert apk.read('assets/'+name)==(ROOT/'android/overlay/assets'/name).read_bytes(),'Embedded guide differs: '+name
    stories=ROOT/'android/overlay/assets/stories'
    story_files=[p for p in stories.rglob('*') if p.is_file()]
    assert story_files,'Offline story bundle missing'
    for path in story_files:
        assert apk.read('assets/stories/'+path.relative_to(stories).as_posix())==path.read_bytes(),'Embedded story differs: '+str(path.relative_to(stories))
    assert len(list((stories/'worlds').glob('*/*/index.html')))==50,'Expected fifty offline chapters'
    assert len(list((stories/'assets/stories').glob('*/*.webp')))==45,'Expected forty-five new chapter comics'
print(json.dumps({'release':release['name'],'sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),
                  'signer_sha256':signer.group(1),'native_libraries':len(libraries),
                  'zip_load_relro_16k_aligned':True,'embedded_source_matches':True,'offline_story_files':len(story_files),'non_debuggable':True},indent=2))
