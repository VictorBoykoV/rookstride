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
parser.add_argument('--abi',action='append',choices=['arm64-v8a','armeabi-v7a','x86_64'],help='Expected packaged ABI; default expects all three')
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
    expected_assets={'assets/engine-info.json','assets/routes-engine-info.json','assets/server-runtime/pins.json','assets/server-runtime/x86_64/runtime.bin','assets/server-runtime/aarch64/runtime.bin','assets/app-guide.html','assets/guide-en-full.html','assets/guide-en.html','assets/guide-ru.html','assets/guide-fa.html','assets/guide-ar.html','assets/guide-zh-Hans.html','assets/guide.html','assets/licenses.html','assets/single_bundle.zip','assets/reinstall_bundle.zip','assets/gateway_bundle.zip','assets/gateway_bundle.sha256','assets/dexopt/baseline.prof','assets/dexopt/baseline.profm'}
    assert all(not name.startswith('assets/') or name in expected_assets for name in apk.namelist()),'Unexpected packaged asset; review before publication'
    from license_page import render as render_licenses
    assert apk.read('assets/licenses.html').decode('utf-8')==render_licenses(ROOT),'License document differs from complete grouped notices'
    libraries=[n for n in apk.namelist() if n.startswith('lib/') and n.endswith('.so')]
    assert {n.split('/')[1] for n in libraries}==set(args.abi or ['arm64-v8a','armeabi-v7a','x86_64'])
    for name in libraries:
        path=Path(stage)/name.replace('/','-');path.write_bytes(apk.read(name))
        headers=output(reader,'--program-headers','--wide',path).splitlines()
        loads=[line.split() for line in headers if line.strip().startswith('LOAD ')]
        relro=[line.split() for line in headers if line.strip().startswith('GNU_RELRO ')]
        assert loads and all(int(row[-1],16)>=16384 for row in loads),'LOAD alignment: '+name
        assert all((int(row[2],16)+int(row[5],16))%16384==0 for row in relro),'RELRO alignment: '+name
    engines=json.loads(apk.read('assets/engine-info.json'))
    assert engines['sources']==json.loads((ROOT/'android/engines/pins.json').read_text())['sources'],'Engine provenance differs'
    for abi in (args.abi or ['arm64-v8a','armeabi-v7a','x86_64']):
        for name in ('librook-awg.so','librook-openvpn.so','libgojni.so','librook-routes.so','librook-files.so'):
            assert 'lib/'+abi+'/'+name in apk.namelist(),'Embedded connection engine missing: '+abi+'/'+name
    worker_info=json.loads(apk.read('assets/routes-engine-info.json'))
    for abi in (args.abi or ['arm64-v8a','armeabi-v7a','x86_64']):
        record=worker_info['outputs']['jniLibs/'+abi+'/librook-routes.so']
        assert hashlib.sha256(apk.read('lib/'+abi+'/librook-routes.so')).hexdigest()==record['sha256'],'Worker binary differs'
    runtime_pins=json.loads((ROOT/'single/routes-pins.json').read_text())
    assert json.loads(apk.read('assets/server-runtime/pins.json'))==runtime_pins
    for machine,record in runtime_pins['assets'].items():
        raw=apk.read('assets/server-runtime/'+machine+'/runtime.bin')
        assert len(raw)==record['archive_bytes'] and hashlib.sha256(raw).hexdigest()==record['archive_sha256'],'Server runtime differs'
    with zipfile.ZipFile(io.BytesIO(apk.read('assets/gateway_bundle.zip'))) as bundle:
        for folder in ('gateway','server','twohop','single'):
            for path in (ROOT/folder).rglob('*'):
                if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pyc','.log'):
                    assert bundle.read(path.relative_to(ROOT).as_posix())==path.read_bytes(),'Embedded source differs: '+str(path.relative_to(ROOT))
    with zipfile.ZipFile(io.BytesIO(apk.read('assets/reinstall_bundle.zip'))) as reinstall:
        paths=[path for path in (ROOT/'reinstall').rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc']
        expected={path.relative_to(ROOT).as_posix() for path in paths}
        assert set(reinstall.namelist())==expected and len(reinstall.namelist())==len(expected),'OS recipe has missing, duplicate or unexpected files'
        for path in paths:
            assert reinstall.read(path.relative_to(ROOT).as_posix())==path.read_bytes(),'OS recipe source differs: '+str(path.relative_to(ROOT))
        upstream=json.loads(reinstall.read('reinstall/upstream.json'))
        for name,digest in upstream['files'].items():
            assert hashlib.sha256(reinstall.read('reinstall/vendor/'+name)).hexdigest()==digest,'Pinned reinstall vendor differs: '+name
    with zipfile.ZipFile(io.BytesIO(apk.read('assets/single_bundle.zip'))) as single:
        for path in (ROOT/'single').rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':assert single.read(path.relative_to(ROOT).as_posix())==path.read_bytes(),'Single recipe differs: '+str(path.relative_to(ROOT))
        assert single.read('server/reset.py')==(ROOT/'server/reset.py').read_bytes(),'Owned IKEv2 reset helper differs'
        assert single.read('server/ike_packages.py')==(ROOT/'server/ike_packages.py').read_bytes(),'Owned IKE package helper missing or changed'
        # Import the exact limited single-server bundle in isolation. Comparing
        # present files alone cannot detect a newly omitted reset dependency.
        recipe=Path(stage)/'single-recipe'
        required=[p for p in (ROOT/'single').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc']+[ROOT/'server/reset.py',ROOT/'server/ike_packages.py']
        for source in required:
            relative=source.relative_to(ROOT);target=recipe/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(single.read(relative.as_posix()))
        output(sys.executable,'-I','-c','import sys;sys.path.insert(0,sys.argv[1]);import reset_server',recipe/'single')
    import importlib.util
    spec=importlib.util.spec_from_file_location('audit_pair',ROOT/'server/pair.py');pair_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair_module)
    assert apk.read('assets/gateway_bundle.sha256').decode().strip()==pair_module.source_digest(ROOT),'Installer identity differs'
    assert apk.read('assets/guide.html')==(ROOT/'android/overlay/assets/guide.html').read_bytes()
    for name in ('guide-en-full.html','guide-en.html','guide-ru.html','guide-fa.html','guide-ar.html','guide-zh-Hans.html'):
        assert apk.read('assets/'+name)==(ROOT/'android/overlay/assets'/name).read_bytes(),'Embedded guide differs: '+name
    assert not any(name.startswith('assets/stories/') for name in apk.namelist()),'Journal edition must not bundle comics'

print(json.dumps({'release':release['name'],'sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),
                  'signer_sha256':signer.group(1),'native_libraries':len(libraries),
                  'zip_load_relro_16k_aligned':True,'embedded_source_matches':True,'reinstall_source_and_vendor_match':True,'offline_story_files':0,'journal':'native-placeholder-no-endpoint','non_debuggable':True},indent=2))
