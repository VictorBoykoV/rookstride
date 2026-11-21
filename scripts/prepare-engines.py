#!/usr/bin/env python3
"""Copy verified source-built engines into the prepared Android project."""
import hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines';OUT=CACHE/'output';APP=ROOT/'.tools/strongswan-source/src/frontends/android/app';MAIN=APP/'src/main'
pins=json.loads((ROOT/'android/engines/pins.json').read_text())
source=ROOT/'android/engines/routes';digest=hashlib.sha256()
for path in sorted([*source.glob('*.go'),source/'go.mod',source/'go.sum']):digest.update(path.name.encode()+b'\0'+path.read_bytes()+b'\0')
worker_info=json.loads((OUT/'routes/android-info.json').read_text());server_info=json.loads((ROOT/'single/routes-pins.json').read_text())
if worker_info.get('source_sha256')!=digest.hexdigest() or server_info.get('source_sha256')!=digest.hexdigest():raise SystemExit('Rebuild the worker from the current exact source before packaging')
required=[OUT/'libxray.aar']+[OUT/'jniLibs'/abi/name for abi in ('arm64-v8a','armeabi-v7a','x86_64') for name in ('librook-awg.so','librook-openvpn.so')]
route_required=[OUT/'routes/jniLibs'/abi/'librook-routes.so' for abi in ('arm64-v8a','armeabi-v7a','x86_64')]
required+=route_required
if any(not p.is_file() or p.stat().st_size==0 for p in required):raise SystemExit('Build pinned VPN engines first: scripts/bootstrap-engines.py; scripts/build-engines.py')
for p in required[1:]:
 dest=MAIN/'jniLibs'/p.parent.name/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
libs=APP/'rookstride-libs';libs.mkdir(exist_ok=True);shutil.copy2(OUT/'libxray.aar',libs/'libxray.aar')
java=CACHE/'awg-android/tunnel/src/main/java/org/amnezia/awg';dest=MAIN/'java/org/amnezia/awg'
for name in ('config','crypto'):
 shutil.copytree(java/name,dest/name,dirs_exist_ok=True)
(dest/'util').mkdir(exist_ok=True);shutil.copy2(java/'util/NonNullForAll.java',dest/'util/NonNullForAll.java');shutil.copy2(java/'GoBackend.java',dest/'GoBackend.java')
info={'sources':pins['sources'],'go_toolchain':pins['go_toolchain'],'outputs':{str(p.relative_to(OUT)):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in required}}
(MAIN/'assets/engine-info.json').write_text(json.dumps(info,indent=2)+'\n')
shutil.copy2(OUT/'routes/android-info.json',MAIN/'assets/routes-engine-info.json')
dest=MAIN/'assets/server-runtime'
# Android's asset merger decompresses .gz files and strips that suffix. Keep
# the pinned gzip stream under a neutral name, exactly as SFTP uploads it.
if dest.exists():shutil.rmtree(dest)
dest.mkdir(exist_ok=True)
runtime=json.loads((ROOT/'single/routes-pins.json').read_text())
for machine,asset in runtime['assets'].items():
 source=OUT/'routes/linux'/machine/'runtime.tar.gz'
 if hashlib.sha256(source.read_bytes()).hexdigest()!=asset['archive_sha256']:raise SystemExit('Server runtime pin changed')
 target=dest/machine;target.mkdir(exist_ok=True);shutil.copy2(source,target/'runtime.bin')
shutil.copy2(ROOT/'single/routes-pins.json',dest/'pins.json')
print('Prepared source-built AWG, Xray and OpenVPN Android engines')
