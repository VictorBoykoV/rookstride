#!/usr/bin/env python3
"""Build the protected VPN worker and reproducible phone-to-VPS payloads."""
import gzip,hashlib,io,json,os,platform,subprocess,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines';OUT=CACHE/'output/routes';OUT.mkdir(parents=True,exist_ok=True)
GO=os.environ.get('ROOKSTRIDE_ROUTES_GO',str(CACHE/'go-sdk/bin/go'))
ENV=dict(os.environ,GOTOOLCHAIN='go1.26.8',GOPATH=str(CACHE/'routes-gopath'),GOCACHE=str(CACHE/'routes-gocache'),GOMAXPROCS='2')
SOURCE=ROOT/'android/engines/routes';TAGS='with_quic,with_naive_outbound,with_utls'
SDK=Path(os.environ.get('ROOKSTRIDE_SDK',str(ROOT/'.tools/sdk')));NDK=SDK/'ndk/30.0.16248370'
HOST='darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64';BIN=NDK/'toolchains/llvm/prebuilt'/HOST/'bin'
def run(args,env):subprocess.run([str(x) for x in args],cwd=SOURCE,env=env,check=True)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
selected=set(sys.argv[1:] or ['android','linux']);outputs={}
source_digest=hashlib.sha256()
for path in sorted([*SOURCE.glob('*.go'),SOURCE/'go.mod',SOURCE/'go.sum']):source_digest.update(path.name.encode()+b'\0'+path.read_bytes()+b'\0')
source_hash=source_digest.hexdigest()
if 'android' in selected:
 for abi,arch,cc in [('arm64-v8a','arm64','aarch64-linux-android26-clang'),('armeabi-v7a','arm','armv7a-linux-androideabi26-clang'),('x86_64','amd64','x86_64-linux-android26-clang')]:
  folder=OUT/'jniLibs'/abi;folder.mkdir(parents=True,exist_ok=True);dest=folder/'librook-routes.so'
  env=dict(ENV,GOOS='android',GOARCH=arch,CGO_ENABLED='1',CC=str(BIN/cc),CXX=str(BIN/cc.replace('-clang','-clang++')),CGO_LDFLAGS='-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384')
  if arch=='arm':env['GOARM']='7'
  run([GO,'build','-tags',TAGS,'-p','2','-trimpath','-buildvcs=false','-buildmode=pie','-ldflags=-s -w -buildid=','-o',dest,'.'],env)
  outputs[str(dest.relative_to(OUT))]={'sha256':digest(dest),'bytes':dest.stat().st_size}
if 'linux' in selected:
 pins=json.loads((ROOT/'single/routes-pins.json').read_text());assets={}
 for machine,arch in [('x86_64','amd64'),('aarch64','arm64')]:
  folder=OUT/'linux'/machine;folder.mkdir(parents=True,exist_ok=True);dest=folder/'rook-routes'
  run([GO,'build','-tags',TAGS+',with_purego,with_gvisor','-p','2','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',dest,'.'],dict(ENV,GOOS='linux',GOARCH=arch,CGO_ENABLED='0'))
  libraries=list((CACHE/'routes-gopath/pkg/mod/github.com/sagernet/cronet-go/lib').glob('linux_'+arch+'@*/libcronet.so'))
  if len(libraries)!=1:raise SystemExit('Expected exactly one pinned Cronet module')
  library=folder/'libcronet.so';library.write_bytes(libraries[0].read_bytes());library.chmod(0o700)
  archive=folder/'runtime.tar.gz'
  with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0,filename='') as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
   for p in (dest,library):
    info=tarfile.TarInfo(p.name);info.size=p.stat().st_size;info.mode=0o700;info.mtime=0;tar.addfile(info,io.BytesIO(p.read_bytes()))
  assets[machine]={'sha256':digest(dest),'bytes':dest.stat().st_size,'archive_sha256':digest(archive),'archive_bytes':archive.stat().st_size,'library_sha256':digest(library),'library_bytes':library.stat().st_size}
 pins['assets']=assets;pins['source_sha256']=source_hash;pins['linux_build_tags']=TAGS+',with_purego,with_gvisor';(ROOT/'single/routes-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
info={'worker':'rookstride-routes-1','go':'go1.26.8','ndk':'30.0.16248370','source_sha256':source_hash,'sing_box':'v1.14.3','outline_sdk':'v0.0.23','cronet':'150.0.7871.63','cronet_build':'upstream-prebuilt','go_sum_sha256':digest(SOURCE/'go.sum'),'outputs':outputs}
if 'android' in selected:(OUT/'android-info.json').write_text(json.dumps(info,indent=2)+'\n')
print('Built:',','.join(sorted(selected)))
