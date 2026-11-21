#!/usr/bin/env python3
"""Build the public OpenVPN3 API and original JNI bridge against static OpenSSL."""
import os,platform,subprocess,tarfile,shutil,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines';BUILD=ROOT/'.build/native-engines';OUT=CACHE/'output/jniLibs'
SDK=Path(os.environ.get('ROOKSTRIDE_SDK',ROOT/'.tools/sdk')).resolve();NDK=Path(os.environ.get('ANDROID_NDK_HOME',SDK/'ndk/27.3.13750724'))
BIN=NDK/'toolchains/llvm/prebuilt'/('darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64')/'bin'
CORE=CACHE/'ovpn3';ASIO=CACHE/'asio/asio/include';JOBS=os.environ.get('ROOKSTRIDE_BUILD_JOBS','2')
def run(args,**kwargs):subprocess.run([str(x) for x in args],check=True,**kwargs)
for abi,target,triple in [('arm64-v8a','android-arm64','aarch64-linux-android'),('armeabi-v7a','android-arm','armv7a-linux-androideabi'),('x86_64','android-x86_64','x86_64-linux-android')]:
 ssl=BUILD/('openssl-'+abi);ssl.mkdir(parents=True,exist_ok=True)
 if not (ssl/'Configure').exists():
  with tarfile.open(ROOT/'.tools/openssl.tar.gz') as t:
   for m in t.getmembers():
    if m.isfile():
     tail=Path(*Path(m.name).parts[1:]);p=ssl/tail;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(t.extractfile(m).read());p.chmod(m.mode&0o777)
 env=dict(os.environ,ANDROID_NDK_HOME=str(NDK),ANDROID_NDK_ROOT=str(NDK),PATH=str(BIN)+os.pathsep+os.environ['PATH'])
 if not (ssl/'libssl.a').exists():
  run(['./Configure',target,'no-shared','no-tests','no-dso','no-module','-fPIC','-O2','-D__ANDROID_API__=26'],cwd=ssl,env=env)
  run(['make','-j'+JOBS,'build_generated','libssl.a','libcrypto.a'],cwd=ssl,env=env)
 out=OUT/abi;out.mkdir(parents=True,exist_ok=True)
 common=[BIN/(triple+'26-clang++'),'-fPIC','-O2','-std=c++17','-fexceptions','-frtti','-fvisibility=hidden','-DASIO_STANDALONE','-DUSE_ASIO','-DUSE_OPENSSL','-DOPENVPN_DISABLE_LZO','-DGIT_VERSION_STRING="rookstride-pinned"','-I'+str(CORE),'-I'+str(ASIO),'-I'+str(ssl/'include')]
 objects=[]
 for source in [CORE/'client/ovpncli.cpp',CORE/'openvpn/crypto/data_epoch.cpp',ROOT/'android/engines/native/openvpn.cpp']:
  obj=BUILD/('openvpn-'+abi)/(source.stem+'.o');obj.parent.mkdir(parents=True,exist_ok=True);stamp=obj.with_suffix('.sha256')
  identity=hashlib.sha256(source.read_bytes()+json.dumps([str(x) for x in common]).encode()+(ROOT/'android/engines/pins.json').read_bytes()).hexdigest()
  if not obj.exists() or not stamp.exists() or stamp.read_text()!=identity:
   run(common+['-c',source,'-o',obj]);stamp.write_text(identity)
  objects.append(obj)
 run([BIN/(triple+'26-clang++'),'-shared',*objects,ssl/'libssl.a',ssl/'libcrypto.a','-llog','-lz','-static-libstdc++','-Wl,--no-undefined','-Wl,--exclude-libs,ALL','-Wl,-Bsymbolic','-Wl,-z,max-page-size=16384','-Wl,-z,common-page-size=16384','-o',out/'librook-openvpn.so'])
 print('Built OpenVPN',abi,flush=True)
