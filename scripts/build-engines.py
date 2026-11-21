#!/usr/bin/env python3
"""Compile pinned native VPN engines for the app's three Android ABIs."""
import json,os,platform,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/'.tools/native-engines';BUILD=ROOT/'.build/native-engines';OUT=CACHE/'output'
BUILD.mkdir(parents=True,exist_ok=True);OUT.mkdir(exist_ok=True)
PINS=json.loads((ROOT/'android/engines/pins.json').read_text())
ENV=dict(os.environ)
GO=ENV.get('ROOKSTRIDE_GO','go')
ENV['GOTOOLCHAIN']=PINS['go_toolchain']
ENV.setdefault('GOPATH',str(CACHE/'gopath'));ENV.setdefault('GOCACHE',str(CACHE/'gocache'))
SDK=Path(ENV.get('ROOKSTRIDE_SDK',ROOT/'.tools/sdk')).resolve()
NDK=Path(ENV.get('ANDROID_NDK_HOME',SDK/'ndk/27.3.13750724'))
HOST='darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64'
BIN=NDK/'toolchains/llvm/prebuilt'/HOST/'bin'
ENV['ANDROID_HOME']=str(SDK);ENV['ANDROID_NDK_HOME']=str(NDK)
ENV['PATH']=str(Path(ENV['GOPATH'])/'bin')+os.pathsep+str(Path(GO).resolve().parent)+os.pathsep+ENV.get('PATH','')
if ENV.get('JAVA_HOME'):ENV['PATH']=str(Path(ENV['JAVA_HOME'])/'bin')+os.pathsep+ENV['PATH']
ENV['GOMAXPROCS']=ENV.get('ROOKSTRIDE_BUILD_JOBS','2')
ENV['GOFLAGS']='-p=2'
def run(args,cwd=None,env=None):subprocess.run([str(x) for x in args],cwd=cwd,env=env or ENV,check=True)
def stage(name,sub=''):
 d=BUILD/name
 if d.exists():shutil.rmtree(d)
 shutil.copytree(CACHE/name/sub,d)
 return d
selected=set(sys.argv[1:] or ['awg','xray','openvpn'])
if 'xray' in selected:run(['javac','-version'])
if 'awg' in selected:
 d=stage('awg-android','tunnel/tools/libwg-go')
 # Upstream may have no UAPI socket in an Android sandbox; cleanup must tolerate it.
 p=d/'api-android.go';s=p.read_text();s=s.replace('uapiFile.Close()','if uapiFile != nil { uapiFile.Close() }');p.write_text(s)
 for abi,arch,cc in [('arm64-v8a','arm64','aarch64-linux-android26-clang'),('armeabi-v7a','arm','armv7a-linux-androideabi26-clang'),('x86_64','amd64','x86_64-linux-android26-clang')]:
  o=OUT/'jniLibs'/abi;o.mkdir(parents=True,exist_ok=True)
  e=dict(ENV,GOOS='android',GOARCH=arch,CGO_ENABLED='1',CC=str(BIN/cc),CGO_CFLAGS='-O2',CGO_LDFLAGS='-Wl,-soname,librook-awg.so -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384')
  if arch=='arm':e['GOARM']='7'
  run([GO,'build','-tags','linux','-trimpath','-buildvcs=false','-buildmode=c-shared','-ldflags=-s -w -buildid=','-o',o/'librook-awg.so'],d,e)
if 'xray' in selected:
 d=stage('libxray');shutil.copy2(ROOT/'android/engines/native/xray_memory.go',d/'rookstride_memory.go');mobile='v0.0.0-20260217195705-b56b3793a9c4'
 run([GO,'install','golang.org/x/mobile/cmd/gomobile@'+mobile],d)
 run([GO,'install','golang.org/x/mobile/cmd/gobind@'+mobile],d)
 (Path(ENV['GOPATH'])/'pkg/gomobile').mkdir(parents=True,exist_ok=True)
 # Avoid upstream geo downloads: generated full-tunnel profiles use no geo rules.
 run([Path(ENV['GOPATH'])/'bin/gomobile','bind','-target=android/arm64,android/arm,android/amd64','-androidapi=26','-javapkg=org.rookstride.engine.xray','-o',OUT/'libxray.aar','-ldflags=-s -w -buildid= -checklinkname=0 -extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384','-trimpath'],d)
if 'openvpn' in selected:
 run([sys.executable,ROOT/'scripts/build-openvpn.py'])
print('Native engines built:',','.join(sorted(selected)))
