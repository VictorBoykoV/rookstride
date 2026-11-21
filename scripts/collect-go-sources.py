#!/usr/bin/env python3
"""Preserve exact source modules and notices used by the Android Go engines."""
import hashlib,json,os,shutil,subprocess,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines';TARGET=CACHE/'sources';TARGET.mkdir(exist_ok=True)
env=dict(os.environ,GOTOOLCHAIN=json.loads((ROOT/'android/engines/pins.json').read_text())['go_toolchain']);go=env.get('ROOKSTRIDE_GO','go')
SDK=Path(env.get('ROOKSTRIDE_SDK',ROOT/'.tools/sdk')).resolve();host='darwin-x86_64' if __import__('platform').system()=='Darwin' else 'linux-x86_64';cc=SDK/'ndk/27.3.13750724/toolchains/llvm/prebuilt'/host/'bin/aarch64-linux-android26-clang'
modules=set()
for folder,tags in [('awg-android','linux'),('libxray','')]:
 d=ROOT/'.build/native-engines'/folder;e=dict(env,GOOS='android',GOARCH='arm64',CGO_ENABLED='1',CC=str(cc))
 template='{{with .Module}}{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{else}}{{.Path}}@{{.Version}}{{end}}{{end}}'
 args=[go,'list','-deps','-f',template]
 if tags:args+=['-tags',tags]
 result=subprocess.check_output(args,cwd=d,env=e,text=True)
 modules.update(v.strip() for v in result.splitlines() if '@' in v and not v.endswith('@'))
records=[]
for module in sorted(modules):
 v=json.loads(subprocess.check_output([go,'mod','download','-json',module],env=env,text=True));files=[];licenses=[]
 for key,suffix in [('Zip','.zip'),('GoMod','.mod'),('Info','.info')]:
  src=Path(v[key]);name=hashlib.sha256(module.encode()).hexdigest()[:20]+suffix;dest=TARGET/name;shutil.copy2(src,dest);files.append({'path':name,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'bytes':dest.stat().st_size})
  if key=='Zip':
   with zipfile.ZipFile(src) as z:
    for p in z.namelist():
     tail=p.split('/',1)[-1];base=Path(p).name.upper()
     if base.startswith(('LICENSE','COPYING','COPYRIGHT','NOTICE')) and len(z.read(p))<200000:
      text=z.read(p).decode('utf-8',errors='replace');licenses.append({'path':p,'text':text})
 records.append({'module':module,'sum':v.get('Sum'),'go_mod_sum':v.get('GoModSum'),'files':files,'licenses':licenses})
version=subprocess.check_output([go,'version'],env=env,text=True).strip();goroot=Path(subprocess.check_output([go,'env','GOROOT'],env=env,text=True).strip())
manifest={'go':version,'modules':records,'go_license':(goroot/'LICENSE').read_text()}
(TARGET/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('Preserved',len(records),'Go source modules and their license notices')
