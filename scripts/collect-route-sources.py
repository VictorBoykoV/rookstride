#!/usr/bin/env python3
"""Collect exact modules/notices for each supported worker build target."""
import hashlib,json,os,shutil,subprocess,sys,tarfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines';TARGET=CACHE/'route-sources';TARGET.mkdir(exist_ok=True)
go=os.environ.get('ROOKSTRIDE_ROUTES_GO',str(CACHE/'go-sdk/bin/go'));env=dict(os.environ,GOTOOLCHAIN='go1.26.8',GOPATH=str(CACHE/'routes-gopath'),GOCACHE=str(CACHE/'routes-gocache'),GOMAXPROCS='2')
source=ROOT/'android/engines/routes';ndk=ROOT/'.tools/sdk/ndk/30.0.16248370/toolchains/llvm/prebuilt';host='darwin-x86_64' if __import__('platform').system()=='Darwin' else 'linux-x86_64'
subprocess.run([sys.executable,str(ROOT/'scripts/bootstrap-routes.py'),'--sources-only'],check=True)
modules=set();template='{{with .Module}}{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{else}}{{.Path}}@{{.Version}}{{end}}{{end}}'
for system,arch,cc in [('android','arm64','aarch64-linux-android26-clang'),('android','arm','armv7a-linux-androideabi26-clang'),('android','amd64','x86_64-linux-android26-clang'),('linux','amd64',None),('linux','arm64',None)]:
 e=dict(env,GOOS=system,GOARCH=arch,CGO_ENABLED='1' if cc else '0');tags='with_quic,with_naive_outbound,with_utls'
 if cc:e['CC']=str(ndk/host/'bin'/cc)
 else:tags+=',with_purego,with_gvisor'
 text=subprocess.check_output([go,'list','-deps','-tags',tags,'-f',template,'.'],cwd=source,env=e,text=True)
 modules.update(v.strip() for v in text.splitlines() if '@' in v and not v.endswith('@'))
records=[]
for module in sorted(modules):
 v=json.loads(subprocess.check_output([go,'mod','download','-json',module],cwd=source,env=env,text=True));files=[];licenses=[]
 for key,suffix in [('Zip','.zip'),('GoMod','.mod'),('Info','.info')]:
  src=Path(v[key]);name=hashlib.sha256(module.encode()).hexdigest()[:20]+suffix;dest=TARGET/name;shutil.copy2(src,dest);files.append(dict(path=name,sha256=hashlib.sha256(dest.read_bytes()).hexdigest(),bytes=dest.stat().st_size))
  if key=='Zip':
   with zipfile.ZipFile(src) as z:
    for path in z.namelist():
     if Path(path).name.upper().startswith(('LICENSE','COPYING','COPYRIGHT','NOTICE')) and not path.endswith('/') and z.getinfo(path).file_size<200000:licenses.append(dict(path=path,text=z.read(path).decode('utf-8',errors='replace')))
 records.append(dict(module=module,sum=v.get('Sum'),go_mod_sum=v.get('GoModSum'),files=files,licenses=licenses))
root=Path(subprocess.check_output([go,'env','GOROOT'],env=env,text=True).strip())
manifest=dict(go='go1.26.8',ndk='30.0.16248370',modules=records,go_license=(root/'LICENSE').read_text(),prebuilt_components=[dict(name='Cronet',version='150.0.7871.63',bindings='0d28acc44093',libraries='c10c03c318db',source='https://github.com/SagerNet/cronet-go',note='Upstream Chromium/Cronet static Android libraries and shared Linux libraries; Rookstride builds the adapter, not Chromium.')])
manifest['supplemental_sources']=json.loads((source/'build-pins.json').read_text())['supplemental_sources'];manifest['extra_licenses']=[]
for record in manifest['supplemental_sources']:
 with tarfile.open(TARGET/record['path']) as tar:
  for member in tar.getmembers():
   if member.isfile() and Path(member.name).name.upper().startswith(('LICENSE','COPYING','COPYRIGHT','NOTICE')) and member.size<200000:
    manifest['extra_licenses'].append(dict(path=member.name,text=tar.extractfile(member).read().decode('utf-8',errors='replace')))
(TARGET/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('Collected',len(records),'worker dependency modules and notices')
