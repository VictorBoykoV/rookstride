#!/usr/bin/env python3
"""Create corresponding source, including pinned upstream archives, without secrets."""
import hashlib
import json
import tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
release=json.loads((ROOT/'release.json').read_text())
OUTPUT=ROOT/('.build/rookstride-'+release['name']+'-source.tar.gz')
OUTPUT.parent.mkdir(exist_ok=True)
archives=[ROOT/'.tools'/n for n in ('strongswan-git.tar.gz','strongswan.tar.gz','openssl.tar.gz')]
if not all(p.is_file() for p in archives): raise SystemExit('Run bootstrap.py first')
dependencies=ROOT/'.tools/dependency-sources'
if not (dependencies/'manifest.json').is_file():raise SystemExit('Run scripts/collect-java-sources.py after the Android build')
for module in json.loads((dependencies/'manifest.json').read_text())['modules']:
    for file in module['files']:
        path=dependencies/file['path']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=file['sha256']:raise SystemExit('Dependency source hash differs: '+file['path'])
archives.extend(sorted(p for p in dependencies.rglob('*') if p.is_file() and p.suffix!='.part'))
native=ROOT/'.tools/native-engines'
for item in json.loads((ROOT/'android/engines/pins.json').read_text())['sources']:
    archive=native/(item['name']+'.tar.gz')
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:raise SystemExit('Missing/changed native engine source: '+item['name'])
    archives.append(archive)
manifest=native/'sources/manifest.json'
if not manifest.is_file():raise SystemExit('Collect resolved Go source modules first')
for module in json.loads(manifest.read_text())['modules']:
    for file in module['files']:
        path=manifest.parent/file['path']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=file['sha256']:raise SystemExit('Go module source differs: '+module['module'])
        archives.append(path)
archives.append(manifest)
route_manifest=native/'route-sources/manifest.json'
if not route_manifest.is_file():raise SystemExit('Collect the new worker dependency sources first')
for module in json.loads(route_manifest.read_text())['modules']:
    for file in module['files']:
        path=route_manifest.parent/file['path']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=file['sha256']:raise SystemExit('Worker dependency source differs: '+module['module'])
        archives.append(path)
archives.append(route_manifest)
for file in json.loads(route_manifest.read_text())['supplemental_sources']:
    path=route_manifest.parent/file['path']
    if hashlib.sha256(path.read_bytes()).hexdigest()!=file['sha256']:raise SystemExit('Supplemental worker source differs')
    archives.append(path)
trust_source=json.loads((ROOT/'single/routes-pins.json').read_text())['trusttunnel']['source'];path=native/'trusttunnel-server.tar.gz'
if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=trust_source['sha256']:raise SystemExit('Pinned TrustTunnel endpoint source missing')
archives.append(path)
files=[ROOT/n for n in ('README.md','LICENSE','NOTICE.md','SECURITY.md','AGENTS.md','.gitignore','.gitattributes','release.json')]
for name in ('android','brand','docs','gateway','licenses','scripts','server','single','tests','twohop','reinstall','website','i18n','stories'):
    files.extend(p for p in (ROOT/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.log') and not (name=='website' and 'qa' in p.parts))
def public_header(info):
    info.uid=info.gid=0;info.uname=info.gname='';return info
with tarfile.open(OUTPUT,'w:gz') as t:
    for p in sorted(files)+archives: t.add(p,arcname=Path('rookstride')/p.relative_to(ROOT),recursive=False,filter=public_header)
h=hashlib.sha256()
with OUTPUT.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
OUTPUT.with_suffix(OUTPUT.suffix+'.sha256').write_text(h.hexdigest()+'  '+OUTPUT.name+'\n')
print(OUTPUT.name,OUTPUT.stat().st_size,'bytes')
