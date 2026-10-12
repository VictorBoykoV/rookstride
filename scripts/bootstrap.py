#!/usr/bin/env python3
"""Download verified source inputs; requires Python 3.9+, JDK 17 and Android SDK."""
import hashlib
import shutil
import tarfile
import urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/'.tools'
INPUTS=(
 ('strongswan-git.tar.gz','https://codeload.github.com/strongswan/strongswan/tar.gz/refs/tags/6.1.0','1fddc160f46f1c1dc6647b6b3dfad7fe98e25f8f7793987f1128aecedb8577cd'),
 ('strongswan.tar.gz','https://github.com/strongswan/strongswan/releases/download/6.1.0/strongswan-6.1.0.tar.gz','d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963'),
 ('openssl.tar.gz','https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz','603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'))
def fetch(name,url,digest):
    p=TOOLS/name
    if not p.exists():
        temporary=p.with_suffix('.part')
        with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Rookstride-source-build'}),timeout=120) as r, temporary.open('wb') as f:
            shutil.copyfileobj(r,f)
        temporary.replace(p)
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    if h.hexdigest()!=digest: raise SystemExit('Checksum mismatch: '+name)
    return p

def extract(archive,destination):
    destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive) as t:
        for member in t.getmembers():
            # Strip the official archive's single top directory; reject links and traversal.
            path=Path(member.name)
            if len(path.parts)<2: continue
            tail=Path(*path.parts[1:])
            # The pinned Git archive has one harmless README alias; materialize it below.
            if member.issym() and tail==Path('README') and member.linkname=='README.md': continue
            if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk():
                raise SystemExit('Unexpected archive path: '+member.name)
            target=destination/tail
            if member.isdir(): target.mkdir(parents=True,exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True,exist_ok=True)
                with t.extractfile(member) as src,target.open('wb') as dst: shutil.copyfileobj(src,dst)
                target.chmod(member.mode&0o777)
    if not (destination/'README').exists() and (destination/'README.md').is_file():
        shutil.copyfile(destination/'README.md',destination/'README')

TOOLS.mkdir(exist_ok=True)
archives=[fetch(*item) for item in INPUTS]
source=TOOLS/'strongswan-source'
if not (source/'src/frontends/android/gradlew').exists():
    extract(archives[0],source)
    # Distribution includes generated headers/prebuilt Android source excluded from Git.
    extract(archives[1],source)
if not (TOOLS/'openssl-3.5.9/Configure').exists(): extract(archives[2],TOOLS/'openssl-3.5.9')
wrapper=source/'src/frontends/android/gradle/wrapper/gradle-wrapper.properties'
s=wrapper.read_text()
if 'distributionSha256Sum=' not in s:
    wrapper.write_text(s+'\ndistributionSha256Sum=fba8464465835e74f7270bbf43d6d8a8d7709ab0a43ce1aa3323f73e9aa0c612\n')
print('Verified strongSwan 6.1.0 and OpenSSL 3.5.9 sources. Next: scripts/build-crypto.sh')
