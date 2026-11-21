#!/usr/bin/env python3
"""Fetch verified embedded-engine sources. Native compilation is a separate step."""
import hashlib,json,shutil,tarfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PINS=json.loads((ROOT/'android/engines/pins.json').read_text())
CACHE=ROOT/'.tools/native-engines';CACHE.mkdir(parents=True,exist_ok=True)
for item in PINS['sources']:
 archive=CACHE/(item['name']+'.tar.gz')
 if not archive.exists():
  temp=archive.with_suffix('.part')
  with urllib.request.urlopen(item['url'],timeout=120) as response,temp.open('wb') as output:shutil.copyfileobj(response,output)
  temp.replace(archive)
 if hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:raise SystemExit('Engine source checksum mismatch: '+item['name'])
 dest=CACHE/item['name'];stamp=dest/'.rookstride-source'
 if stamp.exists() and stamp.read_text()==item['sha256']:continue
 if dest.exists():shutil.rmtree(dest)
 dest.mkdir()
 with tarfile.open(archive) as tar:
  for member in tar.getmembers():
   parts=Path(member.name).parts
   if len(parts)<2:continue
   tail=Path(*parts[1:])
   if tail.is_absolute() or '..' in tail.parts:raise SystemExit('Unsafe engine source path')
   if member.isfile():
    target=dest/tail;target.parent.mkdir(parents=True,exist_ok=True)
    with tar.extractfile(member) as source,target.open('wb') as output:shutil.copyfileobj(source,output)
    target.chmod(member.mode&0o777)
   elif member.issym() or member.islnk():
    # Links are not required by the selected build inputs; never materialize them.
    continue
 stamp.write_text(item['sha256'])
print('Verified AWG, Xray, OpenVPN and Asio engine sources')
