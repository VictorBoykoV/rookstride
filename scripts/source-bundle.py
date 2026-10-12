#!/usr/bin/env python3
"""Create corresponding source, including pinned upstream archives, without secrets."""
import hashlib
import tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.build/rookstride-0.1.0-alpha1-source.tar.gz'
OUTPUT.parent.mkdir(exist_ok=True)
archives=[ROOT/'.tools'/n for n in ('strongswan-git.tar.gz','strongswan.tar.gz','openssl.tar.gz')]
if not all(p.is_file() for p in archives): raise SystemExit('Run bootstrap.py first')
files=[ROOT/n for n in ('README.md','LICENSE','NOTICE.md','SECURITY.md','AGENTS.md','.gitignore')]
for name in ('android','brand','docs','gateway','licenses','scripts','server','tests'):
    files.extend(p for p in (ROOT/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.log'))
with tarfile.open(OUTPUT,'w:gz') as t:
    for p in sorted(files)+archives: t.add(p,arcname=Path('rookstride')/p.relative_to(ROOT),recursive=False)
h=hashlib.sha256()
with OUTPUT.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
OUTPUT.with_suffix(OUTPUT.suffix+'.sha256').write_text(h.hexdigest()+'  '+OUTPUT.name+'\n')
print(OUTPUT.name,OUTPUT.stat().st_size,'bytes')
