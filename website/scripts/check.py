#!/usr/bin/env python3
"""Check the distributable's links, evidence, metadata and public-data boundary."""
import argparse
import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

ROOT=Path(__file__).resolve().parents[1]
from stories import CHAPTERS
CHAPTER_COUNT=len(CHAPTERS)

class Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids=set(); self.refs=[]; self.h1=0; self.metas={}; self.title=''
        self.in_title=False; self.in_json=False; self.json_text=''; self.schemas=[]
        self.lang=None; self.canonical=None; self.scripts=[]; self.images=[]
        self.duplicate_ids=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='html': self.lang=a.get('lang')
        if tag=='h1': self.h1+=1
        if tag=='title': self.in_title=True
        if a.get('id'):
            if a['id'] in self.ids: self.duplicate_ids.append(a['id'])
            self.ids.add(a['id'])
        if tag=='meta': self.metas[a.get('name',a.get('property',''))]=a.get('content','')
        if tag=='link' and a.get('rel')=='canonical': self.canonical=a.get('href')
        if tag=='script':
            if a.get('type')=='application/ld+json': self.in_json=True; self.json_text=''
            else: self.scripts.append(a.get('src'))
        if tag=='img': self.images.append(a)
        for key in ('href','src'):
            if a.get(key): self.refs.append((tag,key,a[key]))
    def handle_endtag(self,tag):
        if tag=='title': self.in_title=False
        if tag=='script' and self.in_json:
            self.schemas.append(json.loads(self.json_text)); self.in_json=False
    def handle_data(self,text):
        if self.in_title: self.title+=text
        if self.in_json: self.json_text+=text

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def check(dist):
    failures=[]; documents={}; references=0; schema_count=0
    def require(condition,message):
        if not condition:failures.append(message)
    for file in sorted(dist.rglob('*.html')):
        doc=Document();doc.feed(file.read_text())
        documents[file.resolve()]=doc
        require(doc.lang=='en',f'{file.name}: missing English lang')
        require(doc.h1==1,f'{file}: expected one primary heading')
        require(20<=len(doc.title)<=90,f'{file}: missing useful title')
        require(65<=len(doc.metas.get('description',''))<=240,f'{file}: missing useful description')
        require(not doc.duplicate_ids,f'{file}: duplicate IDs {doc.duplicate_ids}')
        require(all(src and src.startswith('/assets/') for src in doc.scripts),f'{file}: external/inline executable script')
        require(all('alt' in im and im.get('width') and im.get('height') for im in doc.images),f'{file}: image lacks alt/dimensions')
        for item in doc.schemas:
            require(item.get('@context')=='https://schema.org',f'{file}: invalid JSON-LD context')
            require('@type' in item,f'{file}: missing JSON-LD type')
            require('aggregateRating' not in item and 'review' not in item,f'{file}: invented rating field')
            schema_count+=1
    require(len(documents)==9,'Expected home, six subject pages, text edition and 404')
    require(len({d.title for d in documents.values()})==len(documents),'Titles must be distinct')
    require(len({d.metas.get('description') for d in documents.values()})==len(documents),'Descriptions must be distinct')
    for file,doc in documents.items():
        relative=file.relative_to(dist.resolve()).as_posix()
        source='/'+relative
        for tag,key,ref in doc.refs:
            references+=1
            u=urlparse(urljoin('https://local.example'+source,ref))
            if u.scheme not in ('http','https') or u.netloc!='local.example':continue
            path=dist/unquote(u.path).lstrip('/')
            if u.path.endswith('/'):path=path/'index.html'
            require(path.is_file(),f'{relative}: missing {ref}')
            if path.is_file() and u.fragment and path.suffix=='.html':
                target=documents.get(path.resolve())
                require(target and unquote(u.fragment) in target.ids,f'{relative}: missing anchor {ref}')
    for css in (dist/'assets').glob('*.css'):
        for quoted_double,quoted_single,bare in re.findall(r'''url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)''',css.read_text()):
            ref=(quoted_double or quoted_single or bare).strip()
            if ref.startswith('data:'):continue
            target=(dist/ref.lstrip('/')) if ref.startswith('/') else css.parent/ref
            require(target.is_file(),f'{css.name}: missing asset {ref}')
    release=json.loads((dist/'data/release.json').read_text())
    evidence=json.loads((dist/'data/alpha2-tests.json').read_text())
    require(release['version']==evidence['release']=='0.1.0-alpha2','Release/evidence version mismatch')
    require(release['apk']['sha256']==evidence['apk_sha256'],'APK hash differs from tested evidence')
    require([c['android_api'] for c in evidence['cycles']]==[36,28,26],'Unexpected reported Android cycles')
    require(all(c['result']=='PASS' for c in evidence['cycles']),'Evidence has unreported failed cycles')
    require(len(release['remaining_gates'])>=4,'Remaining release gates must be present')
    for record in (release['apk'],release['corresponding_source']):
        require(re.fullmatch('[a-f0-9]{64}',record['sha256']) is not None,'Invalid artifact hash')
        require(record['url'].startswith('https://github.com/VictorBoykoV/rookstride/releases/download/v0.1.0-alpha2/'),'Wrong artifact URL')
    outputs=ROOT.parents[2]/'outputs'
    artifact_checks=0
    for key,name in [('apk','rookstride-0.1.0-alpha2.apk'),('corresponding_source','rookstride-0.1.0-alpha2-source.tar.gz')]:
        artifact=outputs/name
        if artifact.exists():
            require(sha(artifact)==release[key]['sha256'],f'Local release artifact hash mismatch: {name}')
            require(artifact.stat().st_size==release[key]['bytes'],f'Local artifact size mismatch: {name}')
            artifact_checks+=1
    journal=(dist/'journal/index.html').read_text()
    text=(dist/'journal/text/index.html').read_text()
    require(journal.count('class="comic-page chapter-')==CHAPTER_COUNT*2,'Journal must retain every static source page')
    require(journal.count('class="comic-panel"')==CHAPTER_COUNT*6,'Journal must have every panel')
    require(text.count('class="scene-description"')==CHAPTER_COUNT*6,'Text edition must describe every scene')
    for title in [c['title'] for c in CHAPTERS]:
        require(title in journal and title in text,'Missing complete chapter: '+title)
    routes=(dist/'routes/index.html').read_text()
    require('neither is included in alpha2' in routes and 'local 0.2.0-alpha1 build' in routes,'Published and experimental APK boundaries must be explicit')
    require((dist/'docs/universal-gateway-research.md').is_file(),'Missing full research note')
    for mode in ('panel','page','chapter'):
        require(f'data-reader-mode="{mode}"' in journal,'Missing reader mode: '+mode)
    allowed_ips={'10.254.0.1'}
    scanned=0
    for file in dist.rglob('*'):
        if not file.is_file() or file.suffix not in ('.html','.txt','.json','.css','.js','.svg','.xml','.md'):continue
        public=file.read_text();scanned+=1
        for ip in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',public):
            documented_version = ip == '5.0.1.5' and 'AmneziaVPN '+ip in public
            require(ip in allowed_ips or documented_version,f'{file}: unexpected deployment address')
        require(not re.search(r'-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}',public),f'{file}: private key/token material')
    robots=(dist/'robots.txt').read_text()
    require('User-agent: *' in robots and 'Allow: /' in robots,'Public pages must be crawlable')
    require((dist/'llms.txt').is_file() and (dist/'llms-full.txt').is_file(),'Missing agent references')
    require((dist/'assets/social-card.png').is_file(),'Missing raster social card')
    canonicals=[d.canonical for d in documents.values() if d.canonical]
    if canonicals:
        require((dist/'sitemap.xml').is_file(),'Canonical publication build needs sitemap')
        require('Sitemap:' in robots,'Publication robots missing sitemap reference')
        require(all(urlparse(c).scheme=='https' for c in canonicals),'Public canonicals must use HTTPS')
    else:
        require(not (dist/'sitemap.xml').exists(),'Local-only build must not invent a public sitemap')
    report={'result':'FAIL' if failures else 'PASS','pages':len(documents),'link_asset_references':references,'json_ld_documents':schema_count,'public_text_files_scanned':scanned,'local_release_artifacts_verified':artifact_checks,'static_comic_pages':CHAPTER_COUNT*2,'comic_panels':CHAPTER_COUNT*6,'errors':failures}
    print(json.dumps(report,indent=2))
    return bool(failures)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist',type=Path,default=ROOT/'dist')
    args=parser.parse_args()
    raise SystemExit(check(args.dist.resolve()))
