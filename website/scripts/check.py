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
        self.lang=None; self.direction=None; self.alternates={}; self.canonical=None; self.scripts=[]; self.images=[]
        self.duplicate_ids=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='html': self.lang=a.get('lang');self.direction=a.get('dir','ltr')
        if tag=='h1': self.h1+=1
        if tag=='title': self.in_title=True
        if a.get('id'):
            if a['id'] in self.ids: self.duplicate_ids.append(a['id'])
            self.ids.add(a['id'])
        if tag=='meta': self.metas[a.get('name',a.get('property',''))]=a.get('content','')
        if tag=='link' and a.get('rel')=='alternate':self.alternates[a.get('hreflang')]=a.get('href')
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
        require(doc.lang in ('en','ru','fa','ar','zh-Hans'),f'{file.name}: unsupported/missing language')
        require(doc.direction==('rtl' if doc.lang in ('fa','ar') else 'ltr'),f'{file}: incorrect direction')
        require(doc.h1==1,f'{file}: expected one primary heading')
        require((20 if doc.lang=='en' else 8)<=len(doc.title)<=120,f'{file}: missing useful title')
        require((65 if doc.lang=='en' else 35)<=len(doc.metas.get('description',''))<=450,f'{file}: missing useful description')
        require(not doc.duplicate_ids,f'{file}: duplicate IDs {doc.duplicate_ids}')
        require(all(src and src.startswith('/assets/') for src in doc.scripts),f'{file}: external/inline executable script')
        require(all('alt' in im and im.get('width') and im.get('height') for im in doc.images),f'{file}: image lacks alt/dimensions')
        for item in doc.schemas:
            require(item.get('@context')=='https://schema.org',f'{file}: invalid JSON-LD context')
            require('@type' in item,f'{file}: missing JSON-LD type')
            require('aggregateRating' not in item and 'review' not in item,f'{file}: invented rating field')
            schema_count+=1
    require(len(documents)==104,'Expected 68 English pages and nine beginner pages in each of four additional languages')
    from locales import LANGS,ROUTES,url
    for lang in LANGS:
        for route in ROUTES:
            file=(dist/(url(lang['tag'],route).lstrip('/')+'index.html')).resolve();doc=documents.get(file)
            require(doc is not None and doc.lang==lang['tag'],'Missing/wrong locale page '+str(file))
            if doc and doc.canonical:
                require(set(doc.alternates)=={'en','ru','fa','ar','zh-Hans','x-default'},'Missing hreflang equivalents '+str(file))
                for tag,href in doc.alternates.items():
                    target=(dist/(url('en' if tag=='x-default' else tag,route).lstrip('/')+'index.html')).resolve();other=documents.get(target)
                    require(other and other.alternates.get(lang['tag'])==doc.canonical,'Nonreciprocal language alternate '+str(file))
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
    require('earlier 0.1.0-alpha2' in routes and 'experimental 0.2.0-alpha2' in routes,'Published and experimental APK boundaries must be explicit')
    provider=json.loads((dist/'data/pair-provider-alpha2-tests.json').read_text())
    require(len(provider['fresh_provider_pair_runs'])>=3,'Provider evidence must include repeated full app-configured pairs')
    require(provider['android_36']['screen_navigation'].startswith('incomplete'),'Android 16 UI limit must remain explicit')
    pair_release=json.loads((dist/'data/pair-release.json').read_text())
    require(pair_release['version']=='0.2.0-alpha2' and pair_release['same_signed_apk_fresh_provider_runs']==4,'Wrong pair release identity')
    require(len(pair_release['artifacts'])==4,'Missing corresponding-source or verification files')
    for item in pair_release['artifacts']:
        require(item['url'].startswith('https://github.com/VictorBoykoV/rookstride/releases/download/v0.2.0-alpha2/'),'Wrong pair artifact URL')
        require(re.fullmatch('sha256:[a-f0-9]{64}',item['digest']) is not None,'Wrong pair artifact digest')
    if (dist/'data/ui-release.json').is_file():
        current=json.loads((dist/'data/ui-release.json').read_text())
        version=current['version']
        current_test=json.loads((dist/('data/localization-alpha4-tests.json' if version=='0.2.0-alpha4' else 'data/ui-alpha3-tests.json')).read_text())
        require(version==current_test['release'],'Current release/test identity mismatch')
        require(len(current['artifacts'])==4,'Current APK needs matching source and verification files')
        for item in current['artifacts']:
            require(item['url'].startswith('https://github.com/VictorBoykoV/rookstride/releases/download/v'+version+'/'),'Wrong current artifact URL')
            require(re.fullmatch('sha256:[a-f0-9]{64}',item['digest']) is not None,'Wrong current artifact digest')
            require(item['size']>0,'Empty current artifact')
            if item['name'].endswith('.apk'):require(item['digest']=='sha256:'+current_test['apk']['sha256'],'Current APK differs from tested release')
        require({row['api'] for row in current_test['signed_release_emulators']}=={26,28},'Current emulator scope missing')
        if version=='0.2.0-alpha4':
            require(current['version_code']==6,'Wrong language release version code')
            require(current_test['catalogs']['languages']==['en','ru','fa','ar','zh-Hans'],'Missing language scope')
            require(not current_test['catalogs']['human_native_review'],'Do not imply native human review')
            require(current_test['android_36']['tests']==2 and current_test['android_36']['full_screen_navigation'].startswith('unverified'),'Android 16 resource/full-UI scope must stay separate')
            history=json.loads((dist/'data/ui-alpha3-release.json').read_text());ui=json.loads((dist/'data/ui-alpha3-tests.json').read_text())
            require(history['version']==ui['release']=='0.2.0-alpha3','Historical alpha3 identity changed')
            require(next(a['digest'] for a in history['artifacts'] if a['name'].endswith('.apk'))=='sha256:'+ui['apk']['sha256'],'Historical alpha3 APK evidence changed')
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
