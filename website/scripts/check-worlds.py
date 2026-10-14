#!/usr/bin/env python3
"""Check complete story source, chapter art, hotspots, and the offline reader bundle."""
import argparse,json,re
from urllib.parse import urlparse
from check import Document
from pathlib import Path
from world_reader import image_size
ROOT=Path(__file__).resolve().parents[1]

def check(allow_art=False):
    d=json.loads((ROOT/'content/worlds.json').read_text());errors=[];ready=0;word_count=0;all_text=[]
    def require(ok,message):
        if not ok:errors.append(message)
    require([w['id'] for w in d['worlds']]==['harbor','persia','china','russia','america'],'Expected five connected worlds')
    for w in d['worlds']:
        require(len(w['chapters'])==10,w['id']+': expected ten finished chapters')
        hotspots=ROOT/'brand/chapters'/w['id']/'hotspots.json';hs=json.loads(hotspots.read_text()) if hotspots.is_file() else {}
        for c in w['chapters']:
            require(bool(re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',c['id'])),c['id']+': invalid slug')
            require(len(c['pages'])==4,c['id']+': expected four pages')
            for p in c['pages']:
                words=len(p['text'].split());word_count+=words;all_text.append(p['text'])
                require(words>=45,c['id']+': unfinished narration')
                require(p['focus'] in ('rook','lantern','bridge','book','tower','dragon','friend','route'),c['id']+': invalid focus')
                require(not re.search(r'\b(?:TODO|TBD|placeholder|coming soon)\b',p['text'],re.I),c['id']+': draft text')
            site=ROOT/'dist/worlds'/w['id']/c['id']/'index.html';offline=ROOT.parent/'android/overlay/assets/stories/worlds'/w['id']/c['id']/'index.html'
            for file in (site,offline):
                require(file.is_file(),str(file)+': missing static chapter')
                if file.is_file():
                    raw=file.read_text();require(raw.count('class="narration"')==4,c['id']+': narration missing from static edition')
                    require('data-narrate' in raw and 'chapter-finished' in raw,c['id']+': voice/stop controls missing')
            boxes=hs.get(c['id'],[])
            if not allow_art:require(len(boxes)==4,c['id']+': expected four inspected narration hotspots')
            for box in boxes:
                require(all(isinstance(box.get(k),(int,float)) for k in ('x','y','w','h')),c['id']+': nonnumeric hotspot')
                require(0<=box['x']<=100 and 0<=box['y']<=100 and 0<box['w']<=100-box['x'] and 0<box['h']<=100-box['y'],c['id']+': hotspot outside panel')
                require(bool(box.get('label')),c['id']+': missing visible-object label')
            if c.get('legacyChapter'):continue
            image=ROOT/'brand/chapters'/w['id']/(c['id']+'.webp');master=ROOT/'artwork/chapters'/w['id']/(c['id']+'.png')
            if not image.is_file():
                if not allow_art:require(False,c['id']+': missing original chapter art')
                continue
            try:width,height=image_size(image);require(width>=900 and height>=600,c['id']+': image too small')
            except (ValueError,OSError):require(False,c['id']+': incomplete WebP');continue
            ready+=1;require(image.stat().st_size<=180*1024,c['id']+': reader asset exceeds 180 KiB');require(master.is_file(),c['id']+': missing original master')
    offline_root=ROOT.parent/'android/overlay/assets/stories'
    for file in offline_root.rglob('*.html'):
        raw=file.read_text();doc=Document();doc.feed(raw)
        require('Content-Security-Policy' in raw,str(file)+': missing asset-only policy')
        for tag,key,ref in doc.refs:
            url=urlparse(ref)
            if url.scheme in ('http','https'):
                require(tag=='a' and key=='href',str(file)+': external asset forbidden');continue
            if url.path.startswith('/stories/'):
                target=offline_root/url.path[len('/stories/'):]
                if url.path.endswith('/'):target=target/'index.html'
                require(target.is_file(),str(file)+': missing offline link '+ref)
            elif url.path.startswith('/'):require(False,str(file)+': unbundled local link '+ref)
    require(len(set(all_text))==200,'Narration texts should be unique')
    require([c.get('legacyChapter') for c in d['worlds'][0]['chapters'][:5]]==[1,2,3,4,5],'Original five comic references changed')
    if not allow_art:require(ready==45,'Expected forty-five new complete comic artworks')
    report={'status':'FAIL' if errors else 'ART IN PROGRESS' if allow_art and ready!=45 else 'PASS','worlds':5,'chapters':50,'story_pages':len(all_text),'narration_words':word_count,'new_comic_artworks':ready,'retained_strip_comics':5,'errors':errors}
    print(json.dumps(report,indent=2));return bool(errors)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--allow-art-in-progress',action='store_true');args=p.parse_args();raise SystemExit(check(args.allow_art_in_progress))
