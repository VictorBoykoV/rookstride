"""Original fiction library, shared by the portable site and offline Android app."""
import html,json,shutil
import struct
from stories import CHAPTERS, PANEL_CROPS
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def e(s):return html.escape(str(s),quote=True)

def content():return json.loads((ROOT/'content/worlds.json').read_text())

def helper(role='guide',heading='A little way forward.',copy='Rook carries a lantern, a map, and room for your next choice.',link='/rook/'):
    return f'<aside class="rook-helper" aria-label="A note from Rook"><img src="/assets/rook-{role}.svg" width="108" height="108" alt="Rook as your {e(role)}"><div><p class="eyebrow">A NOTE FROM ROOK</p><h2>{e(heading)}</h2><p>{e(copy)}</p><a href="{link}">Meet your guide →</a></div></aside>'

def lore(data):
    l=data['lore']
    return '<section class="container world-intro"><p class="eyebrow">THE ROOKSTRIDE AMBASSADOR</p><h1>'+e(l['title'])+'</h1><div class="lore-grid"><img src="/assets/rook-guide.svg" width="400" height="400" alt="Rook, the red navigator with a map"><div>'+''.join('<p>'+e(p)+'</p>' for p in l['paragraphs'])+'</div></div><h2>The promises Rook makes.</h2><ul>'+''.join('<li>'+e(r)+'</li>' for r in l['rules'])+'</ul><p>These are original fictional adventures. Rook’s courage is an invitation, not a promise of anonymity or access to every website.</p><a class="button primary" href="/worlds/">Explore his five worlds →</a></section>'

def library(data):
    cards=''
    for w in data['worlds']:
        cards+=f'<a class="world-card world-{w["id"]}" href="/worlds/{w["id"]}/"><img src="/assets/world-{w["id"]}.webp" width="1536" height="1024" alt="Original Rook illustration for {e(w["title"])}" loading="lazy"><div><span>{e(w["region"])} · TEN CHAPTERS</span><h2>{e(w["title"])}</h2><p>{e(w["tagline"])}</p><b>Enter this world →</b></div></a>'
    return '<section class="container world-intro"><p class="eyebrow">FIVE WORLDS / FIFTY COMPLETE STORIES</p><h1>One small bird.<br>A wider world.</h1><p class="lede">From a book in Lantern Harbor to gardens, canals, winter roads, and a town where neighbors keep a common promise. Read a page, listen, or linger.</p><p><a href="/rook/">Read Rook’s origin story</a> · <a href="/journal/">Open the original five strip comics</a></p><div class="world-grid">'+cards+'</div><p class="world-note">The places are fictional worlds inspired by cultures, not portraits of every person in a country. Read the <a href="/worlds/notes/">cultural notes and sources</a>. English stories; no account, reading analytics, or automatic audio.</p></section>'

def world_page(w):
    cards=''.join(f'<a class="chapter-card" href="/worlds/{w["id"]}/{c["id"]}/"><span>CHAPTER {i+1:02d}</span><h2>{e(c["title"])}</h2><p>{e(c["summary"])}</p><small>{e(c["theme"])}</small><b>Read this chapter →</b></a>' for i,c in enumerate(w['chapters']))
    return f'<section class="container world-intro"><p class="eyebrow">{e(w["region"])} / TEN CHAPTERS</p><h1>{e(w["title"])}</h1><p class="lede">{e(w["description"])}</p><img class="world-banner" src="/assets/world-{w["id"]}.webp" width="1536" height="1024" alt="Rook visits {e(w["title"])}"><p>Travel note: {e(w["travel"])} · <a href="/worlds/">All worlds</a></p><div class="chapters-grid">{cards}</div></section>'

# Each transparent scene prop is an original vector drawing, separate from generated world art.
PROPS={
'lantern':'<path d="M74 46q0-30 26-30t26 30M74 52h52l-5 84H79z" fill="#f7d484"/><path d="M86 128V65h28v63" fill="#ffc550"/><path d="M93 117q-14-15 7-32q23 22 0 32" fill="#fff8d9"/>',
'bridge':'<path d="M25 113Q100 23 175 113v30h-27v-20Q100 70 52 123v20H25z" fill="#c5b59d"/><path d="M26 113h148M48 95l14 9m18-36 7 23m31-21-6 22m32 0-8 13"/>',
'book':'<path d="M100 55Q65 33 22 49v91q38-14 78 8q40-22 78-8V49q-43-16-78 6z" fill="#f4f0e7"/><path d="M100 55v93M37 68q26-5 46 6M37 88q26-5 46 6m34-20q23-12 46-6m-46 26q23-12 46-6"/>',
'tower':'<path d="M63 148V52h-7V31h17v13h18V31h18v13h18V31h17v21h-7v96z" fill="#dbc6a8"/><path d="M85 148v-37q15-18 30 0v37" fill="#637c82"/><path d="M84 75v14m32-14v14M64 52h72"/>',
'dragon':'<path d="M57 136q-50-25-24-55q20 22 41 2q3-31 33-29q21-37 59-9l-15 11 23 20-23 11q-26-22-29 6q25 40-17 56z" fill="#638d88"/><path d="M78 81 51 32l51 29m16-4 10-27m-35 86-9 22m27-12 8 13"/><circle cx="138" cy="60" r="4" fill="#141418"/><path d="M156 107q23-12 20 12q-8 17-20-1" fill="#edb462"/>',
'friend':'<path d="M57 65 60 20 79 56m39 0 20-36 4 49" fill="#e5d5bf"/><ellipse cx="100" cy="82" rx="47" ry="38" fill="#e5d5bf"/><path d="M63 115q-13 55 37 49q50 6 37-49" fill="#7faaa5"/><circle cx="84" cy="79" r="5"/><circle cx="117" cy="79" r="5"/><path d="M91 94q9 8 18 0"/>',
'route':'<path d="M45 20h110v120H45z" fill="#f4f0e7"/><path d="M58 112q72 16 72-28T69 61q-13-25 42-27" stroke="#ee3038" stroke-dasharray="7 7"/><circle cx="111" cy="34" r="8" fill="#ee3038"/><path d="m45 140 23-10 32 11 34-10 21 9"/>',
'rook':'<image href="/assets/rook-guide.svg" x="10" y="0" width="180" height="180"/>'}

def image_size(path):
    """Read dimensions from VP8/VP8L/VP8X without a build-time image library."""
    data=path.read_bytes()
    if data[:4]!=b'RIFF' or data[8:12]!=b'WEBP':raise ValueError('Not a complete WebP')
    offset=12
    while offset+8<=len(data):
        kind=data[offset:offset+4];size=int.from_bytes(data[offset+4:offset+8],'little');payload=data[offset+8:offset+8+size]
        if len(payload)!=size:raise ValueError('Incomplete WebP chunk')
        if kind==b'VP8X' and len(payload)>=10:return 1+int.from_bytes(payload[4:7],'little'),1+int.from_bytes(payload[7:10],'little')
        if kind==b'VP8 ':
            start=payload.find(b'\x9d\x01\x2a')
            if start>=0 and len(payload)>=start+7:
                w,h=struct.unpack('<HH',payload[start+3:start+7]);return w&0x3fff,h&0x3fff
        if kind==b'VP8L' and len(payload)>=5:
            bits=int.from_bytes(payload[1:5],'little');return 1+(bits&0x3fff),1+((bits>>14)&0x3fff)
        offset+=8+size+(size%2)
    raise ValueError('No image dimensions')

def scene(page,w,c,index):
    chapter=ROOT/'brand/chapters'/w['id']/(c['id']+'.webp')
    focus=page['focus']
    try:size=image_size(chapter) if chapter.is_file() else None
    except (OSError,ValueError):size=None
    if size:
        width,height=size
        x=(index%2)*width/2;y=(index//2)*height/2;cw=width/2;ch=height/2
        image=f"/assets/stories/{w['id']}/{c['id']}.webp"
        hotspots=ROOT/'brand/chapters'/w['id']/'hotspots.json'
        try:values=json.loads(hotspots.read_text()) if hotspots.is_file() else {}
        except json.JSONDecodeError:values={}
        spot=values.get(c['id'],[{'x':15,'y':15,'w':70,'h':70,'label':'Current story scene'}]*4)[index]
    elif c.get('legacyChapter'):
        legacy=c['legacyChapter']-1;panel=[0,1,3,5][index]
        x,y,cw,ch=PANEL_CROPS[legacy][panel];width=1448;height=1086
        image='/assets/'+CHAPTERS[legacy]['image']
        hotspots=ROOT/'brand/chapters'/w['id']/'hotspots.json'
        try:values=json.loads(hotspots.read_text()) if hotspots.is_file() else {}
        except json.JSONDecodeError:values={}
        spot=values.get(c['id'],[{'x':18,'y':15,'w':64,'h':72,'label':'Current story scene'}]*4)[index]
    else:
        # Cover-based preview while original chapter panels are still being drawn.
        prop=PROPS.get(focus,PROPS['route'])
        return f'<div class="scene-frame" data-focus="{e(focus)}"><img src="/assets/world-{w["id"]}.webp" width="1536" height="1024" alt="World illustration for {e(w["title"])}" loading="lazy"><svg class="story-prop" viewBox="0 0 200 190" role="img" aria-label="{e(focus.capitalize())} story symbol" fill="none" stroke="#141418" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><g class="scene-target">{prop}</g></svg><span class="scene-caption">{e(page["setting"].capitalize())} · {e(focus.capitalize())}</span></div>'
    return f'<div class="scene-frame comic-scene" data-focus="{e(focus)}"><div class="scene-illustration"><svg class="chapter-panel" viewBox="{x} {y} {cw} {ch}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="{e(page["scene"])}"><image href="{image}" width="{width}" height="{height}"/></svg><svg class="scene-highlight" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Narration focus: {e(spot["label"])}"><rect class="scene-target" x="{spot["x"]}" y="{spot["y"]}" width="{spot["w"]}" height="{spot["h"]}" rx="4" fill="none" stroke="#ee3038" stroke-width="1.2"/></svg></div><span class="scene-caption">{e(spot["label"])}</span></div>'

def chapter_page(w,c,index):
    paragraphs=''
    for i,p in enumerate(c['pages']):
        paragraphs+=f'<article class="story-page" id="page-{i+1}" data-page="{i}" data-focus="{e(p["focus"])}"><div class="story-page-heading"><span>{e(w["title"])} / CHAPTER {index+1:02d}</span><span>PAGE {i+1} / {len(c["pages"])}</span></div>{scene(p,w,c,i)}<div class="story-copy"><p class="scene-description">{e(p["scene"])}</p><p class="narration">{e(p["text"])}</p></div></article>'
    legacy=f'<a href="/journal/#chapter-{c["legacyChapter"]}">Also read the original strip comic →</a>' if c.get('legacyChapter') else ''
    nxt=w['chapters'][index+1] if index+1<len(w['chapters']) else None
    nextlink=f'<a href="/worlds/{w["id"]}/{nxt["id"]}/">Choose the next chapter: {e(nxt["title"])} →</a>' if nxt else '<a href="/worlds/">Choose another world →</a>'
    return f'''<section class="container story-intro"><p class="eyebrow"><a href="/worlds/{w['id']}/">{e(w['title'])}</a> / CHAPTER {index+1:02d}</p><h1>{e(c['title'])}</h1><p>{e(c['theme'])}</p>{legacy}</section>
    <section class="container story-reader" data-story-reader data-world="{w['id']}" data-chapter="{c['id']}">
    <div class="story-toolbar"><div role="group" aria-label="Story view"><button type="button" data-story-mode="page" aria-pressed="true">One page</button><button type="button" data-story-mode="chapter" aria-pressed="false">Whole chapter</button></div><button type="button" data-story-motion aria-pressed="true">Page turns on</button></div>
    <div class="narration-controls"><button type="button" data-narrate>▶ Listen to this chapter</button><button type="button" data-voice-stop disabled>Stop</button><label>Voice <select data-voices aria-label="Narrator voice"><option>Finding device voices…</option></select></label><label>Speed <select data-rate aria-label="Narration speed"><option value="0.9">Calm</option><option value="1" selected>Normal</option><option value="1.15">Brisk</option></select></label></div><p class="voice-status" role="status">Optional device narration. No audio starts until you press Listen.</p>
    <div class="story-pages" tabindex="0" aria-label="Story pages; use left and right arrows or swipe">{paragraphs}</div>
    <div class="story-turns"><button type="button" data-story-prev>← Previous page</button><span data-story-status role="status" aria-live="polite">Page 1 / {len(c['pages'])}</span><button type="button" data-story-next>Next page →</button></div>
    <p class="reader-note">Listening turns pages within this chapter and highlights the illustrated scene. Word highlighting depends on the device voice. Narration stops at the chapter’s end. Manual page turns stop the voice.</p>
    <div class="chapter-finished"><h2>A small journey, complete.</h2><p>Take your time. The next chapter starts only when you choose it.</p>{nextlink}</div><noscript><p>All pages are visible above. Device narration and page turns need JavaScript.</p></noscript></section>'''

def notes():
    sources=json.loads((ROOT/'content/cultural-sources.json').read_text())
    # Preserve the carefully sourced human-readable notes without relying on a schema shape.
    rows=[]
    def walk(value):
        if isinstance(value,dict):
            url=value.get('url') or value.get('href')
            if url:rows.append('<li><a href="'+e(url)+'">'+e(value.get('title') or value.get('name') or url)+'</a>'+(' — '+e(value.get('note') or value.get('context') or '') if value.get('note') or value.get('context') else '')+'</li>')
            for child in value.values():walk(child)
        elif isinstance(value,list):
            for child in value:walk(child)
    walk(sources)
    return '<section class="container world-intro"><p class="eyebrow">FICTION &amp; REAL INSPIRATION</p><h1>Stories with a home.<br>Room for everyone.</h1><p>Lantern Harbor is invented. The other worlds draw on selected gardens, waterways, winter crafts, libraries and cultural traditions. They are not accounts of actual people, events, laws, or the experience of an entire country. Local characters bring the knowledge; Rook listens and helps.</p><p>These stories use an accessible English voice. They do not claim to be translated Persian, Chinese, Russian, or regional folklore. The U.S. liberties story names the Second Amendment alongside the wider constitutional tradition; it is fiction, not legal advice. No VPN technology is a guarantee of access or protection.</p><h2>Sources for the cultural notes</h2><ul>'+''.join(dict.fromkeys(rows))+'</ul><p><a href="/data/cultural-sources.json">Read the full source notes</a> · <a href="/rook/">Rook’s character rules</a></p></section>'

def pages(data):
    yield '/rook/','Meet Rook — The Rookstride navigator and his story','Meet Rook, the original red navigator who steps out of a book. Learn his values, origins, and role as the Rookstride guide and ambassador.',lore(data),'lore-page'
    yield '/worlds/','Rook’s five worlds — Fifty illustrated stories','Read fifty complete Rook adventures in five connected fictional worlds, with illustrated pages, optional device narration, and cultural notes.',library(data),'worlds-page'
    yield '/worlds/notes/','Cultural notes — Rook’s five fictional worlds','Read primary sources and the cultural notes behind Rook’s fictional worlds inspired by Persian gardens, China, Russia, and the United States.',notes(),'world-notes-page'
    for w in data['worlds']:
        yield f'/worlds/{w["id"]}/',f'{w["title"]} — Ten Rook adventures',w['description'],world_page(w),'world-page'
        for i,c in enumerate(w['chapters']):yield f'/worlds/{w["id"]}/{c["id"]}/',f'{c["title"]} — Rook’s {w["title"]}',c['summary'],chapter_page(w,c,i),'story-page-body'

def offline(dist):
    target=ROOT.parent/'android/overlay/assets/stories'
    target.mkdir(parents=True,exist_ok=True)
    # The same accessible pages, links and reader run offline inside a locked asset-only origin.
    routes=list(pages(content()))
    all_routes={p:body for p,title,description,body,cls in routes}
    for path,title,description,body,cls in routes:
        out=target/(path.lstrip('/')+'index.html');out.parent.mkdir(parents=True,exist_ok=True)
        nav='<nav class="offline-nav"><a href="/stories/index.html">Worlds</a><a href="/stories/rook/">Meet Rook</a></nav>'
        body=body.replace('href="/worlds/', 'href="/stories/worlds/').replace('href="/rook/', 'href="/stories/rook/').replace('src="/assets/', 'src="/stories/assets/').replace('href="/assets/', 'href="/stories/assets/')
        # Read-only offline fiction links cannot open external pages or invoke arbitrary native operations.
        body=body.replace('href="/journal/','href="/stories/journal/').replace('href="/data/','href="/stories/data/')
        out.write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\'; style-src \'self\'; script-src \'self\'; connect-src \'none\'; base-uri \'none\'"><title>'+e(title)+'</title><link rel="stylesheet" href="/stories/assets/worlds.css">'+nav+'<main>'+body+'</main><script src="/stories/assets/worlds.js" defer></script></html>')
    # Original strip comics stay available in the app as well as the new story plates.
    import re
    for route in ('journal/','journal/text/'):
        source=(dist/(route+'index.html')).read_text()
        main=re.search(r'<main id="main">(.*?)</main>',source,re.S).group(1)
        main=main.replace('href="/worlds/','href="/stories/worlds/').replace('href="/rook/','href="/stories/rook/').replace('href="/journal/','href="/stories/journal/').replace('src="/assets/','src="/stories/assets/').replace('href="/assets/','href="/stories/assets/').replace('data-image="/assets/','data-image="/stories/assets/')
        main=main.replace('href="/"','href="/stories/index.html"').replace('href="/start/"','href="https://github.com/VictorBoykoV/rookstride/blob/main/docs/OPERATIONS.md"')
        file=target/(route+'index.html');file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' data:; style-src \'self\'; script-src \'self\'; connect-src \'none\'; base-uri \'none\'"><title>Rook’s original strip comics</title><link rel="stylesheet" href="/stories/assets/site.css"><link rel="stylesheet" href="/stories/assets/worlds.css">'+nav+'<main>'+main+'</main><script src="/stories/assets/site.js" defer></script></html>')
    shutil.copyfile(target/'worlds/index.html',target/'index.html')
    assets=target/'assets';assets.mkdir(exist_ok=True)
    if (dist/'assets/stories').is_dir():shutil.copytree(dist/'assets/stories',assets/'stories',dirs_exist_ok=True)
    for file in (dist/'assets').glob('chapter-*.webp'):shutil.copyfile(file,assets/file.name)
    for name in ('site.js','site.css','rook.svg','rook-harbor.webp'):shutil.copyfile(dist/'assets'/name,assets/name)
    for file in (dist/'assets').glob('world-*.webp'):shutil.copyfile(file,assets/file.name)
    for file in (dist/'assets').glob('rook-*.svg'):shutil.copyfile(file,assets/file.name)
    for file in ROOT.joinpath('reader').glob('worlds.*'):shutil.copyfile(file,assets/file.name)
    (target/'data').mkdir(exist_ok=True);shutil.copyfile(ROOT/'content/cultural-sources.json',target/'data/cultural-sources.json')
