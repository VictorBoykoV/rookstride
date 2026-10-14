"""Curated beginner pages share the native app's reviewed translation catalogs."""
import html,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CONFIG=json.loads((ROOT/'i18n/languages.json').read_text())
LANGS=CONFIG['locales']
ROUTES=['/','/start/','/architecture/','/routes/','/download/','/open-source/','/rook/','/worlds/','/plans/']
SECTIONS={'/':'home','/start/':'start','/architecture/':'architecture','/routes/':'routes','/download/':'download','/open-source/':'source','/rook/':'rook','/worlds/':'worlds','/plans/':'plans'}
GITHUB='https://github.com/VictorBoykoV/rookstride'
def esc(value):return html.escape(str(value),quote=True)
def catalog(tag):return json.loads((ROOT/'i18n'/ (tag+'.json')).read_text())
def url(tag,path):return path if tag=='en' else '/'+tag.lower()+path

def selector(tag,path):
 t=catalog(tag); supported=path in ROUTES
 links=''.join(f'<a lang="{l["tag"]}" hreflang="{l["tag"]}" data-language="{l["tag"]}" href="{url(l["tag"],path if supported else "/")}"'+(' aria-current="true"' if tag==l['tag'] else '')+f'>{esc(l["name"])}</a>' for l in LANGS)
 return f'<details class="language-picker"><summary>{esc(t["language.label"])} <span aria-hidden="true">⌄</span></summary><div>{links}</div></details>'

def alternate(path,base):
 if not base or path not in ROUTES:return ''
 return ''.join(f'<link rel="alternate" hreflang="{l["tag"]}" href="{base+url(l["tag"],path)}">' for l in LANGS)+f'<link rel="alternate" hreflang="x-default" href="{base+path}">'

def header(tag,path):
 t=catalog(tag);nav=[('start','/start/'),('architecture','/architecture/'),('routes','/routes/'),('plans','/plans/'),('source','/open-source/')]
 links=''.join(f'<a href="{url(tag,p)}"'+(' aria-current="page"' if p==path else '')+f'>{esc(t["nav."+k])}</a>' for k,p in nav)
 return f'<a class="skip-link" href="#main">{esc(t["nav.skip"])}</a><header class="site-header"><div class="header-inner"><a class="wordmark" href="{url(tag,"/")}" aria-label="{esc(t["nav.home"])}"><img src="/assets/rook.svg" width="38" height="38" alt="">rookstride<span class="wordmark-dot">.</span></a><button class="menu-toggle" aria-expanded="false" aria-controls="site-nav" type="button"><span>{esc(t["nav.menu"])}</span><span class="menu-lines" aria-hidden="true"></span></button><nav class="site-nav" id="site-nav" aria-label="{esc(t["nav.menu"])}">{links}<a class="button nav-download" href="{url(tag,"/download/")}">{esc(t["nav.download"])}</a></nav>{selector(tag,path)}</div></header>'

def body(tag,path,release):
 t=catalog(tag);section=SECTIONS[path]
 def e(key):
  value=t[key]
  if key in ('architecture.single_copy','architecture.pair_copy'):
   return '<span class="locale-flow" dir="ltr">'+' → '.join('<bdi dir="auto">'+esc(part)+'</bdi>' for part in value.split(' → '))+'</span>'
  return esc(value)
 def button(key,p,primary=False):return f'<a class="button {"primary" if primary else "outline"}" href="{url(tag,p)}">{e(key)}</a>'
 def card(title,copy,extra=''):return f'<article class="locale-card"><h2>{e(title)}</h2><p>{e(copy)}</p>{extra}</article>'
 def cards(items):return '<div class="locale-grid">'+''.join(card(*item) for item in items)+'</div>'
 heading='home.heading' if path=='/' else section+'.title'
 intro='home.intro' if path=='/' else section+'.intro'
 pose={'/':'guide','/start/':'map','/architecture/':'builder','/routes/':'map','/download/':'lantern','/open-source/':'guide','/rook/':'guide','/worlds/':'celebrate','/plans/':'map'}[path]
 lead=f'<section class="page-heading locale-hero"><div class="container"><div><p class="eyebrow">ROOKSTRIDE / {e("common.alpha")}</p><h1>{e(heading)}</h1><p class="lede">{e(intro)}</p><div class="button-row">{button("common.download","/download/",True)}{button("nav.start","/start/")}</div></div><img src="/assets/rook-{pose}.svg" width="200" height="200" alt="{e("rook.intro")}"></div></section>'
 content=''
 if path=='/':
  content=f'<p class="locale-lede">{e("home.copy")}</p><h2>{e("home.steps_heading")}</h2>'+cards([('home.step'+str(n),'home.step'+str(n)+'_copy') for n in range(1,5)])+card('home.language_heading','home.language_copy')+f'<p>{e("common.free")}</p>'
 elif path=='/start/':
  content=f'<h2>{e("start.need_title")}</h2><ul>'+''.join('<li>'+e('start.need'+str(n))+'</li>' for n in range(1,5))+'</ul><ol class="locale-steps">'+''.join('<li><h2>'+e('start.'+k)+'</h2><p>'+e('start.'+k+'_copy')+'</p></li>' for k in ['download','add','pin','install','wait','resume','connect','check','invite'])+'</ol>'+card('start.reset_title','start.reset_copy',f'<p>{e("start.reset_phrase")}</p>')
 elif path=='/architecture/':content=cards([('architecture.'+k,'architecture.'+k+'_copy') for k in ['single','pair','admin','usage','limits','lockdown']])
 elif path=='/routes/':
  content=cards([('routes.single','routes.single_copy',f'<span class="status-label">{e("common.available")}</span>'),('routes.pair','routes.pair_copy',f'<span class="status-label">{e("common.available")}</span>'),('routes.future','routes.future_copy',f'<span class="status-label planned">{e("common.not_available")}</span>'),('routes.network','routes.network_copy')])+button('nav.plans','/plans/')
 elif path=='/download/':
  artifacts=release['artifacts'];apk=next(a for a in artifacts if a['name'].endswith('.apk'));source=next(a for a in artifacts if a['name'].endswith('-source.tar.gz'))
  fmt=lambda k,**values:esc(t[k].format(**values))
  content=f'<h2>Rookstride <bdi>{esc(release["version"])}</bdi></h2><p>{e("common.alpha")}</p><div class="button-row"><a class="button primary" href="{apk["url"]}">{e("common.download")}</a><a class="button outline" href="{source["url"]}">{e("common.source")}</a><a class="button outline" href="{release["release_url"]}">{e("common.release")}</a></div><p>{fmt("download.size",apk_mib=format(apk["size"]/1024/1024,".1f"),code=release.get("version_code",5))}</p><p>{fmt("download.source_size",source_mib=format(source["size"]/1024/1024,".1f"))}</p><h2>{e("download.verify")}</h2><p>{e("download.hash")}</p><code class="locale-hash" dir="ltr">{apk["digest"].removeprefix("sha256:")}</code><p>{e("download.signer")}</p><code class="locale-hash" dir="ltr">751386cf7143ba92c88084a0b26dfeac86128b2fe0d5277821ee4c67a92ae7ba</code>'+card('download.test_title','download.test_copy',f'<a href="{GITHUB}/blob/main/docs/LOCALIZATION-TESTING.md">{e("app.english_detail")}</a>')+f'<p>{e("download.voice")}</p>'
 elif path=='/open-source/':
  content=cards([('source.app','source.app_copy',f'<a href="{GITHUB}">{e("common.github")}</a>'),('source.single','source.single_copy',f'<a href="https://github.com/VictorBoykoV/single-vps-vpn-gateway">{e("common.github")}</a>'),('source.pair','source.pair_copy',f'<a href="https://github.com/VictorBoykoV/beget-vpn-gateway">{e("common.github")}</a>'),('source.license','source.license_copy'),('source.privacy','source.privacy_copy'),('source.translate','source.translate_copy',f'<a href="{GITHUB}/tree/main/i18n">{e("common.github")}</a>')])
 elif path=='/rook/':
  content=card('rook.origin_title','rook.origin')+f'<blockquote>{e("rook.rule")}</blockquote><h2>{e("rook.roles")}</h2><div class="locale-grid">'+''.join(card('rook.'+k,'rook.'+k+'_copy',f'<img src="/assets/rook-{k}.svg" width="100" height="100" alt="{e("rook."+k)}" loading="lazy">') for k in ['guide','map','builder','lantern','wait','celebrate'])+f'</div><p>{e("rook.fiction")}</p>'+button('nav.worlds','/worlds/')
 elif path=='/worlds/':
  # Routes come from the canonical anthology rather than inferred translated titles.
  from world_reader import content as world_content
  actual=world_content()['worlds']
  content=f'<aside class="locale-notice">{e("worlds.english")}</aside><div class="locale-grid">'+''.join(card('worlds.'+key,'worlds.'+key+'_copy',f'<a href="/worlds/{w["id"]}/" lang="en">{e("worlds.open")}</a>') for key,w in zip(['harbor','persia','china','russia','america'],actual))+f'</div><p>{e("worlds.culture")}</p>'
 elif path=='/plans/':
  content=cards([('plans.languages','plans.languages_copy',f'<span class="status-label">{e("common.available")}</span>')]+[('plans.'+k,'plans.'+k+'_copy',f'<span class="status-label planned">{e("common.not_available")}</span>') for k in ['browser','controller','iphone','telegram','wechat']])+card('plans.gates','plans.gates_copy')+f'<a class="button outline" href="{GITHUB}/blob/main/docs/PLATFORMS-AND-LANGUAGES.md" lang="en">{e("plans.research")}</a>'
 footer=f'<footer class="site-footer"><div class="container"><a class="wordmark" href="{url(tag,"/")}">rookstride.</a><h2>{e("common.choice")}</h2><p>{e("common.scope")}</p><p>{e("language.english_docs")}</p><p>{e("common.site_note")}</p><div class="button-row">{button("nav.source","/open-source/")}{button("nav.worlds","/worlds/")}{button("nav.plans","/plans/")}</div><p>© 2026 Rookstride · GPL-3.0-or-later</p></div></footer>'
 return lead+'<section class="section"><div class="container docs-narrow">'+content+'</div></section>',footer,t[heading]+' — Rookstride',t[intro]+' '+t['common.scope']

def build(dist,base,release):
 urls=[]
 for lang in LANGS:
  tag=lang['tag']
  for path in ROUTES:
   if tag=='en' and path!='/plans/':continue
   page,footer,title,description=body(tag,path,release)
   canonical=f'<link rel="canonical" href="{base+url(tag,path)}">' if base else ''
   schema={'@context':'https://schema.org','@type':'WebPage','name':title,'description':description,'inLanguage':tag,'isAccessibleForFree':True}
   schema_json=json.dumps(schema,ensure_ascii=False).replace('</','<\\/')
   markup=f'<!doctype html><html lang="{tag}" dir="{lang["dir"]}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><meta name="description" content="{esc(description)}"><meta name="robots" content="index,follow,max-image-preview:large">{canonical}{alternate(path,base)}<link rel="icon" href="/assets/rook.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/site.css"><link rel="stylesheet" href="/assets/locales.css"><script type="application/ld+json">{schema_json}</script><script src="/assets/site.js" defer></script><script src="/assets/locales.js" defer></script></head><body class="locale-page" data-language="{tag}" data-route="{path}">{header(tag,path)}<main id="main">{page}</main>{footer}<div class="toast" role="status" aria-live="polite"></div></body></html>'
   target=dist/(url(tag,path).lstrip('/')+'index.html');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(markup);urls.append(url(tag,path))
 # All original English pages retain their rich content, plus language choice.
 for file in dist.rglob('*.html'):
  text=file.read_text()
  if '<html lang="en">' not in text:continue
  path='/'+file.relative_to(dist).parent.as_posix()+'/'
  if path=='/./':path='/'
  if file.name=='404.html':path='/404.html'
  text=text.replace('</head>',alternate(path,base)+'<link rel="stylesheet" href="/assets/locales.css"><script src="/assets/locales.js" defer></script></head>')
  text=text.replace('<body class=', '<body data-language="en" data-route="'+path+'" class=')
  text=text.replace('<nav class="site-nav"',selector('en',path)+'<nav class="site-nav"',1)
  text=text.replace('<a href="/routes/">Routes</a>','<a href="/routes/">Routes</a><a href="/plans/">Plans</a>',1)
  if path not in ROUTES:text=text.replace('<main id="main">','<main id="main"><aside class="locale-notice container">'+esc(catalog('en')['language.fallback'])+selector('en',path)+'</aside>',1)
  file.write_text(text)
 for name in ('locales.css','locales.js'):
  source=(ROOT/'website/reader'/name).read_text()
  if name=='locales.js':source=source.replace('/* translated-hints */null',json.dumps({l['tag']:{'hint':catalog(l['tag'])['language.browser_hint'],'keep':catalog(l['tag'])['language.keep'],'chosen':catalog(l['tag'])['app.chosen_language']} for l in LANGS},ensure_ascii=False))
  (dist/'assets'/name).write_text(source)
 (dist/'data/languages.json').write_text(json.dumps(CONFIG,ensure_ascii=False,indent=2)+'\n')
 (dist/'data/platform-plans.json').write_text(json.dumps({'status':'research-backlog','implemented':['android-single-ikev2','android-pair-ikev2-amneziawg','main-flow-localization'],'planned':['browser-planner-native-handoff','user-controlled-web-connector','iphone-native-admin-vpn','telegram-approved-status','weixin-feasibility'],'credential_boundary':'No root passwords or private keys in public websites, plans or messenger chats.','report':GITHUB+'/blob/main/docs/PLATFORMS-AND-LANGUAGES.md'},indent=2)+'\n')
 return urls
