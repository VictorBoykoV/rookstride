"""Offline, grouped notices. Keep complete text and every component attribution."""
import html
import json
from pathlib import Path

GROUPS=('Rookstride','VPN protocols','Shared components','Build tools')

def protocol_section(name):
    name=name.lower()
    if 'strongswan' in name:return 'IKEv2 · strongSwan'
    if 'amneziawg' in name:return 'AmneziaWG'
    if 'xray' in name or 'xtls/reality' in name:return 'VLESS / REALITY and XHTTP'
    if 'openvpn' in name:return 'OpenVPN'
    if 'trusttunnel' in name:return 'TrustTunnel'
    if 'cronet' in name or 'chromium' in name:return 'NaïveProxy · Chromium / Cronet'
    if 'getoutline' in name or 'go-shadowsocks2' in name:return 'Outline / Shadowsocks'
    return ''

def records(root):
    root=Path(root);out=[]
    def add(group,section,title,text,owner):out.append(dict(group=group,section=section,title=title,text=text,owner=owner))
    for relative,title in [('NOTICE.md','Rookstride notices'),('LICENSE','Rookstride · GPL-3.0-or-later'),('gateway/LICENSE','Single-server installer'),('twohop/LICENSE','Double VPN installer')]:
        p=root/relative;add('Rookstride','',title,p.read_text(),relative)
    for p in sorted((root/'licenses').glob('*')):
        if not p.is_file():continue
        section=protocol_section(p.name)
        add('VPN protocols' if section else 'Shared components',section,p.name,p.read_text(),'licenses/'+p.name)
    for relative in ('.tools/native-engines/sources/manifest.json','.tools/native-engines/route-sources/manifest.json'):
        data=json.loads((root/relative).read_text())
        if data.get('go_license'):add('Build tools','','Go runtime and toolchain',data['go_license'],'Go runtime and toolchain · '+relative)
        for module in data['modules']:
            section=protocol_section(module['module'])
            for notice in module['licenses']:
                title=module['module'].split('@')[0].removeprefix('github.com/')
                add('VPN protocols' if section else 'Shared components',section,title,notice['text'],module['module']+' / '+notice['path'])
        for notice in data.get('extra_licenses',[]):
            section=protocol_section(notice['path']);group='VPN protocols' if section else 'Build tools'
            add(group,section,notice['path'],notice['text'],notice['path'])
    return out

def grouped(root):
    # Merge identical notices only within the same readable section. Preserve all owners.
    result={group:{} for group in GROUPS}
    for item in records(root):
        section=result[item['group']].setdefault(item['section'],{})
        entry=section.setdefault(item['text'],dict(title=item['title'],text=item['text'],owners=[]))
        if item['owner'] not in entry['owners']:entry['owners'].append(item['owner'])
    return result

def render(root):
    groups=grouped(root);escape=html.escape
    page=['''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Licensing</title><style>
*{box-sizing:border-box}html,body{width:100%;min-width:0;margin:0}body{font:15px/1.55 sans-serif;color:#141418;background:#f5f6f8;padding:20px;word-wrap:break-word;overflow-wrap:break-word;overflow-wrap:anywhere}h1{font-size:28px;margin:0 0 8px}h2{font-size:18px;margin:0}p{margin:8px 0 16px;color:#5c616b}a{color:#bf2637}details{min-width:0}summary{cursor:pointer;min-height:48px;padding:14px 0;word-wrap:break-word;overflow-wrap:break-word;overflow-wrap:anywhere;font-weight:600}summary::marker{color:#bf2637}.group{background:#fff;border:1px solid #e0e3e8;border-radius:14px;padding:0 16px;margin:14px 0}.section{border-top:1px solid #e0e3e8}.notice{border-top:1px solid #e0e3e8}.notice summary{font-size:14px;font-weight:500}.body{padding-bottom:12px}.owner{font-size:12px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;overflow-wrap:anywhere;color:#5c616b}pre{font:12px/1.6 monospace;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;overflow-wrap:anywhere;word-break:break-word;margin:12px 0;max-width:100%;min-width:0}small{display:block;font-weight:400;color:#5c616b;font-size:12px}
</style></head><body><h1>Licensing</h1><p>Rookstride · GPL-3.0-or-later.<br>Component notices, grouped for easy browsing.</p>''']
    def notices(entries):
        out=[]
        for entry in sorted(entries.values(),key=lambda x:x['title'].casefold()):
            out.append('<details class="notice"><summary>'+escape(entry['title'])+'</summary><div class="body"><div class="owner">'+escape('\n'.join(entry['owners']))+'</div><pre>'+escape(entry['text'])+'</pre></div></details>')
        return ''.join(out)
    descriptions={'Rookstride':'App license and project notices.','VPN protocols':'Engine notices by connection method.','Shared components':'Networking, encryption and shared libraries.','Build tools':'Runtime and toolchain notices.'}
    for group in GROUPS:
        sections=groups[group]
        page.append('<details class="group" data-license-group="'+escape(group)+'"><summary>'+escape(group)+'<small>'+escape(descriptions[group])+'</small></summary><div class="body">')
        if group=='Rookstride':page.append('<p>Corresponding source is supplied with this build. Each component retains its own license and notices.</p>')
        if group=='VPN protocols':page.append('<p>Hysteria 2, Outline and Shadowsocks also use the shared VPN worker (sing-box). Its notices are under Shared components.</p>')
        for name,entries in sorted(sections.items()):
            if name:page.append('<details class="section"><summary>'+escape(name)+'</summary><div class="body">'+notices(entries)+'</div></details>')
            else:page.append(notices(entries))
        page.append('</div></details>')
    page.append('</body></html>');return ''.join(page)
