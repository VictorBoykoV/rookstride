"""Bounded AWG/OpenVPN image transactions, preserving listener identity and data.

Images are built from the reviewed recipe, staged and addressed by immutable ID.
A listener's original container stays stopped under a private rollback name.
Only recognized Rookstride runtime mounts and launch options are reconstructed.
"""
import json,re,shlex,subprocess
from pathlib import Path
import pair,native_pair,runtime,lifecycle
GROUPS=('awg','openvpn')

def image(tag):
    value=runtime.command(['docker','image','inspect','--format','{{.Id}}',tag]).strip()
    if not re.fullmatch('sha256:[a-f0-9]{64}',value):raise ValueError('Unexpected Docker image identity')
    return value

def inspect(name):
    p=subprocess.run(['docker','container','inspect',name],capture_output=True,text=True,timeout=20)
    if p.returncode:
        if 'no such' in p.stderr.lower():return None
        raise ValueError('Docker inspection failed')
    value=json.loads(p.stdout)
    if len(value)!=1:raise ValueError('Unexpected container inspection')
    return value[0]

def listener(state,sha):
    p=state['protocol'];name=runtime.container(p);c=runtime.check_container(state)
    if not c:raise ValueError('Start or inspect the installed VPN before reviewing its image')
    cfg=c['Config'];host=c['HostConfig'];mounts=c.get('Mounts',[])
    if cfg.get('Entrypoint')!=['/bin/bash'] or cfg.get('Cmd')!=['/rookstride-entry.sh'] or host.get('Privileged') or host.get('NetworkMode') not in ('default','bridge'):raise ValueError('Unrecognized VPN container launch options')
    if sorted(host.get('CapAdd') or [])!=['NET_ADMIN'] or host.get('CapDrop') or host.get('Binds') or host.get('VolumesFrom') or host.get('Links') or host.get('SecurityOpt'):raise ValueError('Unrecognized VPN container privileges')
    devices=host.get('Devices') or []
    if len(devices)!=1 or any(devices[0].get(k)!=v for k,v in {'PathOnHost':'/dev/net/tun','PathInContainer':'/dev/net/tun','CgroupPermissions':'rwm'}.items()):raise ValueError('Unrecognized VPN tunnel device')
    allowed={'net.ipv4.ip_forward':'1','net.ipv6.conf.all.disable_ipv6':'0'}
    if host.get('Sysctls')!=allowed or host.get('RestartPolicy',{}).get('Name') not in ('no','unless-stopped'):raise ValueError('Unrecognized VPN container networking')
    mappings=host.get('PortBindings') or {};port='51820/udp' if p=='awg' else '1194/tcp'
    if set(mappings)!={port} or len(mappings[port])!=1 or mappings[port][0].get('HostIp','') not in ('','0.0.0.0') or mappings[port][0].get('HostPort')!=str(state['port']):raise ValueError('Unrecognized VPN port mapping')
    config={};args=['--name',name,'--restart',host['RestartPolicy']['Name'],'--label','io.rookstride.instance='+state['instance'],'--cap-add','NET_ADMIN','--device','/dev/net/tun']
    for key,val in allowed.items():args+=['--sysctl',key+'='+val]
    if len(mounts)!=2:raise ValueError('Unrecognized VPN container mounts')
    for m in sorted(mounts,key=lambda x:x['Destination']):
        source=Path(m['Source']);pair.protected(source);dest=m['Destination']
        if m.get('Type')!='bind' or dest not in ('/vpn','/rookstride-entry.sh'):raise ValueError('Unrecognized VPN container mount')
        if dest=='/vpn':
            if source!=runtime.directory(p)/'runtime' or not m.get('RW'):raise ValueError('Unrecognized VPN runtime directory')
            # Identity and generated configuration; live counters/logs excluded.
            for file in sorted(source.rglob('*')):
                if file.is_file() and not file.is_symlink() and file.suffix in ('.conf','.ovpn','.crt','.key','.pem','.json'):config[str(file)]=sha(file)
        else:
            if source.name!='entry-'+p+'.sh' or source.parent.name!='single' or m.get('RW'):raise ValueError('Unrecognized VPN entry script')
            config[str(source)]=sha(source)
        args+=['--mount','type=bind,source='+str(source)+',target='+dest+('' if m.get('RW') else ',readonly')]
    for value in cfg.get('Env',[]):
        if value.startswith('ROOK_'):
            key,_,val=value.partition('=')
            if key not in ('ROOK_DNS_ADDRESS','ROOK_DNS_PORT','ROOK_PAIR_ROUTE') or not re.fullmatch('[A-Za-z0-9.:_-]{1,64}',val):raise ValueError('Unrecognized VPN environment')
            args+=['-e',value]
    args+=['-p',str(state['port'])+':'+port,'--entrypoint','/bin/bash']
    return {'kind':'container','name':name,'configs':config,'args':args,'instance':state['instance'],'binary':c['Image'],'original_id':c['Id']}

def bridge(group,manifest,sha):
    path=Path('/etc/systemd/system')/(native_pair.BRIDGE+'.service');pair.protected(path);text=path.read_text();starts=re.findall('^ExecStart=(.+)$',text,re.M)
    if len(starts)!=1 or 'Description=Rookstride owned ' not in text:raise ValueError('Unrecognized bridge service')
    argv=shlex.split(starts[0]);tag='rookstride-'+group+':1'
    if argv[:3]!=['/usr/bin/docker','run','--rm'] or argv.count(tag)!=1 or '--label' not in argv or argv[argv.index('--label')+1]!='io.rookstride.pair='+manifest['plan']['pair']:raise ValueError('Unrecognized bridge image ownership')
    files={}
    for i,value in enumerate(argv):
        if value=='--mount':
            fields=dict(part.split('=',1) for part in argv[i+1].split(',') if '=' in part);source=Path(fields.get('source','/'));pair.protected(source)
            if not (source.is_relative_to(pair.OWN) or source.is_relative_to(pair.RELEASE)):raise ValueError('Unrecognized bridge mount')
            for file in sorted(source.rglob('*')) if source.is_dir() else [source]:
                if file.is_file():files[str(file)]=sha(file)
    return {'kind':'bridge','name':native_pair.BRIDGE,'path':str(path),'text':text,'argv':argv,'configs':files,'binary':image(tag)}

def validate_consumers(services):
    allowed={s['name'] for s in services};ids={s['binary'] for s in services}
    for ident in ids:
        names=runtime.command(['docker','ps','-a','--filter','ancestor='+ident,'--format','{{.Names}}']).splitlines()
        if any(name not in allowed and not re.fullmatch('rookstride-prior-[a-f0-9]{32}-(awg|openvpn)',name) for name in names):raise ValueError('This VPN image also runs an unreviewed container')

def stage(op,source):
    group=op['group'];tag='rookstride-stage-'+group+':'+op['operation'];recipe=source/'single'/('Dockerfile.'+group)
    runtime.command(['docker','build','--pull=false','-t',tag,'-f',str(recipe),str(source/'single')],timeout=1200)
    ident=image(tag);runtime.command(['docker','run','--rm','--network','none',ident,'awg','--version'] if group=='awg' else ['docker','run','--rm','--network','none','--entrypoint','/usr/sbin/openvpn',ident,'--version'],timeout=20)
    op['new_hash']=ident;op['target']='rookstride-'+group+':1';op['candidate_image']=ident;op['old_tag_image']=image(op['target']);op['available']=any(s['binary']!=ident for s in op['snapshot']['services'])
    op['prior_images']={}
    for index,old in enumerate(op['old_hashes']):
        keep='rookstride-prior-'+group+':'+op['operation']+'-'+str(index);runtime.command(['docker','tag',old,keep]);op['prior_images'][old]=keep
    return op

def same_identity(op,sha):
    for service in op['snapshot']['services']:
        for name,digest in service['configs'].items():
            if sha(Path(name))!=digest:raise ValueError('VPN configuration changed after image review')
        if service['kind']=='bridge':
            planned=service['text'].replace(service.get('image_token',op['target']),op['candidate_image'],1) if service.get('image_token') else service['text']
            if Path(service['path']).read_text() not in (service['text'],planned):raise ValueError('Bridge service changed after review')
            current_text=Path(service['path']).read_text();reference=(service['image_token'] if current_text==service['text'] else op['candidate_image']) if service.get('image_token') else op['target']
            if image(reference) not in (service['binary'],op['new_hash']):raise ValueError('Bridge image changed outside this operation')
        else:
            current=inspect(service['name']);prior=inspect(backup(op))
            if prior and (prior['Id']!=service['original_id'] or prior['Image']!=service['binary']):raise ValueError('Retained container identity changed')
            if current and (current['Image'] not in (service['binary'],op['new_hash']) or current['Config'].get('Labels',{}).get('io.rookstride.instance')!=service['instance']):raise ValueError('VPN container changed outside this operation')
            if current and current['Id']!=service['original_id'] and not prior:raise ValueError('Original VPN container is missing')
            if not current and not prior:raise ValueError('Original VPN container is missing')
    for old,tag in op.get('prior_images',{}).items():
        if image(tag)!=old:raise ValueError('Retained image integrity changed')

def backup(op):return 'rookstride-prior-'+op['operation']+'-'+op['group']

def mutate(op,rollback):
    services=op['snapshot']['services'];bridges=[s for s in services if s['kind']=='bridge']
    for s in bridges:runtime.command(['systemctl','stop',s['name']],timeout=40)
    # One owned listener per protocol. Keep its stopped original for rollback.
    for s in services:
        if s['kind']!='container':continue
        current=inspect(s['name']);prior=inspect(backup(op))
        if rollback:
            if prior:
                if current:runtime.command(['docker','rm','-f',s['name']],timeout=40)
                runtime.command(['docker','rename',backup(op),s['name']])
            runtime.command(['docker','start',s['name']],timeout=40)
        else:
            if current and current['Id']==s['original_id']:
                runtime.command(['docker','stop',s['name']],timeout=40);runtime.command(['docker','rename',s['name'],backup(op)]);current=None
            if not current:runtime.command(['docker','create',*s['args'],op['candidate_image'],'/rookstride-entry.sh'],timeout=40)
            runtime.command(['docker','start',s['name']],timeout=40)
    old=op.get('old_tag_image',op['old_hashes'][0]);runtime.command(['docker','tag',old if rollback else op['candidate_image'],op['target']])
    for s in bridges:
        text=s['text'] if rollback or not s.get('image_token') else s['text'].replace(s['image_token'],op['candidate_image'],1)
        path=Path(s['path']);pair.atomic(path,text);path.chmod(0o644)
    if bridges:runtime.command(['systemctl','daemon-reload'])
    for s in bridges:runtime.command(['systemctl','start',s['name']],timeout=40)
