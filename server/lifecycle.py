#!/usr/bin/env python3
"""Owner-controlled, revisioned lifecycle sidecar; immutable pair recipes stay intact.

Protocol adapters stage an independently authenticated replacement exit. Entry listeners and user databases are
never written. The candidate has a separate interface, probe source/table and
service. Every transition is journaled before side effects and can be reconciled.
"""
import contextlib, copy, fcntl, hashlib, ipaddress, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair, native_pair, lifecycle_transport
ROOT=Path('/var/lib/rookstride-lifecycle')
ACTIVE=ROOT/'active.json'
LOCK=Path('/run/rookstride-lifecycle.lock')
MANAGEMENT_LOCK=Path('/run/rookstride-management.lock')
SCHEMA=1
PROBE='10.249.255.253'
TABLE=51832
PRIORITY=89

@contextlib.contextmanager
def management_lock():
    # Shared with delegated users, restores and helper updates; fixed global order.
    with MANAGEMENT_LOCK.open('a') as management, LOCK.open('a') as lock, pair.LOCK.open('a') as pairlock:
        fcntl.flock(management,fcntl.LOCK_EX);fcntl.flock(lock,fcntl.LOCK_EX);fcntl.flock(pairlock,fcntl.LOCK_EX)
        yield

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write(path,value):
    pair.protected(path);pair.atomic(path,json.dumps(value,sort_keys=True))
    fd=os.open(str(path.parent),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
def read(path):
    if not path.exists() and not path.is_symlink():return None
    pair.protected(path)
    return json.loads(path.read_text())

def anchor(m):return digest({'plan':m['plan'],'bundle':m.get('bundle'),'configure_digest':m.get('configure_digest')})
def route_override(m):
    """Read by the boot guard; foreign/corrupt state must never open forwarding."""
    value=read(ACTIVE)
    if value is None:return None
    if value.get('schema')!=SCHEMA or value.get('anchor')!=anchor(m) or value.get('deployment')!=m['plan']['pair']:raise ValueError('Lifecycle route no longer matches this owned pair')
    route=value['route']
    if not re.fullmatch(r'rsx[a-f0-9]{10}',route.get('interface','')):raise ValueError('Invalid lifecycle route interface')
    ipaddress.IPv4Address(route['bridge_ip']);pair.host(route['exit_host'])
    if route.get('exit_protocol') not in lifecycle_transport.SUPPORTED:raise ValueError('Unsupported lifecycle route')
    return value

def reanchor(old_manifest,new_manifest):
    """Idempotent two-anchor reconciliation under lifecycle + pair locks.

    Either file may have reached the reviewed new anchor before process death.
    A third anchor is always a conflict; the recipe and peer digest cannot change.
    """
    if old_manifest['plan']!=new_manifest['plan'] or old_manifest.get('configure_digest')!=new_manifest.get('configure_digest'):raise ValueError('Helper update cannot change the deployment or peer identity')
    if any(op['state'] not in ('accepted','rolled-back','cancelled') for op in records()):raise ValueError('Finish the lifecycle operation before updating its helper')
    old=anchor(old_manifest);new=anchor(new_manifest)
    inventory=read(ROOT/'inventory.json')
    if inventory:
        if inventory['anchor'] not in (old,new):raise ValueError('Logical inventory changed during helper review')
        inventory['anchor']=new;write(ROOT/'inventory.json',inventory)
    active=read(ACTIVE)
    if active:
        if active['anchor'] not in (old,new):raise ValueError('Active lifecycle revision changed during helper review')
        operation=read(ROOT/'operations'/active['operation']/'journal.json')
        if not operation or operation['state']!='accepted' or operation['anchor'] not in (old,new):raise ValueError('Accept the current replacement before updating its helper')
        if old!=new and old not in active.setdefault('helper_anchors',[]):active['helper_anchors'].append(old)
        active['anchor']=new;operation['anchor']=new
        write(ROOT/'operations'/active['operation']/'journal.json',operation);write(ACTIVE,active)
    return {'reanchored':bool(active)}

def server_inventory():
    m=pair.load_manifest()
    if not m:return {'server_id':hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),'deployment_id':'','protocols':[]}
    protocol=m['plan'].get('entry_protocol','ikev2') if m['plan']['role']=='entry' else m['plan'].get('exit_protocol','awg')
    instance=m['plan']['pair']+':'+m['plan']['role'] if protocol=='ikev2' else native_pair.runtime.load(protocol)['instance']
    return {'server_id':hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),'deployment_id':m['plan']['pair'],'protocols':[{'id':m['plan']['pair']+':'+m['plan']['role']+':'+protocol,'protocol':protocol,'instance':instance}]}

def inspect():
    m=pair.load_manifest()
    if not m:return {'schema':SCHEMA,'recognized':False,'read_only':True,'reason':'No owned pair manifest'}
    p=pair.plan(m['plan']);a=route_override(m) if p['role']=='entry' else None
    inventory=read(ROOT/'inventory.json')
    if inventory and (inventory.get('deployment')!=p['pair'] or inventory.get('anchor')!=anchor(m)):raise ValueError('Logical deployment inventory changed')
    if inventory and inventory.get('entry_endpoint'):p=dict(p,server=pair.host(inventory['entry_endpoint']))
    def intact(path,expected):
        try:
            pair.protected(path);return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==expected
        except (ValueError,OSError):return False
    files_ok=all(intact(Path(path),h) for path,h in m.get('file_hashes',{}).items())
    units_ok=all(intact(native_pair.UNIT/(name+'.service'),h) for name,h in m.get('unit_hashes',{}).items())
    # pair.status may reconcile and write an interrupted job. Adoption is strictly
    # observational, so inspect the durable status without performing reconciliation.
    statuses=[read(pair.STATE/pair.ident(job)/'status.json') for job in m.get('jobs',{}).values()]
    idle=all(status and status.get('state') in ('complete','failed','paused') for status in statuses)
    ready=idle and m.get('version')==2 and m.get('configured') is True and not m.get('resetting') and files_ok and units_ok
    return {'schema':SCHEMA,'recognized':True,'deployment':p['pair'],'revision':a['revision'] if a else inventory['revision'] if inventory else 1,'role':p['role'],'plan':p,'anchor':anchor(m),'bundle':m.get('bundle',''),'read_only':not ready,'configured':bool(m.get('configured')),'active':bool(m.get('activated')),'installed_state_verified':files_ok and units_ok,'exit_host':a['route']['exit_host'] if a else p['exit_host'],'capabilities':['inspect','replace-exit-'+p['exit_protocol'],'rollback'] if ready and p['role']=='entry' and p.get('exit_protocol') in lifecycle_transport.SUPPORTED else ['inspect'],'operation':a.get('operation','') if a else ''}

def records():
    if not ROOT.exists():return []
    return [read(p) for p in sorted((ROOT/'operations').glob('*/journal.json'))] if (ROOT/'operations').exists() else []
def public(op):return {k:op[k] for k in ('schema','operation','deployment','expected_revision','state','phase','created','updated','new_exit','expected_exit_ip','retained','usage_generation','candidate_retired') if k in op}
def save(op,state,phase):
    op.update(state=state,phase=phase,updated=time.time());write(ROOT/'operations'/op['operation']/'journal.json',op)
    return public(op)
def owned(req):
    m=pair.load_manifest();info=inspect()
    if not m or req.get('deployment')!=info.get('deployment'):raise ValueError('Unknown deployment')
    if info['read_only'] or m['plan']['role']!='entry':raise ValueError('This deployment is inspection-only; a compatible verified native entry is required')
    return m,info

def prepare(req):
    m,info=owned(req);operation=pair.ident(req.get('operation'));folder=ROOT/'operations'/operation
    if m['plan'].get('exit_protocol') not in lifecycle_transport.SUPPORTED:raise ValueError('This exit transport has no isolated migration adapter')
    previous=read(folder/'journal.json')
    if previous:
        if previous['request_digest']!=digest(req):raise ValueError('Recorded operation parameters changed')
        return public(previous)
    if type(req.get('expected_revision')) is not int or req['expected_revision']!=info['revision']:raise ValueError('Deployment revision changed; inspect and review again')
    if any(v['state'] not in ('accepted','rolled-back','cancelled') for v in records()):raise ValueError('Finish or roll back the recorded operation first')
    if req.get('confirmation')!='REPLACE EXIT AND KEEP ENTRY USERS':raise ValueError('Review the exit replacement before continuing')
    p=copy.deepcopy(m['plan']);p['exit_host']=pair.host(req.get('exit_host'));p['tunnel_port']=req.get('tunnel_port',p['tunnel_port']);p=pair.plan(p)
    if p['exit_host']==info['exit_host']:raise ValueError('Choose a distinct replacement exit')
    material=req.get('transport');native_pair.validate_material(p,material)
    current=read(pair.OWN/'transport.json')
    if not current or material['dns']!=current.get('dns'):raise ValueError('The replacement must preserve the entry clients’ exact private DNS address and port')
    expected=str(ipaddress.IPv4Address(req.get('expected_exit_ip','')))
    policy=req.get('filter_policy',{'level':'standard','enabled':True})
    __import__('recovery').validate_policy(policy)
    op={'schema':SCHEMA,'operation':operation,'deployment':p['pair'],'expected_revision':info['revision'],'anchor':anchor(m),'request_digest':digest(req),'created':time.time(),'plan':p,'new_exit':p['exit_host'],'expected_exit_ip':expected,'previous':read(ACTIVE),'transport':material,'interface':'rsx'+operation[:10],'retained':['entry endpoint','entry listener','VPN accounts and keys','saved client profiles','original pair recipe','old exit rollback route'],'usage_generation':operation,'filter_policy':policy}
    return save(op,'prepared','Replacement reviewed; active route unchanged')

def load_operation(req):
    operation=pair.ident(req.get('operation'));op=read(ROOT/'operations'/operation/'journal.json')
    if not op or op['deployment']!=req.get('deployment'):raise ValueError('Unknown lifecycle operation')
    m,info=owned(req)
    if op['anchor']!=anchor(m):raise ValueError('Owned pair changed during this operation')
    return op,m,info

def command(args,timeout=120):return native_pair.command(args,timeout=timeout)
def candidate_route(op):
    import native_routing as r
    interface=op['interface'];source=PROBE+'/32';vip=op['bridge_ip']
    known_interfaces={interface}|{item.get('interface') for item in records() if item['deployment']==op['deployment'] and item['state'] in ('accepted','rolled-back','cancelled')}
    existing=r.run(['ip','-j','route','show','table',str(TABLE)],False)
    if existing.returncode==0:
        for route in json.loads(existing.stdout):
            if route.get('dst')!='default' or route.get('type') not in (None,'unicast','blackhole') or route.get('type')!='blackhole' and route.get('dev') not in known_interfaces:raise ValueError('The candidate probe table is already used by another route')
    assigned=json.loads(r.run(['ip','-j','address','show']).stdout)
    if any(address.get('local')==PROBE and item.get('ifname')!='lo' for item in assigned for address in item.get('addr_info',[])):raise ValueError('The candidate probe address is already used')
    r.rule(PRIORITY,source,TABLE)
    command(['ip','address','replace',source,'dev','lo'])
    command(['ip','route','replace','blackhole','default','metric','42760','table',str(TABLE)])
    command(['ip','route','replace','default','dev',interface,'metric','10','table',str(TABLE)])
    chain='RSLIFE_PROBE';r.chain('nat',chain);r.ipt('nat','-F',chain);r.ipt('nat','-A',chain,'-s',source,'-o',interface,'-j','SNAT','--to-source',vip);r.jump('nat','POSTROUTING',chain)
    chain='RSLIFE_GUARD';r.chain('filter',chain);r.ipt('filter','-F',chain);r.ipt('filter','-A',chain,'-s',source,'-o',interface,'-j','ACCEPT');r.ipt('filter','-A',chain,'-s',source,'-j','REJECT');r.jump('filter','OUTPUT',chain)

def enable_runtime():
    """Reviewed helper extension: preserve immutable bundle and owned unit hashes."""
    source=Path(__file__).resolve().parent.parent;target=ROOT/'runtime'
    for folder in ('server','single'):
        shutil.copytree(source/folder,target/folder,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    m=pair.load_manifest()
    for name in ('rookstride-pair-routing','rookstride-pair-watch','rookstride-pair-entry','rookstride-pair-bridge'):
        path=native_pair.UNIT/(name+'.service')
        if not path.exists():continue
        text=path.read_text();actual=hashlib.sha256(text.encode()).hexdigest()
        if m.get('unit_hashes',{}).get(name)!=actual:raise ValueError('Owned routing service changed; refusing helper extension')
        old=str(pair.RELEASE/'server/native_routing.py');new=str(target/'server/native_routing.py')
        text=text.replace(old,new)
        if name=='rookstride-pair-bridge' and m['plan']['exit_protocol']=='ikev2' and m['plan']['entry_protocol']!='ikev2':text=text.replace('ExecStartPost=/usr/bin/python3 '+new+' ike-load','ExecStartPost=-/usr/bin/python3 '+new+' ike-load')
        if text!=path.read_text():
            pair.atomic(path,text);path.chmod(0o644);m['unit_hashes'][name]=hashlib.sha256(text.encode()).hexdigest();pair.write_manifest(m)
    command(['systemctl','daemon-reload']);command(['systemctl','restart','rookstride-pair-watch'])

def candidate_unit(op):
    if op['plan']['exit_protocol']!='awg':return lifecycle_transport.unit(op)
    folder=ROOT/'operations'/op['operation'];unitname='rookstride-lifecycle-'+op['operation'];script=folder/'bridge.sh'
    return f'''[Unit]\nDescription=Rookstride staged replacement exit\nAfter=docker.service network-online.target\nRequires=docker.service\n[Service]\nExecStartPre=-/usr/bin/docker rm -f {unitname}\nExecStart=/usr/bin/docker run --rm --name {unitname} --label io.rookstride.lifecycle={op['operation']} --network host --cap-add NET_ADMIN --device /dev/net/tun --mount type=bind,source={folder},target=/vpn,readonly --mount type=bind,source={script},target=/bridge.sh,readonly --entrypoint /bin/bash rookstride-awg:1 /bridge.sh\nExecStop=/usr/bin/docker stop {unitname}\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target docker.service\n'''

def stage(op):
    enable_runtime()
    if op['plan']['exit_protocol']!='awg':return stage_native(op)
    folder=ROOT/'operations'/op['operation'];unitname='rookstride-lifecycle-'+op['operation'];unit=native_pair.UNIT/(unitname+'.service')
    text=op['transport']['profile']['content'];address=re.search(r'^Address\s*=\s*([^,\s]+)',text,re.M)
    if not address:raise ValueError('Candidate connection has no private address')
    op['bridge_ip']=str(ipaddress.IPv4Interface(address[1]).ip)
    text=re.sub(r'^DNS\s*=.*\n','',text,flags=re.M);text=text.replace('[Interface]','[Interface]\nTable = off',1)
    write(folder/'route.json',{'interface':op['interface'],'bridge_ip':op['bridge_ip']})
    pair.atomic(folder/'awg-exit.conf',text)
    # The script is copied to a separately owned directory, never over the pair bundle.
    script=folder/'bridge.sh';source=Path(__file__).with_name('native-bridge-awg.sh').read_text();source=source.replace('awg-exit',op['interface'])
    # The bind-mounted filename stays fixed even when the network interface differs.
    source=source.replace('/vpn/'+op['interface']+'.conf','/vpn/awg-exit.conf');pair.atomic(script,source)
    content=candidate_unit(op)
    if unit.exists() and hashlib.sha256(unit.read_bytes()).hexdigest()!=hashlib.sha256(content.encode()).hexdigest():raise ValueError('Candidate service ownership changed')
    pair.protected(unit);pair.atomic(unit,content);unit.chmod(0o644)
    op['service_sha256']=hashlib.sha256(content.encode()).hexdigest();op['script_sha256']=hashlib.sha256(source.encode()).hexdigest();save(op,'staging','Waiting for isolated candidate bridge readiness')
    command(['systemctl','daemon-reload']);command(['systemctl','enable','--now',unitname])
    for _ in range(150):
        result=subprocess.run(['ip','-j','address','show','dev',op['interface']],capture_output=True,text=True)
        if result.returncode==0:
            try:
                interfaces=json.loads(result.stdout)
                if any('UP' in item.get('flags',[]) and any(address.get('local')==op['bridge_ip'] for address in item.get('addr_info',[])) for item in interfaces):break
            except (ValueError,TypeError):pass
        time.sleep(.2)
    else:raise ValueError('Candidate exit interface did not acquire its reviewed address and become ready')
    candidate_route(op)

def stage_native(op):
    content=lifecycle_transport.prepare(op);unitname='rookstride-lifecycle-'+op['operation'];unit=native_pair.UNIT/(unitname+'.service')
    if unit.exists() and hashlib.sha256(unit.read_bytes()).hexdigest()!=hashlib.sha256(content.encode()).hexdigest():raise ValueError('Candidate service ownership changed')
    pair.protected(unit);pair.atomic(unit,content);unit.chmod(0o644)
    op['service_sha256']=hashlib.sha256(content.encode()).hexdigest();save(op,'staging','Waiting for isolated candidate authentication')
    command(['systemctl','daemon-reload']);command(['systemctl','enable','--now',unitname])
    for _ in range(120):
        try:address=lifecycle_transport.ready(op)
        except (OSError,RuntimeError):address=''
        if address:op['bridge_ip']=address;break
        time.sleep(.5)
    else:raise ValueError('The candidate exit did not authenticate and acquire its private address')
    save(op,'staging','Candidate authenticated; testing its independent route');candidate_route(op)

def verify_route(op,source):
    actual=command(['curl','-4','--curves','X25519','--interface',source,'--connect-timeout','10','--max-time','30','-fsS','https://api.ipify.org'])
    if actual!=op['expected_exit_ip']:raise ValueError('Candidate did not use the reviewed exit address')
    p=dict(op['plan'],test_ip=source);native_pair.dns_check(p,op['transport'],blocking=op.get('filter_policy',{}).get('enabled',True))

def set_active(value):
    if value is None:
        pair.protected(ACTIVE);ACTIVE.unlink(missing_ok=True)
    else:write(ACTIVE,value)

def retire_candidate(op):
    """Stop a terminal unused bridge; retain its owned files and journal."""
    active=read(ACTIVE)
    if active and active.get('operation')==op['operation'] or op.get('previous') and op['previous'].get('operation')==op['operation']:raise ValueError('The candidate is still selected by a route')
    if any(other['operation']!=op['operation'] and other['state'] not in ('rolled-back','cancelled') and other.get('previous') and other['previous'].get('operation')==op['operation'] for other in records()):raise ValueError('Another operation still retains this rollback bridge')
    unitname='rookstride-lifecycle-'+pair.ident(op['operation']);unit=native_pair.UNIT/(unitname+'.service');pair.protected(unit)
    if not unit.is_file() or hashlib.sha256(unit.read_bytes()).hexdigest()!=op.get('service_sha256') or unit.read_text()!=candidate_unit(op):raise ValueError('Candidate service ownership changed; it was not stopped')
    command(['systemctl','disable','--now',unitname])
    op['candidate_retired']=True

def transition(req):
    op,m,info=load_operation(req);action=req['action']
    if action=='status':return public(op)
    if action=='stage':
        if op['state'] in ('verified','active','accepted'):return public(op)
        if op['state'] not in ('prepared','staging'):raise ValueError('Candidate cannot be staged in this state')
        save(op,'staging','Preparing isolated replacement bridge')
        stage(op);verify_route(op,PROBE)
        return save(op,'verified','Candidate exit, DNS and blocking verified; current route unchanged')
    if action=='cutover':
        if op['state'] in ('active','accepted'):return public(op)
        current=read(ACTIVE)
        reconciled=current and current.get('operation')==op['operation']
        if op['state'] not in ('verified','cutting-over') or not reconciled and info['revision']!=op['expected_revision']:raise ValueError('Candidate or deployment revision changed')
        # Retry after process death re-verifies the same candidate; no new install.
        candidate_route(op);verify_route(op,PROBE)
        save(op,'cutting-over','Closing forwarding before route cutover')
        import native_routing as r
        r.apply('quiesce')
        try:
            set_active({'schema':SCHEMA,'deployment':op['deployment'],'anchor':op['anchor'],'revision':op['expected_revision']+1,'operation':op['operation'],'route':{'interface':op['interface'],'bridge_ip':op['bridge_ip'],'exit_host':op['new_exit'],'exit_protocol':op['plan']['exit_protocol']}})
            r.apply('refresh');verify_route(op,m['plan']['test_ip']);r.apply('activate')
        except Exception:
            r.apply('quiesce');save(op,'cutting-over','Cutover stopped with forwarding closed; resume or roll back');raise
        return save(op,'active','New exit active; saved entry profiles retained; accept or roll back')
    if action=='rollback':
        if op['state']=='rolled-back':
            retire_candidate(op);return save(op,'rolled-back','Previous exit restored; unused candidate bridge stopped')
        if op['state']=='accepted':raise ValueError('Accepted replacement requires a new reviewed migration')
        if op['state'] not in ('verified','cutting-over','active','rolling-back'):raise ValueError('No verified route to roll back')
        import native_routing as r
        save(op,'rolling-back','Closing forwarding and restoring the recorded previous route');r.apply('quiesce');set_active(op['previous']);r.apply('refresh')
        # Previous route verification is mandatory; no failed rollback opens traffic.
        value=read(pair.OWN/'transport.json') if op['previous'] is None else read(ROOT/'operations'/op['previous']['operation']/'journal.json')['transport']
        expected=req.get('previous_exit_ip')
        if not expected:raise ValueError('Verify the original exit public address before rollback')
        verify_route(dict(op,transport=value,expected_exit_ip=str(ipaddress.IPv4Address(expected))),m['plan']['test_ip']);r.apply('activate')
        retire_candidate(op)
        return save(op,'rolled-back','Previous exit verified and restored')
    if action=='accept':
        if op['state']=='accepted':return public(op)
        if op['state']!='active':raise ValueError('Verify active client traffic before accepting')
        if req.get('confirmation')!='CLIENT TRAFFIC VERIFIED':raise ValueError('Confirm independent saved-client verification')
        return save(op,'accepted','Replacement accepted; old server retained for explicit removal')
    raise ValueError('Unsupported lifecycle action')

def cleanup_review(m):
    if not ROOT.exists():return {'files':[],'services':[],'interfaces':[],'fingerprint':''}
    pair.protected(ROOT);route_override(m) if m['plan']['role']=='entry' else None
    services=[];interfaces=[];hasher=hashlib.sha256()
    for path in sorted(ROOT.rglob('*')):
        pair.protected(path)
        if path.is_file():hasher.update(str(path.relative_to(ROOT)).encode()+path.read_bytes())
    for op in records():
        if op['deployment']!=m['plan']['pair']:raise ValueError('Lifecycle data belongs to another deployment')
        if not op.get('interface'):continue
        name='rookstride-lifecycle-'+pair.ident(op['operation']);unit=native_pair.UNIT/(name+'.service')
        if unit.exists():
            pair.protected(unit);expected=hashlib.sha256(candidate_unit(op).encode()).hexdigest()
            if hashlib.sha256(unit.read_bytes()).hexdigest()!=expected:raise ValueError('Lifecycle bridge service ownership changed')
            services.append(name)
        interfaces.append(op['interface'])
        if op['plan']['exit_protocol']=='ikev2':
            folder=lifecycle_transport.ike_folder(op)
            for path in folder.rglob('*'):
                pair.protected(path)
                if path.is_file():hasher.update(str(path).encode()+path.read_bytes())
    return {'files':[str(ROOT)]+[str(lifecycle_transport.ike_folder(op)) for op in records() if op.get('interface') and op['plan']['exit_protocol']=='ikev2']+[str(native_pair.UNIT/(name+'.service')) for name in services],'services':services,'interfaces':interfaces,'fingerprint':hasher.hexdigest()}

def cleanup_network(review):
    import native_routing as r
    for name in review['services']:command(['systemctl','disable','--now',name])
    for interface in review['interfaces']:
        if not re.fullmatch(r'rsx[a-f0-9]{10}',interface):raise ValueError('Invalid lifecycle cleanup interface')
        r.run(['ip','link','del',interface],False)
    if review['interfaces']:
        for table,chain,parent in [('nat','RSLIFE_PROBE','POSTROUTING'),('filter','RSLIFE_GUARD','OUTPUT')]:
            while r.ipt(table,'-C',parent,'-j',chain,check=False).returncode==0:r.ipt(table,'-D',parent,'-j',chain)
            r.ipt(table,'-F',chain,check=False);r.ipt(table,'-X',chain,check=False)
        while r.run(['ip','rule','del','priority',str(PRIORITY),'from',PROBE+'/32','lookup',str(TABLE)],False).returncode==0:pass
        r.run(['ip','route','flush','table',str(TABLE)],False);r.run(['ip','address','del',PROBE+'/32','dev','lo'],False)

def dispatch(req):
    if not isinstance(req,dict):raise ValueError('Expected a JSON request')
    if req.get('action')=='inspect':return inspect()
    if req.get('action')!='status':__import__('user_updates').ensure_no_runtime_update(destructive=True)
    if req.get('action')=='prepare-exit':return prepare(req)
    return transition(req)
def main():
    os.umask(0o077)
    if os.geteuid()!=0:raise SystemExit('Owner SSH or passwordless sudo is required')
    try:
        raw=sys.stdin.buffer.read(262145)
        if len(raw)>262144:raise ValueError('Lifecycle request too large')
        req=json.loads(raw)
        if req.get('action')=='inspect':result=dispatch(req) # No lock file or inventory write on adoption.
        else:
            pair.protected(ROOT);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
            with management_lock():result=dispatch(req)
        print(json.dumps({'ok':True,'result':result}))
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__}));raise SystemExit(1)
if __name__=='__main__':main()
