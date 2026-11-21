#!/usr/bin/env python3
"""Bounded JSON/SSH API for independent single-server recipes (schema1)."""
import fcntl,hashlib,json,os,re,secrets,shutil,subprocess,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import model,runtime,filtering,install_retry
import reset_server
from inspect_server import inspect
PAIR_SOURCE=Path('/opt/rookstride-pair/single')
PAIR_MANIFEST=Path('/etc/rookstride-pair/manifest.json')
SERVER_HELPERS=('reset.py','ike_packages.py')
MANAGEMENT_LOCK=Path('/run/rookstride-management.lock')
SINGLE_LOCK=Path('/run/rookstride-single.lock')

def digest(source):
    h=hashlib.sha256()
    for p in sorted(source.iterdir()):
        if p.is_file() and (p.suffix in ('.py','.json','.sh') or p.name.startswith('Dockerfile.')):
            if p.is_symlink():raise ValueError('Unexpected installer link')
            h.update(p.name.encode()+b'\0'+p.read_bytes()+b'\0')
    for name in SERVER_HELPERS:
        helper=source.parent/'server'/name
        if helper.is_symlink() or not helper.is_file():raise ValueError('Owned-reset helper is missing or changed')
        h.update(('server/'+name).encode()+b'\0'+helper.read_bytes()+b'\0')
    return h.hexdigest()

def prepare_helper():
    """Enroll immutable code before any unit refers to a transient SSH upload."""
    source=Path(__file__).resolve().parent;identity=digest(source)
    pair_source=PAIR_SOURCE
    if PAIR_MANIFEST.exists():
        if not pair_source.is_dir() or digest(pair_source)!=identity:raise ValueError('This Double VPN uses another installer version. Review its update before changing users or services.')
        runtime.HELPER=pair_source/'run.py';return pair_source
    release=runtime.ROOT/'releases'/identity/'single'
    if release.exists():
        if digest(release)!=identity:raise ValueError('Installed helper integrity changed')
    else:
        parent=release.parent.parent;parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        stage=parent/('.upload-'+secrets.token_hex(16));stage.mkdir(mode=0o700)
        try:
            shutil.copytree(source,stage/'single',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            (stage/'server').mkdir(mode=0o700)
            for name in SERVER_HELPERS:shutil.copy2(source.parent/'server'/name,stage/'server'/name)
            if digest(stage/'single')!=identity:raise ValueError('Installer source changed during enrollment')
            os.rename(stage,release.parent)
        finally:
            if stage.exists():shutil.rmtree(stage)
    current=runtime.ROOT/'current';temporary=runtime.ROOT/('.current-'+secrets.token_hex(8));temporary.symlink_to(release.parent);os.replace(temporary,current)
    runtime.HELPER=release/'run.py';return release

def job_path(ident):
    if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('Invalid installation identifier')
    return runtime.STATE/'jobs'/ident

def progress(job,stage,phase,state='running',extra=None):
    meta=json.loads((job/'meta.json').read_text()) if (job/'meta.json').exists() else {}
    runtime.atomic(job/'status.json',json.dumps({'job':job.name,'stage':stage,'phase':phase,'state':state,'updated':time.time(),**meta,**(extra or {})}))

def plan(req):
    config=model.validate(req);inventory=inspect()
    if not inventory['compatible_os']:raise ValueError('; '.join(inventory.get('os_assessment',{}).get('errors',[])) or 'Use Ubuntu 22.04 or newer with apt and systemd')
    if inventory.get('pair_node'):
        # Explicit coexistence is intentionally narrow: independent OpenVPN NAT
        # clients do not enter the native AWG pair's guarded 10.66/24 source route.
        if PAIR_MANIFEST.is_symlink() or PAIR_MANIFEST.stat().st_uid!=0:raise ValueError('Pair ownership cannot be verified')
        owned=json.loads(PAIR_MANIFEST.read_text());p=owned['plan'] if owned else {}
        if not owned or req.get('coexist_pair')!=p.get('pair') or owned.get('version')!=2 or p.get('role')!='entry' or p.get('entry_protocol')!='awg' or p.get('client_pool')!='10.66.0.0/24' or config['protocol']!='openvpn' or owned.get('resetting') or not owned.get('activated'):raise ValueError('This coexistence adapter requires an active native AWG pair entry and a separately reviewed OpenVPN listener')
        for job in owned.get('jobs',{}).values():
            if not isinstance(job,str) or not re.fullmatch('[a-f0-9]{32}',job):raise ValueError('Invalid owned pair job')
            status=Path('/var/lib/rookstride-pair')/job/'status.json'
            if not status.is_file() or json.loads(status.read_text()).get('state') in ('starting','running','awaiting-reboot'):raise ValueError('Finish pair maintenance before adding an independent VPN')
    inventory['ports']=list(inventory['ports'])
    # Stopped owned VPNs still reserve their configured transport and port.
    for protocol,settings in model.PROTOCOLS.items():
        if (runtime.directory(protocol)/'state.json').exists():
            state=runtime.load(protocol);inventory['ports'].append({'port':state['port'],'transport':settings['transport']})
    if inventory.get('owned_ikev2'):
        inventory['ports'].extend({'port':p,'transport':'udp'} for p in (500,4500))
    ssh_port=req.get('sshPort',22)
    if not isinstance(ssh_port,int) or isinstance(ssh_port,bool) or not 1<=ssh_port<=65535:raise ValueError('Invalid SSH port')
    if 'port' not in req:config['port']=model.free_port(config['protocol'],inventory['ports'],ssh_port)
    if any(v['port']==config['port'] and v['transport']==model.PROTOCOLS[config['protocol']]['transport'] for v in inventory['ports']):raise ValueError('That VPN port is already in use. Choose a free port.')
    if config['port']==ssh_port:raise ValueError('Choose a port other than your SSH port')
    if (runtime.directory(config['protocol'])/'state.json').exists():raise ValueError('This protocol is installed. Manage it or review a VPN reset first.')
    return {'protocol':config['protocol'],'port':config['port'],'transport':model.PROTOCOLS[config['protocol']]['transport'],
            'preserves':['Ubuntu','SSH','administrator credentials','other applications'],'requires_runtime':('Xray' if config['protocol'] in ('xray','xhttp') else 'Verified phone runtime') if model.proxy_protocol(config['protocol']) else 'Docker',
            'client':model.PROTOCOLS[config['protocol']]['client'],'os':inventory['os']}

def start(req):
    if req.get('install_context') is not None:
        existing=install_retry.existing_start(req,digest(Path(__file__).resolve().parent))
        if existing is not None:return existing
        ensure_idle()
    if 'filter_only' in req and not isinstance(req['filter_only'],bool):raise ValueError('Expected a boolean filter flag')
    if req.get('filter_only'):
        inventory=inspect()
        if inventory.get('pair_node') or not inventory['compatible_os']:raise ValueError('Private filtering requires a compatible single-server installation')
        state=runtime.load(req.get('protocol'));review={'protocol':state['protocol'],'port':state['port'],'filter_only':True};config={'protocol':state['protocol'],'instance':state['instance'],'filter_only':True}
    else:review=plan(req);config=model.validate(req)
    config['port']=review['port']
    if req.get('coexist_pair'):config['coexist_pair']=req['coexist_pair']
    jobs=runtime.STATE/'jobs';jobs.mkdir(mode=0o700,parents=True,exist_ok=True)
    for p in jobs.glob('*/status.json'):
        if json.loads(p.read_text()).get('state') in ('starting','running'):raise ValueError('An installation is recorded as running. Check its progress first.')
    release=prepare_helper();identity=digest(release)
    ident=uuid.uuid4().hex;job=job_path(ident);job.mkdir(mode=0o700)
    if not config.get('filter_only'):
        config['instance']=uuid.uuid4().hex;config['owner']='rookstride-single-v1';config['initialLogin']=config.pop('login')
    if 'password' in config:config['initialPassword']=config.pop('password')
    meta={'protocol':config['protocol'],'bundle':identity,'filter_only':bool(config.get('filter_only')),
          **install_retry.initial_meta(req,config,identity,ident)}
    runtime.atomic(job/'meta.json',json.dumps(meta))
    runtime.atomic(job/'request.json',json.dumps(config));progress(job,1,'Starting installation','starting')
    install_retry.register(req,ident,meta)
    spawn(ident,release)
    if 'install_context' in meta:return install_retry.response(ident,meta)
    return {'job':ident,'state':'starting','plan':review,'bundle':identity}

def spawn(ident,release):
    job=job_path(ident)
    p=subprocess.run(['systemd-run','--unit=rookstride-single-install-'+ident,'--collect','--property=UMask=0077',sys.executable,str(release/'run.py'),'execute',ident],capture_output=True,text=True,timeout=30)
    if p.returncode:
        (job/'request.json').unlink(missing_ok=True);progress(job,1,'Could not start installer','failed');raise ValueError('Could not start the server job')

def retry_install(req):
    source=digest(Path(__file__).resolve().parent)
    release=runtime.ROOT/'releases'/source/'single'
    install_retry.secure(release)
    if not release.is_dir() or digest(release)!=source:raise ValueError('The original immutable installer is unavailable')
    return install_retry.retry(req,source,plan,lambda ident:spawn(ident,release),progress)

def execute(ident):
    job=job_path(ident);state=json.loads((job/'request.json').read_text())
    try:
        if state.get('filter_only'):
            current=runtime.load(state['protocol'])
            if current['instance']!=state['instance']:raise ValueError('The VPN changed. Inspect before enabling filtering.')
            runtime.enable_filter(current,lambda stage,phase:progress(job,stage,phase))
        else:runtime.install(state,lambda stage,phase:progress(job,stage,phase))
        progress(job,7,'VPN and ad blocking ready','complete')
    except Exception as e:
        message=str(e) if isinstance(e,ValueError) else type(e).__name__
        last=json.loads((job/'status.json').read_text()).get('stage',0)
        marker=None
        if isinstance(e,filtering.AcquisitionUnavailable):
            with MANAGEMENT_LOCK.open('a') as shared,SINGLE_LOCK.open('a') as lock:
                fcntl.flock(shared,fcntl.LOCK_EX);fcntl.flock(lock,fcntl.LOCK_EX)
                try:marker=install_retry.failure_marker(ident,e)
                except (ValueError,OSError,subprocess.SubprocessError):pass
                progress(job,last,'Installation stopped: '+message,'failed',{'retryable':marker} if marker else None)
                if marker:install_retry.seal_failure(ident)
        else:progress(job,last,'Installation stopped: '+message,'failed')
    finally:(job/'request.json').unlink(missing_ok=True)

def status(ident):
    job=job_path(ident);value=json.loads((job/'status.json').read_text())
    if value['state'] in ('starting','running') and time.time()-value['updated']>20:
        active=subprocess.run(['systemctl','is-active','--quiet','rookstride-single-install-'+ident]).returncode==0
        if not active:progress(job,value['stage'],'Installation was interrupted. Inspect this VPN before retrying.','failed');value=json.loads((job/'status.json').read_text())
    return install_retry.status_receipt(ident,value)

def reset_plan(protocol):
    state=runtime.load(protocol)
    if not model.proxy_protocol(protocol):runtime.check_container(state)
    token=secrets.token_hex(32);record={'token':token,'expires':time.time()+300,'configuration':hashlib.sha256(json.dumps(state,sort_keys=True).encode()).hexdigest(),'protocol':protocol}
    runtime.atomic(runtime.directory(protocol)/'reset.json',json.dumps(record))
    return dict(record,scope='This VPN and its connection profiles. Ubuntu, SSH, administrator credentials and other applications stay.')

def reset_apply(req):
    protocol=req['protocol'];state=runtime.load(protocol);p=runtime.directory(protocol);review=json.loads((p/'reset.json').read_text())
    if req.get('confirmation')!='DELETE VPN' or not isinstance(req.get('token'),str) or not secrets.compare_digest(req['token'],review['token']) or time.time()>review['expires']:raise ValueError('Review this reset again')
    if hashlib.sha256(json.dumps(state,sort_keys=True).encode()).hexdigest()!=review['configuration']:raise ValueError('The VPN changed. Review this reset again.')
    runtime.user_updates.remove_retained_containers(protocol,runtime.command)
    for job in (runtime.STATE/'jobs').glob('*/status.json'):
        if json.loads(job.read_text()).get('state') in ('starting','running'):raise ValueError('Wait for the current installation to finish')
    if model.proxy_protocol(protocol):
        descriptions={'xray':'Description=Rookstride Xray VPN','xhttp':'Description=Rookstride XHTTP VPN'}
        suffixes=['','-endpoint'] if protocol=='trusttunnel' else ['']
        if protocol in model.ADDITIONAL and protocol!='xhttp':suffixes+=['-certificate','-certificate-timer']
        for suffix in suffixes:
            name='rookstride-single-'+protocol+suffix;unit=Path('/etc/systemd/system')/(name+'.service')
            if suffix=='-certificate-timer':name='rookstride-single-'+protocol+'-certificate.timer';unit=Path('/etc/systemd/system')/name
            if unit.exists() or unit.is_symlink():
                expected=descriptions.get(protocol,'Description=Rookstride managed '+protocol+' VPN'+suffix)
                if not unit.is_file() or unit.is_symlink() or expected not in unit.read_text():raise ValueError('Service ownership changed')
                runtime.command(['systemctl','disable','--now',name]);unit.unlink()
        runtime.command(['systemctl','daemon-reload'])
        if state.get('metrics_port'):
            import routes
            routes.clear_local(state,runtime)
    else:
        if protocol=='openvpn' and state.get('access_mode')=='password':
            for suffix in ('.timer','.service'):
                unit=Path('/etc/systemd/system/rookstride-single-openvpn-certificate'+suffix)
                if unit.exists():
                    if unit.is_symlink() or 'Description=Rookstride managed openvpn VPN-certificate' not in unit.read_text():raise ValueError('Certificate service ownership changed')
                    runtime.command(['systemctl','disable','--now',unit.name]);unit.unlink()
            runtime.command(['systemctl','daemon-reload'])
        existing=runtime.check_container(state)
        if existing:runtime.command(['docker','rm','-f',runtime.container(protocol)])
    if p.is_symlink():raise ValueError('VPN path changed')
    shutil.rmtree(p)
    return {'reset':True,'message':'VPN removed. Ubuntu and SSH retained.'}

def ensure_idle():
    for p in (runtime.STATE/'jobs').glob('*/status.json'):
        if status(p.parent.name).get('state') in ('starting','running'):raise ValueError('Wait for the current installation to finish')
    for p in Path('/var/lib/rookstride/jobs').glob('*/status.json'):
        if json.loads(p.read_text()).get('state') in ('starting','running'):raise ValueError('Inspect the existing IKEv2 installation before resetting or adding protocols')

def action(req):
    if not isinstance(req,dict):raise ValueError('Expected a request object')
    mode=req.get('action')
    if mode not in ('inspect','status','profile','job','plan','reset-plan','reset-server-plan','filter-reset-plan'):
        runtime.user_updates.ensure_no_runtime_update(destructive=mode in ('start','reset-apply','reset-server-apply','filter-reset-apply'))
    if mode in ('reset-plan','reset-apply') and PAIR_MANIFEST.exists():
        owned=json.loads(PAIR_MANIFEST.read_text());state=runtime.load(req.get('protocol'))
        if state.get('protocol')!='openvpn' or state.get('coexist_pair')!=owned.get('plan',{}).get('pair'):raise ValueError('This protocol belongs to a two-server VPN. Use Remove all VPN setups to remove this node safely.')
    if mode=='inspect':
        result=inspect();result['installed_protocols']=[];result['installed_instances']={};result['coexisting_protocols']={};result['filtering']=filtering.inspect()
        for protocol in model.PROTOCOLS:
            if (runtime.directory(protocol)/'state.json').exists():
                state=runtime.load(protocol);result['installed_protocols'].append(protocol);result['installed_instances'][protocol]=state['instance']
                coexist=runtime.coexist_pair(state,PAIR_MANIFEST)
                if coexist:result['coexisting_protocols'][protocol]=coexist
        jobs=sorted((runtime.STATE/'jobs').glob('*/status.json'),key=lambda p:p.stat().st_mtime)
        result['job']=status(jobs[-1].parent.name) if jobs else None
        return result
    if mode in ('plan','reset-plan','reset-apply','reset-server-plan','reset-server-apply','filter-reset-plan','filter-reset-apply') or mode=='start' and req.get('install_context') is None:ensure_idle()
    if mode in ('filter-reset-plan','filter-reset-apply'):
        if filtering.references():raise ValueError('Installed VPNs use this filter. Use the all-VPN reset to remove it.')
        if mode=='filter-reset-plan':return filtering.reset_plan()
        filtering.reset_apply(req);return {'reset':True,'message':'Incomplete ad blocking removed. Existing VPN accounts stay.'}
    if mode=='reset-server-plan':return reset_server.plan(reset_plan)
    if mode=='reset-server-apply':return reset_server.apply(req,reset_apply)
    if mode=='plan':return plan(req)
    if mode=='start':return start(req)
    if mode=='retry':return retry_install(req)
    if mode=='job':return status(req.get('job'))
    if mode=='reset-plan':return reset_plan(req.get('protocol'))
    if mode=='reset-apply':return reset_apply(req)
    if mode in ('add-user','remove-user','edit-user','adguard'):prepare_helper()
    state=runtime.load(req.get('protocol'))
    if mode not in ('status',):
        for path in (runtime.STATE/'jobs').glob('*/status.json'):
            if json.loads(path.read_text()).get('state') in ('starting','running'):raise ValueError('Wait for the installation to finish')
    if mode=='status':return runtime.health(state)
    if mode=='profile':return runtime.profile(state,req.get('login'))
    if mode=='adguard':
        if not state.get('filtering'):raise ValueError('Enable ad blocking on this VPN first')
        return filtering.control(req)
    if mode=='add-user':return runtime.add_user(state,req.get('login'),password=req.get('password'),person=req.get('person'),device=req.get('device'))
    if mode=='edit-user':return runtime.edit_user(state,req)
    if mode=='remove-user':return runtime.remove_user(state,req.get('login'))
    raise ValueError('Unsupported VPN action')

def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0:raise ValueError('Administrator access is required')
        if runtime.ROOT.is_symlink() or runtime.STATE.is_symlink():raise ValueError('Unexpected helper directory link')
        if len(sys.argv)==3 and sys.argv[1]=='execute':execute(sys.argv[2]);return
        if len(sys.argv)==3 and sys.argv[1]=='local-guard':
            import routes
            state=runtime.load(sys.argv[2]);routes.restrict_local(state,runtime)
            if state['protocol'] in routes.PROTOCOLS and not any(u.get('enabled',True) for u in state['users']):raise ValueError('No enabled VPN users')
            return
        if len(sys.argv)==3 and sys.argv[1]=='renew-certificate':
            import routes
            with Path('/run/rookstride-management.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX);routes.renew_certificate(sys.argv[2],runtime)
            return
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('Request is too large')
        request=json.loads(raw)
        with MANAGEMENT_LOCK.open('a') as shared,SINGLE_LOCK.open('a') as lock:
            fcntl.flock(shared,fcntl.LOCK_EX);fcntl.flock(lock,fcntl.LOCK_EX);result=action(request)
        print(json.dumps({'ok':True,'result':result}))
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e) if isinstance(e,ValueError) else type(e).__name__}));raise SystemExit(1)
if __name__=='__main__':main()
