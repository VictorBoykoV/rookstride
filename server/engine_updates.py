#!/usr/bin/env python3
"""Reviewed, resumable executable updates. Identity/configuration is never migrated.

Candidates come only from this app's pinned source/verified uploaded runtime.
Unknown configuration formats or distro-package upgrades are not guessed. The
operation retains the previous executable/unit before mutation and requires an
unchanged identity/config snapshot before apply, rollback or acceptance.
"""
import contextlib,copy,hashlib,io,json,os,platform,re,shlex,shutil,subprocess,sys,tarfile,time,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair,lifecycle,native_pair
import runtime,routes,filtering,engine_containers,engine_packages,engine_lifecycle
ROOT=Path('/var/lib/rookstride-engine-updates')
SOURCE=Path(__file__).resolve().parent.parent
UNIT=Path('/etc/systemd/system')
GROUPS={'ikev2':(), 'awg':('awg',),'openvpn':('openvpn',),'xray':('xray','xhttp'),'routes':routes.PROTOCOLS,'trusttunnel':('trusttunnel',)}
TERMINAL=('accepted','rolled-back','cancelled','abandoned')
LABELS={'ikev2':'IKEv2 signed system packages','awg':'AmneziaWG container','openvpn':'OpenVPN container','xray':'Xray (VLESS and XHTTP)','routes':'Rookstride transport runtime','trusttunnel':'TrustTunnel endpoint'}

def read(path):return lifecycle.read(path)
def write(path,value):return lifecycle.write(path,value)
def sha(path):
    pair.protected(path)
    if not path.is_file() or path.stat().st_size>128*1024*1024:raise ValueError('Unexpected engine/configuration file')
    return hashlib.sha256(path.read_bytes()).hexdigest()
def binary_path(value,group):
    path=Path(value);pair.protected(path)
    if group=='xray' and path!=runtime.ROOT/'bin/xray' and not (path.parent.parent==lifecycle.ROOT/'operations' and re.fullmatch('[a-f0-9]{32}',path.parent.name) and path.name=='xray'):raise ValueError('Unrecognized Xray executable')
    if group=='routes' and (path.parent.parent!=routes.WORKER or not re.fullmatch('[a-f0-9]{64}',path.parent.name) or path.name!='rook-routes'):raise ValueError('Unrecognized transport executable')
    if group=='trusttunnel' and (path.parent.parent!=routes.WORKER/'trusttunnel' or not re.fullmatch('v[0-9][A-Za-z0-9._-]{0,63}',path.parent.name) or path.name!='trusttunnel_endpoint'):raise ValueError('Unrecognized TrustTunnel executable')
    return path

def unit(name,group):
    path=UNIT/(name+'.service');pair.protected(path);text=path.read_text()
    if len(text)>32768 or not re.search('^Description=Rookstride ',text,re.M):raise ValueError('Service ownership cannot be verified')
    starts=re.findall('^ExecStart=(.+)$',text,re.M)
    if len(starts)!=1:raise ValueError('Unexpected engine service command')
    argv=shlex.split(starts[0]);binary_path(argv[0],group)
    expected=3 if group=='routes' else 4 if group=='xray' else 3
    if len(argv)!=expected or group=='routes' and argv[1]!='run' or group=='xray' and argv[1:3]!=['run','-config']:raise ValueError('Unrecognized engine configuration contract')
    configs=argv[2:] if group=='routes' else argv[3:] if group=='xray' else argv[1:]
    for value in configs:
        file=Path(value);pair.protected(file)
        if not (file.is_relative_to(runtime.STATE) or file.is_relative_to(pair.OWN) or file.is_relative_to(lifecycle.ROOT/'operations')):raise ValueError('Unrecognized engine configuration path')
    value={'name':name,'path':str(path),'text':text,'argv':argv,'configs':{value:sha(Path(value)) for value in configs},'binary':sha(Path(argv[0]))}
    if group=='routes':value['library']=sha(Path(argv[0]).parent/'libcronet.so')
    return value

def identity_files(states):
    result={}
    for protocol in states:
        state=runtime.load(protocol);folder=runtime.directory(protocol)
        for path in sorted(folder.rglob('*')):
            if path.is_file() and path.suffix in ('.key','.pem','.crt'):result[str(path)]=sha(path)
        for key in ('certificate','key'):
            value=state.get('public_tls',{}).get(key)
            if value:result[str(value)]=sha(Path(value))
    return result

def snapshot(group,during=False):
    if group not in GROUPS:raise ValueError('Unsupported engine update group')
    __import__('maintenance').ensure_no_pending_update()
    manifest=pair.load_manifest();services=[];states={};identity={}
    if not during:
        __import__('maintenance').check_idle(manifest or {})
        for jobs in (runtime.STATE/'jobs',Path('/var/lib/rookstride/jobs')):
            for status_file in jobs.glob('*/status.json'):
                if read(status_file).get('state') in ('starting','running','awaiting-reboot'):raise ValueError('Finish or inspect the current VPN installation before reviewing runtimes')
    if manifest:
        if not during:
            info=lifecycle.inspect()
            if info.get('read_only'):raise ValueError('Inspect the existing pair before updating its runtime')
        identity={'plan':manifest['plan'],'bundle':manifest['bundle'],'configure_digest':manifest.get('configure_digest'),'files':{path:sha(Path(path)) for path in manifest.get('file_hashes',{})}}
    for protocol in GROUPS[group]:
        if not (runtime.directory(protocol)/'state.json').exists():continue
        state=runtime.load(protocol);states[protocol]=lifecycle.digest(state)
        name='rookstride-single-'+protocol+('-endpoint' if group=='trusttunnel' else '')
        services.append(engine_containers.listener(state,sha) if group in engine_containers.GROUPS else unit(name,group))
    if manifest and manifest['plan']['role']=='entry' and group!='trusttunnel' and manifest['plan']['exit_protocol'] in GROUPS[group]:services.append(engine_containers.bridge(group,manifest,sha) if group in engine_containers.GROUPS else unit(native_pair.BRIDGE,group))
    sidecars=engine_lifecycle.records(manifest,('ikev2',) if group=='ikev2' else GROUPS[group],verify_units=not during) if group!='trusttunnel' else []
    if group=='ikev2':services=engine_packages.snapshot(manifest,sha,['rookstride-lifecycle-'+op['operation'] for op in sidecars])
    else:
        for op in sidecars:
            if group in engine_containers.GROUPS:service=engine_lifecycle.docker(op,group,sha,engine_containers.image)
            else:
                service=unit('rookstride-lifecycle-'+op['operation'],group)
                if not during and service['text']!=lifecycle.candidate_unit(op):raise ValueError('Accepted bridge service ownership changed')
                engine_lifecycle.decorate(service,op)
            services.append(service)
    if manifest:identity['active_route']=lifecycle.route_override(manifest)
    if not services:raise ValueError('This server has no installed runtime in that group')
    if group in engine_containers.GROUPS:engine_containers.validate_consumers(services)
    # Engine settings and user databases are distinct from dynamic counters/logs.
    value={'group':group,'states':states,'services':services,'identity_files':identity_files(states),'pair':identity,'machine':sha(Path('/etc/machine-id'))}
    value['fingerprint']=lifecycle.digest(value)
    return value

def current_versions(snap):return sorted(set(s['binary'] for s in snap['services']))
def candidate_label(group):
    if group=='ikev2':return 'Exact versions from this Ubuntu release’s signed repositories'
    if group in engine_containers.GROUPS:return 'App-reviewed image recipe · '+sha(SOURCE/'single'/('Dockerfile.'+group))[:12]
    if group=='xray':return runtime.PINS['xray']['version']
    pins=json.loads((SOURCE/'single/routes-pins.json').read_text())
    return pins['trusttunnel']['version'] if group=='trusttunnel' else pins['runtime']+' · '+pins['assets'][platform.machine()]['sha256'][:12]
def inspect():
    groups=[]
    for group in GROUPS:
        try:
            snap=snapshot(group);groups.append({'group':group,'title':LABELS[group],'supported':True,'protocols':list(snap['states']),'includes_bridge':any(s['name']==native_pair.BRIDGE for s in snap['services']),'fingerprint':snap['fingerprint'],'current_hashes':current_versions(snap),'candidate':candidate_label(group)})
        except (FileNotFoundError,ValueError,KeyError) as error:
            groups.append({'group':group,'title':LABELS[group],'supported':False,'reason':str(error) if isinstance(error,ValueError) else 'Runtime is not installed or its ownership is incomplete'})
    operations=[public(read(path)) for path in ROOT.glob('*/journal.json')]
    return {'schema':1,'groups':groups,'operations':operations,'preserves':['VPN accounts and passwords','server keys and certificates','ad blocking settings','connection profiles'],'interruption':'Affected connections reconnect during the runtime restart'}
def public(op):
    return {k:op[k] for k in ('operation','group','state','phase','candidate','old_hashes','new_hash','available','created','updated','error','direction','candidate_versions') if k in op}
def record(op,state,phase):
    op.update(state=state,phase=phase,updated=time.time());write(ROOT/op['operation']/'journal.json',op);return public(op)
def load(operation):
    value=read(ROOT/pair.ident(operation)/'journal.json')
    if not value:raise ValueError('No recorded engine update')
    return value

def prepare(req):
    ident=pair.ident(req.get('operation'));group=req.get('group');old=read(ROOT/ident/'journal.json')
    request={'operation':ident,'group':group,'fingerprint':req.get('fingerprint')}
    if old:
        if old['request']!=request:raise ValueError('Engine update review changed')
        return public(old)
    for path in ROOT.glob('*/journal.json'):
        if read(path)['state'] not in TERMINAL:raise ValueError('Finish or roll back the recorded engine update first')
    snap=snapshot(group)
    if snap['fingerprint']!=req.get('fingerprint'):raise ValueError('Server users, services or runtime changed; inspect the update again')
    folder=ROOT/ident;pair.protected(folder);folder.mkdir(parents=True,mode=0o700)
    source=folder/'source';source.mkdir(mode=0o700)
    for name in ('server','single','gateway','twohop'):shutil.copytree(SOURCE/name,source/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    op={'schema':1,'operation':ident,'group':group,'snapshot':snap,'request':request,'candidate':candidate_label(group),'old_hashes':current_versions(snap),'created':time.time(),'was_active':bool(pair.load_manifest() and pair.load_manifest().get('activated'))}
    record(op,'preparing','Preparing the app-reviewed runtime; VPN unchanged')
    launch(op,'stage')
    return public(op)

def launch(op,action):
    # The detached worker persists its checkpoint before any side effect.
    script=ROOT/op['operation']/'source/server/engine_updates.py'
    runtime.command(['systemd-run','--quiet','--collect','--unit=rookstride-engine-'+op['operation']+'-'+action,'--property=Type=exec','--property=UMask=0077','--property=TimeoutStartSec=30min','/usr/bin/python3',str(script),'worker',op['operation'],action],timeout=30)

def copy_binary(source,target):
    pair.protected(target);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=target.with_name('.'+target.name+'-'+os.urandom(8).hex());shutil.copyfile(source,tmp);tmp.chmod(0o700);os.replace(tmp,target)
def stage(op):
    folder=ROOT/op['operation'];target=folder/'candidate';target.mkdir(mode=0o700,exist_ok=True);group=op['group']
    if group=='ikev2':
        engine_packages.stage(op,folder)
        op['candidate']='; '.join(name+' '+version for name,version in sorted(op['candidate_versions'].items()))
        if snapshot(group)['fingerprint']!=op['snapshot']['fingerprint']:raise ValueError('Server changed while preparing packages; cancel and review again')
        return record(op,'prepared','Exact signed package sets retained; review the VPN restart')
    if group in engine_containers.GROUPS:
        engine_containers.stage(op,SOURCE)
        if snapshot(group)['fingerprint']!=op['snapshot']['fingerprint']:raise ValueError('Server changed while preparing the image; cancel and review again')
        return record(op,'prepared','Reviewed image built and retained; review the VPN restart')
    if group=='xray':
        asset=runtime.PINS['xray']['assets'][platform.machine()];raw=filtering.pinned_download(asset['url'],asset['sha256'],asset['bytes'],asset['bytes'])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info=archive.getinfo('xray')
            if not 0<info.file_size<128*1024*1024:raise ValueError('Unexpected Xray executable size')
            value=archive.read('xray')
        binary=target/'xray';binary.write_bytes(value);binary.chmod(0o700);op['target']=str(runtime.ROOT/'bin/xray')
    elif group=='routes':
        binary=routes.worker();op['target']=str(binary);op['new_library_hash']=sha(binary.parent/'libcronet.so')
    else:
        pins=json.loads((SOURCE/'single/routes-pins.json').read_text())['trusttunnel'];asset=pins['assets'][platform.machine()]
        raw=filtering.pinned_download(asset['url'],asset['sha256'],asset['bytes'],asset['bytes'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            members=[m for m in archive.getmembers() if m.isfile() and m.name.endswith('/trusttunnel_endpoint')]
            if len(members)!=1 or not 0<members[0].size<128*1024*1024:raise ValueError('Unexpected TrustTunnel executable')
            value=archive.extractfile(members[0]).read()
        binary=target/'trusttunnel_endpoint';binary.write_bytes(value);binary.chmod(0o700)
        op['target']=str(routes.WORKER/'trusttunnel'/pins['version']/'trusttunnel_endpoint')
    op['candidate_file']=str(binary);op['new_hash']=sha(binary);op['available']=any(old!=op['new_hash'] for old in op['old_hashes'])
    binary_path(op['target'],group)
    if snapshot(group)['fingerprint']!=op['snapshot']['fingerprint']:raise ValueError('Server changed while preparing the runtime; cancel and review again')
    prior=folder/'prior';prior.mkdir(mode=0o700,exist_ok=True)
    files={s['argv'][0] for s in op['snapshot']['services']}
    if group=='routes':files.update(str(Path(s['argv'][0]).parent/'libcronet.so') for s in op['snapshot']['services'])
    destination=Path(op['target'])
    if destination.exists():files.add(str(destination))
    op['previous_binaries']={}
    for index,value in enumerate(sorted(files)):
        path=Path(value);backup=prior/('binary-'+str(index));copy_binary(path,backup);op['previous_binaries'][value]={'backup':str(backup),'sha256':sha(path)}
    if group=='xray':
        version=runtime.ROOT/'bin/version';op['old_version']=version.read_text() if version.exists() else None
    for service in op['snapshot']['services']:
        args=[str(binary),*service['argv'][1:]]
        if group=='xray':runtime.command([str(binary),'run','-test','-config',service['argv'][-1]],timeout=20)
        else:
            if not shutil.which('unshare'):raise ValueError('Runtime staging requires network namespace support')
            process=subprocess.Popen(['unshare','--net','--',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                time.sleep(2)
                if process.poll() is not None:raise ValueError('The staged runtime did not accept the existing configuration')
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
    return record(op,'prepared','Runtime verified against existing configuration; review the restart')

def same_identity(op):
    __import__('maintenance').ensure_no_pending_update()
    if op['group']=='xray' and 'old_version' in op:
        marker=runtime.ROOT/'bin/version';pair.protected(marker)
        current_version=marker.read_text() if marker.exists() else None
        if current_version not in (op['old_version'],runtime.PINS['xray']['version']):raise ValueError('Xray version marker changed outside this operation')
    if op['group'] in (*engine_containers.GROUPS,'ikev2'):
        previous=op['snapshot'];manifest=pair.load_manifest();identity={}
        if manifest:identity={'plan':manifest['plan'],'bundle':manifest['bundle'],'configure_digest':manifest.get('configure_digest'),'files':{path:sha(Path(path)) for path in manifest.get('file_hashes',{})},'active_route':lifecycle.route_override(manifest)}
        if previous['machine']!=sha(Path('/etc/machine-id')) or identity!=previous['pair'] or any(lifecycle.digest(runtime.load(protocol))!=digest for protocol,digest in previous['states'].items()):raise ValueError('Server identity, users or deployment changed after review')
        (engine_packages.same_identity if op['group']=='ikev2' else engine_containers.same_identity)(op,sha)
        for service in previous['services']:
            if 'lifecycle' in service:engine_lifecycle.validate(service)
        if identity_files(previous['states'])!=previous.get('identity_files',{}):raise ValueError('VPN identity files changed after review')
        return previous
    current=snapshot(op['group'],during=True);previous=op['snapshot']
    for key in ('machine','pair','states','identity_files'):
        if current.get(key)!=previous.get(key):raise ValueError('Server identity, users or deployment changed after review; no runtime was replaced')
    if len(current['services'])!=len(previous['services']):raise ValueError('Shared engine consumers changed')
    for old,new in zip(previous['services'],current['services']):
        if 'lifecycle' in old:engine_lifecycle.validate(old)
        if old['name']!=new['name'] or old['configs']!=new['configs']:raise ValueError('Engine configuration changed after review')
        planned=old['text'].replace('ExecStart='+old['argv'][0]+' ','ExecStart='+op['target']+' ',1)
        if new['text'] not in (old['text'],planned) or new['binary'] not in (old['binary'],op['new_hash']):raise ValueError('Engine files changed outside this operation')
        if op['group']=='routes' and new.get('library') not in (old.get('library'),op.get('new_library_hash')):raise ValueError('Transport library changed outside this operation')
    return current

def quiesce():
    m=pair.load_manifest()
    if m and m['plan']['role']=='entry':__import__('native_routing').apply('quiesce')

def restart(op,rollback):
    for service in op['snapshot']['services']:
        text=service['text'] if rollback else service['text'].replace('ExecStart='+service['argv'][0]+' ','ExecStart='+op['target']+' ',1)
        path=Path(service['path']);pair.atomic(path,text);path.chmod(0o644)
    runtime.command(['systemctl','daemon-reload'])
    m=pair.load_manifest()
    if m:
        # Unit content is the only reviewed manifest change; keys/plan stay exact.
        for service in op['snapshot']['services']:
            if service['name'] in m.get('unit_hashes',{}):m['unit_hashes'][service['name']]=sha(Path(service['path']))
        pair.write_manifest(m)
    engine_lifecycle.update(op,rollback)
    for service in op['snapshot']['services']:runtime.command(['systemctl','restart',service['name']],timeout=40)

def verify(op):
    for service in op['snapshot']['services']:
        if service.get('kind')=='container':continue
        if subprocess.run(['systemctl','is-active','--quiet',service['name']],capture_output=True,timeout=10).returncode:raise ValueError('Updated engine service is not ready')
    for protocol in op['snapshot']['states']:
        state=runtime.load(protocol);health=runtime.health(state)
        if not health.get('running'):raise ValueError('Updated VPN service did not pass its health check')
        if not state.get('pair_dns'):
            if state.get('filtering') and not filtering.ready():raise ValueError('Ad blocking/DNS did not pass its check')
            if any(user.get('enabled',True) for user in state['users']):
                if protocol in ('xray','xhttp') and not runtime.reality_client_ready(state):raise ValueError('Updated VPN did not carry a real encrypted website request')
                elif protocol in routes.PROTOCOLS:routes.verify_connection(state,runtime)
    # Pair forwarding is only reopened by the coordinator's separate full route
    # verification after both nodes finish. A local health check cannot open it.

def mutate(op,rollback):
    same_identity(op);quiesce();record(op,'rolling-back' if rollback else 'applying','Restoring the previous runtime' if rollback else 'Restarting the reviewed VPN runtime')
    if op['group'] in (*engine_containers.GROUPS,'ikev2'):
        (engine_packages.mutate if op['group']=='ikev2' else engine_containers.mutate)(op,rollback);engine_lifecycle.update(op,rollback);verify(op)
        same_identity(op)
        return record(op,'rolled-back' if rollback else 'verified','Previous image verified' if rollback else 'Runtime image verified; check a saved client before accepting')
    if rollback:
        for destination,saved in op['previous_binaries'].items():
            if sha(Path(saved['backup']))!=saved['sha256']:raise ValueError('Retained runtime integrity failed')
            copy_binary(Path(saved['backup']),Path(destination))
        # Unused new content-addressed paths remain caches; restored units point
        # only at the hash-verified previous executable and its retained library.
        if op['group']=='xray':
            marker=runtime.ROOT/'bin/version';pair.protected(marker)
            if op.get('old_version') is not None:pair.atomic(marker,op['old_version'])
            else:marker.unlink(missing_ok=True)
    else:
        if sha(Path(op['candidate_file']))!=op['new_hash']:raise ValueError('Staged runtime changed before apply')
        if op['group']=='routes' and sha(Path(op['candidate_file']).parent/'libcronet.so')!=op['new_library_hash']:raise ValueError('Staged runtime library changed before apply')
        if Path(op['candidate_file'])!=Path(op['target']):copy_binary(Path(op['candidate_file']),Path(op['target']))
        if op['group']=='xray':pair.atomic(runtime.ROOT/'bin/version',runtime.PINS['xray']['version'])
    restart(op,rollback);verify(op)
    return record(op,'rolled-back' if rollback else 'verified','Previous runtime verified' if rollback else 'Runtime verified; check a saved client before accepting')

def status(op,persist=False):
    if op['state'] in ('preparing','applying','rolling-back'):
        phase='stage' if op['state']=='preparing' else op.get('direction','apply')
        unit='rookstride-engine-'+op['operation']+'-'+phase
        active=subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,timeout=10).returncode==0
        if not active:
            latest=load(op['operation'])
            if latest['state']!=op['state']:return latest
            latest.update(state='prepare-failed' if phase=='stage' else phase+'-failed',phase='The runtime job stopped; review or resume this recorded operation')
            if persist:write(ROOT/op['operation']/'journal.json',latest)
            return latest
    return op

def transition(req):
    op=status(load(req.get('operation')),persist=True);action=req.get('action')
    if action=='status':return public(op)
    if action=='abandon':
        if req.get('confirmation')!='ABANDON ENGINE ROLLBACK':raise ValueError('Review abandoning the retained runtime rollback before continuing maintenance')
        if op['state'] in ('preparing','applying','rolling-back'):raise ValueError('Wait for the recorded runtime job to stop before abandoning its rollback')
        return record(op,'abandoned','Runtime rollback abandoned by the owner; inspect or remove this VPN before reuse')
    if action=='cancel':
        if op['state'] not in ('prepared','prepare-failed','cancelled'):raise ValueError('Only an unapplied runtime preparation can be cancelled')
        return record(op,'cancelled','Prepared update cancelled; running VPN unchanged')
    if action=='accept':
        if op['state']=='accepted':return public(op)
        if op['state']!='verified' or req.get('confirmation')!='SAVED CLIENT TRAFFIC VERIFIED':raise ValueError('Verify a saved client before accepting the engine update')
        same_identity(op);return record(op,'accepted','Runtime update accepted; retained rollback data stays private')
    if action not in ('apply','rollback'):raise ValueError('Unsupported engine update action')
    if action=='apply' and op['state'] in ('verified','accepted'):return public(op)
    if action=='rollback' and op['state']=='rolled-back':return public(op)
    if op['state'] in TERMINAL:raise ValueError('This engine operation has finished')
    if action=='apply' and op['state'] not in ('prepared','apply-failed'):raise ValueError('Prepare the runtime before applying it')
    if action=='rollback' and op['state'] not in ('verified','apply-failed','rollback-failed'):raise ValueError('No applied runtime needs rollback')
    if req.get('confirmation')!='RESTART REVIEWED VPN RUNTIMES':raise ValueError('Review the affected VPN restart first')
    same_identity(op);op['direction']=action;record(op,'rolling-back' if action=='rollback' else 'applying','Runtime operation started');launch(op,action);return public(op)

def pair_guard(req):
    m=pair.load_manifest()
    if not m or m['plan']['role']!='entry' or m['plan']['pair']!=req.get('deployment'):raise ValueError('Owned pair entry required')
    if req['action']=='guard':quiesce();return {'guarded':True}
    expected=str(__import__('ipaddress').IPv4Address(req.get('expected_exit_ip','')))
    blocking=req.get('filtering_enabled',True)
    if type(blocking) is not bool:raise ValueError('Invalid filtering verification policy')
    if lifecycle.route_override(m):
        plan,transport=__import__('recovery').effective_topology(m)
        for attempt in range(3):
            __import__('native_routing').apply('refresh')
            try:lifecycle.verify_route({'plan':plan,'transport':transport,'expected_exit_ip':expected,'filter_policy':{'enabled':blocking}},plan['test_ip']);break
            except (ValueError,OSError,subprocess.SubprocessError):
                if attempt==2:raise
                time.sleep(2)
        m['verified']=True;pair.write_manifest(m);__import__('native_routing').apply('activate')
    else:native_pair.verify(m['plan'],{'expected_exit_ip':expected,'filtering_enabled':blocking},True)
    return {'verified':True,'forwarding':'active'}

def dispatch(req):
    if not isinstance(req,dict):raise ValueError('Expected a JSON object')
    if req.get('action')=='inspect':return inspect()
    if req.get('action')=='filter-policy':return {'enabled':bool(__import__('recovery').filtering_api('dns_info').get('protection_enabled',True))}
    if req.get('action')=='prepare':return prepare(req)
    if req.get('action') in ('guard','verify-pair'):return pair_guard(req)
    return transition(req)
def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0:raise ValueError('Owner SSH access is required')
        if len(sys.argv)==4 and sys.argv[1]=='worker':
            with lifecycle.management_lock():
                op=load(sys.argv[2]);action=sys.argv[3]
                try:
                    if action=='stage' and op['state']=='preparing':stage(op)
                    elif action in ('apply','rollback') and op.get('direction')==action and op['state'] in ('applying','rolling-back'):mutate(op,action=='rollback')
                    else:raise ValueError('Recorded engine operation changed')
                except Exception as error:
                    if action!='stage':
                        with contextlib.suppress(Exception):quiesce()
                    op['error']=str(error) if isinstance(error,ValueError) else type(error).__name__
                    record(op,'prepare-failed' if action=='stage' else action+'-failed','Runtime operation paused; review or roll back')
                    raise
            return
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('Request too large')
        request=json.loads(raw)
        # Progress reads never wait behind a long-running installation lock.
        # Journal writes are atomic; a reported interruption is reconciled again
        # under the lock before a resumed mutation.
        if isinstance(request,dict) and request.get('action')=='status':result=public(status(load(request.get('operation'))))
        else:
            with lifecycle.management_lock():result=dispatch(request)
        print(json.dumps({'ok':True,'result':result}))
    except Exception as error:
        print(json.dumps({'ok':False,'error':str(error) if isinstance(error,ValueError) else type(error).__name__}));raise SystemExit(1)
if __name__=='__main__':main()
