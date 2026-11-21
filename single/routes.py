"""Owned HTTPS/QUIC recipes with private filtering and scoped session estimates.

The phone uploads the pinned worker from its APK over verified SSH. Private
certificate authorities are transported only inside encrypted connection exports;
certificate validation is never disabled.
"""
import base64,fcntl,hashlib,io,ipaddress,json,lzma,os,platform,re,secrets,shlex,shutil,socket,ssl,subprocess,tarfile,tempfile,time,urllib.request
from pathlib import Path
import model,filtering,access,public_tls,user_updates

PROTOCOLS=('hysteria2','outline','shadowsocks','trusttunnel','naive')
WORKER=Path('/opt/rookstride-routes')
PINS=Path(__file__).parent/'routes-pins.json'

def port(excluded=()):
    used=filtering.ports()|set(excluded)
    for value in range(24000,65000):
        if value not in used:return value
    raise ValueError('No free private service port')

def worker():
    pins=json.loads(PINS.read_text());asset=pins['assets'].get(platform.machine())
    if not asset:raise ValueError('The app has no compatible VPN runtime for this server')
    binary=WORKER/asset['sha256']/'rook-routes'
    library=binary.parent/'libcronet.so'
    if WORKER.is_symlink() or binary.parent.is_symlink() or any(p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=asset[key] for p,key in ((binary,'sha256'),(library,'library_sha256'))):raise ValueError('The verified phone VPN runtime has not been transferred')
    return binary

def tls_paths(state,runtime):
    if access.reusable(state) and state.get('public_tls'):return Path(state['public_tls']['certificate']),Path(state['public_tls']['key'])
    folder=runtime.directory(state['protocol'])/'tls';leaf=state.get('tls_leaf','')
    if leaf and not re.fullmatch('leaf-[a-f0-9]{32}',leaf):raise ValueError('Invalid certificate generation')
    target=folder/leaf if leaf else folder
    if folder.is_symlink() or target.is_symlink():raise ValueError('Unexpected certificate link')
    return target/'server.pem',target/'server.key'

def tls_material(state,runtime):
    if access.reusable(state):
        old=state.get('public_tls',{}).get('sha256');state['public_tls']=public_tls.ensure(state['server']);state['tls_name']=state['public_tls']['identity'];state['tls_mode']='public-authority'
        return old!=state['public_tls']['sha256']
    folder=runtime.directory(state['protocol'])/'tls'
    if folder.is_symlink():raise ValueError('Unexpected certificate link')
    folder.mkdir(mode=0o700,exist_ok=True);cert,key=tls_paths(state,runtime);ca=folder/'ca.pem'
    if cert.exists() and key.exists() and ca.exists() and subprocess.run(['openssl','x509','-checkend',str(7*86400),'-noout','-in',str(cert)],capture_output=True,timeout=10).returncode==0:return False
    host=model.hostname(state.get('tls_name',state['server']));kind='IP' if is_ip(host) else 'DNS'
    runtime.atomic(folder/'extension.conf','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+kind+':'+host+'\n')
    if not ca.exists():runtime.command(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','3650','-subj','/CN=Rookstride private VPN authority','-keyout',str(folder/'ca.key'),'-out',str(ca)])
    # A generation is complete before config switches to it. Interrupted renewal
    # cannot leave the active service with mismatched certificate/key files.
    name='leaf-'+secrets.token_hex(16);generation=folder/name;generation.mkdir(mode=0o700)
    key=generation/'server.key';cert=generation/'server.pem'
    runtime.command(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=Rookstride VPN','-keyout',str(key),'-out',str(generation/'request.pem')])
    runtime.command(['openssl','x509','-req','-in',str(generation/'request.pem'),'-CA',str(ca),'-CAkey',str(folder/'ca.key'),'-CAcreateserial','-days','30','-extfile',str(folder/'extension.conf'),'-out',str(cert)])
    runtime.command(['openssl','verify','-CAfile',str(ca),str(cert)])
    for file in folder.rglob('*'):
        if file.is_symlink():raise ValueError('Unexpected certificate link')
        file.chmod(0o700 if file.is_dir() else 0o600)
    state['tls_leaf']=name;state['tls_mode']='private-authority-pinned-through-ssh'
    return True

def certificate_timer(state,runtime):
    name=service_name(state)+'-certificate';prefix=Path('/etc/systemd/system')/name
    service='[Unit]\nDescription=Rookstride managed '+state['protocol']+' VPN-certificate\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStopSec=10\nExecStart=/usr/bin/python3 '+str(runtime.helper_path())+' renew-certificate '+state['protocol']+'\n'
    timer='[Unit]\nDescription=Rookstride managed '+state['protocol']+' VPN-certificate-timer\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n'
    if access.reusable(state):timer=timer.replace('OnCalendar=daily','OnBootSec=10min\nOnUnitActiveSec=4h').replace('RandomizedDelaySec=3600','RandomizedDelaySec=600')
    for suffix,text in (('.service',service),('.timer',timer)):
        path=Path(str(prefix)+suffix)
        if (path.exists() or path.is_symlink()) and (path.is_symlink() or 'Description=Rookstride managed '+state['protocol']+' VPN-certificate' not in path.read_text()):raise ValueError('Certificate service ownership changed')
        runtime.atomic(path,text,0o644)
    runtime.command(['systemctl','daemon-reload']);runtime.command(['systemctl','enable','--now',name+'.timer'])

def renew_certificate(protocol,runtime):
    if protocol=='openvpn':return runtime.renew_password_certificate(runtime.load(protocol))
    if protocol not in PROTOCOLS:raise ValueError('Unsupported certificate owner')
    state=runtime.load(protocol)
    if tls_material(state,runtime):apply(state,runtime);runtime.save(state)

def is_ip(value):
    try:ipaddress.ip_address(value);return True
    except ValueError:return False

def toml_quote(value):
    # TOML requires real Unicode scalars, not JSON's surrogate-pair escapes.
    return json.dumps(value,ensure_ascii=False)

def new_user(state,login,password=None):
    user={'login':(access.login if access.reusable(state) else model.label)(login),'enabled':True,'created':int(time.time()),'password':secrets.token_urlsafe(11)}
    if access.reusable(state):user['password']=access.password(password)
    if state['protocol'] in ('outline','shadowsocks'):
        used=[v.get('private_port') for v in state['users']]+[state['port'],state['metrics_port']]
        user.update(password=base64.b64encode(secrets.token_bytes(32)).decode(),path='/'+secrets.token_hex(24),private_port=port(used))
    return user

def route_policy(state,dns):
    outbound={'type':'direct','tag':'internet','domain_resolver':{'server':'private-dns'}}
    if state.get('pair_dns'):outbound['inet4_bind_address']='10.66.0.1'
    config={'log':{'disabled':True},'inbounds':[],'outbounds':[outbound],
      'dns':{'servers':[{'type':'tcp','tag':'private-dns','server':dns['address'],'server_port':dns['dns_port']}],'strategy':'ipv4_only'},
      'route':{'default_domain_resolver':'private-dns','final':'internet','rules':[
       {'port':53,'action':'route-options','override_address':dns['address'],'override_port':dns['dns_port']},
       {'port':853,'action':'reject'},
       {'ip_version':6,'action':'reject'},
       {'action':'resolve','server':'private-dns','strategy':'ipv4_only'},
       {'ip_is_private':True,'action':'reject'}]}}
    # The explicit rewritten DNS endpoint is the only permitted private target.
    config['route']['rules'].insert(1,{'ip_cidr':[dns['address']+'/32'],'port':dns['dns_port'],'action':'route','outbound':'internet'})
    if state.get('pair_dns'):config['dns']['servers'][0]['inet4_bind_address']='10.66.0.1'
    return config

def configuration(state,runtime):
    p=runtime.directory(state['protocol']);dns=state.get('pair_dns') or filtering.load();cfg=route_policy(state,dns)
    enabled=[u for u in state['users'] if u.get('enabled',True)];cert,key=tls_paths(state,runtime);tls={'enabled':True,'certificate_path':str(cert),'key_path':str(key)}
    result={'schema':1,'box':cfg,'metrics':{'listen':'127.0.0.1:'+str(state['metrics_port']),'token':state['metrics_token'],'users':{}}}
    protocol=state['protocol']
    if protocol=='hysteria2':
        cfg['inbounds']=[{'type':'hysteria2','tag':'phone','listen':'0.0.0.0','listen_port':state['port'],'users':[{'name':u['login'],'password':access.wire_password(state,u)} for u in enabled],
          # Keep QUIC + Salamander + UDP/IP below a 1280-byte outer path.
          # The Android TUN MTU alone does not constrain these server packets.
          'initial_packet_size':1200,'disable_path_mtu_discovery':True,
          'tls':tls}]
        if not access.reusable(state):cfg['inbounds'][0]['obfs']={'type':'salamander','password':state['obfs']}
    elif protocol=='naive':
        cfg['inbounds']=[{'type':'naive','tag':'phone','listen':'0.0.0.0','listen_port':state['port'],'network':'tcp','users':[{'username':u['login'],'password':u['password']} for u in enabled],'tls':tls}]
    elif protocol in ('outline','shadowsocks'):
        targets={}
        for index,u in enumerate(enabled):
            tag='phone-'+str(index);cfg['inbounds'].append({'type':'shadowsocks','tag':tag,'listen':'127.0.0.1','listen_port':u['private_port'],'method':'chacha20-ietf-poly1305','password':u['password']})
            targets[u['path']]='127.0.0.1:'+str(u['private_port']);result['metrics']['users'][tag]=u['login']
        result['websocket']={'listen':'0.0.0.0:'+str(state['port']),'certificate_path':tls['certificate_path'],'key_path':tls['key_path'],'targets':targets}
    elif protocol=='trusttunnel':
        cfg['inbounds']=[{'type':'socks','tag':'forwarder','listen':'127.0.0.1','listen_port':state['forwarder_port']}]
    return result

def service_name(state):return 'rookstride-single-'+state['protocol']

def retained_engine(state,suffix=''):
    """Account/config edits retain the installed engine; upgrades are reviewed separately."""
    unit=Path('/etc/systemd/system')/(service_name(state)+suffix+'.service')
    if not unit.exists():return None
    if unit.is_symlink() or unit.stat().st_uid!=os.geteuid():raise ValueError('VPN service ownership changed')
    text=unit.read_text();description='Description=Rookstride managed '+state['protocol']+' VPN'+suffix
    starts=re.findall('^ExecStart=(.+)$',text,re.M)
    if description not in text or len(starts)!=1:raise ValueError('VPN service ownership changed')
    argv=shlex.split(starts[0]);binary=Path(argv[0])
    if suffix:
        if binary.parent.parent!=WORKER/'trusttunnel' or binary.name!='trusttunnel_endpoint' or not re.fullmatch('v[0-9][A-Za-z0-9._-]{0,63}',binary.parent.name):raise ValueError('Unrecognized installed TrustTunnel engine')
    elif binary.parent.parent!=WORKER or binary.name!='rook-routes' or not re.fullmatch('[a-f0-9]{64}',binary.parent.name):raise ValueError('Unrecognized installed transport engine')
    for path in (binary,*binary.parents):
        if path.is_symlink() or path.exists() and (path.stat().st_uid not in (0,os.geteuid()) or path.stat().st_mode&0o022):raise ValueError('Installed VPN engine ownership changed')
    if not binary.is_file() or not suffix and hashlib.sha256(binary.read_bytes()).hexdigest()!=binary.parent.name:raise ValueError('Installed VPN engine integrity changed')
    return binary

def write_unit(state,runtime,binary,args,suffix=''):
    name=service_name(state)+suffix;unitpath=Path('/etc/systemd/system')/(name+'.service')
    description='Description=Rookstride managed '+state['protocol']+' VPN'+suffix
    if unitpath.exists() and (unitpath.is_symlink() or description not in unitpath.read_text()):raise ValueError('VPN service ownership changed')
    # Paths are owned, fixed-schema values; no user text is interpreted by a shell.
    pre='ExecStartPre=/usr/bin/python3 '+str(runtime.helper_path())+' local-guard '+state['protocol']+'\n' if not suffix else ''
    unit='[Unit]\n'+description+'\nAfter=network-online.target\nWants=network-online.target\n[Service]\n'+pre+'ExecStart='+str(binary)+' '+' '.join(str(v) for v in args)+'\nRestart=on-failure\nRestartSec=2\nTimeoutStopSec=10\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=/run\nProtectHome=true\n[Install]\nWantedBy=multi-user.target\n'
    if suffix=='-endpoint':unit=unit.replace('After=network-online.target','After=network-online.target '+service_name(state)+'.service\nRequires='+service_name(state)+'.service')
    if state.get('pair_dns'):unit=unit.replace('After=network-online.target','After=network-online.target rookstride-pair-routing.service\nRequires=rookstride-pair-routing.service')
    runtime.atomic(unitpath,unit,0o644)
    runtime.command(['systemctl','daemon-reload']);runtime.command(['systemctl','enable',name]);runtime.command(['systemctl','restart',name])

def apply(state,runtime):
    p=runtime.directory(state['protocol']);config=configuration(state,runtime);runtime.atomic(p/'worker.json',json.dumps(config))
    restrict_local(state,runtime)
    if not any(u.get('enabled',True) for u in state['users']):
        for suffix in (['-endpoint',''] if state['protocol']=='trusttunnel' else ['']):
            name=service_name(state)+suffix;unit=Path('/etc/systemd/system')/(name+'.service')
            if unit.exists():
                if unit.is_symlink() or 'Description=Rookstride managed '+state['protocol']+' VPN'+suffix not in unit.read_text():raise ValueError('VPN service ownership changed')
                runtime.command(['systemctl','disable','--now',name])
        return user_updates.result(False,'stopped')
    write_unit(state,runtime,retained_engine(state) or worker(),['run',p/'worker.json'])
    if state['protocol']=='trusttunnel':apply_trust(state,runtime)
    certificate_timer(state,runtime)
    return user_updates.result(True)

def _clear_local(state,runtime):
    comment='ROOK_LOCAL_'+state['instance']
    if not re.fullmatch('ROOK_LOCAL_[a-f0-9]{32}',comment):raise ValueError('Invalid local service owner')
    for line in runtime.command(['iptables','-w','10','-S','OUTPUT']).splitlines():
        fields=shlex.split(line)
        if '--comment' in fields and fields[fields.index('--comment')+1]==comment:
            if fields[:2]!=['-A','OUTPUT']:raise ValueError('Unexpected local service rule')
            runtime.command(['iptables','-w','10','-D',*fields[1:]])

def clear_local(state,runtime):
    with Path('/run/rookstride-local-guard.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);_clear_local(state,runtime)

def restrict_local(state,runtime):
    # Upstream TrustTunnel metrics and private forwarding listeners have no
    # bearer-token interface. Only the root-owned daemons/admin helper may dial
    # them, including from other processes on a shared VPS.
    with Path('/run/rookstride-local-guard.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);_clear_local(state,runtime)
        ports=[state['metrics_port'],state.get('trust_metrics_port'),state.get('forwarder_port')]+[u.get('private_port') for u in state['users']]
        for value in sorted(set(p for p in ports if p)):
            runtime.command(['iptables','-w','10','-I','OUTPUT','1','-d','127.0.0.1/32','-p','tcp','--dport',str(value),'-m','owner','!','--uid-owner','0','-m','comment','--comment','ROOK_LOCAL_'+state['instance'],'-j','REJECT'])

def install(state,phase,runtime):
    prepared=None
    if not state.get('pair_dns'):
        phase(2,'Preparing and verifying private ad blocking');prepared=filtering.prepare_binary()
    p=runtime.directory(state['protocol']);p.mkdir(mode=0o700,parents=True,exist_ok=True);state['users']=[];runtime.save(state)
    phase(2,'Preparing the verified phone VPN runtime');worker()
    runtime.command(['apt-get','update'],timeout=600);runtime.command(['apt-get','install','-y','openssl','iproute2'],timeout=600)
    if state.get('pair_dns'):phase(3,'Using private ad blocking on the exit server')
    else:
        phase(3,'Installing private ad blocking');filtering.ensure(lambda text:phase(3,text),docker=False,prepared=prepared);state['filtering']=filtering.load()['instance']
    phase(4,'Creating private connection credentials')
    # The official endpoint requires SNI, which TLS omits for IP literals.
    # An SSH-authenticated private identity needs no public DNS registration.
    if not access.reusable(state) and state['protocol']=='trusttunnel' and is_ip(state['server']):state['tls_name']='vpn-'+state['instance']+'.internal'
    tls_material(state,runtime)
    state['metrics_port']=port([state['port']]);state['metrics_token']=secrets.token_hex(32)
    if not access.reusable(state) and state['protocol']=='hysteria2':state['obfs']=secrets.token_urlsafe(24)
    if state['protocol']=='trusttunnel':state['forwarder_port']=port([state['port'],state['metrics_port']]);state['trust_metrics_port']=port([state['port'],state['metrics_port'],state['forwarder_port']])
    state['users']=[new_user(state,state['initialLogin'],state.pop('initialPassword',None))];runtime.save(state)
    phase(5,'Starting the VPN');apply(state,runtime)
    phase(6,'Checking the VPN, private DNS and connection statistics')
    for _ in range(40):
        try:
            if health(state,runtime)['running'] and statistics(state):break
        except (OSError,ValueError):pass
        time.sleep(.5)
    else:raise ValueError('The VPN or statistics service did not become ready')
    if not state.get('pair_dns') and not filtering.ready():raise ValueError('Private DNS verification failed')
    if not state.get('pair_dns'):
        phase(6,'Testing an actual encrypted VPN connection and statistics')
        verify_connection(state,runtime)
    runtime.save(state)

def endpoint_route_mtu(address):
    """Read the current IPv4 route; unknown paths keep the runtime defaults."""
    try:
        address=str(ipaddress.IPv4Address(address))
        result=subprocess.run(['ip','-j','-4','route','get',address],capture_output=True,text=True,timeout=2)
        if result.returncode:return None
        rows=json.loads(result.stdout)
        if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):return None
        row=rows[0];dev=row.get('dev')
        if row.get('type','unicast')!='unicast' or row.get('dst') not in (address,address+'/32') or not isinstance(dev,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',dev):return None
        metrics=row.get('metrics',{})
        if isinstance(metrics,list):
            if len(metrics)!=1:return None
            metrics=metrics[0]
        if not isinstance(metrics,dict):return None
        mtus=[]
        if 'mtu' in metrics:
            value=metrics['mtu']
            if type(value)!=int or not 68<=value<=65535:return None
            mtus.append(value)
        try:
            text=(Path('/sys/class/net')/dev/'mtu').read_text().strip()
            if re.fullmatch(r'[0-9]{2,5}',text) and 68<=int(text)<=65535:mtus.append(int(text))
        except OSError:pass
        return min(mtus) if mtus else None
    except (OSError,ValueError,subprocess.TimeoutExpired):return None

def client_config(profile,socks_port,server=None,protect_path=None):
    validate_profile(profile)
    protocol=profile['protocol'];address=server or profile['server']
    if not is_ip(address):address=socket.getaddrinfo(address,profile['port'],socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    tls={'enabled':True,'server_name':profile['server_name'],'certificate':[profile['certificate']]}
    outbound={'tag':'vpn','server':address,'server_port':profile['port']}
    if protect_path:outbound['protect_path']=protect_path
    if protocol=='hysteria2':
        password=profile['login']+':'+profile['password'] if profile.get('access_mode')=='password' else profile['password']
        outbound.update(type='hysteria2',password=password,tls=tls)
        if profile.get('obfs'):outbound['obfs']={'type':'salamander','password':profile['obfs']}
        # Only server TUN bridges use port zero. Keep Chrome imitation on normal
        # paths; quic-go's Chrome preset otherwise forces a 1250-byte UDP payload
        # even when initial_packet_size is smaller. Account for Salamander too.
        if socks_port==0:
            mtu=endpoint_route_mtu(address);overhead=20+8+(8 if profile.get('obfs') else 0)
            if mtu is not None and mtu<1250+overhead:
                if mtu<1200+overhead:raise ValueError('The exit route MTU is below the QUIC minimum')
                outbound.update(initial_packet_size=1200,disable_path_mtu_discovery=True,disable_chrome_parrot=True)
    elif protocol=='naive':outbound.update(type='naive',username=profile['login'],password=profile['password'],tls=tls,udp_over_tcp=True,quic=False)
    elif protocol in ('outline','shadowsocks'):outbound.update(type='outline-wss',method=profile['method'],password=profile['password'],path=profile['path'],certificate=profile['certificate'],server_name=profile['server_name'])
    elif protocol=='trusttunnel':outbound.update(type='trusttunnel-h2',username=profile['login'],password=profile['password'],certificate=profile['certificate'],server_name=profile['server_name'])
    else:raise ValueError('Unsupported managed connection format')
    outbounds=[outbound]
    if protocol=='naive':
        outer={'type':'endpoint-only','tag':'transport','server':address,'server_port':profile['port']}
        if protect_path:outer['protect_path']=protect_path
        outbound.pop('protect_path',None);outbound['detour']='transport';outbounds.append(outer)
    return {'schema':1,'box':{'log':{'disabled':True},'inbounds':[{'type':'socks','tag':'phone','listen':'127.0.0.1','listen_port':socks_port}],'outbounds':outbounds,
        'dns':{'servers':[{'type':'tcp','tag':'tunnel-dns','server':'1.1.1.1','server_port':53,'detour':'vpn'}],'strategy':'ipv4_only'},'route':{'default_domain_resolver':'tunnel-dns','final':'vpn'}}}

def validate_profile(profile):
    allowed={'schema','protocol','server','port','login','password','certificate','server_name','method','path','obfs','access_mode'}
    if not isinstance(profile,dict) or set(profile)-allowed or profile.get('schema')!=1 or profile.get('protocol') not in PROTOCOLS:raise ValueError('Unsupported connection profile')
    if 'access_mode' in profile and (profile['access_mode']!='password' or profile.get('protocol') not in access.PASSWORD_PROTOCOLS):raise ValueError('Unsupported sign-in mode')
    host=model.hostname(profile.get('server'));(access.login if profile.get('access_mode')=='password' else model.label)(profile.get('login'))
    name=profile.get('server_name');private_name=profile['protocol']=='trusttunnel' and isinstance(name,str) and re.fullmatch('vpn-[a-f0-9]{32}\\.internal',name)
    public=profile.get('access_mode')=='password' and profile['protocol'] in access.PASSWORD_PROTOCOLS
    secret=profile.get('password')
    if public:access.password(secret)
    elif not isinstance(secret,str) or not 8<=len(secret)<=256:raise ValueError('Invalid connection secret')
    if (name!=host and not private_name and not (public and name==public_tls.tls_name(host))) or type(profile.get('port')) is not int or not 1<=profile['port']<=65535:raise ValueError('Invalid connection identity')
    certificate=profile.get('certificate','')
    if not isinstance(certificate,str) or len(certificate)>512000:raise ValueError('Invalid certificate authority')
    try:ssl.create_default_context().load_verify_locations(cadata=certificate)
    except (ValueError,TypeError,ssl.SSLError):raise ValueError('Invalid certificate authority') from None
    if profile['protocol'] in ('outline','shadowsocks') and (profile.get('method')!='chacha20-ietf-poly1305' or not re.fullmatch('/[a-f0-9]{48}',profile.get('path',''))):raise ValueError('Invalid WebSocket profile')
    if profile['protocol']=='hysteria2' and (public and 'obfs' in profile or not public and not 16<=len(profile.get('obfs',''))<=128):raise ValueError('Invalid QUIC obfuscation key')
    return profile

def verify_connection(state,runtime):
    user=next(u for u in state['users'] if u.get('enabled',True));export=json.loads(profile(state,user,runtime)['content'])
    with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));listen=reserve.getsockname()[1]
    # Test the local listener without requiring the VPS to hairpin through its
    # public address. The expected TLS identity remains the advertised name.
    config=client_config(export,listen,server='127.0.0.1')
    with tempfile.TemporaryDirectory(prefix='verify-',dir=runtime.directory(state['protocol'])) as folder:
        path=Path(folder)/'client.json';runtime.atomic(path,json.dumps(config));process=subprocess.Popen([str(worker()),'run',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while process.poll() is None and time.monotonic()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',listen),timeout=.3):break
                except OSError:time.sleep(.1)
            if process.poll() is not None or not any(runtime.socks_https_ready(listen,host) for host in ('example.com','www.cloudflare.com')):raise ValueError('The encrypted VPN connection check failed on the server')
        finally:
            process.terminate()
            try:process.wait(timeout=6)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)

def statistics(state):
    endpoint='http://127.0.0.1:'+str(state['trust_metrics_port'])+'/clients' if state['protocol']=='trusttunnel' else 'http://127.0.0.1:'+str(state['metrics_port'])+'/statistics'
    request=urllib.request.Request(endpoint,headers={'Authorization':'Bearer '+state['metrics_token']})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=4) as response:
        raw=response.read(1024*1024+1)
    if len(raw)>1024*1024:raise ValueError('Unexpected statistics response size')
    return json.loads(raw)

def health(state,runtime):
    name=service_name(state);running=subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0
    if state['protocol']=='trusttunnel':running=running and subprocess.run(['systemctl','is-active','--quiet',name+'-endpoint']).returncode==0
    dns={'installed':True,'remote':True,'running':None,'scope':'exit server'} if state.get('pair_dns') else filtering.inspect()
    users=[{'login':u['login'],'person':u.get('person',u['login']),'device':u.get('device',u['login']),'kind':'device','enabled':u.get('enabled',True)} for u in state['users']]
    connections=[];available=False
    if running:
        try:
            data=statistics(state);available=True
            generation=data.get('generation','') if isinstance(data,dict) else runtime.command(['systemctl','show','--property=InvocationID','--value',name+'-endpoint'])
            rows={v['username']:{'upload':v['inbound'],'download':v['outbound'],'sessions':v['sessions']} for v in data} if isinstance(data,list) else data.get('users',{})
            for user in users:
                row=rows.get(user['login'],{});sessions=max(0,int(row.get('sessions',0)))
                connections.append({'user':user['login'],'upload':max(0,int(row.get('upload',0))),'download':max(0,int(row.get('download',0))),'recent':sessions>0,'sessions':sessions,'counter_scope':'current server daemon','generation':generation,'vpn_addresses':[]})
        except (OSError,ValueError,KeyError,TypeError):available=False
    return {'protocol':state['protocol'],'instance':state['instance'],'port':state['port'],'running':running,'services':{'protocol':running,'adguard':dns['running']},'users':users,'connections':connections,'filtering':dns,'monitoring_available':available,'statistics_kind':'sessions','recent_peers':sum(c['recent'] for c in connections),'statistics_enabled':available,'edit_users':True,'capabilities':{'profiles':True,'users':True,'disconnect':False,'adguard':bool(state.get('filtering'))},'client':'Rookstride','access_mode':state.get('access_mode','profile'),'manual_sign_in':access.reusable(state),'password_policy':access.policy() if access.reusable(state) else None,'account_updates':user_updates.impact(state)}

def profile(state,user,runtime):
    content={'schema':1,'protocol':state['protocol'],'server':state['server'],'port':state['port'],'login':user['login'],'password':user['password'],'certificate':public_tls.roots() if access.reusable(state) else (runtime.directory(state['protocol'])/'tls/ca.pem').read_text(),'server_name':state.get('tls_name',state['server'])}
    if state['protocol'] in ('outline','shadowsocks'):content.update(method='chacha20-ietf-poly1305',path=user['path'])
    if access.reusable(state):content['access_mode']='password'
    elif state['protocol']=='hysteria2':content['obfs']=state['obfs']
    return {'format':state['protocol'],'name':'rookstride-'+re.sub(r'[^A-Za-z0-9_-]','_',user['login'])+'.rookvpn','content':json.dumps(content,separators=(',',':')),'client':'Rookstride'}

def apply_trust(state,runtime):
    binary=retained_engine(state,'-endpoint')
    if binary is None:
        pins=json.loads(PINS.read_text())['trusttunnel'];asset=pins['assets'].get(platform.machine())
        if not asset:raise ValueError('TrustTunnel requires an x86_64 or aarch64 VPS')
        raw=filtering.pinned_download(asset['url'],asset['sha256'],asset['bytes'],asset['bytes'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            members=[m for m in archive.getmembers() if m.isfile() and m.name.endswith('/trusttunnel_endpoint')]
            if len(members)!=1 or members[0].size>64*1024*1024:raise ValueError('Unexpected TrustTunnel package')
            data=archive.extractfile(members[0]).read()
        binary=WORKER/'trusttunnel'/pins['version']/'trusttunnel_endpoint';binary.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if binary.is_symlink():raise ValueError('Unexpected VPN runtime link')
        if not binary.exists() or hashlib.sha256(binary.read_bytes()).digest()!=hashlib.sha256(data).digest():
            tmp=binary.with_suffix('.new');tmp.write_bytes(data);tmp.chmod(0o700);tmp.replace(binary)
    p=runtime.directory('trusttunnel');quote=toml_quote;cert,key=tls_paths(state,runtime)
    settings='listen_address = '+quote('0.0.0.0:'+str(state['port']))+'\nipv6_available = false\nallow_private_network_connections = true\ncredentials_file = '+quote(str(p/'credentials.toml'))+'\nclient_listener_timeout_secs = 86400\n[listen_protocols.http2]\n[listen_protocols.http1]\n[forward_protocol.socks5]\naddress = '+quote('127.0.0.1:'+str(state['forwarder_port']))+'\nextended_auth = false\n[metrics]\naddress = '+quote('127.0.0.1:'+str(state['trust_metrics_port']))+'\nrequest_timeout_secs = 3\nper_client_metrics = true\n'
    runtime.atomic(p/'vpn.toml',settings)
    runtime.atomic(p/'hosts.toml','[[main_hosts]]\nhostname = '+quote(state.get('tls_name',state['server']))+'\ncert_chain_path = '+quote(str(cert))+'\nprivate_key_path = '+quote(str(key))+'\n')
    runtime.atomic(p/'credentials.toml',''.join('[[client]]\nusername = '+quote(u['login'])+'\npassword = '+quote(u['password'])+'\n' for u in state['users'] if u.get('enabled',True)))
    write_unit(state,runtime,binary,[p/'vpn.toml',p/'hosts.toml'],'-endpoint')
