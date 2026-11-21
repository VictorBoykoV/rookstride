"""Owned, independent single-server adapters. Existing two-hop recipes are untouched."""
import base64,hashlib,io,json,os,platform,re,secrets,shutil,socket,ssl,subprocess,tempfile,time,urllib.request,uuid,zipfile
from pathlib import Path
import model
import access,public_tls,user_updates
import filtering
ROOT=Path('/opt/rookstride-single')
STATE=Path('/var/lib/rookstride-single')
PINS=json.loads((Path(__file__).parent/'pins.json').read_text())
HELPER=None
PAIR_MANIFEST=Path('/etc/rookstride-pair/manifest.json')

def coexist_pair(state,manifest=None):
    """Read-only ownership hint, never permission to install or reset a listener."""
    if state.get('protocol')!='openvpn' or state.get('owner')!='rookstride-single-v1':return ''
    identity=state.get('coexist_pair','')
    if not isinstance(identity,str) or not re.fullmatch('[a-f0-9]{32}',identity):return ''
    path=manifest or PAIR_MANIFEST
    try:
        for item in (path,path.parent):
            if item.is_symlink() or item.stat().st_uid!=os.geteuid() or item.stat().st_mode&0o022:return ''
        if path.stat().st_size>262144:return ''
        owned=json.loads(path.read_text())
        if not isinstance(owned,dict) or not isinstance(owned.get('plan'),dict):return ''
        p=owned['plan']
        if owned.get('version')==2 and p.get('pair')==identity and p.get('role')=='entry' and p.get('entry_protocol')=='awg' and p.get('client_pool')=='10.66.0.0/24':return identity
    except (OSError,ValueError,TypeError):pass
    return ''

def helper_path():
    return HELPER or Path(__file__).resolve().with_name('run.py')

def atomic(path,value,mode=0o600):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('Unexpected link in VPN data')
    temporary=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    with os.fdopen(fd,'w') as out:out.write(value)
    os.replace(temporary,path)

def command(args,data=None,timeout=120):
    if args[0]=='apt-get':
        args=[args[0],'-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3',*args[1:]]
    p=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise ValueError('Could not complete '+Path(args[0]).name+' operation')
    if len(p.stdout)>2*1024*1024:raise ValueError('Unexpected command response size')
    return p.stdout.strip()

def directory(protocol):
    if protocol not in model.PROTOCOLS:raise ValueError('Unsupported protocol')
    p=STATE/protocol
    if p.is_symlink() or STATE.is_symlink():raise ValueError('Unexpected link in VPN data')
    return p

def load(protocol):
    p=directory(protocol)/'state.json'
    if p.is_symlink():raise ValueError('Unexpected state link')
    state=json.loads(p.read_text())
    if state.get('protocol')!=protocol or state.get('owner')!='rookstride-single-v1':raise ValueError('VPN ownership cannot be verified')
    return state

def save(state):atomic(directory(state['protocol'])/'state.json',json.dumps(state))

def docker_ready():
    if not shutil.which('docker'):
        command(['apt-get','update'],timeout=600)
        command(['apt-get','install','-y','docker.io'],timeout=1200)
    command(['systemctl','start','docker'])
    command(['docker','info','--format','{{.ServerVersion}}'])

def container(protocol):return 'rookstride-single-'+protocol

def check_container(state):
    try:p=subprocess.run(['docker','container','inspect',container(state['protocol'])],capture_output=True,text=True,timeout=20)
    except FileNotFoundError:
        # A cold install owns its partial state before apt installs Docker.
        # Missing executable alone is insufficient if a container store remains.
        if not Path('/var/lib/docker').exists() and not Path('/var/lib/containerd').exists():return None
        raise ValueError('Docker is unavailable but container data remains; restore Docker before reviewing removal')
    if p.returncode:
        if "no such object" in p.stderr.lower() or "no such container" in p.stderr.lower():return None
        raise ValueError("Docker could not inspect the VPN container; no data was removed")
    value=json.loads(p.stdout)[0]
    if value['Config'].get('Labels',{}).get('io.rookstride.instance')!=state['instance']:raise ValueError('Container belongs to a different installation')
    return value

def awg_key(kind,data=None):return command(['docker','run','--rm','-i','rookstride-awg:1','awg',kind],data)

def xray_keys(output):
    parsed={key.strip():value.strip() for key,value in (line.split(':',1) for line in output.splitlines() if ':' in line)}
    private=parsed.get('PrivateKey',parsed.get('Private key',''))
    public=parsed.get('Password (PublicKey)',parsed.get('Password',parsed.get('PublicKey',parsed.get('Public key',''))))
    for value in (private,public):
        try:
            if len(base64.b64decode(value+'='*(-len(value)%4),altchars=b'-_',validate=True))!=32:raise ValueError()
        except (ValueError,base64.binascii.Error):raise ValueError('Unexpected Xray key format') from None
    return private,public

def install_xray_binary():
    binary=ROOT/'bin/xray';asset=PINS['xray']['assets'].get(platform.machine())
    if asset is None:raise ValueError('Xray requires an x86_64 or aarch64 VPS')
    if binary.exists() and (ROOT/'bin/version').read_text()==PINS['xray']['version']:return binary
    raw=filtering.pinned_download(asset['url'],asset['sha256'],asset['bytes'],asset['bytes'])
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:data=archive.read('xray')
    binary.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    temp=binary.with_suffix('.new');temp.write_bytes(data);temp.chmod(0o700);temp.replace(binary)
    atomic(ROOT/'bin/version',PINS['xray']['version'])
    return binary

def probe_tls_context():
    # A stable reference handshake for readiness, independent of new distro
    # key-share defaults. OpenSSL 3.5+/4's default handshake reset on the
    # test underlay even without a VPN; X25519 succeeded with verified TLS.
    # This changes only our probe, never the VPN engines, users or system policy.
    context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
    # Older Python/OpenSSL EC APIs cannot select X25519 with this method. Their
    # existing default handshake passed the older-Ubuntu control tests.
    if ssl.OPENSSL_VERSION_INFO>=(3,5):context.set_ecdh_curve('X25519')
    return context

def reality_target_ready(host):
    context=probe_tls_context();context.minimum_version=ssl.TLSVersion.TLSv1_3;context.set_alpn_protocols(['h2'])
    try:
        with socket.create_connection((host,443),timeout=6) as raw:
            with context.wrap_socket(raw,server_hostname=host) as tls:
                return tls.version()=='TLSv1.3' and tls.selected_alpn_protocol()=='h2'
    except (OSError,ValueError):return False

REALITY_TARGETS=('www.cloudflare.com','www.microsoft.com')

def reality_targets(state):
    # XHTTP's repeated outer handshakes need a cover target that accepts its
    # exact TLS flight. A generic TLS/h2 preflight alone cannot establish that.
    return ('www.apple.com',)+REALITY_TARGETS if state.get('protocol')=='xhttp' else REALITY_TARGETS

def choose_reality_target(state):
    # Existing explicit CLI targets stay explicit. New phone installs need no SNI field.
    candidates=reality_targets(state) if state.get('sni_auto') else (state['sni'],)
    for host in candidates:
        if reality_target_ready(host):return host
    raise ValueError('The server could not reach a compatible REALITY website. Try again later or choose another protocol.')

def receive_exact(stream,size):
    result=b''
    while len(result)<size:
        chunk=stream.recv(size-len(result))
        if not chunk:raise OSError('The connection closed during verification')
        result+=chunk
    return result

def socks_https_ready(port,host):
    # Resolve the website through the real VLESS server; never use a direct fallback.
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=8) as stream:
            stream.sendall(b'\x05\x01\x00')
            if receive_exact(stream,2)!=b'\x05\x00':return False
            name=host.encode('ascii');stream.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+b'\x01\xbb')
            reply=receive_exact(stream,4)
            if reply[:3]!=b'\x05\x00\x00':return False
            if reply[3]==1:receive_exact(stream,4)
            elif reply[3]==4:receive_exact(stream,16)
            elif reply[3]==3:receive_exact(stream,receive_exact(stream,1)[0])
            else:return False
            receive_exact(stream,2)
            with probe_tls_context().wrap_socket(stream,server_hostname=host) as tls:
                tls.sendall(('HEAD / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode('ascii'))
                status=b''
                while b'\r\n' not in status and len(status)<512:
                    chunk=tls.recv(min(256,512-len(status)))
                    if not chunk:return False
                    status+=chunk
                if b'\r\n' not in status:return False
                status=status.split(b'\r\n',1)[0].split()
                return len(status)>=2 and status[0] in (b'HTTP/1.0',b'HTTP/1.1') and status[1].isdigit() and 200<=int(status[1])<400
    except (OSError,ValueError):return False

def reality_client_ready(state):
    # Independent client processes exercise fresh REALITY handshakes. Do not
    # accept one lucky request from an intermittently compatible cover target.
    return all(reality_session_ready(state) for _ in range(3 if state.get('protocol')=='xhttp' else 1))

def reality_session_ready(state):
    # TLS1.3/h2 alone is insufficient. Prove authentication and HTTPS through Xray.
    users=[u for u in state['users'] if u.get('enabled',True)]
    if not users:return False
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    config={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':False}}],
      'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':state['port'],'users':[{'id':users[0]['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
      'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':state['sni'],'fingerprint':'chrome','publicKey':state['public'],'shortId':state['shortId']}}}]}
    process=None
    if state.get('protocol')=='xhttp':
        outbound=config['outbounds'][0];outbound['settings']['vnext'][0]['users'][0].pop('flow',None)
        outbound['streamSettings']['network']='xhttp';outbound['streamSettings']['xhttpSettings']={'path':state['path'],'mode':'auto'}
    with tempfile.TemporaryDirectory(prefix='connection-check-',dir=directory(state['protocol'])) as folder:
        path=Path(folder)/'client.json';atomic(path,json.dumps(config))
        try:
            process=subprocess.Popen([str(ROOT/'bin/xray'),'run','-config',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+5
            while process.poll() is None and time.monotonic()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.1)
            if process.poll() is not None:return False
            checks=(socks_https_ready(port,host) for host in ('example.com','www.cloudflare.com'))
            return all(checks) if state.get('protocol')=='xhttp' else any(checks)
        except OSError:return False
        finally:
            if process is not None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

def verify_reality_route(state,phase):
    candidates=[state['sni']]
    if state.get('sni_auto'):candidates.extend(host for host in reality_targets(state) if host!=state['sni'])
    for index,host in enumerate(candidates):
        if index:
            if not reality_target_ready(host):continue
            phase(6,'Trying the next verified connection target');state['sni']=host;save(state);apply_config(state)
        phase(6,'Testing an actual encrypted VPN connection')
        if reality_client_ready(state):return
    raise ValueError('The encrypted VPN connection check failed from this server. Try again or choose another protocol.')

def install(state,phase):
    protocol=state['protocol']
    if protocol in model.ADDITIONAL and protocol!='xhttp':
        import routes
        return routes.install(state,phase,__import__(__name__))
    prepared=None
    if not state.get('pair_dns'):
        phase(2,'Preparing and verifying private ad blocking');prepared=filtering.prepare_binary()
    p=directory(protocol);p.mkdir(mode=0o700,parents=True,exist_ok=True)
    initial_password=state.pop('initialPassword',None)
    state['users']=[];save(state)  # Own partial installs before the first external mutation.
    if protocol in ('awg','openvpn'):
        phase(2,'Preparing the VPN runtime');docker_ready()
        if protocol=='awg':
            command(['docker','build','-t','rookstride-awg:1','-f',str(Path(__file__).parent/'Dockerfile.awg'),str(Path(__file__).parent)],timeout=600)
            state['private']=awg_key('genkey');state['public']=awg_key('pubkey',state['private']+'\n');state['parameters']=model.awg_parameters()
        else:
            command(['docker','build','-t','rookstride-openvpn:1','-f',str(Path(__file__).parent/'Dockerfile.openvpn'),str(Path(__file__).parent)],timeout=1200)
    else:
        phase(2,'Downloading and verifying Xray');binary=install_xray_binary()
        phase(2,'Checking the encrypted connection target');state['sni']=choose_reality_target(state)
        state['private'],state['public']=xray_keys(command([str(binary),'x25519']))
        state['shortId']=secrets.token_hex(8)
        import routes
        state['metrics_port']=routes.port([state['port']])
        if protocol=='xhttp':state['path']='/'+secrets.token_hex(24)
    if state.get('pair_dns'):phase(3,'Using private ad blocking on the exit server')
    else:
        phase(3,'Installing private ad blocking');filtering.ensure(lambda text:phase(3,text),docker=not model.proxy_protocol(protocol),prepared=prepared);state['filtering']=filtering.load()['instance']
    phase(4,'Creating private connection credentials');state['users']=[]
    save(state)
    if protocol=='openvpn' and not access.reusable(state):
        runtime=p/'runtime';runtime.mkdir(mode=0o700)
        image='rookstride-openvpn:1'
        command(['docker','run','--rm','--mount','type=bind,source='+str(runtime)+',target=/vpn',image,'init'],timeout=300)
    if protocol=='openvpn' and access.reusable(state):
        phase(4,'Preparing reusable VPN sign-in');state['public_tls']=public_tls.ensure(state['server']);state['tls_name']=state['public_tls']['identity']
        if state['public_tls']['common_name']!=state['tls_name']:raise ValueError('This public certificate has no compatible OpenVPN name. Use a shorter VPN domain.')
    add_user(state,state['initialLogin'],apply=False,password=initial_password)
    phase(5,'Starting the VPN');apply_config(state,first=True)
    phase(6,'Checking the VPN service and ad blocking')
    for attempt in range(20):
        if health(state)['running']:break
        time.sleep(.5)
    else:raise ValueError('VPN service did not become ready')
    if not state.get('pair_dns') and not filtering.ready():raise ValueError('Private DNS verification failed')
    if protocol in ('xray','xhttp') and not state.get('pair_dns'):verify_reality_route(state,phase)
    save(state)

def enable_filter(state,phase):
    phase(3,'Installing private ad blocking');filtering.ensure(lambda text:phase(3,text),docker=not model.proxy_protocol(state['protocol']))
    state['filtering']=filtering.load()['instance'];save(state);phase(4,'Updating the VPN DNS route')
    if not model.proxy_protocol(state['protocol']):
        owned=check_container(state)
        if owned:command(['docker','rm','-f',container(state['protocol'])])
    apply_config(state,first=True);phase(6,'Checking VPN and private DNS')
    if not health(state)['running'] or not filtering.ready():raise ValueError('VPN or private DNS verification failed')

def add_user(state,login,apply=True,password=None,person=None,device=None):
    (access.login if access.reusable(state) else model.label)(login)
    if person is not None:person=model.display_label(person)
    if device is not None:device=model.display_label(device)
    if any(u['login']==login for u in state['users']):raise ValueError('That login already exists')
    if state['protocol']=='openvpn' and not access.reusable(state) and login in state.get('revoked',[]):raise ValueError('That certificate name was revoked. Choose another login.')
    user={'login':login,'enabled':True,'created':int(time.time())}
    if state['protocol'] in model.ADDITIONAL and state['protocol']!='xhttp':
        import routes
        user=routes.new_user(state,login,password)
    elif state['protocol']=='awg':
        used={int(u['address'].split('.')[-1]) for u in state['users']};offset=next((i for i in range(2,254) if i not in used),None)
        if offset is None:raise ValueError('This VPN has no free client addresses')
        user.update(private=awg_key('genkey'),psk=awg_key('genpsk'),address=('10.66.0.' if state.get('pair_dns') else '10.67.0.')+str(offset),ipv6='fd42:670::'+format(offset,'x'))
        user['public']=awg_key('pubkey',user['private']+'\n')
    elif state['protocol'] in ('xray','xhttp'):user['uuid']=str(uuid.uuid4())
    elif access.reusable(state):user['password_hash']=access.hash_password(password)
    else:
        command(['docker','run','--rm','--mount','type=bind,source='+str(directory('openvpn')/'runtime')+',target=/vpn','rookstride-openvpn:1','add',login],timeout=180)
    if person is not None:user['person']=model.display_label(person)
    if device is not None:user['device']=model.display_label(device)
    state['users'].append(user);save(state)
    if apply:
        if state['protocol'] in ('xray','xhttp'):
            import xray_users
            if xray_users.add(state,user,__import__(__name__)):return {'login':login,'listener_restarted':False,'update':'live'}
        # A new certificate is signed by the already loaded CA; the listener
        # reads it from the incoming TLS handshake. No listener setting changes.
        # Retain the normal start/recovery path when the owned container is down.
        existing=check_container(state) if state['protocol']=='openvpn' and not access.reusable(state) else None
        if existing and existing.get('State',{}).get('Running'):outcome=user_updates.result()
        else:outcome=apply_config(state)
        return {'login':login,**(outcome or {})}
    return {'login':login,'update':'prepared','listener_restarted':False}

def apply_config(state,first=False):
    protocol=state['protocol'];p=directory(protocol);runtime=p/'runtime';runtime.mkdir(mode=0o700,exist_ok=True)
    if protocol in model.ADDITIONAL and protocol!='xhttp':
        import routes
        return routes.apply(state,__import__(__name__))
    if protocol in ('xray','xhttp'):
        if state.get('metrics_port'):
            import routes
            routes.restrict_local(state,__import__(__name__))
        atomic(runtime/'server.json',json.dumps(model.xray_server(state,filtering.load() if state.get('filtering') else None)))
        binary=ROOT/'bin/xray';command([str(binary),'run','-test','-config',str(runtime/'server.json')])
        unit='''[Unit]\nDescription=Rookstride Xray VPN\nAfter=network-online.target\nWants=network-online.target\n[Service]\nExecStart='''+str(binary)+' run -config '+str(runtime/'server.json')+'''\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n[Install]\nWantedBy=multi-user.target\n'''
        if state.get('pair_dns'):unit=unit.replace('After=network-online.target', 'After=network-online.target rookstride-pair-routing.service\nRequires=rookstride-pair-routing.service')
        if protocol=='xhttp':unit=unit.replace('Description=Rookstride Xray VPN','Description=Rookstride XHTTP VPN')
        if state.get('metrics_port'):
            helper=helper_path();unit=unit.replace('[Service]\n','[Service]\nExecStartPre=/usr/bin/python3 '+str(helper)+' local-guard '+protocol+'\nReadWritePaths=/run\n',1)
        unitpath=Path('/etc/systemd/system/rookstride-single-'+protocol+'.service')
        if unitpath.exists() and (unitpath.is_symlink() or ('Description=Rookstride XHTTP VPN' if protocol=='xhttp' else 'Description=Rookstride Xray VPN') not in unitpath.read_text()):raise ValueError('Unexpected Xray service ownership')
        atomic(unitpath,unit,0o644);command(['systemctl','daemon-reload']);command(['systemctl','enable','rookstride-single-'+protocol]);command(['systemctl','restart','rookstride-single-'+protocol])
        time.sleep(1);return user_updates.result(True)
    if protocol=='openvpn' and access.reusable(state):
        state['public_tls']=public_tls.ensure(state['server']);state['tls_name']=state['public_tls']['identity']
        atomic(runtime/'public-server.pem',Path(state['public_tls']['certificate']).read_text());atomic(runtime/'public-server.key',Path(state['public_tls']['key']).read_text());atomic(runtime/'public-roots.pem',public_tls.roots())
        atomic(runtime/'credentials.json',json.dumps({u['login']:u['password_hash'] for u in state['users'] if u.get('enabled',True)}))
    if protocol=='awg':atomic(runtime/'server.conf',model.awg_server(state))
    else:atomic(runtime/'server.conf',model.openvpn_server(state))
    existing=check_container(state)
    if existing and not first:
        restarted=False
        if protocol=='awg':command(['docker','exec','-i',container(protocol),'awg','syncconf','rsawg0','/dev/stdin'],model.awg_server(state))
        elif not access.reusable(state) or state.get('applied_tls_sha')!=state['public_tls']['sha256']:
            command(['docker','restart',container(protocol)]);restarted=True
        if access.reusable(state):state['applied_tls_sha']=state['public_tls']['sha256'];save(state);password_timer(state)
        return user_updates.result(restarted)
    if existing:raise ValueError('A VPN container is already present')
    image='rookstride-awg:1' if protocol=='awg' else 'rookstride-openvpn:1'
    name='entry-awg.sh' if protocol=='awg' else 'entry-openvpn.sh'
    source=Path(__file__).parent/name
    # Only the runtime directory is mounted; peer private keys stay outside the container.
    args=['docker','run','-d','--name',container(protocol),'--restart','no' if state.get('pair_dns') else 'unless-stopped','--label','io.rookstride.instance='+state['instance'],
          '--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.ip_forward=1',
          '--sysctl','net.ipv6.conf.all.disable_ipv6=0','--mount','type=bind,source='+str(runtime)+',target=/vpn',
          '--mount','type=bind,source='+str(source)+',target=/rookstride-entry.sh,readonly',
          '-p',str(state['port'])+(':'+str(51820)+'/udp' if protocol=='awg' else ':1194/tcp'),'--entrypoint','/bin/bash',image,'/rookstride-entry.sh']
    if state.get('pair_dns'):
        dns=state['pair_dns'];args[2:2]=['-e','ROOK_DNS_ADDRESS='+dns['address'],'-e','ROOK_DNS_PORT='+str(dns['dns_port']),'-e','ROOK_PAIR_ROUTE=1']
    elif state.get('filtering'):
        dns=filtering.load();args[2:2]=['-e','ROOK_DNS_ADDRESS='+dns['address'],'-e','ROOK_DNS_PORT='+str(dns['dns_port'])]
        filtering.network_start()
    command(args);time.sleep(2)
    if protocol=='openvpn' and access.reusable(state):state['applied_tls_sha']=state['public_tls']['sha256'];save(state);password_timer(state)
    return user_updates.result(False,'started')

def awg_connections(state, dump, now=None):
    """Public-key matched live counters; never return keys or infer physical devices."""
    now=int(time.time() if now is None else now);result=[]
    accounts={u['public']:u for u in state['users'] if u.get('enabled',True)}
    for line in dump.splitlines()[1:]:
        cells=line.split('\t')
        if len(cells)!=8 or cells[0] not in accounts:continue
        try:handshake,received,sent=(int(cells[i]) for i in (4,5,6))
        except ValueError:continue
        if min(handshake,received,sent)<0 or max(received,sent)>(1<<63)-1:continue
        user=accounts[cells[0]]
        result.append(dict(user=user['login'],upload=received,download=sent,
            recent=0<handshake<=now and now-handshake<=180,handshake=handshake,
            vpn_addresses=[user['address']],counter_scope='current server interface'))
    return result

def health(state):
    if state['protocol'] in model.ADDITIONAL and state['protocol']!='xhttp':
        import routes
        return routes.health(state,__import__(__name__))
    if state['protocol'] in ('xray','xhttp'):running=subprocess.run(['systemctl','is-active','--quiet','rookstride-single-'+state['protocol']]).returncode==0
    else:
        value=check_container(state);running=bool(value and value['State']['Running'])
        if running and state['protocol']=='awg':
            try:
                port=command(['docker','exec',container('awg'),'awg','show','rsawg0','listen-port'])
                peers=command(['docker','exec',container('awg'),'awg','show','rsawg0','peers']).splitlines()
                running=port=='51820' and len(peers)==sum(bool(u.get('enabled',True)) for u in state['users'])
            except ValueError:running=False
    dns={'installed':True,'remote':True,'running':None,'scope':'exit server'} if state.get('pair_dns') else filtering.inspect() if state.get('filtering') else {'installed':False,'running':False}
    users=[{'login':u['login'],'person':u.get('person',u['login']),'device':u.get('device',u['login']),'kind':'device','enabled':u.get('enabled',True)} for u in state['users']]
    connections=[];monitoring=False
    if state['protocol']=='openvpn' and running:
        try:
            import openvpn_metrics
            connections=openvpn_metrics.read(state,value,__import__(__name__));monitoring=True
        except (OSError,ValueError,KeyError,TypeError):pass
    if state['protocol'] in ('xray','xhttp') and running and state.get('metrics_port'):
        try:
            data=json.loads(command([str(ROOT/'bin/xray'),'api','statsquery','--server=127.0.0.1:'+str(state['metrics_port']),'-pattern','user>>>'],timeout=5))
            values={s['name']:int(s.get('value',0)) for s in data.get('stat',[])}
            generation=command(['systemctl','show','--property=InvocationID','--value','rookstride-single-'+state['protocol']])
            connections=[{'user':u['login'],'upload':values.get('user>>>'+u['login']+'>>>traffic>>>uplink',0),'download':values.get('user>>>'+u['login']+'>>>traffic>>>downlink',0),'recent':False,'counter_scope':'current server daemon','generation':generation,'vpn_addresses':[]} for u in state['users']]
            monitoring=True
        except (ValueError,OSError,KeyError,TypeError):pass
    if state['protocol']=='awg' and running:
        try:
            dump=command(['docker','exec',container('awg'),'awg','show','rsawg0','dump'])
            if dump and len(dump.splitlines()[0].split('\t'))>=4:
                connections=awg_connections(state,dump)
                started=value['State']['StartedAt'];generation=hashlib.sha256((state['instance']+':'+started).encode()).hexdigest()
                for row in connections:row['generation']=generation
                monitoring=True
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):connections=[]
    return {'protocol':state['protocol'],'instance':state.get('instance',''),'port':state.get('port',model.PROTOCOLS[state['protocol']]['port']),'running':running,'services':{'protocol':running,'adguard':dns['running']},'users':users,'connections':connections,
            'filtering':dns,'monitoring_available':monitoring,'statistics_kind':'sessions' if state['protocol']=='openvpn' else 'traffic' if state['protocol'] in ('xray','xhttp') else 'handshake','statistics_scope':'active-sessions' if state['protocol']=='openvpn' else 'daemon','recent_peers':sum(c['recent'] for c in connections),'statistics_enabled':False,'edit_users':True,'capabilities':{'profiles':True,'users':True,'disconnect':False,'adguard':bool(state.get('filtering'))},'client':model.PROTOCOLS[state['protocol']]['client'],'access_mode':state.get('access_mode','profile'),'password_policy':access.policy() if access.reusable(state) else None,'manual_sign_in':access.reusable(state),'account_updates':user_updates.impact(state),'coexist_pair':coexist_pair(state)}

def profile(state,login):
    user=next((u for u in state['users'] if u['login']==(access.login if access.reusable(state) else model.label)(login)),None)
    if not user or not user.get('enabled',True):raise ValueError('Login is not available')
    protocol=state['protocol']
    if protocol=='openvpn' and access.reusable(state):return {'format':'openvpn','name':'rookstride-'+re.sub(r'[^A-Za-z0-9_-]','_',login)+'.ovpn','content':model.openvpn_password_client(state,public_tls.roots()),'client':'Rookstride','access_mode':'password','server':state['server'],'server_name':state['tls_name'],'port':state['port'],'login':login}
    if protocol in model.ADDITIONAL and protocol!='xhttp':
        import routes
        return routes.profile(state,user,__import__(__name__))
    if protocol=='awg':text=model.awg_client(state,user);extension='conf'
    elif protocol in ('xray','xhttp'):text=model.xray_uri(state,user);extension='txt'
    else:
        p=directory(protocol)/'runtime'
        cert=(p/'pki/issued'/ (login+'.crt')).read_text();cert=cert[cert.index('-----BEGIN CERTIFICATE-----'):]
        text=model.openvpn_client(state,user,(p/'pki/ca.crt').read_text(),cert,(p/'pki/private'/(login+'.key')).read_text(),(p/'tls-crypt.key').read_text());extension='ovpn'
    name='rookstride-'+login+'.'+extension
    if protocol=='awg':name='rook-'+hashlib.sha256((state['public']+':'+user['public']).encode()).hexdigest()[:10]+'.conf'
    return {'format':protocol,'name':name,'content':text,'client':model.PROTOCOLS[protocol]['client']}

def edit_user(state,req):
    user=next((u for u in state['users'] if u['login']==(access.login if access.reusable(state) else model.label)(req.get('login'))),None)
    if not user:raise ValueError('Login not found')
    # This is a partial update. Validate every supplied field before changing
    # either the in-memory identity or the saved account, including when a
    # password and display labels are submitted together.
    updates={key:model.display_label(req[key]) for key in ('person','device') if key in req}
    if 'password' in req:
        if not access.reusable(state):raise ValueError('This connection uses a generated device key')
        if state['protocol']=='openvpn':updates['password_hash']=access.hash_password(req['password'])
        else:updates['password']=access.password(req['password'])
    if not updates:return {'edited':False,'login':user['login'],**user_updates.result()}
    user.update(updates)
    if 'password' in req:
        save(state);outcome=apply_config(state)
        if state['protocol']=='openvpn':outcome=user_updates.merge(outcome,disconnect_password_user(state,user['login']))
        return {'edited':True,'login':user['login'],**(outcome or {})}
    save(state)
    return {'edited':True,'login':user['login'],**user_updates.result()}

def remove_user(state,login):
    user=next((u for u in state['users'] if u['login']==(access.login if access.reusable(state) else model.label)(login)),None)
    if not user:raise ValueError('Login not found')
    if state['protocol']=='openvpn' and not access.reusable(state):
        state.setdefault('revoked',[]).append(login)
        command(['docker','run','--rm','--mount','type=bind,source='+str(directory('openvpn')/'runtime')+',target=/vpn','rookstride-openvpn:1','revoke',login],timeout=180)
    state['users']=[u for u in state['users'] if u['login']!=login];save(state)
    # The already-loaded CA accepts new certificates; the CRL is re-read by
    # OpenVPN on authentication. Terminate only the revoked common name when
    # its owned listener and root-local management socket are available.
    if state['protocol']=='openvpn' and not access.reusable(state):
        existing=check_container(state)
        if existing and existing.get('State',{}).get('Running'):
            outcome=disconnect_password_user(state,login)
        else:outcome=apply_config(state)
    else:
        outcome=apply_config(state)
        if state['protocol']=='openvpn':outcome=user_updates.merge(outcome,disconnect_password_user(state,login))
    return {'removed':True,**(outcome or {})}


def password_timer(state):
    import routes
    routes.certificate_timer(state,__import__(__name__))

def renew_password_certificate(state):
    if state['protocol']!='openvpn' or not access.reusable(state):raise ValueError('No password-based OpenVPN installation')
    previous=state.get('public_tls',{}).get('sha256');state['public_tls']=public_tls.ensure(state['server'])
    if previous!=state['public_tls']['sha256']:apply_config(state)
    save(state)

def disconnect_password_user(state,login):
    # Historical name retained for callers; certificate and password accounts
    # both identify their own sessions by the validated common name.
    (access.login if access.reusable(state) else model.label)(login)
    try:return user_updates.terminate(state,login,__import__(__name__))
    except (OSError,ValueError):
        # Revocation must terminate existing sessions even on old installations
        # without the management socket. Report this interruption explicitly.
        command(['docker','restart',container('openvpn')])
        return user_updates.result(True)
