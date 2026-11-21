"""Owned IKEv2/AWG entry with an independently authenticated exit transport.

Only reviewed routes are enabled. Client packets keep their source until the
host's guarded routing table; encrypted entry replies keep the normal uplink.
"""
import base64,hashlib,ipaddress,json,os,re,secrets,shutil,socket,struct,subprocess,sys,time,uuid
from pathlib import Path
import pair,ike_packages
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
import runtime,model,filtering
from urllib.parse import urlsplit,parse_qs

BRIDGE='rookstride-pair-bridge'
INTERFACE='awg-exit'
UNIT=Path('/etc/systemd/system')
IKE_CREDENTIALS=Path('/etc/swanctl/rookstride-pair')
IKE_SOCKET=Path('/run/charon.vici')
IKE_SHARED=Path('/etc/strongswan.d/rookstride-pair.conf')
IKE_DROP=Path('/etc/systemd/system/strongswan-starter.service.d/rookstride-pair-native.conf')
IKE_NETWORK=Path('/etc/single-vps-vpn/network.env')

def initial():return json.loads((pair.OWN/'initial-user.json').read_text())
def modern(p):return pair.native_plan(p)
_diagnostic=None
def command(args,data=None,timeout=120):
    # Only package/image preparation is recorded; never profile/key commands.
    safe=args[0]=='apt-get' or args[:2]==['docker','build']
    if not safe:return runtime.command(args,data,timeout)
    if args[0]=='apt-get':args=[args[0],'-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3']+args[1:]
    result=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if _diagnostic is not None:
        _diagnostic.write(result.stdout[-16000:]+result.stderr[-16000:]);_diagnostic.flush()
    if result.returncode:raise ValueError('VPN component preparation failed. Check package/image downloads and free disk space, then check and resume. Private server diagnostics record the cause.')
    return result.stdout.strip()
def material(p):
    user=initial();protocol=p['exit_protocol']
    if p['role']!='exit':return {}
    if protocol!='ikev2':
        state=runtime.load(protocol);profile=runtime.profile(state,user['login']);dns=filtering.load()
        value={'profile':profile,'dns':{'address':dns['address'],'dns_port':53 if model.proxy_protocol(protocol) else dns['dns_port']}}
    elif p['exit_protocol']=='ikev2':
        cert=Path('/etc/ipsec.d/certs/server-cert.pem')
        config=Path('/etc/ipsec.conf').read_text();name=re.search(r'^\s*leftcert\s*=\s*(\S+)',config,re.M)
        if not name or '/' in name[1]:raise ValueError('Unexpected IKEv2 certificate path')
        cert=Path('/etc/ipsec.d/certs')/name[1]
        env=dict(line.split('=',1) for line in Path('/etc/single-vps-vpn/network.env').read_text().splitlines() if '=' in line)
        value={'profile':{'server':p['exit_host'],'identity':p['exit_host'],'certificate':base64.b64encode(__import__('ssl').PEM_cert_to_DER_cert(cert.read_text())).decode(),'login':user['login'],'password':user['password']},'dns':{'address':env.get('DNS_IP','10.254.0.1'),'dns_port':53}}
    return dict(value,protocol=protocol,endpoint=p['exit_host'])

def validate_material(p,value):
    if p['role']=='exit':
        if value is not None:raise ValueError('Exit configuration does not accept another node profile')
        return
    if not isinstance(value,dict) or value.get('protocol')!=p['exit_protocol'] or value.get('endpoint')!=p['exit_host']:raise ValueError('Exit profile does not match the reviewed route')
    dns=value.get('dns',{});address=ipaddress.ip_address(dns.get('address',''))
    if address.version!=4 or not address.is_private or type(dns.get('dns_port')) is not int or not 1<=dns['dns_port']<=65535:raise ValueError('Invalid private exit DNS')
    profile=value.get('profile')
    if not isinstance(profile,dict):raise ValueError('Missing exit connection')
    if p['exit_protocol']=='awg':
        content=profile.get('content','')
        if not isinstance(content,str) or len(content)>8192 or '[Interface]' not in content or '[Peer]' not in content:raise ValueError('Invalid exit AWG connection')
        if re.search(r'^\s*(?:PreUp|PostUp|PreDown|PostDown|SaveConfig|Table)\s*=',content,re.M|re.I):raise ValueError('Executable directives are not allowed in an exit profile')
        endpoint=re.search(r'^Endpoint\s*=\s*(\S+)',content,re.M)
        if not endpoint or endpoint[1]!=p['exit_host']+':'+str(p['tunnel_port']):raise ValueError('Exit endpoint changed')
        sections=[];fields={};section=''
        for line in content.splitlines():
            line=line.strip()
            if not line or line.startswith('#'):continue
            if line.startswith('['):
                if line not in ('[Interface]','[Peer]') or line in sections:raise ValueError('Exit profile must contain exactly one interface and peer')
                sections.append(line);section=line;continue
            if '=' not in line or not section:raise ValueError('Invalid exit profile field')
            name,item=(x.strip() for x in line.split('=',1));token=(section,name.lower())
            if token in fields:raise ValueError('Duplicate exit profile field')
            fields[token]=item
        if sections!=['[Interface]','[Peer]']:raise ValueError('Invalid exit profile sections')
        for token in [('[Interface]','privatekey'),('[Peer]','publickey'),('[Peer]','presharedkey')]:pair.key(fields.get(token))
        if fields.get(('[Peer]','allowedips'))!='0.0.0.0/0, ::/0':raise ValueError('The exit profile must carry the full VPN route')
    elif p['exit_protocol']=='ikev2':
        if profile.get('server')!=p['exit_host'] or profile.get('identity')!=p['exit_host']:raise ValueError('IKEv2 exit identity changed')
        pair.host(profile['server']);model.label(profile.get('login'));pair.vpn_password(profile.get('password'))
        try:
            certificate=base64.b64decode(profile['certificate'],validate=True)
            if not 100<len(certificate)<8192:raise ValueError()
        except (ValueError,KeyError,TypeError):raise ValueError('Invalid pinned exit certificate')
    elif p['exit_protocol']=='openvpn':openvpn_profile(p,profile)
    elif p['exit_protocol'] in ('xray','xhttp'):xray_outbound(p,profile)
    else:
        import routes
        if profile.get('format')!=p['exit_protocol']:raise ValueError('Exit profile format changed')
        try:content=json.loads(profile.get('content',''))
        except (ValueError,TypeError):raise ValueError('Invalid exit connection') from None
        routes.validate_profile(content)
        if content['protocol']!=p['exit_protocol'] or content['server']!=p['exit_host'] or content['port']!=p['tunnel_port']:raise ValueError('Exit connection identity changed')

def openvpn_profile(p,profile):
    """Parse only this installer's export. No remote options, scripts or paths execute."""
    content=profile.get('content','')
    if not isinstance(content,str) or not 500<len(content)<32768:raise ValueError('Invalid OpenVPN exit profile')
    blocks={};outside=content
    for name in ('ca','cert','key','tls-crypt'):
        matches=re.findall(r'<'+name+r'>\n(.*?)\n</'+name+r'>',content,re.S)
        if len(matches)!=1:raise ValueError('Missing or duplicate OpenVPN inline credentials')
        blocks[name]=matches[0];outside=outside.replace('<'+name+'>\n'+matches[0]+'\n</'+name+'>','')
    expected=['client','dev tun','tun-mtu 1280','proto tcp-client','remote '+p['exit_host']+' '+str(p['tunnel_port']),'nobind','persist-key','persist-tun','remote-cert-tls server','verify-x509-name server name','tls-version-min 1.2','data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM','redirect-gateway def1 ipv6','block-ipv6','verb 3']
    if outside.strip().splitlines()!=expected:raise ValueError('Unexpected OpenVPN exit options')
    for name,body in blocks.items():
        if not re.fullmatch(r'[A-Za-z0-9+/=\s:.,()#_\-]+',body):raise ValueError('Invalid inline OpenVPN credentials')
    return '\n'.join(line for line in expected if not line.startswith(('dev ','redirect-gateway','block-ipv6')))+'\ndev '+INTERFACE+'\ndev-type tun\nroute-nopull\nroute-noexec\npull-filter ignore "redirect-gateway"\npull-filter ignore "block-ipv6"\npull-filter ignore "dhcp-option"\n'+''.join('<'+name+'>\n'+body+'\n</'+name+'>\n' for name,body in blocks.items())

def xray_outbound(p,profile):
    content=profile.get('content','')
    if not isinstance(content,str) or len(content)>8192:raise ValueError('Invalid Xray exit profile')
    url=urlsplit(content);query=parse_qs(url.query,strict_parsing=True,keep_blank_values=True)
    allowed={'encryption':'none','security':'reality','type':'tcp','flow':'xtls-rprx-vision','fp':'chrome'}
    if p['exit_protocol']=='xhttp':allowed.update(type='xhttp',flow='',mode='auto')
    extras={'path'} if p['exit_protocol']=='xhttp' else set()
    if url.scheme!='vless' or url.hostname!=p['exit_host'] or url.port!=p['tunnel_port'] or url.password or url.path or set(query)!=set(allowed)|{'sni','pbk','sid'}|extras or any(len(v)!=1 for v in query.values()) or any(query[k][0]!=v for k,v in allowed.items()):raise ValueError('Xray exit identity or options changed')
    identity=str(uuid.UUID(url.username or ''));sni=model.hostname(query['sni'][0]);public=query['pbk'][0];sid=query['sid'][0]
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',public) or len(base64.urlsafe_b64decode(public+'='))!=32 or not re.fullmatch(r'[0-9a-f]{16}',sid):raise ValueError('Invalid REALITY exit keys')
    result={'tag':'exit','protocol':'vless','settings':{'vnext':[{'address':p['exit_host'],'port':p['tunnel_port'],'users':[{'id':identity,'encryption':'none','flow':'xtls-rprx-vision'}]}]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':sni,'fingerprint':'chrome','publicKey':public,'shortId':sid,'spiderX':'/'}}}
    if p['exit_protocol']=='xhttp':
        if not re.fullmatch('/[a-f0-9]{48}',query['path'][0]):raise ValueError('Invalid XHTTP path')
        result['settings']['vnext'][0]['users'][0].pop('flow');result['streamSettings'].update(network='xhttp',xhttpSettings={'path':query['path'][0],'mode':'auto'})
    return result

def unit(name,content):
    path=UNIT/(name+'.service');pair.protected(path);m=pair.load_manifest();expected=hashlib.sha256(content.encode()).hexdigest()
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() not in (m.get('unit_hashes',{}).get(name),expected):raise ValueError('An owned route service was changed; refusing to replace or execute it')
    pair.atomic(path,content);path.chmod(0o644);m.setdefault('unit_hashes',{})[name]=expected;pair.write_manifest(m)

def network(action):
    from native_routing import apply
    return apply(action)

def start_bridge():
    # A failed configure may leave a live daemon with an exhausted handshake.
    # Restart only this owned bridge while entry forwarding is still guarded.
    command(['systemctl','daemon-reload']);command(['systemctl','enable',BRIDGE]);command(['systemctl','restart',BRIDGE])

def bootstrap(p,job,log):
    global _diagnostic
    _diagnostic=log
    if p['client_pool']!='10.66.0.0/24':raise ValueError('This route requires the reserved entry client pool')
    if p['role']=='entry':
        pair.job_state(job,state='running',phase='Preparing the guarded entry network')
        command(['apt-get','update'],timeout=600);command(['apt-get','install','-y','iproute2','iptables','curl','dnsutils'],timeout=1200)
        network('quiesce')
        if p['entry_protocol'] in ('awg','openvpn') or p['exit_protocol'] in ('awg','openvpn'):
            runtime.docker_ready()
        if p['entry_protocol']=='awg' or p['exit_protocol']=='awg':command(['docker','build','-t','rookstride-awg:1','-f',str(pair.RELEASE/'single/Dockerfile.awg'),str(pair.RELEASE/'single')],timeout=900)
        if 'openvpn' in (p['entry_protocol'],p['exit_protocol']):command(['docker','build','-t','rookstride-openvpn:1','-f',str(pair.RELEASE/'single/Dockerfile.openvpn'),str(pair.RELEASE/'single')],timeout=1200)
        if set(('xray','xhttp'))&{p['entry_protocol'],p['exit_protocol']}:runtime.install_xray_binary()
        unit('rookstride-pair-routing',f'''[Unit]\nDescription=Rookstride two-server forwarding guard\nAfter=network-online.target\nWants=network-online.target\nBefore=docker.service strongswan-starter.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py boot\n[Install]\nWantedBy=multi-user.target\n''')
        command(['systemctl','daemon-reload']);command(['systemctl','enable','rookstride-pair-routing']);return True
    user=initial()
    if p['exit_protocol']!='ikev2':
        protocol=p['exit_protocol'];state={'protocol':protocol,'server':p['exit_host'],'port':p['tunnel_port'],'initialLogin':user['login'],'instance':uuid.uuid4().hex,'owner':'rookstride-single-v1','sni':'www.cloudflare.com','sni_auto':True}
        if not (runtime.directory(protocol)/'state.json').exists():runtime.install(state,lambda index,text:pair.job_state(job,state='running',phase=text))
        elif not runtime.health(runtime.load(protocol))['running']:raise ValueError('Incomplete exit VPN: review removal before retrying')
    else:
        if not IKE_NETWORK.exists():
            pair.job_state(job,state='running',phase='Installing the IKEv2 exit and private DNS')
            password=job/'vpn-password';pair.atomic(password,user['password']+'\n')
            try:
                pair.run(['bash',str(pair.RELEASE/'gateway/scripts/install.sh')],env=dict(os.environ,SERVER_ID=p['exit_host'],VPN_USER=user['login'],VPN_PASSWORD_FILE=str(password),IKE_OWNER_HASH_FILE=str(pair.OWN/'ike-files.sha256')),stdout=log,stderr=log)
            finally:password.unlink(missing_ok=True)
        else:
            if not (pair.OWN/'ike-files.sha256').is_file():raise ValueError('Incomplete IKEv2 ownership record. Review this node’s managed removal before installing again.')
            command(['sha256sum','--check','--status',str(pair.OWN/'ike-files.sha256')])
            pair.run(['bash',str(pair.RELEASE/'gateway/scripts/verify.sh')],stdout=log,stderr=log)
        pair.job_state(job,state='running',phase='Adding private exit management')
        pair.run(['bash',str(pair.RELEASE/'server/enroll.sh')],env=dict(os.environ,ROOKSTRIDE_STATS='true'),stdout=log,stderr=log)
    return True

def awg_bridge(p,value):
    folder=pair.OWN/'bridge';folder.mkdir(mode=0o700,exist_ok=True)
    text=value['profile']['content'];address=re.search(r'^Address\s*=\s*([^,\s]+)',text,re.M)
    if not address:raise ValueError('Exit connection has no private address')
    vip=str(ipaddress.ip_interface(address[1]).ip)
    text=re.sub(r'^DNS\s*=.*\n','',text,flags=re.M);text=text.replace('[Interface]','[Interface]\nTable = off',1)
    pair.atomic(folder/'awg-exit.conf',text)
    script=pair.RELEASE/'server/native-bridge-awg.sh'
    unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned AWG exit connection\nAfter=docker.service rookstride-pair-routing.service network-online.target\nRequires=docker.service rookstride-pair-routing.service\nPartOf=docker.service\n[Service]\nExecStartPre=-/usr/bin/docker rm -f {BRIDGE}\nExecStart=/usr/bin/docker run --rm --name {BRIDGE} --label io.rookstride.pair={p['pair']} --network host --cap-add NET_ADMIN --device /dev/net/tun --mount type=bind,source={folder},target=/vpn,readonly --mount type=bind,source={script},target=/bridge.sh,readonly --entrypoint /bin/bash rookstride-awg:1 /bridge.sh\nExecStop=/usr/bin/docker stop {BRIDGE}\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target docker.service\n''')
    start_bridge()
    for _ in range(100):
        if subprocess.run(['ip','link','show',INTERFACE],capture_output=True).returncode==0:return vip
        time.sleep(.2)
    raise ValueError('AWG exit interface did not become ready')

def ike_bridge(p,value):
    profile=value['profile'];folder=IKE_CREDENTIALS
    # An owned daemon/configuration preserves host DNS. Use the root-only VICI
    # path already permitted by Ubuntu’s swanctl AppArmor policy.
    shared=p['entry_protocol']=='ikev2'
    command(['apt-get','update'],timeout=600)
    ike_packages.install('starter' if shared else 'systemd',['strongswan-swanctl','libcharon-extra-plugins','libstrongswan-extra-plugins'])
    for service in (() if shared else ('strongswan','strongswan-starter')):
        subprocess.run(['systemctl','disable','--now',service],capture_output=True,timeout=40)
        if subprocess.run(['systemctl','is-active','--quiet',service],capture_output=True).returncode==0:raise ValueError('Another IKEv2 daemon could not be stopped')
    pair.protected(folder);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    certificate=base64.b64decode(profile['certificate'],validate=True);pair.atomic(folder/'exit.pem',__import__('ssl').DER_cert_to_PEM_cert(certificate))
    # Certificate pinning is explicit via the exact exported end-entity cert.
    config=f'''connections {{
 route-exit {{
  version = 2
  remote_addrs = {profile['server']}
  vips = 0.0.0.0
  proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048
  encap = yes
  dpd_delay = 20s
  local {{
   auth = eap-mschapv2
   id = {profile['login']}
   eap_id = {profile['login']}
  }}
  remote {{
   auth = pubkey
   id = {profile['identity']}
   certs = {folder}/exit.pem
  }}
  children {{
   route-exit {{
    remote_ts = 0.0.0.0/0
    if_id_in = 42
    if_id_out = 42
    start_action = none
    dpd_action = restart
    close_action = start
    esp_proposals = aes256gcm16,aes256-sha256
   }}
  }}
 }}
}}
secrets {{
 eap-route {{
  id = {profile['login']}
  secret = {json.dumps(profile['password'],ensure_ascii=False)}
 }}
}}
'''
    pair.atomic(folder/'swanctl.conf',config)
    if shared:
        unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned IKEv2 exit in the entry daemon\nAfter=strongswan-starter.service rookstride-pair-routing.service network-online.target\nRequires=strongswan-starter.service rookstride-pair-routing.service\nPartOf=strongswan-starter.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStartPre=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py xfrm\nExecStart=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py ike-load\nExecStop=-/usr/sbin/swanctl --terminate --ike route-exit --timeout 5 --uri unix://{IKE_SOCKET}\n[Install]\nWantedBy=multi-user.target strongswan-starter.service\n''')
        start_bridge();return wait_ike_vip()
    strong=f'''charon-systemd {{\n load_modular = yes\n install_routes = no\n plugins {{\n include /etc/strongswan.d/charon/*.conf\n resolve {{\n load = no\n }}\n vici {{\n socket = unix://{IKE_SOCKET}\n }}\n }}\n}}\n''';pair.atomic(folder/'strongswan.conf',strong)
    files=command(['dpkg-query','-L','charon-systemd']).splitlines()
    binaries=[path for path in files if path.startswith('/usr/') and Path(path).name=='charon-systemd' and Path(path).is_file() and os.access(path,os.X_OK)]
    if len(binaries)!=1:raise ValueError('The packaged IKEv2 client binary could not be identified')
    daemon=binaries[0]
    unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned IKEv2 exit connection\nAfter=network-online.target rookstride-pair-routing.service\nRequires=rookstride-pair-routing.service\n[Service]\nEnvironment=STRONGSWAN_CONF={folder}/strongswan.conf\nExecStartPre=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py xfrm\nExecStart={daemon}\nExecStartPost=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py ike-load\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n''')
    start_bridge();return wait_ike_vip()

def ike_vip():
    from rookstride.vici import Vici
    with Vici(str(IKE_SOCKET)) as v:
        for result in v.request('list-sas',event='list-sa'):
            for ike in result.values():
                if not isinstance(ike,dict) or ike.get('state')!='ESTABLISHED':continue
                if not any(c.get('state')=='INSTALLED' for c in ike.get('child-sas',{}).values()):continue
                for address in ike.get('local-vips',[]):
                    if ipaddress.ip_address(address).version==4:return address
    return ''

def wait_ike_vip():
    for _ in range(60):
        try:
            vip=ike_vip()
            if vip:return vip
        except (OSError,RuntimeError):pass
        time.sleep(1)
    raise ValueError('The entry could not authenticate to the IKEv2 exit')

def interface_vip():
    value=subprocess.run(['ip','-j','-4','address','show','dev',INTERFACE],capture_output=True,text=True)
    if value.returncode:return ''
    return next((a['local'] for row in json.loads(value.stdout) for a in row.get('addr_info',[]) if a.get('family')=='inet'),'')

def packet_bridge(p,value):
    folder=pair.OWN/'bridge';folder.mkdir(mode=0o700,exist_ok=True)
    if p['exit_protocol']=='openvpn':
        pair.atomic(folder/'client.ovpn',openvpn_profile(p,value['profile']))
        unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned OpenVPN exit connection\nAfter=docker.service rookstride-pair-routing.service network-online.target\nRequires=docker.service rookstride-pair-routing.service\nPartOf=docker.service\n[Service]\nExecStartPre=-/usr/bin/docker rm -f {BRIDGE}\nExecStart=/usr/bin/docker run --rm --name {BRIDGE} --label io.rookstride.pair={p['pair']} --network host --cap-add NET_ADMIN --device /dev/net/tun --mount type=bind,source={folder},target=/vpn,readonly --entrypoint /usr/sbin/openvpn rookstride-openvpn:1 --config /vpn/client.ovpn\nExecStop=/usr/bin/docker stop {BRIDGE}\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target docker.service\n''')
    elif p['exit_protocol'] in ('xray','xhttp'):
        outbound=xray_outbound(p,value['profile'])
        config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'bridge','protocol':'tun','settings':{'name':INTERFACE,'MTU':1280}}],'outbounds':[{'tag':'blocked','protocol':'blackhole'},outbound],'routing':{'rules':[{'type':'field','inboundTag':['bridge'],'network':'tcp,udp','outboundTag':'exit'}]}}
        pair.atomic(folder/'client.json',json.dumps(config));binary=runtime.ROOT/'bin/xray'
        command([str(binary),'run','-test','-config',str(folder/'client.json')])
        unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned Xray REALITY exit connection\nAfter=rookstride-pair-routing.service network-online.target\nRequires=rookstride-pair-routing.service\n[Service]\nExecStart={binary} run -config {folder}/client.json\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n''')
    else:
        import routes
        config=routes.client_config(json.loads(value['profile']['content']),0)
        config['box']['inbounds']=[{'type':'tun','tag':'bridge','interface_name':INTERFACE,'address':['10.69.0.2/30'],'mtu':1280,'auto_route':False,'stack':'gvisor'}]
        pair.atomic(folder/'worker.json',json.dumps(config));binary=routes.worker()
        features=json.loads(command([str(binary),'features']))
        if features.get('schema')!=1 or features.get('tun_gvisor') is not True:raise ValueError('The server VPN runtime lacks its two-server packet engine. Update Rookstride and redeploy.')
        unit(BRIDGE,f'''[Unit]\nDescription=Rookstride owned {p['exit_protocol']} exit connection\nAfter=rookstride-pair-routing.service network-online.target\nRequires=rookstride-pair-routing.service\n[Service]\nExecStart={binary} run {folder}/worker.json\nRestart=always\nRestartSec=3\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n''')
    start_bridge()
    for _ in range(120):
        if p['exit_protocol'] in ('xray','xhttp') and subprocess.run(['ip','link','show',INTERFACE],capture_output=True).returncode==0:
            command(['ip','address','replace','10.69.0.2/32','dev',INTERFACE]);command(['ip','link','set',INTERFACE,'mtu','1280','up'])
        vip=interface_vip()
        if vip:return vip
        time.sleep(.5)
    raise ValueError('The exit VPN interface did not become ready')

def owned_file(path,text):
    pair.protected(path);m=pair.load_manifest();digest=hashlib.sha256(text.encode()).hexdigest()
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() not in (m.get('file_hashes',{}).get(str(path)),digest):raise ValueError('An owned route configuration was changed')
    pair.atomic(path,text);m.setdefault('file_hashes',{})[str(path)]=digest;pair.write_manifest(m)

def ike_entry(p,value,job,log):
    # A shared daemon needs no automatic host routes: only the owned source table
    # carries phone traffic. Its inbound server and named outbound SA coexist.
    owned_file(IKE_SHARED,'charon {\n install_routes = no\n plugins {\n resolve {\n load = no\n }\n }\n}\n')
    IKE_DROP.parent.mkdir(exist_ok=True)
    owned_file(IKE_DROP,'[Unit]\nRequires=rookstride-pair-routing.service\nAfter=rookstride-pair-routing.service\n')
    user=initial()
    if not IKE_NETWORK.exists():
        password=job/'vpn-password';pair.atomic(password,user['password']+'\n')
        try:pair.run(['bash',str(pair.RELEASE/'gateway/scripts/install.sh')],env=dict(os.environ,SERVER_ID=p['server'],VPN_USER=user['login'],VPN_PASSWORD_FILE=str(password),CLIENT_POOL=p['client_pool'],DNS_IP=value['dns']['address'],ROOKSTRIDE_PAIR_ENTRY='YES',VPN_PORT=str(p['vpn_port']),IKE_OWNER_HASH_FILE=str(pair.OWN/'ike-files.sha256')),stdout=log,stderr=log)
        finally:password.unlink(missing_ok=True)
    else:
        if not (pair.OWN/'ike-files.sha256').is_file():raise ValueError('Incomplete IKEv2 ownership record. Review this node’s managed removal before installing again.')
        command(['sha256sum','--check','--status',str(pair.OWN/'ike-files.sha256')])
    pair.run(['bash',str(pair.RELEASE/'server/enroll.sh')],env=dict(os.environ,ROOKSTRIDE_STATS=str(user.get('statistics',False)).lower()),stdout=log,stderr=log)
    if p.get('access_mode')=='password':
        pair.job_state(job,state='running',phase='Preparing trusted entry sign-in')
        pair.run(['/usr/bin/python3','/opt/rookstride/server/ike_public.py','enable'],stdout=log,stderr=log)

def configure(p,req,job,log):
    global _diagnostic
    _diagnostic=log
    m=pair.require_owner(p)
    if m['configured']:return
    if p['role']=='exit':m['configured']=True;pair.write_manifest(m);return
    value=req.get('transport');validate_material(p,value);pair.atomic(pair.OWN/'transport.json',json.dumps(value))
    if p['entry_protocol']=='ikev2':ike_entry(p,value,job,log)
    vip=awg_bridge(p,value) if p['exit_protocol']=='awg' else ike_bridge(p,value) if p['exit_protocol']=='ikev2' else packet_bridge(p,value)
    m=pair.require_owner(p);m['bridge_ip']=vip;pair.write_manifest(m)
    user=initial();state={'protocol':p['entry_protocol'],'server':p['server'],'port':p['vpn_port'],'initialLogin':user['login'],'instance':uuid.uuid4().hex,'owner':'rookstride-single-v1','pair_dns':value['dns'],'pair':p['pair']}
    if p.get('access_mode')=='password':state.update(access_mode='password',initialPassword=user['password'])
    if p['entry_protocol']!='ikev2':
        protocol=p['entry_protocol'];state.update(sni='www.cloudflare.com',sni_auto=True)
        if not (runtime.directory(protocol)/'state.json').exists():runtime.install(state,lambda index,text:pair.job_state(job,state='running',phase=text))
        proxy=model.proxy_protocol(protocol);dependency='rookstride-single-'+protocol+'.service' if proxy else 'docker.service'
        unit('rookstride-pair-entry',f'''[Unit]\nDescription=Rookstride owned {protocol} entry\nAfter={dependency} rookstride-pair-routing.service {BRIDGE}.service\nRequires={dependency} rookstride-pair-routing.service\nPartOf={dependency}\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={'/usr/bin/systemctl start rookstride-single-'+protocol if proxy else '/usr/bin/docker start rookstride-single-'+protocol}\nExecStartPost=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py refresh\nExecStop={'/usr/bin/true' if proxy else '/usr/bin/docker stop rookstride-single-'+protocol}\n[Install]\nWantedBy=multi-user.target\n''')
    else:unit('rookstride-pair-entry',f'''[Unit]\nDescription=Rookstride owned IKEv2 entry\nAfter=strongswan-starter.service rookstride-pair-routing.service {BRIDGE}.service\nRequires=strongswan-starter.service rookstride-pair-routing.service\nPartOf=strongswan-starter.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py refresh\n[Install]\nWantedBy=multi-user.target strongswan-starter.service\n''')
    unit('rookstride-pair-watch',f'''[Unit]\nDescription=Rookstride owned route recovery\nAfter=rookstride-pair-entry.service\nRequires=rookstride-pair-routing.service\n[Service]\nExecStart=/usr/bin/python3 {pair.RELEASE}/server/native_routing.py watch\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target docker.service\n''')
    command(['systemctl','daemon-reload']);command(['systemctl','enable','--now','rookstride-pair-entry','rookstride-pair-watch']);network('refresh')
    m=pair.require_owner(p);m['configured']=True;pair.write_manifest(m)

def dns_answer(reply,identifier):
    if len(reply)<12:raise ValueError('Incomplete exit DNS reply')
    tx,flags,questions,answers,_,_=struct.unpack('!HHHHHH',reply[:12])
    if tx!=identifier or not flags&0x8000 or flags&0x200 or questions!=1:raise ValueError('Invalid exit DNS reply')
    offset=12
    def skip_name(position):
        while position<len(reply):
            size=reply[position];position+=1
            if size==0:return position
            if size&0xc0==0xc0:
                if position>=len(reply):break
                return position+1
            if size>63 or position+size>len(reply):break
            position+=size
        raise ValueError('Incomplete exit DNS name')
    offset=skip_name(offset)+4;addresses=[]
    for _ in range(answers):
        offset=skip_name(offset)
        if offset+10>len(reply):raise ValueError('Incomplete exit DNS answer')
        kind,klass,ttl,size=struct.unpack('!HHIH',reply[offset:offset+10]);offset+=10
        if offset+size>len(reply):raise ValueError('Incomplete exit DNS data')
        if kind==1 and klass==1 and size==4:addresses.append(str(ipaddress.IPv4Address(reply[offset:offset+size])))
        offset+=size
    return flags&15,addresses

def dns_check(p,value,blocking=True):
    for name,blocked in ([('example.com',False),('doubleclick.net',True)] if blocking else [('example.com',False)]):
        identifier=secrets.randbelow(65536);question=b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0\0\1\0\1'
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
            stream.settimeout(8);stream.bind((p['test_ip'],0));stream.connect((value['dns']['address'],value['dns']['dns_port']));stream.send(struct.pack('!HHHHHH',identifier,0x100,1,0,0,0)+question);reply=stream.recv(4096)
        code,addresses=dns_answer(reply,identifier)
        # Native filtering uses NXDOMAIN; the IKEv2 filter uses null-IP answers.
        good=(code==3 or code==0 and addresses and all(a=='0.0.0.0' for a in addresses)) if blocked else code==0 and addresses and all(not ipaddress.IPv4Address(a).is_unspecified for a in addresses)
        if not good:raise ValueError('Exit DNS did not pass allowed and blocked-domain checks')

def verify(p,req,activate=False):
    expected=str(ipaddress.IPv4Address(req.get('expected_exit_ip','')))
    value=json.loads((pair.OWN/'transport.json').read_text())
    for attempt in range(3):
        network('refresh')
        try:actual=command(['curl','-4','--curves','X25519','--interface',p['test_ip'],'--connect-timeout','10','--max-time','30','-fsS','https://api.ipify.org'])
        except (ValueError,OSError,subprocess.SubprocessError):
            if attempt==2:raise
            time.sleep(2);continue
        # A wrong exit is a route failure, never a startup delay to overlook.
        if actual!=expected:raise ValueError('The second hop did not use the expected exit address')
        try:
            if type(req.get('filtering_enabled',True)) is not bool:raise ValueError('Invalid filtering verification policy')
            dns_check(p,value,blocking=req.get('filtering_enabled',True))
        except (ValueError,OSError,subprocess.SubprocessError):
            if attempt==2:raise
            time.sleep(2);continue
        break
    m=pair.require_owner(p);m['verified']=True;pair.write_manifest(m)
    if activate:network('activate')

def dispatch(req,m):
    action=req.get('command');p=m['plan']
    if action=='material':return material(p)
    if action=='health':
        protocol=p['entry_protocol'] if p['role']=='entry' else p['exit_protocol']
        if protocol!='ikev2':return runtime.health(runtime.load(protocol))
        from rookstride.admin import health
        return health()
    if action=='overview':return {'role':p['role'],'configured':m['configured'],'activated':m.get('activated',False),'completed_at':m.get('first_activated_at',0),'exit_ip':command(['curl','-4','--curves','X25519','--connect-timeout','10','--max-time','20','-fsS','https://api.ipify.org']) if p['role']=='exit' and m['configured'] else '','jobs':{k:pair.status(v) for k,v in m['jobs'].items()}}
    if action=='pause' and p['role']=='entry':network('quiesce');return {'paused':True}
    raise ValueError('Unsupported two-server command')
