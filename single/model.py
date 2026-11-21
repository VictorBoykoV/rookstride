"""Validated single-server protocol configuration; no shell interpolation."""
import base64
import ipaddress
import re
import secrets
import access
from urllib.parse import urlencode, quote

PROTOCOLS={'awg':{'name':'AmneziaWG 3.1','port':51820,'transport':'udp','client':'AmneziaWG'},
           'xray':{'name':'VLESS · REALITY (TCP)','port':443,'transport':'tcp','client':'v2rayNG'},
           'openvpn':{'name':'OpenVPN','port':1194,'transport':'tcp','client':'OpenVPN for Android'}}
ADDITIONAL=('xhttp','hysteria2','outline','shadowsocks','trusttunnel','naive')
for _id,_name,_transport in [('xhttp','VLESS · XHTTP / REALITY','tcp'),('hysteria2','Hysteria 2','udp'),
    ('outline','Outline · Shadowsocks / WSS','tcp'),('shadowsocks','Shadowsocks · v2ray-plugin / WSS','tcp'),
    ('trusttunnel','TrustTunnel · HTTP/2','tcp'),('naive','NaïveProxy · HTTP/2','tcp')]:
    PROTOCOLS[_id]={'name':_name,'port':443,'transport':_transport,'client':'Rookstride'}

def proxy_protocol(protocol):return protocol in ('xray','xhttp',*ADDITIONAL)

def hostname(value):
    if not isinstance(value,str) or len(value)>253 or not value or value!=value.strip():raise ValueError('Enter a server address')
    try:ipaddress.IPv4Address(value);return value
    except ValueError:pass
    if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',part) for part in value.split('.')):raise ValueError('Invalid hostname')
    return value

def label(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}',value):raise ValueError('Use letters, numbers, dashes or underscores for the login')
    return value

def display_label(value):
    if not isinstance(value,str) or not 1<=len(value)<=80 or any(ord(c)<32 or 127<=ord(c)<=159 or 0xd800<=ord(c)<=0xdfff for c in value):raise ValueError('Use a name of 1–80 printable characters')
    return value

def validate(req):
    protocol=req.get('protocol')
    if protocol not in PROTOCOLS:raise ValueError('Unsupported single-server protocol')
    host=hostname(req.get('server'))
    port=req.get('port',PROTOCOLS[protocol]['port'])
    if not isinstance(port,int) or isinstance(port,bool) or not 1<=port<=65535 or port==22:raise ValueError('Choose a VPN port other than SSH port 22')
    authentication=access.mode(req)
    login=(access.login if authentication=='password' else label)(req.get('login','this-phone'))
    sni=hostname(req.get('sni','www.cloudflare.com'))
    config=dict(protocol=protocol,server=host,port=port,login=login,sni=sni)
    if authentication=='password' and protocol=='openvpn':
        import public_tls
        if len(public_tls.tls_name(host))>64:raise ValueError('OpenVPN username/password sign-in needs a VPN domain no longer than 64 characters')
    if authentication=='password':config.update(access_mode='password',password=access.password(req.get('password')))
    if protocol in ('xray','xhttp'):config['sni_auto']='sni' not in req
    return config

def free_port(protocol,listeners,ssh_port):
    """Pick from the server inventory; never replace an existing listener."""
    if not isinstance(ssh_port,int) or isinstance(ssh_port,bool) or not 1<=ssh_port<=65535:raise ValueError('Invalid SSH port')
    used={v['port'] for v in listeners if v['transport']==PROTOCOLS[protocol]['transport']}|{22,ssh_port}
    preferred={'awg':(51820,443,51821),'openvpn':(1194,443,1195)}.get(protocol,(443,8443,9443))
    for candidates in (preferred,range(20000,65536),range(1024,20000)):
        for port in candidates:
            if port not in used:return port
    raise ValueError('No free VPN port is available on this server')

def awg_parameters():
    return dict(Jc='5',Jmin='10',Jmax='50',S1='12',S2='12',S3='12',S4='12',H1='1',H2='2',H3='3',H4='4',
                HeaderProtectionKey=base64.b64encode(secrets.token_bytes(32)).decode(),ContentPaddingAddition='10-100',
                RekeyAfterTime='100-120',RekeyTimeout='3-7',RejectAfterTime='150-180',KeepaliveTimeout='5-15',
                MaxHandshakeAttempts='15-20',RandomTrailers='on',DisableCookies='off')

def awg_server(state):
    result='[Interface]\nPrivateKey = '+state['private']+'\nListenPort = 51820\n'
    result+=''.join(k+' = '+v+'\n' for k,v in state['parameters'].items())
    for user in state['users']:
        if not user.get('enabled',True):continue
        result+='\n[Peer]\nPublicKey = '+user['public']+'\nPresharedKey = '+user['psk']+'\nAllowedIPs = '+user['address']+'/32, '+user['ipv6']+'/128\n'
    return result

def awg_client(state,user):
    value='[Interface]\nPrivateKey = '+user['private']+'\nAddress = '+user['address']+'/32, '+user['ipv6']+'/128\nMTU = 1280\nDNS = 1.1.1.1, 9.9.9.9\n'
    value+=''.join(k+' = '+v+'\n' for k,v in state['parameters'].items())
    return value+'\n[Peer]\nPublicKey = '+state['public']+'\nPresharedKey = '+user['psk']+'\nEndpoint = '+state['server']+':'+str(state['port'])+'\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'

def xray_server(state,dns=None):
    clients=[dict(id=u['uuid'],email=u['login'],flow='xtls-rprx-vision') for u in state['users'] if u.get('enabled',True)]
    config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'phone','listen':'0.0.0.0','port':state['port'],'protocol':'vless',
      'settings':{'clients':clients,'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality',
      'realitySettings':{'show':False,'dest':state['sni']+':443','xver':0,'serverNames':[state['sni']],
      'privateKey':state['private'],'shortIds':[state['shortId']]}}}],
      'outbounds':[{'tag':'internet','protocol':'freedom','settings':{'domainStrategy':'UseIPv4'}},{'tag':'block','protocol':'blackhole'}],
      'routing':{'domainStrategy':'IPOnDemand','rules':[{'type':'field','ip':['10.0.0.0/8','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fc00::/7','fe80::/10'],'outboundTag':'block'}]}}
    if state.get('protocol')=='xhttp':
        stream=config['inbounds'][0]['streamSettings'];stream['network']='xhttp';stream['xhttpSettings']={'path':state['path'],'mode':'auto'}
        for user in clients:user.pop('flow',None)
    if state.get('metrics_port'):
        config.update(stats={},api={'tag':'private-statistics','services':['StatsService','HandlerService']},policy={'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}})
        config['inbounds'].append({'tag':'statistics','listen':'127.0.0.1','port':state['metrics_port'],'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}})
        config['routing']['rules'].insert(0,{'type':'field','inboundTag':['statistics'],'outboundTag':'private-statistics'})
    if dns:
        config['dns']={'servers':['tcp+local://'+dns['address']+':'+str(dns['dns_port'])],'queryStrategy':'UseIPv4'}
        config['outbounds'].append({'tag':'filtered-dns','protocol':'dns','settings':{'network':'tcp','address':dns['address'],'port':dns['dns_port']}})
        config['routing']['rules'].insert(0,{'type':'field','network':'tcp,udp','port':'53','outboundTag':'filtered-dns'})
        config['routing']['rules'].insert(1,{'type':'field','network':'tcp,udp','port':'853','outboundTag':'block'})
    if state.get('pair_dns'):
        # Every proxied connection binds to the owned source-policy address.
        # No unbound/default freedom outbound may bypass the bridge.
        dns=state['pair_dns'];source='10.66.0.1'
        internet={'tag':'pair-internet','protocol':'freedom','sendThrough':source,'settings':{'domainStrategy':'UseIPv4'}}
        redirected={'tag':'pair-dns','protocol':'freedom','sendThrough':source,'settings':{'domainStrategy':'UseIPv4','redirect':dns['address']+':'+str(dns['dns_port'])}}
        config['inbounds'][0]['tag']='phone'
        config['outbounds']=[{'tag':'block','protocol':'blackhole'},internet,redirected]
        config['dns']={'servers':['tcp://'+dns['address']+':'+str(dns['dns_port'])],'queryStrategy':'UseIPv4','tag':'pair-resolver'}
        config['routing']['domainStrategy']='AsIs'
        config['routing']['rules']=[{'type':'field','inboundTag':['pair-resolver'],'network':'tcp,udp','outboundTag':'pair-internet'},
          {'type':'field','inboundTag':['phone'],'network':'tcp,udp','port':'53','outboundTag':'pair-dns'},
          {'type':'field','network':'tcp,udp','port':'853','outboundTag':'block'},*config['routing']['rules'],
          {'type':'field','inboundTag':['phone'],'network':'tcp,udp','outboundTag':'pair-internet'}]
        if state.get('metrics_port'):config['routing']['rules'].insert(0,{'type':'field','inboundTag':['statistics'],'outboundTag':'private-statistics'})
    return config

def xray_uri(state,user):
    options={'encryption':'none','security':'reality','type':'tcp','flow':'xtls-rprx-vision','sni':state['sni'],'fp':'chrome','pbk':state['public'],'sid':state['shortId']}
    if state.get('protocol')=='xhttp':options.update(type='xhttp',flow='',path=state['path'],mode='auto')
    query=urlencode(options)
    return 'vless://'+user['uuid']+'@'+state['server']+':'+str(state['port'])+'?'+query+'#'+quote(user['login'])

def openvpn_server(state=None):
    if state and access.reusable(state):return openvpn_password_server(state)
    pool='10.66.0.0' if state and state.get('pair_dns') else '10.68.0.0'
    return '''port 1194
proto tcp-server
dev tun
tun-mtu 1280
topology subnet
server 10.68.0.0 255.255.255.0
server-ipv6 fd42:680::/64
push "redirect-gateway def1 ipv6"
push "block-ipv6"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 9.9.9.9"
ca /vpn/pki/ca.crt
cert /vpn/pki/issued/server.crt
key /vpn/pki/private/server.key
crl-verify /vpn/pki/crl.pem
management /vpn/management.sock unix
dh none
tls-crypt /vpn/tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
auth SHA256
keepalive 10 60
persist-key
persist-tun
status /vpn/status.csv 5
status-version 3
verb 3
'''.replace('server 10.68.0.0 ', 'server '+pool+' ')

def openvpn_client(state,user,ca,cert,key,tls):
    return 'client\ndev tun\ntun-mtu 1280\nproto tcp-client\nremote '+state['server']+' '+str(state['port'])+'''\nnobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
redirect-gateway def1 ipv6
block-ipv6
verb 3
'''+''.join('<'+n+'>\n'+v.strip()+'\n</'+n+'>\n' for n,v in [('ca',ca),('cert',cert),('key',key),('tls-crypt',tls)])


def openvpn_password_server(state):
    pool='10.66.0.0' if state.get('pair_dns') else '10.68.0.0'
    return '''port 1194
proto tcp-server
dev tun
tun-mtu 1280
topology subnet
server POOL 255.255.255.0
push "redirect-gateway def1"
push "block-ipv6"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 9.9.9.9"
cert /vpn/public-server.pem
key /vpn/public-server.key
ca /vpn/public-roots.pem
dh none
verify-client-cert none
username-as-common-name
duplicate-cn
script-security 2
auth-user-pass-verify /usr/local/bin/rookstride-openvpn-password via-file
management /vpn/management.sock unix
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
auth SHA256
keepalive 10 60
persist-key
persist-tun
status /vpn/status.csv 5
status-version 3
verb 3
'''.replace('POOL',pool)

def openvpn_password_client(state,roots):
    # The template contains no per-device certificate, private key or server leaf pin.
    return 'client\ndev tun\ntun-mtu 1280\nproto tcp-client\nremote '+state['server']+' '+str(state['port'])+'''\nnobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth-nocache
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
redirect-gateway def1 ipv6
block-ipv6
verb 3
'''+'verify-x509-name '+state.get('tls_name',state['server'])+' name\n<ca>\n'+roots.strip()+'\n</ca>\n'
