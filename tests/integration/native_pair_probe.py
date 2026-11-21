#!/usr/bin/env python3
"""Opt-in disposable-lab real client/outage probe. Never an installer.
JSON stdin: expected_exit, canary_url, canary_token. Run on the owned entry.
Private credentials and diagnostics stay in the root-only owned test directory.
"""
import ipaddress,json,os,re,socket,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/opt/rookstride-pair/server')
import pair,native_pair
runtime=native_pair.runtime
CLIENT='rookstride-pair-test-client'
def run(args,timeout=90,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError('QA operation failed: '+Path(args[0]).name)
 return p
def main():
 if os.geteuid()!=0 or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes':raise PermissionError('Explicit root disposable-lab scope required')
 request=json.loads(sys.stdin.buffer.read(8192));ipaddress.IPv4Address(request['expected_exit'])
 if not re.fullmatch(r'http://198\.18\.[0-9]{1,3}\.[0-9]{1,3}:18080/canary',request['canary_url']):raise ValueError('Use an exit-only benchmark-range canary')
 m=pair.load_manifest();p=m['plan']
 if m.get('version')!=2 or p['role']!='entry' or not m.get('activated'):raise ValueError('An activated owned native entry is required')
 if p['exit_protocol']=='ikev2' and not native_pair.ike_vip():raise RuntimeError('The IKEv2 bridge has no established CHILD_SA; an active service alone is insufficient')
 folder=pair.OWN/'client-test';folder.mkdir(mode=0o700,exist_ok=True);os.umask(0o077)
 checks={};protocol=p['entry_protocol'];runtime.docker_ready()
 if run(['docker','inspect',CLIENT],check=False).returncode==0:raise ValueError('Another QA client already exists')
 main_route=run(['ip','route','show','default','table','main']).stdout
 direct=run(['curl','--connect-timeout','2','--max-time','4','-fsS',request['canary_url']],check=False)
 checks['canary_not_on_entry_route']=direct.returncode!=0
 assert checks['canary_not_on_entry_route']
 if protocol=='awg':
  state=runtime.load('awg');text=runtime.profile(state,state['initialLogin'])['content'];vip=state['users'][0]['address'];advertised_dns=re.search(r'^DNS\s*=\s*([^,\s]+)',text,re.M)[1];runtime.atomic(folder/'client.conf','\n'.join(line for line in text.splitlines() if not line.startswith('DNS ='))+'\n')
  recipe='FROM rookstride-awg:1\nRUN apk add --no-cache curl bind-tools\n'
  script='''set -euo pipefail
amneziawg-go -f client &
for n in {1..100}; do [[ -S /var/run/amneziawg/client.sock ]] && break; sleep .1; done
awg-quick strip /lab/client.conf > /lab/wire.conf
awg setconf client /lab/wire.conf
ip address add VIP/32 dev client
ip -6 address add fd42:670::2/128 dev client
ip link set client mtu 1280 up
gateway=$(ip -4 route show default | awk '{print $3}')
ip route add ENDPOINT/32 via "$gateway" dev eth0
ip route replace default dev client
ip -6 route replace default dev client
touch /lab/ready
tail -f /dev/null
'''.replace('VIP',vip).replace('ENDPOINT',p['server'])
 elif protocol in ('openvpn','xray'):
  if run(['docker','image','inspect','rookstride-openvpn:1'],check=False).returncode:run(['docker','build','-t','rookstride-openvpn:1','-f',str(pair.RELEASE/'single/Dockerfile.openvpn'),str(pair.RELEASE/'single')],timeout=1200)
  recipe="FROM rookstride-openvpn:1\nRUN apt-get -o Acquire::Retries=3 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y curl dnsutils iproute2\n"
  state=runtime.load(protocol);advertised_dns='1.1.1.1';vip=''
  if protocol=='openvpn':
   runtime.atomic(folder/'client.ovpn',runtime.profile(state,state['initialLogin'])['content'])
   if state.get('access_mode')=='password':runtime.atomic(folder/'password',state['initialLogin']+'\n'+native_pair.initial()['password']+'\n')
   script="""set -euo pipefail
openvpn --config /lab/client.ovpn --log /lab/openvpn-client.log --daemon
for n in {1..200}; do
 if grep -F 'Initialization Sequence Completed' /lab/openvpn-client.log >/dev/null; then touch /lab/ready; break; fi
 sleep .2
done
[[ -f /lab/ready ]]
tail -f /dev/null
"""
   if state.get('access_mode')=='password':script=script.replace('openvpn --config /lab/client.ovpn','openvpn --config /lab/client.ovpn --auth-user-pass /lab/password')
  else:
   # Use the real exported VLESS/REALITY identity, with the same TUN contract
   # as the embedded client, isolated from the entry host's routing table.
   import base64,shutil
   user=next(u for u in state['users'] if u['login']==state['initialLogin']);uri=runtime.profile(state,user['login'])['content']
   outbound=native_pair.xray_outbound(dict(p,exit_host=p['server'],tunnel_port=p['vpn_port']),{'content':uri})
   config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'phone','protocol':'tun','settings':{'name':'client','MTU':1280}}],'outbounds':[{'tag':'blocked','protocol':'blackhole'},outbound],'routing':{'rules':[{'type':'field','inboundTag':['phone'],'network':'tcp,udp','outboundTag':'exit'}]}}
   runtime.atomic(folder/'xray.json',json.dumps(config));shutil.copy2(runtime.ROOT/'bin/xray',folder/'xray');(folder/'xray').chmod(0o700)
   vip='10.70.0.2'
   script="""set -euo pipefail
/lab/xray run -config /lab/xray.json > /lab/xray-client.log 2>&1 &
for n in {1..100}; do ip link show client >/dev/null 2>&1 && break; sleep .2; done
ip address add 10.70.0.2/32 dev client
ip link set client mtu 1280 up
gateway=$(ip -4 route show default | awk '{print $3}')
ip route add ENDPOINT/32 via "$gateway" dev eth0
ip route replace default dev client
ip -6 route replace default dev client
touch /lab/ready
tail -f /dev/null
""".replace('ENDPOINT',socket.gethostbyname(p['server']))
 else:
  if run(['docker','image','inspect','rookstride-openvpn:1'],check=False).returncode:run(['docker','build','-t','rookstride-openvpn:1','-f',str(pair.RELEASE/'single/Dockerfile.openvpn'),str(pair.RELEASE/'single')],timeout=1200)
  recipe="FROM rookstride-openvpn:1\nRUN apt-get -o Acquire::Retries=3 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y strongswan libcharon-extra-plugins libstrongswan-extra-plugins curl dnsutils iproute2\n"
  user=native_pair.initial();advertised_dns=re.search(r'^\s*rightdns\s*=\s*([^,\s]+)',Path('/etc/ipsec.conf').read_text(),re.M)[1];server_address=socket.gethostbyname(p['server']);server_identity=p['server'] if re.fullmatch(r'[0-9.]+',p['server']) else '@'+p['server'];runtime.atomic(folder/'ca.pem',Path('/etc/ipsec.d/cacerts/single-vps-ca.pem').read_text());runtime.atomic(folder/'ipsec.secrets',user['login']+' : EAP '+json.dumps(user['password'])+'\n')
  runtime.atomic(folder/'ipsec.conf','config setup\n uniqueids=never\nca qa\n cacert=/lab/ca.pem\n auto=add\nconn qa\n keyexchange=ikev2\n left=%defaultroute\n leftauth=eap-mschapv2\n leftid='+user['login']+'\n eap_identity='+user['login']+'\n leftsourceip=%config4,%config6\n right='+server_address+'\n rightid='+server_identity+'\n rightauth=pubkey\n rightsubnet=0.0.0.0/0,::/0\n rightikeport='+str(p['vpn_port'])+'\n dpddelay=10s\n dpdaction=restart\n auto=add\n')
  if p.get('access_mode')=='password':
   certificates=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',Path('/etc/ssl/certs/ca-certificates.crt').read_text(),re.S);authorities=folder/'cacerts';authorities.mkdir(mode=0o700,exist_ok=True)
   for number,certificate in enumerate(certificates):runtime.atomic(authorities/(str(number)+'.pem'),certificate+'\n',0o644)
   text=(folder/'ipsec.conf').read_text();text=text.replace('ca qa\n cacert=/lab/ca.pem\n auto=add\n','');runtime.atomic(folder/'ipsec.conf',text)
  runtime.atomic(folder/'strongswan.conf','charon {\n load_modular = yes\n plugins {\n include /etc/strongswan.d/charon/*.conf\n resolve { load = no }\n }\n}\n')
  script='''set -euo pipefail
cp /lab/ipsec.conf /etc/ipsec.conf
cp /lab/ipsec.secrets /etc/ipsec.secrets
cp /lab/strongswan.conf /etc/strongswan.conf
if [[ -d /lab/cacerts ]]; then cp /lab/cacerts/*.pem /etc/ipsec.d/cacerts/; fi
ipsec start
loaded=false
for n in {1..100}; do
 if ipsec statusall qa | grep -F "qa:" >/dev/null; then loaded=true; break; fi
 sleep .2
done
[[ $loaded == true ]]
ipsec up qa
ipsec status qa | grep -F ESTABLISHED >/dev/null
ipsec status qa | grep -F INSTALLED >/dev/null
touch /lab/ready
tail -f /dev/null
''';vip=''
 runtime.atomic(folder/'build/Dockerfile.qa',recipe);runtime.atomic(folder/'start.sh',script)
 run(['docker','build','-t','rookstride-qa-'+protocol+':1','-f',str(folder/'build/Dockerfile.qa'),str(folder/'build')],timeout=1200)
 (folder/'ready').unlink(missing_ok=True)
 try:
  run(['docker','run','-d','--name',CLIENT,'--label','io.rookstride.pair.test='+p['pair'],'--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv6.conf.all.disable_ipv6=0','--dns','1.1.1.1','--mount','type=bind,source='+str(folder)+',target=/lab','--entrypoint','/bin/bash','rookstride-qa-'+protocol+':1','/lab/start.sh'])
  for _ in range(100):
   if (folder/'ready').exists():break
   time.sleep(.5)
  else:raise RuntimeError('QA phone-side client did not authenticate')
  if protocol in ('ikev2','openvpn'):
   addresses=json.loads(run(['docker','exec',CLIENT,'ip','-j','-4','address']).stdout);vip=next(a['local'] for row in addresses for a in row.get('addr_info',[]) if ipaddress.ip_address(a['local']) in ipaddress.ip_network(p['client_pool']))
  checks['real_entry_client_authenticated']=True
  address=socket.gethostbyname('api.ipify.org')
  def client(args,timeout=45):return run(['docker','exec',CLIENT,*args],timeout=timeout,check=False)
  def https():return client(['curl','-4','--interface',vip,'--resolve','api.ipify.org:443:'+address,'--connect-timeout','5','--max-time','15','-fsS','https://api.ipify.org'])
  def canary():return client(['curl','-4','--interface',vip,'--connect-timeout','3','--max-time','6','-fsS',request['canary_url']])
  # Exercise the DNS address/port the phone actually receives. The entry/exit
  # translation is part of the route, not just the private resolver's listener.
  resolver={'address':str(ipaddress.IPv4Address(advertised_dns)),'dns_port':53}
  def dns(name,tcp=False):return client(['dig','-b',vip,'+time=3','+tries=1',*(['+tcp'] if tcp else []),'@'+resolver['address'],'-p',str(resolver['dns_port']),name,'A'])
  def connected():
   a,b,c,d=https(),canary(),dns('example.com'),dns('doubleclick.net',True)
   result=dict(https=a.returncode==0 and a.stdout.strip()==request['expected_exit'],canary=b.returncode==0 and b.stdout.strip()==request['canary_token'],allowed_dns=c.returncode==0 and 'status: NOERROR' in c.stdout and re.search(r'\sIN\s+A\s+(?!0\.0\.0\.0)[0-9.]+',c.stdout) is not None,blocked_dns=d.returncode==0 and ('status: NXDOMAIN' in d.stdout or re.search(r'\sIN\s+A\s+0\.0\.0\.0',d.stdout) is not None))
   runtime.atomic(folder/'private-probe.json',json.dumps(dict(checks=result,codes=[x.returncode for x in (a,b,c,d)],errors=[x.stderr[-500:] for x in (a,b,c,d)])))
   return all(result.values())
  for _ in range(12):
   if connected():break
   time.sleep(2)
  else:raise RuntimeError('QA client did not pass exit-canary/HTTPS/allowed/blocked DNS')
  checks.update(https_expected_exit=True,exit_only_canary=True,allowed_udp_dns=True,blocked_tcp_dns=True,advertised_phone_dns_route=True)
  if protocol=='xray':
   started=time.monotonic();run(['systemctl','restart','rookstride-single-xray'],timeout=20)
   for _ in range(20):
    if connected():break
    time.sleep(1)
   else:raise RuntimeError('Xray entry did not recover after its own service restart')
   checks['xray_entry_service_restart_recovers']=time.monotonic()-started<30
   assert checks['xray_entry_service_restart_recovers']
  run(['systemctl','stop',native_pair.BRIDGE]);time.sleep(1)
  checks['bridge_outage_blocks_client_https']=https().returncode!=0;checks['bridge_outage_blocks_exit_canary']=canary().returncode!=0
  checks['bridge_outage_blocks_client_udp_dns']=dns('example.net').returncode!=0
  checks['bridge_outage_blocks_client_tcp_dns']=dns('example.net',True).returncode!=0
  checks['entry_host_internet_survives']=run(['curl','-4','--curves','X25519','--connect-timeout','5','--max-time','15','-fsS','https://api.ipify.org'],check=False).returncode==0
  assert all(checks.values())
  run(['systemctl','start',native_pair.BRIDGE])
  for _ in range(20):
   if connected():break
   time.sleep(3)
  else:raise RuntimeError('QA route did not recover after bridge restart')
  checks['bridge_restart_recovers_full_client_route']=True
  checks['host_main_default_unchanged']=run(['ip','route','show','default','table','main']).stdout==main_route
  assert all(checks.values());print(json.dumps({'route':protocol+'->'+p['exit_protocol'],'checks':checks,'client':'real isolated Linux protocol client; not Android or carrier acceptance'}))
 finally:
  run(['systemctl','start',native_pair.BRIDGE],check=False);logs=run(['docker','logs',CLIENT],check=False);runtime.atomic(folder/'private-client.log',(logs.stdout+logs.stderr)[-16000:]);run(['docker','rm','-f',CLIENT],check=False)
if __name__=='__main__':main()
