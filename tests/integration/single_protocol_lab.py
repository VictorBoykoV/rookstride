#!/usr/bin/env python3
"""Run only on a disposable Ubuntu runner. Never reads saved operator credentials."""
import json,os,secrets,socket,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'single'))
import model,runtime,run as api,filtering
protocol=sys.argv[1];assert protocol in model.PROTOCOLS and os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')=='yes'
assert os.geteuid()==0
release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
report={'protocol':protocol,'environment':'disposable Ubuntu '+release.get('VERSION_ID','').strip('"'),'checks':{}}
process=None;client='rookstride-lab-client';network='rookstride-lab-network';server=None;blocker=None

def check(args,**kwargs):
 p=subprocess.run(args,capture_output=True,text=True,timeout=kwargs.pop('timeout',180),**kwargs)
 if p.returncode:raise AssertionError('Lab command failed: '+Path(args[0]).name+' '+p.stderr[-600:])
 return p.stdout.strip()

# Run host Python in the actual client network namespace, or tunnel TCP DNS over
# the local SOCKS client. Public resolver addresses must be intercepted server-side.
DNS_PROBE = r"""
import socket,struct,sys,json
name,transport,socks=sys.argv[1:]
question=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
packet=struct.pack('!HHHHHH',41872,256,1,0,0,0)+question
def read(s,n):
 data=b''
 while len(data)<n:
  block=s.recv(n-len(data))
  if not block:raise OSError('Truncated DNS reply')
  data+=block
 return data
try:
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as s:
  s.settimeout(5)
  if socks=='yes':
   s.connect(('127.0.0.1',1080));s.sendall(b'\5\1\0');assert read(s,2)==b'\5\0'
   s.sendall(b'\5\1\0\1'+socket.inet_aton('1.1.1.1')+struct.pack('!H',53))
   header=read(s,4);assert header[1]==0
   read(s,{1:4,4:16}.get(header[3],0)+2)
  else:s.connect(('1.1.1.1',53))
  if transport=='tcp':s.sendall(struct.pack('!H',len(packet))+packet);reply=read(s,struct.unpack('!H',read(s,2))[0])
  else:s.send(packet);reply=s.recv(4096)
  assert len(reply)>=12 and reply[:2]==packet[:2]
  print(json.dumps(dict(rcode=reply[3]&15,answers=struct.unpack('!H',reply[6:8])[0])))
except (OSError,AssertionError):print(json.dumps(dict(unavailable=True)))
"""
def dns_probe(name,transport):
 args=[sys.executable,'-c',DNS_PROBE,name,transport,'yes' if protocol=='xray' else 'no']
 if protocol!='xray':
  pid=check(['docker','inspect','--format','{{.State.Pid}}',client]);args=['nsenter','-t',pid,'-n']+args
 return json.loads(check(args))

try:
 if not Path('/dev/net/tun').exists():
  Path('/dev/net').mkdir(exist_ok=True);check(['mknod','/dev/net/tun','c','10','200'])
 sentinel=Path('/var/tmp/rookstride-unrelated-site');sentinel.write_text('keep this unrelated application')
 if '--busy-default' in sys.argv:
  blocker=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if model.PROTOCOLS[protocol]['transport']=='udp' else socket.SOCK_STREAM)
  blocker.bind(('0.0.0.0',model.PROTOCOLS[protocol]['port']))
  if model.PROTOCOLS[protocol]['transport']=='tcp':blocker.listen(1)
 if '--existing' in sys.argv:
  server=runtime.load(protocol);report['checks']['existing_installation']=True
 else:
  req={'action':'start','protocol':protocol,'server':'172.17.0.1','login':'lab-phone'}
  started=api.action(req);job=started['job'];deadline=time.time()+1200
  while True:
   status=api.action({'action':'job','job':job})
   if status['state']=='complete':break
   if status['state']=='failed':raise AssertionError(status['phase'])
   if time.time()>deadline:raise AssertionError('Installation deadline')
   time.sleep(3)
  server=runtime.load(protocol);report['checks']['detached_install']=True
  assert server['port']==started['plan']['port'];report['checks']['automatic_port_persisted']=True
  if blocker:
   assert server['port']!=model.PROTOCOLS[protocol]['port'];report['checks']['busy_default_preserved']=True
 health=api.action({'action':'status','protocol':protocol});assert health['running'];report['checks']['service_ready']=True
 # No client tunnel exists yet: administration must remain independent of it.
 api.action({'action':'add-user','protocol':protocol,'login':'offline-admin'});assert api.action({'action':'profile','protocol':protocol,'login':'offline-admin'})['content']
 api.action({'action':'remove-user','protocol':protocol,'login':'offline-admin'});report['checks']['account_management_without_tunnel']=True
 exported=api.action({'action':'profile','protocol':protocol,'login':'lab-phone'});assert exported['content'];report['checks']['profile_export']=True
 private=Path('/var/tmp/rookstride-single-lab');private.mkdir(mode=0o700,exist_ok=True)
 (private/'ready').unlink(missing_ok=True);(private/'client.log').unlink(missing_ok=True)
 if protocol=='xray':
  user=server['users'][0]
  config={'log':{'loglevel':'info'},'inbounds':[{'listen':'127.0.0.1','port':1080,'protocol':'socks','settings':{'udp':True}}],
   'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':server['port'],'users':[{'id':user['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
   'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':server['sni'],'fingerprint':'chrome','publicKey':server['public'],'shortId':server['shortId'],'spiderX':'/'}}}]}
  runtime.atomic(private/'client.json',json.dumps(config));binary=runtime.ROOT/'bin/xray'
  check([str(binary),'run','-test','-config',str(private/'client.json')]);out=(private/'client.log').open('w');process=subprocess.Popen([str(binary),'run','-config',str(private/'client.json')],stdout=out,stderr=out);time.sleep(2)
  body=check(['curl','--curves','X25519','--tlsv1.2','--fail','--silent','--show-error','--max-time','40','--socks5-hostname','127.0.0.1:1080','https://example.com/']);assert 'Example Domain' in body
 else:
  file=private/('client.conf' if protocol=='awg' else 'client.ovpn');text=exported['content'];file.write_text(text);file.chmod(0o600)
  if protocol=='awg':
   # Configure the interface directly; test an explicit DNS request through it below.
   file.write_text('\n'.join(v for v in text.splitlines() if not v.startswith('DNS ='))+'\n')
   image='rookstride-awg:1';script='set -e; apk add --no-cache curl;  amneziawg-go -f client & for n in {1..100}; do [[ -S /var/run/amneziawg/client.sock ]] && break; sleep .1; done; [[ -S /var/run/amneziawg/client.sock ]]; awg-quick strip /lab/client.conf > /lab/wire.conf; awg setconf client /lab/wire.conf; ip address add 10.67.0.2/32 dev client; ip -6 address add fd42:670::2/128 dev client; ip link set client mtu 1280 up; gateway=$(ip -4 route show default | awk \'{print $3}\'); ip route add 172.17.0.1/32 via $gateway dev eth0; ip route replace default dev client; ip -6 route replace default dev client; touch /lab/ready; tail -f /dev/null'
  else:
   # Prepare disposable checking tools before connecting the client. Package
   # availability is independent of the protocol route under test; reuse cache.
   qa=private/'qa';qa.mkdir(exist_ok=True);dockerfile=qa/'Dockerfile'
   dockerfile.write_text('FROM rookstride-openvpn:1\nRUN apt-get -o Acquire::Retries=3 update -qq && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y -qq --no-install-recommends curl\n')
   check(['docker','build','-t','rookstride-lab-openvpn:1','-f',str(dockerfile),str(qa)],timeout=600)
   image='rookstride-lab-openvpn:1';script='set -e; openvpn --config /lab/client.ovpn --log /lab/client.log --daemon; tail -f /dev/null'
  check(['docker','network','create','--subnet','172.30.61.0/24',network])
  check(['docker','run','-d','--name',client,'--network',network,'--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv6.conf.all.disable_ipv6=0','--mount','type=bind,source='+str(private)+',target=/lab','--entrypoint','/bin/bash',image,'-c',script])
  deadline=time.time()+40
  while time.time()<deadline:
   ready=(private/'ready').exists() if protocol=='awg' else (private/'client.log').exists() and 'Initialization Sequence Completed' in (private/'client.log').read_text()
   if ready:break
   time.sleep(1)
  assert ready,'Client did not finish configuring its tunnel'
  if protocol=='awg':check(['docker','exec',client,'nslookup','example.com','1.1.1.1'])
  body=check(['docker','exec',client,'curl','--curves','X25519','--tlsv1.2','--ipv4','--interface','client' if protocol=='awg' else 'tun0','--fail','--silent','--show-error','--max-time','40','https://example.com/']);assert 'Example Domain' in body
  if protocol=='awg':
   handshake=check(['docker','exec',runtime.container(protocol),'awg','show','rsawg0','latest-handshakes']);assert any(int(v.split()[1])>0 for v in handshake.splitlines())
 if protocol=='openvpn':
  deadline=time.monotonic()+20
  while True:
   counters=api.action({'action':'status','protocol':protocol})
   if counters['monitoring_available'] and sum(x['upload'] for x in counters['connections'])>0 and sum(x['download'] for x in counters['connections'])>0:break
   assert time.monotonic()<deadline,'OpenVPN did not expose its actual traffic counters'
   time.sleep(1)
  assert counters['statistics_kind']=='sessions' and counters['statistics_scope']=='active-sessions'
  assert any(x['sessions']>0 and x['generation'] for x in counters['connections'])
  report['checks']['actual_session_statistics']=True
 report['checks']['real_client_https']=True
 assert health['filtering']['running']
 transports=('tcp',) if protocol=='xray' else ('udp','tcp')
 for transport in transports:
  allowed=dns_probe('example.com',transport);blocked=dns_probe('doubleclick.net',transport)
  assert allowed.get('rcode')==0 and allowed.get('answers',0)>0, 'Allowed DNS did not resolve'
  assert blocked.get('rcode')==3, 'Ad DNS bypassed the private filter'
 # Deliberately stop only the owned filter. DNS must not fall back to public DNS.
 check(['systemctl','stop','rookstride-filter'])
 try:
  for transport in transports:
   outage=dns_probe(secrets.token_hex(12)+'.example.com',transport)
   assert outage.get('unavailable') or outage.get('rcode')==2, 'DNS answered an uncached name during filter outage: '+repr(outage)
 finally:check(['systemctl','start','rookstride-filter'])
 deadline=time.monotonic()+45
 while time.monotonic()<deadline and not filtering.ready():time.sleep(1)
 assert filtering.ready(), 'Private DNS recovery failed; service='+str(filtering.inspect().get('running'))+' protection='+str(filtering.api('dns_info').get('protection_enabled'));report['checks']['private_ad_dns']=True;report['checks']['dns_filter_outage_no_fallback']=True
 api.action({'action':'add-user','protocol':protocol,'login':'lab-second'});assert any(u['login']=='lab-second' for u in api.action({'action':'status','protocol':protocol})['users'])
 api.action({'action':'remove-user','protocol':protocol,'login':'lab-second'});assert not any(u['login']=='lab-second' for u in api.action({'action':'status','protocol':protocol})['users']);report['checks']['add_remove_user']=True
 if '--keep-installed' not in sys.argv:
  review=api.action({'action':'reset-plan','protocol':protocol})
  api.action({'action':'reset-apply','protocol':protocol,'token':review['token'],'confirmation':'DELETE VPN'})
  assert not (runtime.directory(protocol)/'state.json').exists();assert sentinel.read_text()=='keep this unrelated application';report['checks']['owned_reset_preserves_other_data']=True
 report['status']='PASS'
except Exception:
 if protocol!='xray':
  log=subprocess.run(['docker','logs',client],capture_output=True,text=True);print(log.stdout[-3000:]+log.stderr[-3000:])
  if protocol=='awg':
   for node,interface in ((runtime.container(protocol),'rsawg0'),(client,'client')):
    for field in ('listen-port','latest-handshakes','transfer'):
     print(node,field,subprocess.run(['docker','exec',node,'awg','show',interface,field],capture_output=True,text=True).stdout)
   print(subprocess.run(['docker','exec',client,'ip','route'],capture_output=True,text=True).stdout)
   log=subprocess.run(['docker','logs','--tail','40',runtime.container(protocol)],capture_output=True,text=True);print('Disposable server diagnostic:\n'+log.stdout[-3000:]+log.stderr[-3000:])
   print(subprocess.run(['docker','inspect','--format','{{.RestartCount}} {{json .State}}',runtime.container(protocol)],capture_output=True,text=True).stdout)
 if protocol=='xray':
  logfile=Path('/var/tmp/rookstride-single-lab/client.log')
  if logfile.exists():print('Disposable client diagnostic:\n'+logfile.read_text()[-6000:])
  print(check(['journalctl','-u','rookstride-single-xray','-n','30','--no-pager']))
 raise
finally:
 if process:process.terminate();process.wait(timeout=10)
 if blocker:blocker.close()
 if protocol!='xray':
  subprocess.run(['docker','rm','-f',client],capture_output=True);subprocess.run(['docker','network','rm',network],capture_output=True)
 target=ROOT/'.build'/('single-'+protocol+'-lab.json');target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(report,indent=2))
 print(json.dumps(report,indent=2))
