#!/usr/bin/env python3
"""Independent client traffic probe. Accepts only explicitly supplied private lab exports."""
import argparse,contextlib,hashlib,http.client,ipaddress,json,os,socket,ssl,struct,subprocess,tempfile,time,urllib.parse,urllib.request
from pathlib import Path
import dns_wire
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--worker',type=Path,required=True);p.add_argument('--profile',type=Path,required=True);p.add_argument('--xray',type=Path);p.add_argument('--canary');p.add_argument('--diagnostic',action='store_true');p.add_argument('--private-canary-port',type=int);p.add_argument('--pair-outage',action='store_true');p.add_argument('--repeat',type=int,default=1);p.add_argument('--transfer-bytes',type=int,default=0);args=p.parse_args()
assert 1<=args.repeat<=100
assert 0<=args.transfer_bytes<=4*1024*1024 and (not args.transfer_bytes or args.canary)
if args.pair_outage and (os.geteuid()!=0 or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes' or not args.canary):raise PermissionError('Pair outage checks require an explicit disposable root lab and exit canary')
import sys
sys.path.insert(0,str(args.source/'single'));import routes,runtime,model
export=json.loads(args.profile.read_text());protocol=export['format'];profile=json.loads(export['content']) if protocol!='xhttp' else None
if args.pair_outage:
 manifest=json.loads(Path('/etc/rookstride-pair/manifest.json').read_text());assert manifest.get('version')==2 and manifest.get('activated') and manifest['plan']['role']=='entry' and manifest['plan']['entry_protocol']==protocol
 try:urllib.request.urlopen(args.canary,timeout=3)
 except OSError:pass
 else:raise AssertionError('The exit canary is reachable on the entry normal route')
with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
if protocol=='xhttp':
 from urllib.parse import urlsplit,parse_qs
 url=urlsplit(export['content']);q=parse_qs(url.query,keep_blank_values=True)
 cfg={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':url.hostname,'port':url.port,'users':[{'id':url.username,'encryption':'none'}]}]},'streamSettings':{'network':'xhttp','security':'reality','realitySettings':{'serverName':q['sni'][0],'fingerprint':'chrome','publicKey':q['pbk'][0],'shortId':q['sid'][0]},'xhttpSettings':{'path':q['path'][0],'mode':'auto'}}}]};binary=args.xray
else:cfg=routes.client_config(profile,port);binary=args.worker
assert binary and binary.is_file()
if args.diagnostic:
 (cfg['box'] if protocol!='xhttp' else cfg)['log']={'level':'debug'} if protocol!='xhttp' else {'loglevel':'debug'}
def exact(s,n):
 result=b''
 while len(result)<n:
  v=s.recv(n-len(result))
  if not v:raise OSError('Incomplete SOCKS response')
  result+=v
 return result
def socks(command,address,destination_port):
 s=socket.create_connection(('127.0.0.1',port),3);s.settimeout(15);s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
 if address is None:target=b'\x01\x00\x00\x00\x00'
 else:
  try:target=b'\x01'+socket.inet_aton(address)
  except OSError:encoded=address.encode('ascii');target=b'\x03'+bytes([len(encoded)])+encoded
 s.sendall(b'\x05'+bytes([command])+b'\x00'+target+struct.pack('!H',destination_port));head=exact(s,4)
 if head[:3]!=b'\x05\x00\x00':s.close();raise OSError('SOCKS destination rejected')
 host=socket.inet_ntoa(exact(s,4)) if head[3]==1 else socket.inet_ntop(socket.AF_INET6,exact(s,16)) if head[3]==4 else exact(s,exact(s,1)[0]).decode();number=struct.unpack('!H',exact(s,2))[0]
 return s,(host,number)
def https(host):
 s,_=socks(1,host,443)
 # Use an interoperable reference handshake rather than the host's newest
 # default key-share list; retain trusted CAs, hostname verification and TLS.
 context=runtime.probe_tls_context()
 with context.wrap_socket(s,server_hostname=host) as c:
  c.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode());response=http.client.HTTPResponse(c);response.begin();assert 200<=response.status<400;data=response.read(2*1024*1024);return data

startup_retries=0
def startup_https(host):
 global startup_retries
 for attempt in range(3):
  try:return https(host)
  except OSError:
   if attempt==2:raise
   startup_retries+=1;time.sleep(1)

def dns(name,tcp=False):
 ident=int.from_bytes(os.urandom(2),'big');wire=struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\x00\x00\x01\x00\x01'
 if tcp:
  s,_=socks(1,'9.9.9.9',53)
  with s:s.sendall(struct.pack('!H',len(wire))+wire);reply=exact(s,struct.unpack('!H',exact(s,2))[0])
 else:
  control,relay=socks(3,None,0)
  if relay[0] in ('0.0.0.0','::'):relay=('127.0.0.1',relay[1])
  with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as packet:
   packet.settimeout(12);packet.sendto(b'\0\0\0\x01'+socket.inet_aton('9.9.9.9')+b'\0\x35'+wire,relay);raw,_=packet.recvfrom(65535)
  assert raw[:3]==b'\0\0\0';offset=10 if raw[3]==1 else 22 if raw[3]==4 else 7+raw[4];reply=raw[offset:]
 return dns_wire.response(reply,ident)
def canary():
 u=urllib.parse.urlsplit(args.canary);s,_=socks(1,u.hostname,u.port or 80)
 with s:
  s.sendall(('GET '+(u.path or '/')+' HTTP/1.0\r\nHost: '+u.hostname+'\r\n\r\n').encode());data=b''
  while True:
   chunk=s.recv(4096)
   if not chunk:break
   data+=chunk
   if len(data)>16384:raise ValueError('Oversized lab canary')
 assert b'ROOK_EXIT_ONLY' in data,'Exit-only canary missing'
 return True
with tempfile.TemporaryDirectory(prefix='rookstride-client-') as folder:
 os.chmod(folder,0o700);path=Path(folder)/'client.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
 log=(Path(folder)/'private.log').open('w');process=subprocess.Popen([str(binary),*(['run','-config',str(path)] if protocol=='xhttp' else ['run',str(path)])],stdout=log,stderr=log)
 try:
  deadline=time.monotonic()+15
  while time.monotonic()<deadline and process.poll() is None:
   try:
    with socket.create_connection(('127.0.0.1',port),.2):break
   except OSError:time.sleep(.1)
  assert process.poll() is None,'Client did not start'
  for _ in range(args.repeat):assert len(startup_https('example.com'))>100
  ip=str(ipaddress.IPv4Address(startup_https('api.ipify.org').strip().decode()))
  results={}
  for transport in ('tcp','udp'):
   allowed=dns('example.com',transport=='tcp');blocked=dns('doubleclick.net',transport=='tcp');assert dns_wire.allowed(allowed),(transport,'allowed DNS failed',allowed);assert dns_wire.blocked(blocked),(transport,'ad domain escaped',blocked);results[transport+'_dns_filtered']=True
  if args.canary:
   canary();results['exit_only_canary']=True
  if args.transfer_bytes:
   target=urllib.parse.urlsplit(args.canary);s,_=socks(1,target.hostname,target.port or 80)
   with s:
    s.sendall(('GET /bulk?bytes='+str(args.transfer_bytes)+' HTTP/1.1\r\nHost: '+target.hostname+'\r\nConnection: close\r\n\r\n').encode());response=http.client.HTTPResponse(s);response.begin();assert response.status==200;data=response.read(args.transfer_bytes+1)
   expected=(b'rookstride-'*((args.transfer_bytes+10)//11))[:args.transfer_bytes]
   assert len(data)==args.transfer_bytes and hashlib.sha256(data).digest()==hashlib.sha256(expected).digest(),'Bulk transfer changed or stopped early'
   results['bulk_transfer_verified']=True;results['bulk_bytes']=len(data)
  if args.private_canary_port:
   for target in ('127.0.0.1','localhost'):
    try:
     s,_=socks(1,target,args.private_canary_port)
     with s:
      s.settimeout(4);s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n');data=s.recv(4096)
     assert not data,'A private server listener was reachable through the VPN'
    except OSError:pass
   results['private_literal_and_hostname_rejected']=True
  if args.pair_outage:
   default=subprocess.check_output(['ip','route','show','default','table','main'])
   try:
    subprocess.run(['systemctl','stop','rookstride-pair-bridge'],check=True,timeout=30);time.sleep(1)
    for name,attempt in [('https',lambda:https('example.com')),('canary',canary),('tcp_dns',lambda:dns('example.net',True)),('udp_dns',lambda:dns('example.net',False))]:
     try:attempt()
     except (OSError,AssertionError):results['outage_blocks_'+name]=True
     else:raise AssertionError('Exit outage leaked '+name)
    with urllib.request.urlopen('https://example.com',timeout=15,context=runtime.probe_tls_context()) as host:assert host.status==200
    results['entry_host_internet_retained']=True
    assert default==subprocess.check_output(['ip','route','show','default','table','main']);results['main_default_unchanged']=True
   finally:subprocess.run(['systemctl','start','rookstride-pair-bridge'],check=True,timeout=30)
   for attempt in range(12):
    try:
     assert len(https('example.com'))>100;canary();assert dns_wire.allowed(dns('example.net',True));assert dns_wire.blocked(dns('doubleclick.net',False));break
    except (OSError,AssertionError):
     if attempt==11:raise
     time.sleep(1)
   results['recovers_after_exit_restart']=True
  print(json.dumps(dict(protocol=protocol,https=True,startup_retries=startup_retries,exit_sha256=hashlib.sha256(ip.encode()).hexdigest(),**results)))
 except Exception:
  if args.diagnostic:
   log.flush();data=(Path(folder)/'private.log').read_text()
   if profile:
    for key in ('password','login','path','obfs'):
     if profile.get(key):data=data.replace(profile[key],'[redacted]')
   print(data[-5000:],file=sys.stderr)
  raise
 finally:
  process.terminate()
  try:process.wait(timeout=6)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
  log.close()
