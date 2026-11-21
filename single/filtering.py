"""Owned private AdGuard resolver for the three native single-server adapters."""
import base64,hashlib,http.client,io,ipaddress,json,os,platform,pwd,re,secrets,shutil,socket,ssl,struct,subprocess,sys,tarfile,tempfile,time,urllib.request,urllib.error
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path('/opt/rookstride-filter')
DATA=Path('/var/lib/rookstride-filter')
UNIT=Path('/etc/systemd/system/rookstride-filter.service')
NETWORK=Path('/etc/systemd/system/rookstride-filter-network.service')
OWNER='rookstride-native-filter-v1'
ADDRESSES=('10.253.0.1','10.255.253.1','172.31.255.254','192.168.254.254')
CHAIN='ROOKFILTER_INPUT'
PAIR_TRANSPORT=Path('/etc/rookstride-pair/transport.json')
FILTERS={'standard':('AdGuard DNS filter','https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt'),
 'strong':('HaGeZi Multi PRO','https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt'),
 'strict':('HaGeZi Multi PRO++','https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt')}
ASSETS={'x86_64':('amd64','28593bc761d71469abdbc6f39ca42cbed763ec92b63082c729177b037ed51d18',12553060,705629752),
 'aarch64':('arm64','d5e17d0d724418ddef8b7723ed8ade7eef4e621ec5b0e43a341859cca71a3d8f',11455816,705629749)}

def command(args,check=True,data=None,timeout=90):
 p=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise ValueError('Private DNS operation failed: '+Path(args[0]).name)
 return p

def atomic(path,value,mode=0o600):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 if path.is_symlink():raise ValueError('Unexpected private DNS link')
 fd,name=tempfile.mkstemp(dir=path.parent,prefix='.rook-')
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,'w') as out:out.write(value);out.flush();os.fsync(out.fileno())
  os.replace(name,path)
 finally:
  if os.path.exists(name):os.unlink(name)

def exists():return (DATA/'state.json').exists() or DATA.is_symlink()
def load():
 if ROOT.is_symlink() or DATA.is_symlink() or (DATA/'state.json').is_symlink():raise ValueError('Unexpected private DNS link')
 v=json.loads((DATA/'state.json').read_text())
 if v.get('owner')!=OWNER or v.get('address') not in ADDRESSES:raise ValueError('Private DNS ownership changed')
 for key in ('dns_port','api_port'):
  if not isinstance(v.get(key),int) or not 1024<=v[key]<=65535:raise ValueError('Invalid private DNS port')
 return v

def save(v):atomic(DATA/'state.json',json.dumps(v))
def ports():
 result=set()
 for n in ('tcp','tcp6','udp','udp6'):
  path=Path('/proc/net')/n
  if not path.exists():continue
  for line in path.read_text().splitlines()[1:]:result.add(int(line.split()[1].split(':')[1],16))
 return result

def choose_address():
 addresses=json.loads(command(['ip','-j','address','show']).stdout);routes=json.loads(command(['ip','-j','route','show','table','all']).stdout)
 occupied=[ipaddress.ip_network(a['local']+'/'+str(a['prefixlen']),strict=False) for row in addresses for a in row.get('addr_info',[]) if a.get('family')=='inet']
 for row in routes:
  if row.get('dst') and row['dst']!='default':
   try:occupied.append(ipaddress.ip_network(row['dst'],strict=False))
   except ValueError:pass
 # A pair entry's remote resolver is not a host route. Reserving that address
 # prevents a coexisting single VPN from shadowing the exit DNS locally.
 transport=PAIR_TRANSPORT
 if transport.exists():
  if transport.is_symlink():raise ValueError('Unexpected pair DNS identity link')
  remote=json.loads(transport.read_text()).get('dns',{}).get('address')
  if remote:occupied.append(ipaddress.ip_network(str(ipaddress.IPv4Address(remote))+'/32'))
 for value in ADDRESSES:
  if not any(ipaddress.ip_address(value) in net for net in occupied):return value
 raise ValueError('No free private DNS address; review existing server routes first')

def bridge():
 p=command(['docker','network','inspect','bridge'],False) if shutil.which('docker') else None
 if p is None or p.returncode:return None
 v=json.loads(p.stdout)[0];name=v.get('Options',{}).get('com.docker.network.bridge.name','docker0')
 if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',name):raise ValueError('Unexpected Docker bridge')
 networks=[str(ipaddress.IPv4Network(x['Subnet'],strict=False)) for x in v.get('IPAM',{}).get('Config',[]) if ':' not in x.get('Subnet','')]
 return (name,networks)

def network_start():
 v=load();assigned=json.loads(command(['ip','-j','address','show','dev','lo']).stdout)
 if not any(a.get('local')==v['address'] for row in assigned for a in row.get('addr_info',[])):command(['ip','address','add',v['address']+'/32','dev','lo'])
 command(['iptables','-N',CHAIN],False);command(['iptables','-F',CHAIN]);docker=bridge()
 for transport in ('udp','tcp'):
  prefix=['iptables','-A',CHAIN,'-d',v['address'],'-p',transport,'--dport',str(v['dns_port'])]
  command(prefix+['-i','lo','-j','ACCEPT'])
  if docker:
   for subnet in docker[1]:command(prefix+['-i',docker[0],'-s',subnet,'-j','ACCEPT'])
  command(prefix+['-j','DROP'])
 if command(['iptables','-C','INPUT','-j',CHAIN],False).returncode:command(['iptables','-I','INPUT','1','-j',CHAIN])

def network_stop():
 v=load()
 if not command(['iptables','-C','INPUT','-j',CHAIN],False).returncode:command(['iptables','-D','INPUT','-j',CHAIN])
 if not command(['iptables','-S',CHAIN],False).returncode:command(['iptables','-F',CHAIN]);command(['iptables','-X',CHAIN])
 command(['ip','address','del',v['address']+'/32','dev','lo'],False)

def api(endpoint,body=None):
 v=load();auth=base64.b64encode(('admin:'+v['password']).encode()).decode()
 req=urllib.request.Request('http://127.0.0.1:'+str(v['api_port'])+'/control/'+endpoint,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 with opener.open(req,timeout=65 if endpoint=='filtering/add_url' else 15) as response:
  data=response.read(1024*1024+1)
  if len(data)>1024*1024:raise ValueError('Oversized private DNS response')
  return json.loads(data) if data.startswith(b'{') else {}

def control(req):
 if 'enabled' in req:
  if not isinstance(req['enabled'],bool):raise ValueError('Expected a boolean protection flag')
  api('protection',dict(enabled=req['enabled'],duration=0))
 level=req.get('level')
 if level:
  if level not in FILTERS:raise ValueError('Unknown filter strength')
  before=api('filtering/status');name,url=FILTERS[level]
  if not any(f['url']==url for f in before.get('filters',[])):api('filtering/add_url',dict(name=name,url=url,whitelist=False))
  api('filtering/set_url',dict(url=url,data=dict(url=url,name=name,enabled=True)))
  for attempt in range(15):
   status=api('filtering/status')
   if any(f['url']==url and f.get('enabled') and f.get('rules_count',0)>0 for f in status.get('filters',[])):break
   time.sleep(1)
  else:raise ValueError('The new list is not ready. Previous filtering remains active.')
  for f in before.get('filters',[]):
   if f['url'] in [x[1] for x in FILTERS.values()] and f['url']!=url:api('filtering/set_url',dict(url=f['url'],data=dict(url=f['url'],name=f['name'],enabled=False)))
 stats=api('stats');filters=api('filtering/status');dns=api('dns_info')
 return dict(protection_enabled=dns.get('protection_enabled',True),blocked=stats.get('num_blocked_filtering',0),queries=stats.get('num_dns_queries',0),scope='All VPNs sharing this server ad blocker',filters=[dict(name=f['name'],enabled=f['enabled'],rules=f.get('rules_count',0)) for f in filters.get('filters',[])])

def query(name):
 v=load();ident=secrets.randbelow(65536);question=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(6);s.sendto(struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+question,(v['address'],v['dns_port']));reply=s.recv(4096)
 if len(reply)<12 or struct.unpack('!H',reply[:2])[0]!=ident:raise ValueError('Invalid private DNS response')
 return reply[3]&15

def ready():
 try:
  if command(['systemctl','is-active','--quiet','rookstride-filter'],False).returncode or query('example.com')!=0:return False
  # A deliberately paused filter is a working resolver, not a broken install.
  expected=3 if api('dns_info').get('protection_enabled',True) else 0
  return query('doubleclick.net')==expected
 except (OSError,ValueError):return False

def wait_ready(phase,fresh=False):
 # A failed initial download otherwise remains empty until the daily update.
 # Retry only enabled empty lists; never change the user's selected protection.
 deadline=time.monotonic()+120
 for attempt in range(40):
  try:
   working=ready()
   if working and not fresh:return
   status=api('filtering/status');enabled=[f for f in status.get('filters',[]) if f.get('enabled',True)]
   empty=bool(status.get('enabled',True) and enabled and any(f.get('rules_count',0)<=0 for f in enabled))
   if working and enabled and not empty:return
   if empty and attempt in (0,10,20):
    phase('Retrying the enabled ad-block list download')
    api('filtering/refresh',dict(whitelist=False,force=True))
  except (OSError,ValueError):pass
  if time.monotonic()>=deadline:break
  phase('Waiting for private ad blocking to become ready');time.sleep(2)
 raise ValueError('Private DNS did not pass its allowed/blocked-domain checks. Check server HTTPS access, then check and resume.')

def references():
 if not exists():return []
 v=load();result=[]
 import model
 for protocol in model.PROTOCOLS:
  p=Path('/var/lib/rookstride-single')/protocol/'state.json'
  if p.is_file():
   state=json.loads(p.read_text())
   if state.get('owner')=='rookstride-single-v1' and state.get('filtering')==v['instance']:result.append(protocol)
 return result

def inspect():
 if not exists():return {'installed':False,'running':False}
 v=load();return {'installed':True,'running':not command(['systemctl','is-active','--quiet','rookstride-filter'],False).returncode,'instance':v['instance'],'used_by':references()}

CACHE=Path('/var/cache/rookstride/artifacts')

class AcquisitionUnavailable(ValueError):
 """Bounded transport acquisition exhausted; never checksum/state validation."""

class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  if urlsplit(newurl).scheme!='https':raise ValueError('VPN component redirects must use HTTPS')
  return super().redirect_request(req,fp,code,msg,headers,newurl)

def https_open(request,timeout):
 if urlsplit(request.full_url).scheme!='https':raise ValueError('VPN components must use HTTPS')
 response=urllib.request.build_opener(HTTPSOnlyRedirect()).open(request,timeout=timeout)
 if urlsplit(response.geturl()).scheme!='https':
  response.close();raise ValueError('VPN component response must use HTTPS')
 return response

def pinned_download(url,expected,limit,expected_size=None,fallbacks=()):
 # Public software only: managed VPN resets retain verified package downloads.
 if CACHE.is_symlink() or CACHE.parent.is_symlink():raise ValueError('Unexpected component cache link')
 CACHE.mkdir(mode=0o700,parents=True,exist_ok=True);path=CACHE/expected
 def verify(data):
  if len(data)>limit or expected_size is not None and len(data)!=expected_size or hashlib.sha256(data).hexdigest()!=expected:raise ValueError('VPN component checksum or size differs')
  return data
 if path.is_symlink():raise ValueError('Unexpected component cache link')
 if path.exists():
  with path.open('rb') as f:return verify(f.read(limit+1))
 deadline=time.monotonic()+180
 sources=[(url,{})]+list(fallbacks)
 for attempt in range(3):
  try:
   data=bytearray()
   source,headers=sources[min(attempt,len(sources)-1)]
   request=urllib.request.Request(source,headers={'User-Agent':'Rookstride-installer',**headers})
   with https_open(request,timeout=45) as response:
    while True:
     block=response.read(65536)
     if not block:break
     data.extend(block)
     if len(data)>limit or time.monotonic()>deadline:raise ValueError('VPN component download exceeded its limit')
   raw=verify(bytes(data));fd,name=tempfile.mkstemp(dir=CACHE,prefix='.verified-')
   try:
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    os.replace(name,path)
   finally:
    if os.path.exists(name):os.unlink(name)
   return raw
  except urllib.error.HTTPError as e:
   if e.code not in (408,429,500,502,503,504) and (attempt or not fallbacks):raise ValueError('VPN component download was rejected; check package availability') from None
  except urllib.error.URLError as e:
   # urllib wraps certificate/SSL validation failures in URLError. These are
   # validation failures, never evidence that a fresh install may be replayed.
   if isinstance(e.reason,ssl.SSLError) and not isinstance(e.reason,ssl.SSLEOFError):raise ValueError('VPN component TLS validation failed') from None
  except ssl.SSLEOFError:pass
  except ssl.SSLError:raise ValueError('VPN component TLS validation failed') from None
  except (TimeoutError,ConnectionError,http.client.IncompleteRead):pass
  if attempt==2 or time.monotonic()>=deadline:break
  # Try the pinned alternate origin immediately after the first origin fails.
  if not fallbacks or attempt:time.sleep(2*(attempt+1))
 raise AcquisitionUnavailable('VPN component download did not complete after three attempts. Check server HTTPS access and resume.')

def prepare_binary():
 # Only the verified public cache may change here. In particular, a network
 # failure must not publish a filter or a protocol's empty installation state.
 if exists():
  load()
  if (DATA/'agh').is_symlink():raise ValueError('Unexpected private DNS link')
  for p in (UNIT,NETWORK,ROOT/'AdGuardHome',ROOT/'filtering.py',DATA/'agh/AdGuardHome.yaml'):
   if p.is_symlink():raise ValueError('Unexpected private DNS link')
   if not p.is_file():raise ValueError('Private DNS setup is incomplete. Review its owned reset before retrying.')
  fingerprint();return None
 for p in (ROOT,DATA,UNIT,NETWORK):
  if p.exists() or p.is_symlink():raise ValueError('Existing private DNS files need review')
 if platform.machine() not in ASSETS:raise ValueError('Private DNS supports x86_64 and aarch64')
 arch,expected,size,asset=ASSETS[platform.machine()];url='https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.80/AdGuardHome_linux_'+arch+'.tar.gz'
 alternate='https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/assets/'+str(asset)
 data=pinned_download(url,expected,64*1024*1024,size,((alternate,{'Accept':'application/octet-stream'}),))
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
  items=[item for item in archive.getmembers() if not Path(item.name).is_absolute() and '..' not in Path(item.name).parts and Path(item.name)==Path('AdGuardHome/AdGuardHome')]
  if len(items)!=1 or not items[0].isfile() or not 0<items[0].size<=100*1024*1024:raise ValueError('Unexpected private DNS binary')
  item=items[0]
  binary=archive.extractfile(item).read()
  if len(binary)!=item.size:raise ValueError('Incomplete private DNS binary')
 return binary

def install_binary(prepared):
 path=ROOT/'AdGuardHome';path.write_bytes(prepared);path.chmod(0o755)

def ensure_dependencies(phase):
 # Minimal cloud images need not contain the firewall/user-management tools.
 packages={name for tool,name in (('ip','iproute2'),('iptables','iptables'),('openssl','openssl'),('useradd','passwd')) if not shutil.which(tool)}
 if command(['/usr/bin/python3','-c','import bcrypt'],False).returncode:packages.add('python3-bcrypt')
 if packages:
  phase('Preparing private DNS dependencies')
  command(['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3','update','-qq'],timeout=1200)
  command(['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3','install','-y','-qq',*sorted(packages)],timeout=1200)

def ensure(phase=lambda text:None,docker=False,prepared=None):
 if exists():
  prepare_binary()
  phase("Reusing shared ad blocking; verifying private DNS")
  load();ROOT.chmod(0o755);DATA.chmod(0o755)
  if docker and not load().get('docker'):
   value=load();value['docker']=True;save(value)
   if NETWORK.is_file():
    text=NETWORK.read_text()
    if not text.startswith('[Unit]\nDescription=Rookstride private DNS network'):raise ValueError('Private DNS service ownership changed')
    atomic(NETWORK,text.replace('After=network.target docker.service','After=network.target docker.service\nWants=docker.service'),0o644);command(['systemctl','daemon-reload'])
  fingerprint();network_start();command(['systemctl','enable','--now','rookstride-filter'])
  wait_ready(phase);return
 for p in (ROOT,DATA,UNIT,NETWORK):
  if p.exists() or p.is_symlink():raise ValueError('Existing private DNS files need review')
 if prepared is None:
  phase('Preparing and verifying AdGuard Home');prepared=prepare_binary()
 try:pwd.getpwnam('rookfilter')
 except KeyError:pass
 else:raise ValueError('Private DNS service account name is already in use')
 ensure_dependencies(phase)
 if not command(['iptables','-S',CHAIN],False).returncode:raise ValueError('Private DNS firewall name is already in use')
 address=choose_address();used=ports();dns=next(p for p in range(5354,5400) if p not in used);used.add(dns);http=next(p for p in range(3001,3100) if p not in used)
 # crypt was removed in Python 3.13. Use Ubuntu's maintained bcrypt package;
 # the generated dashboard secret travels through stdin, never process arguments.
 hashed=command(['/usr/bin/python3','-c','import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.buffer.read(),bcrypt.gensalt(rounds=12)).decode())'],data=(password:=secrets.token_hex(24))).stdout.strip()
 if not hashed.startswith(('$2a$','$2b$','$2y$')):raise ValueError('System bcrypt support is required for private DNS')
 DATA.mkdir(mode=0o755);ROOT.mkdir(mode=0o755);DATA.chmod(0o755);ROOT.chmod(0o755);state=dict(owner=OWNER,instance=secrets.token_hex(16),address=address,dns_port=dns,api_port=http,password=password,docker=docker);save(state)
 install_binary(prepared);atomic(ROOT/'filtering.py',Path(__file__).read_text(),0o755)
 command(['useradd','--system','--user-group','--home-dir',str(DATA/'agh'),'--no-create-home','--shell','/usr/sbin/nologin','rookfilter']);user=pwd.getpwnam('rookfilter');state['uid']=user.pw_uid;save(state)
 for p in (DATA/'agh',DATA/'agh/work'):p.mkdir(mode=0o700);os.chown(p,user.pw_uid,user.pw_gid)
 cfg={'http':{'address':'127.0.0.1:'+str(http),'session_ttl':'30d'},'users':[{'name':'admin','password':hashed}],'auth_attempts':5,'block_auth_min':15,'language':'en',
  'dns':{'bind_hosts':[address],'port':dns,'upstream_dns':['https://dns.quad9.net/dns-query','https://cloudflare-dns.com/dns-query'],'upstream_mode':'parallel','upstream_timeout':'5s','bootstrap_dns':['9.9.9.9','1.1.1.1'],'fallback_dns':['https://cloudflare-dns.com/dns-query'],'allowed_clients':[],'use_private_ptr_resolvers':False,'edns_client_subnet':{'enabled':False,'use_custom':False},'serve_plain_dns':True,'enable_dnssec':True,'aaaa_disabled':True},
  'querylog':{'enabled':False,'file_enabled':False},'statistics':{'enabled':True,'interval':'1d'},'filters':[{'enabled':True,'url':FILTERS['standard'][1],'name':FILTERS['standard'][0],'id':1}],
  'filtering':{'protection_enabled':True,'filtering_enabled':True,'blocking_mode':'nxdomain','filters_update_interval':24,'blocked_response_ttl':10},'dhcp':{'enabled':False},'tls':{'enabled':False},'schema_version':34}
 config=DATA/'agh/AdGuardHome.yaml';atomic(config,json.dumps(cfg));os.chown(config,user.pw_uid,user.pw_gid)
 atomic(NETWORK,'[Unit]\nDescription=Rookstride private DNS network\nAfter=network.target docker.service\n'+('Wants=docker.service\n' if docker else '')+'Before=rookstride-filter.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 '+str(ROOT/'filtering.py')+' boot\nExecStop=/usr/bin/python3 '+str(ROOT/'filtering.py')+' stop-network\n[Install]\nWantedBy=multi-user.target\n',0o644)
 atomic(UNIT,'[Unit]\nDescription=Rookstride private DNS filter\nRequires=rookstride-filter-network.service\nAfter=rookstride-filter-network.service network-online.target\n[Service]\nUser=rookfilter\nGroup=rookfilter\nExecStart='+str(ROOT/'AdGuardHome')+' -c '+str(config)+' -w '+str(DATA/'agh/work')+' --no-check-update\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths='+str(DATA/'agh')+'\n[Install]\nWantedBy=multi-user.target\n',0o644)
 command(['systemctl','daemon-reload']);command(['systemctl','enable','--now','rookstride-filter'])
 phase('Loading the ad-block list and checking private DNS')
 wait_ready(phase,fresh=True)

def fingerprint():
 v=load();h=hashlib.sha256()
 if v.get('uid') is not None:
  try:user=pwd.getpwnam('rookfilter')
  except KeyError:raise ValueError('Private DNS service identity changed')
  if user.pw_uid!=v['uid'] or user.pw_dir!=str(DATA/'agh') or user.pw_shell!='/usr/sbin/nologin':raise ValueError('Private DNS service identity changed')
 for p in (DATA/'state.json',DATA/'agh/AdGuardHome.yaml',ROOT/'filtering.py',UNIT,NETWORK):
  if p.is_symlink():raise ValueError('Private DNS ownership changed')
  h.update(str(p).encode()+b'\0'+(p.read_bytes() if p.exists() else b''))
 for p in (UNIT,NETWORK):
  if p.exists() and not p.read_text().startswith('[Unit]\nDescription=Rookstride private DNS'):raise ValueError('Private DNS service ownership changed')
 return h.hexdigest()

def reset_plan():
 value=dict(token=secrets.token_hex(32),expires=time.time()+300,configuration=fingerprint());atomic(DATA/'reset.json',json.dumps(value));return dict(token=value['token'],scope='Private native-protocol ad blocking, DNS rules and aggregate DNS statistics. OS, SSH and unrelated software stay.')

def reset_apply(req):
 review=json.loads((DATA/'reset.json').read_text())
 if req.get('confirmation')!='DELETE VPN' or not secrets.compare_digest(str(req.get('token','')),review['token']) or time.time()>review['expires'] or fingerprint()!=review['configuration']:raise ValueError('Review the private DNS reset again')
 for p in (UNIT,NETWORK):
  if p.exists():command(['systemctl','disable','--now',p.name])
 network_stop()
 for p in (UNIT,NETWORK):p.unlink(missing_ok=True)
 command(['systemctl','daemon-reload'])
 if load().get('uid') is not None:command(['userdel','rookfilter'])
 shutil.rmtree(ROOT);shutil.rmtree(DATA)

if __name__=='__main__':
 if len(sys.argv)!=2 or os.geteuid()!=0:raise SystemExit('Root operation required')
 if sys.argv[1]=='boot':network_start()
 elif sys.argv[1]=='stop-network':network_stop()
 else:raise SystemExit('Unsupported private DNS operation')
