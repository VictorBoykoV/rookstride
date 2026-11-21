"""Versioned identity allowlists for native VPN recovery; no executable files."""
import base64,copy,hashlib,ipaddress,json,re,ssl,subprocess,tempfile,uuid
from pathlib import Path
import pair,native_pair,recovery_ike

NATIVE=set(native_pair.model.PROTOCOLS)|{'ikev2'}
WORKERS={'hysteria2','outline','shadowsocks','trusttunnel','naive'}
COMMON={'protocol','server','port','initialLogin','instance','owner','pair_dns','pair','filtering','users','sni','sni_auto','access_mode'}
FIELDS={'ikev2':{'aliases'},'awg':{'private','public','parameters'},'xray':{'private','public','shortId'},'xhttp':{'private','public','shortId','path'},'openvpn':{'revoked','tls_name'}}
for protocol in WORKERS:FIELDS[protocol]={'tls_name','tls_mode','tls_leaf','obfs'}
USER_COMMON={'login','enabled','created','person','device'}
USERS={'ikev2':{'password'},'awg':{'private','public','psk','address','ipv6'},'xray':{'uuid'},'xhttp':{'uuid'},'openvpn':{'password_hash'}}
for protocol in WORKERS:USERS[protocol]={'password','path'}
EPHEMERAL={'metrics_port','metrics_token','forwarder_port','trust_metrics_port','public_tls','applied_tls_sha'}
MAX_FILES_BYTES=786432

def derived_public(private):
 # RFC8410 PKCS8 wrapper for a raw X25519 private key. Only derived public bytes
 # leave this subprocess; neither arguments nor errors contain secret material.
 raw=bytes.fromhex('302e020100300506032b656e04220420')+private
 result=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=raw,capture_output=True,timeout=15)
 prefix=bytes.fromhex('302a300506032b656e032100')
 if result.returncode or not result.stdout.startswith(prefix) or len(result.stdout)!=len(prefix)+32:raise ValueError('Recovery X25519 identity could not be verified')
 return result.stdout[-32:]
def key_pair(private,public,url=False):
 decode=lambda value:base64.urlsafe_b64decode(value+'='*(-len(value)%4)) if url else base64.b64decode(value,validate=True)
 if derived_public(decode(private))!=decode(public):raise ValueError('Recovery private and public identity do not match')

def supported(protocol):return protocol in NATIVE

def clean_state(state):
 value=copy.deepcopy(state)
 for name in EPHEMERAL:value.pop(name,None)
 for user in value.get('users',[]):
  user.pop('administration_account_id',None);user.pop('private_port',None)
 return value

def names(state):
 protocol=state['protocol'];result=[]
 if protocol in WORKERS|{'ikev2'} and state.get('access_mode')!='password':
  leaf=state.get('tls_leaf','');prefix='tls/'+(leaf+'/' if leaf else '')
  result=['tls/ca.pem','tls/ca.key',prefix+'server.pem',prefix+'server.key']
 elif protocol=='openvpn' and state.get('access_mode')!='password':
  result=['runtime/tls-crypt.key','runtime/pki/ca.crt','runtime/pki/private/ca.key','runtime/pki/issued/server.crt','runtime/pki/private/server.key','runtime/pki/crl.pem','runtime/pki/index.txt','runtime/pki/index.txt.attr','runtime/pki/serial']
  for user in state['users']:
   result+=['runtime/pki/issued/'+user['login']+'.crt','runtime/pki/private/'+user['login']+'.key']
 return result

def optional_names(state):return ['runtime/pki/crlnumber'] if state['protocol']=='openvpn' and state.get('access_mode')!='password' else []

def files(state):
 if state['protocol']=='ikev2':return recovery_ike.files(state)
 root=native_pair.runtime.directory(state['protocol']);result={}
 for name in names(state)+[name for name in optional_names(state) if (root/name).exists()]:
  path=root/name
  for parent in (path,*path.parents):
   pair.protected(parent)
   if parent==root:break
  if not path.is_file() or path.stat().st_size>131072:raise ValueError('Recovery identity file is missing or too large')
  data=path.read_bytes();result[name]={'content':base64.b64encode(data).decode(),'sha256':hashlib.sha256(data).hexdigest()}
 return result

def decode_files(state,value):
 if not isinstance(value,dict) or not set(names(state))<=set(value) or set(value)-set(names(state))-set(optional_names(state)):raise ValueError('Recovery has missing or unexpected protocol identity files')
 decoded={};total=0
 for name,record in value.items():
  if not isinstance(record,dict) or set(record)!={'content','sha256'}:raise ValueError('Invalid recovery identity record')
  try:data=base64.b64decode(record['content'],validate=True)
  except (ValueError,TypeError):raise ValueError('Invalid recovery identity encoding') from None
  if not 0<len(data)<=131072 or hashlib.sha256(data).hexdigest()!=record.get('sha256'):raise ValueError('Recovery identity checksum changed')
  total+=len(data)
  if total>MAX_FILES_BYTES:raise ValueError('Recovery identity material is too large')
  decoded[name]=data
 return decoded

def validate_state(state,role):
 if not isinstance(state,dict) or state.get('protocol') not in NATIVE:raise ValueError('Unsupported recovery identity adapter')
 protocol=state['protocol']
 if set(state)-COMMON-FIELDS[protocol] or state.get('owner')!='rookstride-single-v1':raise ValueError('Unexpected recovery identity fields')
 pair.host(state.get('server'));pair.ident(state.get('instance'));pair.username(state.get('initialLogin'))
 if type(state.get('port')) is not int or not 1<=state['port']<=65535:raise ValueError('Invalid recovery listener port')
 if state.get('access_mode','profile') not in ('profile','password') or state.get('access_mode')=='password' and protocol not in {'ikev2','openvpn','hysteria2','trusttunnel','naive'}:raise ValueError('Invalid recovery authentication mode')
 if not isinstance(state.get('users'),list) or not 1<=len(state['users'])<=252:raise ValueError('Invalid recovery account count')
 seen=set();addresses=set();identities=set()
 for user in state['users']:
  if not isinstance(user,dict) or set(user)-USER_COMMON-USERS[protocol]:raise ValueError('Unexpected recovery account fields')
  login=pair.username(user.get('login'))
  if login in seen:raise ValueError('Duplicate recovery login')
  seen.add(login)
  if type(user.get('enabled')) is not bool or type(user.get('created')) is not int or user['created']<0:raise ValueError('Invalid recovery user state')
  for label in ('person','device'):
   if label in user:native_pair.model.display_label(user[label])
  if protocol=='awg':
   for key in ('private','public','psk'):pair.key(user.get(key))
   key_pair(user['private'],user['public'])
   address=ipaddress.IPv4Address(user['address']);pool=ipaddress.IPv4Network('10.66.0.0/24' if role=='entry' else '10.67.0.0/24')
   if address not in pool or address in (pool.network_address,pool.broadcast_address):raise ValueError('Recovery client pool changed')
   ipaddress.IPv6Address(user['ipv6'])
   if str(address) in addresses or user['public'] in identities:raise ValueError('Duplicate recovery client identity')
   addresses.add(str(address));identities.add(user['public'])
  elif protocol in ('xray','xhttp'):
   if str(uuid.UUID(user.get('uuid','')))!=user.get('uuid') or user['uuid'] in identities:raise ValueError('Invalid or duplicate recovery client UUID')
   identities.add(user['uuid'])
  elif protocol=='openvpn':
   if state.get('access_mode')=='password':
    if not re.fullmatch(r'pbkdf2-sha256\$310000\$[a-f0-9]{32}\$[a-f0-9]{64}',user.get('password_hash','')):raise ValueError('Invalid recovery password hash')
   else:native_pair.model.label(login)
  else:
   secret=user.get('password');pair.vpn_password(secret)
   if protocol in ('outline','shadowsocks'):
    if not re.fullmatch(r'/[a-f0-9]{48}',user.get('path','')):raise ValueError('Invalid private WebSocket route')
 if protocol=='ikev2':recovery_ike.ike_public.aliases(state.get('aliases',[]))
 elif protocol=='awg':
  pair.key(state.get('private'));pair.key(state.get('public'));key_pair(state['private'],state['public']);parameters=state.get('parameters')
  if not isinstance(parameters,dict) or set(parameters)!=set(native_pair.model.awg_parameters()):raise ValueError('Invalid AWG identity parameters')
  for name,value in parameters.items():
   if name=='HeaderProtectionKey':pair.key(value)
   elif not isinstance(value,str) or not re.fullmatch(r'(?:[0-9]{1,10}(?:-[0-9]{1,10})?|on|off)',value):raise ValueError('Invalid AWG identity parameter value')
 elif protocol in ('xray','xhttp'):
  for key in ('private','public'):
   if not re.fullmatch(r'[A-Za-z0-9_-]{43}',state.get(key,'')) or len(base64.urlsafe_b64decode(state[key]+'='))!=32:raise ValueError('Invalid REALITY identity')
  key_pair(state['private'],state['public'],True)
  if not re.fullmatch(r'[a-f0-9]{16}',state.get('shortId','')):raise ValueError('Invalid REALITY short identity')
  native_pair.model.hostname(state.get('sni'))
  if protocol=='xhttp' and not re.fullmatch(r'/[a-f0-9]{48}',state.get('path','')):raise ValueError('Invalid XHTTP route')
 elif protocol=='openvpn':
  revoked=state.get('revoked',[])
  if not isinstance(revoked,list) or len(revoked)>10000 or len(revoked)!=len(set(revoked)):raise ValueError('Invalid revoked certificate names')
  for login in revoked:native_pair.model.label(login)
 elif protocol in WORKERS:
  if state.get('tls_leaf') and not re.fullmatch(r'leaf-[a-f0-9]{32}',state['tls_leaf']):raise ValueError('Invalid TLS identity generation')
  native_pair.model.hostname(state.get('tls_name',state['server']))
  if protocol=='hysteria2' and state.get('access_mode')!='password' and (not isinstance(state.get('obfs'),str) or not 16<=len(state['obfs'])<=128):raise ValueError('Missing QUIC obfuscation identity')
 return state

def verify_certificates(state,data):
 if not data:return
 protocol=state['protocol'];checks=[]
 if protocol in WORKERS|{'ikev2'}:
  leaf=state.get('tls_leaf','');prefix='tls/'+(leaf+'/' if leaf else '')
  checks=[('tls/ca.pem','tls/ca.key',None),(prefix+'server.pem',prefix+'server.key','tls/ca.pem')]
 elif protocol=='openvpn':
  checks=[('runtime/pki/ca.crt','runtime/pki/private/ca.key',None),('runtime/pki/issued/server.crt','runtime/pki/private/server.key','runtime/pki/ca.crt')]
  checks += [('runtime/pki/issued/'+u['login']+'.crt','runtime/pki/private/'+u['login']+'.key','runtime/pki/ca.crt') for u in state['users']]
  if not re.fullmatch(rb'[0-9A-Fa-f]+\s*',data['runtime/pki/serial']) or 'runtime/pki/crlnumber' in data and not re.fullmatch(rb'[0-9A-Fa-f]+\s*',data['runtime/pki/crlnumber']):raise ValueError('Invalid OpenVPN authority counters')
  if not re.fullmatch(rb'unique_subject\s*=\s*(?:yes|no)\s*',data['runtime/pki/index.txt.attr']):raise ValueError('Unexpected OpenVPN authority attributes')
  for line in data['runtime/pki/index.txt'].decode().splitlines():
   fields=line.split('\t')
   if len(fields)!=6 or fields[0] not in ('V','R','E') or not re.fullmatch(r'[0-9A-Fa-f]+',fields[3]) or fields[4]!='unknown' or not re.fullmatch(r'/CN=[A-Za-z0-9_-]{1,64}',fields[5]):raise ValueError('Unexpected OpenVPN authority index')
  if not re.fullmatch(rb'(?s)(?:#[^\n]*\n)*-----BEGIN OpenVPN Static key V1-----\s*[0-9a-f\s]+-----END OpenVPN Static key V1-----\s*',data['runtime/tls-crypt.key']):raise ValueError('Invalid OpenVPN transport key')
 with tempfile.TemporaryDirectory(prefix='rook-recovery-verify-') as folder:
  root=Path(folder)
  for name,content in data.items():
   path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);path.chmod(0o600)
  def run(args):
   value=subprocess.run(['openssl',*args],capture_output=True,timeout=15)
   if value.returncode:raise ValueError('Recovery certificate or private key did not verify')
   return value.stdout
  for cert,key,ca in checks:
   public=run(['x509','-in',str(root/cert),'-pubkey','-noout']);private_public=run(['pkey','-in',str(root/key),'-pubout'])
   if not public.startswith(b'-----BEGIN PUBLIC KEY-----') or public!=private_public:raise ValueError('Recovery certificate and key do not match')
   if ca:
    verify_args=['verify','-CAfile',str(root/ca)]
    if protocol in WORKERS|{'ikev2'}:
     endpoint=state.get('tls_name',state['server'])
     try:ipaddress.ip_address(endpoint);option='-verify_ip'
     except ValueError:option='-verify_hostname'
     verify_args += [option,endpoint]
    if protocol=='openvpn' and (cert.endswith('/server.crt') or any(cert.endswith('/'+u['login']+'.crt') and u.get('enabled',True) for u in state['users'])):verify_args += ['-CRLfile',str(root/'runtime/pki/crl.pem'),'-crl_check']
    if not run([*verify_args,str(root/cert)]).strip().endswith(b': OK'):raise ValueError('Recovery certificate verification was not confirmed')
   if protocol=='openvpn' and cert.startswith('runtime/pki/issued/'):
    name=Path(cert).stem;subject=run(['x509','-in',str(root/cert),'-noout','-subject','-nameopt','RFC2253']).decode().strip().replace('subject= ','subject=')
    if subject!='subject=CN='+name:raise ValueError('OpenVPN certificate account identity changed')
  if protocol=='openvpn':run(['crl','-in',str(root/'runtime/pki/crl.pem'),'-CAfile',str(root/'runtime/pki/ca.crt'),'-verify','-noout'])

def validate(state,role,identity_files):
 validate_state(state,role);data=decode_files(state,identity_files);verify_certificates(state,data);return data

def restore_state(snapshot,current):
 state=copy.deepcopy(snapshot['state']);state['instance']=current['instance']
 for key in ('filtering','pair_dns',*EPHEMERAL):
  state.pop(key,None)
  if key in current:state[key]=copy.deepcopy(current[key])
 if state['protocol'] in ('outline','shadowsocks'):
  import routes
  used=[state['port'],state['metrics_port']]
  for user in state['users']:user['private_port']=routes.port(used);used.append(user['private_port'])
 return state

def install_files(state,data):
 root=native_pair.runtime.directory(state['protocol'])
 for name,content in data.items():
  path=root/name
  for parent in (path,*path.parents):
   pair.protected(parent)
   if parent==root:break
  native_pair.runtime.atomic(path,content.decode())

def client_profile(state,login,identity_files):
 user=next((u for u in state['users'] if u['login']==login and u['enabled']),None)
 if user is None:raise ValueError('Archived bridge user is not enabled')
 protocol=state['protocol'];data=decode_files(state,identity_files)
 if protocol=='ikev2':return recovery_ike.profile(state,login,data)
 if protocol=='awg':return native_pair.model.awg_client(state,user)
 if protocol in ('xray','xhttp'):return native_pair.model.xray_uri(state,user)
 if protocol=='openvpn':
  if state.get('access_mode')=='password':return None # Pair exit currently uses certificate mode.
  cert=data['runtime/pki/issued/'+login+'.crt'].decode();cert=cert[cert.index('-----BEGIN CERTIFICATE-----'):]
  return native_pair.model.openvpn_client(state,user,data['runtime/pki/ca.crt'].decode(),cert,data['runtime/pki/private/'+login+'.key'].decode(),data['runtime/tls-crypt.key'].decode())
 value={'schema':1,'protocol':protocol,'server':state['server'],'port':state['port'],'login':login,'password':user['password'],'server_name':state.get('tls_name',state['server'])}
 if state.get('access_mode')=='password':value['access_mode']='password'
 else:value['certificate']=data['tls/ca.pem'].decode()
 if protocol in ('outline','shadowsocks'):value.update(method='chacha20-ietf-poly1305',path=user['path'])
 if protocol=='hysteria2' and state.get('access_mode')!='password':value['obfs']=state['obfs']
 return value
