"""IKEv2 recovery data only: approved identity files and parsed EAP accounts."""
import base64,hashlib,ipaddress,json,re,shlex,ssl,urllib.request,urllib.parse,uuid
from pathlib import Path
import pair,native_pair,ike_public
from rookstride import admin
FILES={'tls/ca.pem':Path('/etc/ipsec.d/cacerts/single-vps-ca.pem'),'tls/ca.key':Path('/root/single-vps-vpn/ca-key.pem'),'tls/server.pem':ike_public.CERT,'tls/server.key':ike_public.KEY}

def accounts():
 result=[];catalog=admin.catalog()
 for line in admin.SECRETS.read_text().splitlines():
  try:parts=shlex.split(line,comments=True)
  except ValueError:raise ValueError('An IKE secret record could not be interpreted safely') from None
  if len(parts)>=3 and parts[1:3]==[':','EAP']:
   if len(parts)!=4:raise ValueError('Unsupported IKE account record')
   login=pair.username(parts[0]);password=pair.vpn_password(parts[3]);metadata=catalog.get(login,{})
   result.append({'login':login,'password':parts[3],'enabled':True,'created':0,'person':metadata.get('person',login),'device':metadata.get('device','Shared login')})
 return result

def state(p):
 for path in (admin.SECRETS,admin.STATE/'users.json',ike_public.CERT):pair.protected(path)
 public=ike_public.status();endpoint=p['server'] if p['role']=='entry' else p['exit_host'];initial=native_pair.initial()
 value={'protocol':'ikev2','server':endpoint,'port':p['vpn_port'] if p['role']=='entry' else p['tunnel_port'],'initialLogin':initial['login'],'instance':hashlib.sha256(ike_public.CERT.read_bytes()).hexdigest()[:32],'owner':'rookstride-single-v1','users':accounts(),'access_mode':'password' if public else 'profile'}
 if public:value['aliases']=public.get('aliases',[])
 if p['role']=='entry':value.update(pair=p['pair'],pair_dns=json.loads((pair.OWN/'transport.json').read_text())['dns'])
 return value

def files(value):
 if value.get('access_mode')=='password':return {}
 result={}
 for name,path in FILES.items():
  pair.protected(path);data=path.read_bytes()
  if not 0<len(data)<131072:raise ValueError('Invalid owned IKE identity file')
  result[name]={'content':base64.b64encode(data).decode(),'sha256':hashlib.sha256(data).hexdigest()}
 return result

def restore(value,data,new_endpoint=False):
 if value.get('access_mode')=='password' and value.get('aliases') and not new_endpoint:ike_public.enable(value['aliases'])
 # Preserve the freshly generated RSA directive, never restore arbitrary secrets
 # syntax or include statements. Rebuild each EAP record from validated fields.
 lines=[]
 for line in admin.SECRETS.read_text().splitlines():
  parts=shlex.split(line,comments=True)
  if not parts:continue
  if len(parts)==4 and parts[1:3]==[':','RSA'] and parts[3]=='single-vps-server-key.pem':lines.append(line)
  elif len(parts)==4 and parts[1:3]==[':','EAP']:continue
  else:raise ValueError('The fresh IKE secret file contains unrecognized directives')
 if len(lines)!=1:raise ValueError('The fresh IKE server identity directive is missing')
 changed={str(admin.SECRETS)}
 for name,content in data.items():
  path=FILES[name];pair.protected(path);pair.atomic(path,content.decode());changed.add(str(path))
 if new_endpoint and data:
  # Updated profiles use the reviewed new endpoint; keep the CA but sign a new
  # endpoint-bound leaf. No insecure hostname-validation bypass is introduced.
  folder=pair.OWN/'recovery-identity';folder.mkdir(mode=0o700,parents=True,exist_ok=True);name=value['server']
  try:ipaddress.ip_address(name);kind='IP'
  except ValueError:kind='DNS'
  pair.atomic(folder/'extensions','basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\nsubjectAltName='+kind+':'+name+'\n')
  native_pair.command(['openssl','req','-new','-key',str(ike_public.KEY),'-subj','/CN='+name,'-out',str(folder/'request.pem')])
  native_pair.command(['openssl','x509','-req','-in',str(folder/'request.pem'),'-CA',str(FILES['tls/ca.pem']),'-CAkey',str(FILES['tls/ca.key']),'-CAserial',str(folder/'serial'),'-CAcreateserial','-days','825','-extfile',str(folder/'extensions'),'-out',str(ike_public.CERT)])
 catalog={}
 for user in value['users']:
  if not user['enabled']:continue
  secret=user['password'].replace('\\','\\\\').replace('"','\\"');lines.append(user['login']+' : EAP "'+secret+'"')
  catalog[user['login']]={'person':user.get('person',user['login']),'device':user.get('device','Shared login'),'kind':'shared'}
 pair.atomic(admin.SECRETS,'\n'.join(lines)+'\n');pair.atomic(admin.STATE/'users.json',json.dumps(catalog))
 # Advance only these reviewed data files. Unknown config hashes are retained.
 path=pair.OWN/'ike-files.sha256';pair.protected(path);output=[];seen=set()
 for line in path.read_text().splitlines():
  digest,filename=line.split('  ',1)
  if filename in changed:digest=hashlib.sha256(Path(filename).read_bytes()).hexdigest();seen.add(filename)
  output.append(digest+'  '+filename)
 required=changed-{str(FILES['tls/ca.key'])}
 if not required<=seen:raise ValueError('The owned IKE identity checksums are incomplete')
 pair.atomic(path,'\n'.join(output)+'\n');native_pair.command(['ipsec','rereadall']);native_pair.command(['ipsec','reload'])
 native_pair.command(['systemctl','is-active','--quiet','strongswan-starter'])

def profile(value,login,data):
 user=next(u for u in value['users'] if u['login']==login and u['enabled'])
 if not data:raise ValueError('The IKE exit bridge requires the reviewed pinned server identity')
 return {'server':value['server'],'identity':value['server'],'certificate':base64.b64encode(ssl.PEM_cert_to_DER_cert(data['tls/server.pem'].decode())).decode(),'login':login,'password':user['password']}

def filter_api(endpoint,body=None):
 login=Path('/root/single-vps-vpn/adguard-login.txt');pair.protected(login);creds=dict(line.split(': ',1) for line in login.read_text().splitlines() if ': ' in line);url=creds['Dashboard'];parsed=urllib.parse.urlsplit(url)
 if parsed.scheme!='http' or parsed.port!=3000 or parsed.username or parsed.path not in ('','/') or not ipaddress.ip_address(parsed.hostname).is_private:raise ValueError('Unexpected owned IKE DNS dashboard')
 authorization=base64.b64encode((creds['Username']+':'+creds['Password']).encode()).decode();request=urllib.request.Request(url.rstrip('/')+'/control/'+endpoint,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Basic '+authorization,'Content-Type':'application/json'})
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=65) as response:
  raw=response.read(1048577)
  if len(raw)>1048576:raise ValueError('Private filtering response too large')
  return json.loads(raw) if raw.startswith(b'{') else {}
