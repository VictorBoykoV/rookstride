#!/usr/bin/env python3
"""Versioned, server-enforced administrative access over a forced SSH command.

There is no network listener. The only remote entry is a locked per-credential
Unix account, mapped by sudo's authenticated SUDO_USER, never a JSON actor field.
A paired authority proxies bounded JSON to a fixed, pinned peer; no forwarding.
"""
import base64, contextlib, fcntl, hashlib, json, os, re, secrets, shutil, sqlite3, struct, subprocess, sys, tempfile, time
from pathlib import Path

SCHEMA = 1
ROOT = Path('/var/lib/rookstride-access')
HELPER = '/usr/local/sbin/rookstride-access'
ACCOUNTS = Path('/var/lib/rookstride-access-accounts')
SINGLE_STATE = Path('/var/lib/rookstride-single')
MAX_REQUEST = 65536
ROLES = {
 'owner': {'access.read','audit.read','users.read','usage.read','users.create','users.revoke','users.update','users.profile','grants.manage','invitations.manage','peers.manage','lifecycle.inspect','services.manage','filtering.read','filtering.manage'},
 'infrastructure': {'access.read','audit.read','users.read','usage.read','users.create','users.revoke','users.update','users.profile','lifecycle.inspect','services.manage','filtering.read','filtering.manage'},
 'user_manager': {'users.read','usage.read','users.create','users.revoke','users.update','users.profile'},
 'viewer': {'users.read','usage.read','audit.read','lifecycle.inspect'},
}
OPS = {'usage.read':'usage.read','users.list':'users.read','users.create':'users.create','users.revoke':'users.revoke','users.update':'users.update','users.profile':'users.profile','lifecycle.inspect':'lifecycle.inspect','services.review':'services.manage','services.apply':'services.manage','filtering.read':'filtering.read','filtering.review':'filtering.manage','filtering.apply':'filtering.manage'}
ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$')

# Fixed adapter code, not supplied by a client. Instance verification and the
# existing protocol operation share the legacy management locks, closing the
# check/use gap against concurrent owner reset/reinstallation.
ADAPTER_RUNNER = r"""
import contextlib,fcntl,hashlib,importlib,importlib.util,json,secrets,sys
from pathlib import Path
request=json.load(sys.stdin);helper=Path(sys.argv[1]);kind=sys.argv[2]
try:
 # Older phones sent unused optional labels as empty strings. Normalize only
 # this isolated create request; the authority's original replay digest stays
 # unchanged, and password/login and edit validation remain the protocol's.
 if request.get('action')=='add-user':
  for field in ('person','device'):
   if request.get(field)=='':request.pop(field)
 with contextlib.ExitStack() as stack:
  locks=['/run/rookstride-management.lock']+(['/run/rookstride-single.lock'] if kind=='single' else [])
  for name in locks:
   lock=stack.enter_context(open(name,'a'));fcntl.flock(lock,fcntl.LOCK_EX)
  if kind=='single':
   sys.path.insert(0,str(helper.parent));spec=importlib.util.spec_from_file_location('rookstride_scoped_protocol',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
   if module.runtime.load(request['protocol']).get('instance')!=request['expected_instance']:raise ValueError('Installed protocol identity changed; owner inspection is required')
   if request.get('_pair_id'):
    state=module.runtime.load(request['protocol']);manifest=json.loads(Path('/etc/rookstride-pair/manifest.json').read_text());plan=manifest.get('plan',{})
    if manifest.get('version')!=2 or plan.get('pair')!=request['_pair_id']:raise ValueError('Pair identity changed before account operation')
    if request['_pair_mode']=='coexist':
     if request['protocol']!='openvpn' or state.get('coexist_pair')!=plan['pair'] or plan.get('role')!='entry' or plan.get('entry_protocol')!='awg' or plan.get('client_pool')!='10.66.0.0/24' or not manifest.get('activated') or manifest.get('resetting'):raise ValueError('Coexisting protocol ownership changed')
    elif request['protocol']!=(plan.get('entry_protocol') if plan.get('role')=='entry' else plan.get('exit_protocol')):raise ValueError('Paired protocol ownership changed')
  else:
   sys.path.insert(0,str(helper.parent.parent));module=importlib.import_module('rookstride.admin')
   if module.health().get('instance')!=request['expected_instance']:raise ValueError('Installed IKEv2 identity changed; owner inspection is required')
  def identities():
   if kind=='single':return {u['login']:u.get('administration_account_id') for u in module.runtime.load(request['protocol']).get('users',[])}
   return {login:meta.get('administration_account_id') for login,meta in module.catalog().items()}
  if request.get('expected_account_id') and identities().get(request.get('login'))!=request['expected_account_id']:raise ValueError('This account was replaced; it is no longer issued by this administrator')
  before_ids=identities()
  if kind=='single' and request['action']=='add-user' and 'password' in request:
   state=module.runtime.load(request['protocol'])
   password_users=state.get('access_mode')=='password' and state['protocol'] in ('openvpn','hysteria2','trusttunnel','naive')
   # Legacy key-only create requests supplied an unused empty password. Never
   # report success for a chosen password that this installation will ignore.
   if not password_users and request['password']!='':raise ValueError('This VPN uses a generated connection profile, not a chosen password')
  if request['action']=='scoped-infrastructure':
   operation=request['_operation'];parameters=request.get('_parameters',{})
   if kind!='single':raise ValueError('Delegated listener and ad blocker maintenance requires the native service adapter. The owner can maintain this IKEv2 installation.')
   state=module.runtime.load(request['protocol']);affected=[{'protocol':state['protocol'],'instance':state['instance']}]
   material={'state':state};group=operation.split('.')[0]
   for filename in ('worker.json','runtime/server.json'):
    config=module.runtime.directory(state['protocol'])/filename
    if config.is_file():
     if config.is_symlink():raise ValueError('Unexpected VPN configuration link')
     material[filename]=hashlib.sha256(config.read_bytes()).hexdigest()
   if group=='services':
    if request.get('_pair_id') or state.get('pair_dns') or state.get('coexist_pair'):raise ValueError('Double VPN listener maintenance needs the owner routing controller; this action was not started')
    units=[]
    if state['protocol'] in ('awg','openvpn'):
     inspected=module.runtime.check_container(state)
     if not inspected:raise ValueError('The owned VPN container is missing; ask the owner to repair this installation')
     material['container']={'Id':inspected['Id'],'Config':inspected['Config'],'HostConfig':inspected['HostConfig']}
    else:
     for suffix in (['','-endpoint'] if state['protocol']=='trusttunnel' else ['']):
      name='rookstride-single-'+state['protocol']+suffix;path=Path('/etc/systemd/system')/(name+'.service')
      if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:raise ValueError('VPN service ownership changed')
      content=path.read_text()
      if 'Description=Rookstride ' not in content:raise ValueError('VPN service is not recognized')
      units.append(name);material[name]=content
   else:
    if not state.get('filtering'):raise ValueError('This VPN uses remote or unavailable ad blocking; manage the exit server instead')
    current=module.runtime.filtering.load()
    if current['instance']!=state['filtering']:raise ValueError('Ad blocker identity changed')
    affected=[]
    for protocol in module.runtime.filtering.references():
     other=module.runtime.load(protocol);affected.append({'protocol':protocol,'instance':other['instance']})
    material.update(filter=current,affected=affected)
   guard=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
   if operation.endswith('.apply'):
    if request.get('_guard')!=guard:raise ValueError('Service state changed after review; inspect it again')
    module.runtime.user_updates.ensure_no_runtime_update()
    if group=='filtering':
     if sorted(affected,key=lambda o:o['protocol'])!=sorted(request.get('_affected',[]),key=lambda o:o['protocol']):raise ValueError('Shared ad blocker consumers changed')
     result=module.runtime.filtering.control(parameters)
    else:
     if parameters.get('action')=='repair':module.runtime.apply_config(state)
     elif state['protocol'] in ('awg','openvpn'):module.runtime.command(['docker','restart',module.runtime.container(state['protocol'])])
     else:
      for unit in units:module.runtime.command(['systemctl','restart',unit])
     health=module.runtime.health(state);result={'changed':True,'running':bool(health.get('running')),'listener_restarted':True}
   elif operation=='filtering.read':result={**module.runtime.filtering.control({}),'_affected':affected}
   else:result={'guard':guard,'affected':affected,'review':parameters,'message':'This restarts the selected VPN listener. Connected users may reconnect; accounts and profiles are kept.' if group=='services' else 'This changes ad blocking for every VPN using this shared resolver.'}
  elif request['action']=='edit-user' and kind=='ikev2' and 'password' in request:
   if request['login'] not in [u['login'] for u in module.user_inventory()]:raise ValueError('User does not exist')
   meta=module.catalog().get(request['login'],{})
   result=module.dispatch({**request,'action':'add-user','replace':True,'person':request.get('person',meta.get('person',request['login'])),'device':request.get('device',meta.get('device','Shared login'))})
  else:result=module.action(request) if kind=='single' else module.dispatch(request)
  if request['action']=='edit-user' and kind=='ikev2' and before_ids.get(request.get('login')):
   catalog=module.catalog();catalog[request['login']]['administration_account_id']=before_ids[request['login']];module.atomic(module.STATE/'users.json',json.dumps(catalog))
  if request['action']=='add-user':
   account_id=secrets.token_hex(16)
   if kind=='single':
    state=module.runtime.load(request['protocol']);user=next(u for u in state['users'] if u['login']==request['login']);user['administration_account_id']=account_id;module.runtime.save(state)
   else:
    catalog=module.catalog();catalog[request['login']]['administration_account_id']=account_id;module.atomic(module.STATE/'users.json',json.dumps(catalog))
   result['_created_account_id']=account_id
  result['_account_ids']=identities()
 print(json.dumps({'ok':True,'result':result}))
except Exception as error:
 print(json.dumps({'ok':False,'error':str(error) if isinstance(error,ValueError) else 'Protocol action failed'}))
 if request.get('action')!='scoped-infrastructure':sys.exit(1)
"""

class Denied(ValueError): pass

def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def token(prefix=''): return prefix + secrets.token_hex(16)
def ident(value):
 if not isinstance(value,str) or not ID.fullmatch(value): raise ValueError('Invalid identifier')
 return value

def bounded_text(value, maximum=128):
 if not isinstance(value,str) or not value.strip() or len(value)>maximum or any(ord(c)<32 for c in value): raise ValueError('Invalid display value')
 return value

def public_key(value):
 if not isinstance(value,str) or len(value)>1800: raise ValueError('Invalid device key')
 parts=value.strip().split()
 if len(parts)!=2 or parts[0]!='ssh-rsa': raise ValueError('A RSA device key is required')
 try:
  raw=base64.b64decode(parts[1],validate=True); pos=0; fields=[]
  for _ in range(3):
   n=struct.unpack('>I',raw[pos:pos+4])[0];pos+=4
   if n>1024 or pos+n>len(raw):raise ValueError()
   fields.append(raw[pos:pos+n]);pos+=n
  if pos!=len(raw) or fields[0]!=b'ssh-rsa' or int.from_bytes(fields[1],'big')!=65537 or not 3072<=int.from_bytes(fields[2],'big').bit_length()<=8192:raise ValueError()
 except (ValueError,struct.error):raise ValueError('Invalid device RSA key') from None
 return 'ssh-rsa '+parts[1]

def fingerprint(key): return 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1])).digest()).decode().rstrip('=')

def run(args, data=None, limit=2*1024*1024):
 # Bound output while it arrives, rather than after communicate has allocated it.
 # Fixed executable/arguments only; no client-controlled shell or environment.
 import selectors
 selector=selectors.DefaultSelector();process=subprocess.Popen(args,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 output=bytearray();errors=0;offset=0;deadline=time.monotonic()+120
 try:
  for stream,label in ((process.stdout,'out'),(process.stderr,'err')):os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,label)
  if data is not None:
   if not data:process.stdin.close()
   else:os.set_blocking(process.stdin.fileno(),False);selector.register(process.stdin,selectors.EVENT_WRITE,'in')
  while selector.get_map():
   if time.monotonic()>=deadline:raise subprocess.TimeoutExpired(args,120)
   for key,event in selector.select(min(.25,max(0,deadline-time.monotonic()))):
    stream=key.fileobj
    if key.data=='in':
     try:offset+=os.write(stream.fileno(),data[offset:offset+8192])
     except BrokenPipeError:offset=len(data)
     if offset==len(data):selector.unregister(stream);stream.close()
    else:
     value=os.read(stream.fileno(),65536)
     if not value:selector.unregister(stream);stream.close();continue
     if key.data=='out':
      if len(output)+len(value)>limit:raise ValueError('Management response too large')
      output.extend(value)
     else:
      errors+=len(value)
      if errors>65536:raise ValueError('Management diagnostic output too large')
  if process.wait(timeout=max(.1,deadline-time.monotonic())):raise ValueError('Local management operation failed')
  return bytes(output)
 finally:
  selector.close()
  if process.poll() is None:process.kill()
  process.wait()
  for stream in (process.stdin,process.stdout,process.stderr):
   if stream is not None and not stream.closed:stream.close()

def make_key():
 with tempfile.TemporaryDirectory() as temp:
  path=Path(temp)/'key';run(['/usr/bin/ssh-keygen','-q','-t','rsa','-b','3072','-m','PEM','-N','','-f',str(path)])
  return path.read_text(),public_key(' '.join(path.with_suffix('.pub').read_text().split()[:2]))

def proof_message(invitation, key):
 return ('rookstride-admin-enroll-v1\n'+invitation['id']+'\n'+invitation['server_id']+'\n'+invitation['nonce']+'\n'+fingerprint(key)+'\n').encode()

def verify_proof(invitation,key,signature):
 try:
  key=public_key(key);raw=base64.b64decode(key.split()[1],validate=True);offset=0;modulus=b''
  for _ in range(3):
   length=struct.unpack('>I',raw[offset:offset+4])[0];offset+=4;modulus=raw[offset:offset+length];offset+=length
  signature=base64.b64decode(signature,validate=True)
  if len(signature)!=(int.from_bytes(modulus,'big').bit_length()+7)//8:raise ValueError()
 except (ValueError,TypeError,struct.error):raise Denied('Invalid device proof') from None
 with tempfile.TemporaryDirectory() as temp:
  p=Path(temp);(p/'key').write_text(key+'\n');(p/'signature').write_bytes(signature)
  (p/'public.pem').write_bytes(run(['/usr/bin/ssh-keygen','-e','-m','PKCS8','-f',str(p/'key')]))
  try:
   verified=run(['/usr/bin/openssl','dgst','-sha256','-verify',str(p/'public.pem'),'-signature',str(p/'signature')],proof_message(invitation,key))
   if verified.strip()!=b'Verified OK':raise ValueError('Signature verification did not succeed')
  except ValueError:raise Denied('Device key proof was rejected') from None

class System:
 """Privileged OS effects. Tests inject an isolated implementation, not auth."""
 def account(self,name,key,expires=None):
  if not re.fullmatch(r'rs[bdp][a-f0-9]{20}',name):raise ValueError('Invalid credential account')
  home=ACCOUNTS/name
  import pwd
  try:
   info=pwd.getpwnam(name)
   if info.pw_dir!=str(home) or info.pw_shell!='/bin/sh':raise ValueError('Credential account conflict')
  except KeyError:run(['/usr/sbin/useradd','--system','--no-create-home','--home-dir',str(home),'--shell','/bin/sh','--gid','rookstride-access',name])
  home.parent.mkdir(mode=0o755,parents=True,exist_ok=True);home.parent.chmod(0o755)
  home.mkdir(mode=0o755,parents=True,exist_ok=True);os.chown(home,0,0);home.chmod(0o755)
  line='restrict,command="/usr/bin/sudo -n '+HELPER+'"'
  # Ubuntu 22.04's OpenSSH 8.9 accepts only server-local absolute timestamps,
  # not the newer UTC suffix. The dispatcher independently enforces epoch
  # expiry on every bootstrap request, including an already-open SSH session.
  if expires:line+=',expiry-time="'+time.strftime('%Y%m%d%H%M%S',time.localtime(expires))+'"'
  effective=run(['/usr/sbin/sshd','-T','-C','user='+name+',host=localhost,addr=127.0.0.1']).decode()
  required=['forcecommand /usr/bin/sudo -n '+HELPER,'disableforwarding yes','permittty no','permituserrc no','passwordauthentication no','authenticationmethods publickey','authorizedkeysfile '+str(ACCOUNTS)+'/%u/authorized_keys']
  if any(item not in effective.splitlines() for item in required):raise Denied('SSH restrictions are overridden; owner review is required')
  self.atomic(home/'authorized_keys',line+' '+public_key(key)+'\n',0o644)
 def revoke(self,name):
  p=ACCOUNTS/name/'authorized_keys'
  if p.exists():self.atomic(p,'',0o644)
  # Ends existing SSH sessions as well as new connections. No generic forwards exist.
  subprocess.run(['/usr/bin/pkill','-KILL','-u',name],capture_output=True,timeout=10)
 def atomic(self,path,text,mode=0o600):
  if path.is_symlink():raise ValueError('Unexpected management state link')
  temporary=path.with_name(path.name+'.'+secrets.token_hex(6));fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
  with os.fdopen(fd,'w') as out:os.fchmod(out.fileno(),mode);out.write(text);out.flush();os.fsync(out.fileno())
  os.replace(temporary,path)
 def execute(self,obj,operation,parameters):
  # The root-enrolled object fixes the protocol, installation identity and adapter.
  live=discover(obj['server_id'],obj['deployment_id'])
  if obj not in live:raise Denied('Installed protocol identity changed; owner inspection is required')
  action={'usage.read':'status','users.list':'status','users.create':'add-user','users.revoke':'remove-user','users.update':'edit-user','users.profile':'profile','services.review':'scoped-infrastructure','services.apply':'scoped-infrastructure','filtering.read':'scoped-infrastructure','filtering.review':'scoped-infrastructure','filtering.apply':'scoped-infrastructure'}[operation]
  req={'action':action,**parameters}
  if action=='scoped-infrastructure':req={'action':action,'_operation':operation,**parameters}
  if obj['protocol']=='ikev2':
   helper=Path('/opt/rookstride/server/rookstride/admin.py');kind='ikev2'
  else:
   req['protocol']=obj['protocol'];helper=Path('/opt/rookstride-single/current/single/run.py')
   pair_manifest=Path('/etc/rookstride-pair/manifest.json')
   if pair_manifest.is_file():
    manifest=json.loads(pair_manifest.read_text());plan=manifest.get('plan',{})
    state=json.loads((Path('/var/lib/rookstride-single')/obj['protocol']/'state.json').read_text())
    req['_pair_mode']=pair_protocol_mode(manifest,obj,state);req['_pair_id']=plan['pair']
    helper=Path('/opt/rookstride-pair/single/run.py')
   resolved=helper.resolve()
   if not (str(resolved).startswith('/opt/rookstride-single/releases/') or str(resolved)=='/opt/rookstride-pair/single/run.py'):raise Denied('Protocol helper path is not owned')
   for path in (resolved,*resolved.parents):
    if path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode & 0o022):raise Denied('Protocol helper ownership changed')
   kind='single'
  if not helper.is_file():raise ValueError('Compatible owner-installed protocol helper is required')
  for path in (helper.resolve(),*helper.resolve().parents):
   if path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode & 0o022):raise Denied('Protocol helper ownership changed')
  req['expected_instance']=obj['instance']
  args=['/usr/bin/python3','-I','-c',ADAPTER_RUNNER,str(helper),kind]
  result=json.loads(run(args,canonical(req).encode()))
  if not result.get('ok'):raise ValueError(result.get('error','Protocol action failed; inspect the VPN before retrying') if action=='scoped-infrastructure' else 'Protocol action failed; inspect the VPN before retrying')
  data=result['result']
  if operation=='usage.read':
   fields=('user','upload','download','generation','counter_scope','recent')
   return {'connections':[{k:row[k] for k in fields if k in row} for row in data.get('connections',[])], 'monthly':[{k:row[k] for k in ('user','upload','download') if k in row} for row in data.get('monthly',[])], 'monitoring_available':data.get('monitoring_available',False),'estimated':True,'_account_ids':data.get('_account_ids',{})}
  if operation=='users.list':
   # Health contains users, sessions and usage. Never return daemon state or secrets.
   return {'users':[{'login':u['login'],'person':u.get('person',''),'device':u.get('device',''),'_account_id':data.get('_account_ids',{}).get(u['login'])} for u in data.get('users',[])]}
  return data
 def peer(self,peer,request):
  # All endpoint, account, key and pin values originate in owner-only linking.
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);(p/'key').write_text(peer['private_key']);(p/'key').chmod(0o600)
   host=peer['endpoint']['host'];port=peer['endpoint']['port']
   known_host=host if port==22 else '['+host+']:'+str(port)
   (p/'known').write_text(known_host+' '+peer['endpoint']['host_key']+'\n')
   args=['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(p/'known'),'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms='+peer['endpoint']['host_key'].split()[0],'-o','ConnectTimeout=15','-o','ConnectionAttempts=1','-i',str(p/'key'),'-p',str(port),peer['account']+'@'+host,'rookstride-access-v1']
   result=json.loads(run(args,canonical(request).encode()))
   if not result.get('ok'):raise ValueError('The paired node rejected this management request')
   return result['result']

def discover(server_id,deployment_id):
 result=[]
 for path in sorted(Path('/var/lib/rookstride-single').glob('*/state.json')):
  if path.is_symlink():continue
  state=json.loads(path.read_text())
  if state.get('owner')!='rookstride-single-v1':continue
  protocol=state.get('protocol');instance=state.get('instance')
  if protocol not in ('awg','openvpn','xray','xhttp','hysteria2','trusttunnel','naive','shadowsocks','outline'):continue
  ident(instance);result.append({'kind':'protocol','id':'vpn-'+hashlib.sha256((server_id+':'+protocol+':'+instance).encode()).hexdigest()[:24], 'server_id':server_id,'deployment_id':deployment_id,'protocol':protocol,'instance':instance})
 if Path('/usr/local/sbin/rookstride-admin').is_file():
  status=json.loads(run(['/usr/local/sbin/rookstride-admin'],b'{"action":"status"}'))
  if status.get('ok') and status['result'].get('instance'):
   instance=status['result']['instance'];result.append({'kind':'protocol','id':'vpn-'+hashlib.sha256((server_id+':ikev2:'+instance).encode()).hexdigest()[:24],'server_id':server_id,'deployment_id':deployment_id,'protocol':'ikev2','instance':instance})
 return result

def pair_protocol_mode(manifest,obj,state):
 plan=manifest.get('plan',{})
 if manifest.get('version')!=2 or state.get('owner')!='rookstride-single-v1' or state.get('instance')!=obj['instance'] or state.get('protocol')!=obj['protocol']:raise Denied('Protocol is not owned by this native deployment')
 expected=plan.get('entry_protocol') if plan.get('role')=='entry' else plan.get('exit_protocol')
 if expected==obj['protocol']:return 'primary'
 if obj['protocol']=='openvpn' and state.get('coexist_pair')==plan.get('pair') and plan.get('role')=='entry' and plan.get('entry_protocol')=='awg' and plan.get('client_pool')=='10.66.0.0/24' and manifest.get('activated') and not manifest.get('resetting'):return 'coexist'
 raise Denied('Protocol is not a reviewed coexisting deployment')

def update_policy(obj):
 protocol=obj['protocol'];create='live' if protocol in ('awg','ikev2','openvpn') else 'restart-review';revoke='live' if protocol in ('awg','ikev2') else 'restart-review'
 if protocol in ('xray','xhttp'):
  path=Path('/var/lib/rookstride-single')/protocol/'runtime/server.json'
  try:
   config=json.loads(path.read_text())
   if 'HandlerService' in config.get('api',{}).get('services',[]) and config['inbounds'][0].get('tag')=='phone':create='live'
  except (OSError,ValueError,KeyError,IndexError,TypeError):pass
 return {'create':create,'revoke':revoke,'update':'live' if protocol in ('awg','ikev2') else 'restart-review','warning':'This change can reconnect other VPN users. Existing profiles remain unchanged.' if 'restart-review' in (create,revoke) else ''}

def installed_access_mode(obj):
 """Advertise current owned installation facts, never a protocol-name guess."""
 try:
  if obj['protocol']=='ikev2':return 'password' if obj in discover(obj['server_id'],obj['deployment_id']) else 'unknown'
  path=SINGLE_STATE/obj['protocol']/'state.json'
  if path.is_symlink():return 'unknown'
  state=json.loads(path.read_text())
  if state.get('owner')!='rookstride-single-v1' or state.get('protocol')!=obj['protocol'] or state.get('instance')!=obj['instance']:return 'unknown'
  mode=state.get('access_mode','profile')
  if mode=='password':return 'password' if obj['protocol'] in ('openvpn','hysteria2','trusttunnel','naive') else 'unknown'
  return 'profile' if mode=='profile' else 'unknown'
 except (OSError,ValueError,KeyError,TypeError,AttributeError):return 'unknown'

def scope_valid(scope):
 if not isinstance(scope,dict) or set(scope)-{'kind','id','users'} or scope.get('kind') not in ('server','deployment','protocol') or scope.get('users','own') not in ('own','all'):raise ValueError('Invalid authority scope')
 return {'kind':scope['kind'],'id':ident(scope.get('id')),'users':scope.get('users','own')}

def covers(scope,obj):
 return scope['id']==(obj['id'] if scope['kind']=='protocol' else obj.get(scope['kind']+'_id'))

class Access:
 def __init__(self,path=ROOT,system=None,clock=time.time):
  self.path=Path(path);self.path.mkdir(mode=0o700,parents=True,exist_ok=True);self.system=system or System();self.clock=clock
  self.db=sqlite3.connect(str(self.path/'authority.sqlite'),timeout=30,isolation_level=None);self.db.row_factory=sqlite3.Row
  self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
  self.db.executescript('''CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,value TEXT,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER,actor TEXT,operation TEXT,object_id TEXT,revision INTEGER,result TEXT);
CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,actor TEXT,digest TEXT,state TEXT,result TEXT);''')
  self.actor='';self.current_request={}
 def get(self,kind,id,default=None):
  row=self.db.execute('SELECT value FROM records WHERE kind=? AND id=?',(kind,id)).fetchone();return json.loads(row[0]) if row else default
 def put(self,kind,id,value):self.db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)',(kind,id,canonical(value)))
 def all(self,kind):return [json.loads(row[0]) for row in self.db.execute('SELECT value FROM records WHERE kind=? ORDER BY id',(kind,))]
 def revision(self):return self.get('meta','config',{}).get('revision',0)
 def bump(self):
  c=self.get('meta','config');c['revision']+=1;self.put('meta','config',c);return c['revision']
 def audit(self,action,obj,result):
  self.db.execute('INSERT INTO audit(at,actor,operation,object_id,revision,result) VALUES(?,?,?,?,?,?)',(int(self.clock()),self.actor,action,str(obj)[:128],self.revision(),result))
  self.db.execute('DELETE FROM audit WHERE seq < (SELECT COALESCE(MAX(seq),0)-9999 FROM audit)')
 def initialize(self,server_id,deployment_id,endpoint,objects):
  if self.get('meta','config'):raise ValueError('Administration is already enabled; no state was replaced')
  c={'server_id':ident(server_id),'deployment_id':ident(deployment_id),'endpoint':endpoint,'revision':1}
  self.db.execute('BEGIN IMMEDIATE')
  try:
   self.put('meta','config',c)
   for obj in objects:self.put('object',obj['id'],obj)
   self.db.execute('COMMIT')
  except Exception:self.db.execute('ROLLBACK');raise
  return {'schema':SCHEMA,'revision':1,'objects':objects}
 def principal(self,account):
  if account!='@owner' and self.get('meta','config',{}).get('disabled'):raise Denied('Administrator sharing has been disabled')
  if account=='@owner':return {'id':'@owner','role':'owner','scope':None,'grant_id':'@owner'}
  credential=self.get('credential',account)
  if not credential or credential.get('revoked'):raise Denied('This management credential is revoked or unknown')
  if credential['kind']=='bootstrap':return {'bootstrap':credential}
  if credential['kind']=='peer':return {'peer':credential}
  device=self.get('device',credential['device_id']);grant=self.get('grant',device['grant_id']) if device else None
  if not device or device.get('revoked') or not grant or grant.get('revoked'):raise Denied('This administrator no longer has access')
  return {**device,**grant,'id':device['id']}
 def check(self,principal,capability,obj=None):
  if capability not in ROLES.get(principal.get('role'),set()):raise Denied('This role does not permit the operation')
  if obj is not None and principal.get('scope') and not covers(principal['scope'],obj):raise Denied('This object is outside the administrator scope')
 def expected(self,req):
  if type(req.get('expected_revision')) is not int or req['expected_revision']!=self.revision():raise Denied('Management state changed; refresh before this change')
 def request(self,account,req):
  if not isinstance(req,dict) or req.get('schema')!=SCHEMA or not isinstance(req.get('operation'),str) or not re.fullmatch(r'[a-z][a-z0-9.-]{0,63}',req['operation']):raise ValueError('Unsupported management request schema')
  if len(canonical(req).encode())>MAX_REQUEST:raise ValueError('Request is too large')
  self.actor=account;self.account=account;self.current_request=req;self.peer_descriptions={};op=req['operation'];obj=req.get('object_id','')
  self.db.execute('BEGIN IMMEDIATE')
  try:
   principal=self.principal(account);self.actor=principal.get('id',account)
   result=self.dispatch(principal,req)
   self.audit(op,obj,'allowed');self.db.execute('COMMIT');return {'schema':SCHEMA,'revision':self.revision(),**result}
  except Exception:
   self.db.execute('ROLLBACK');self.audit(op,obj,'denied-or-failed');raise
 def dispatch(self,p,req):
  op=req['operation']
  if 'bootstrap' in p:return self.redeem(p['bootstrap'],req)
  if 'peer' in p:return self.peer_dispatch(p['peer'],req)
  if op=='capabilities':
   return {'role':p['role'],'scope':p.get('scope'),'capabilities':sorted(ROLES[p['role']]),'objects':[self.describe(o) for o in self.all('object') if p.get('scope') is None or covers(p['scope'],o)],'peer_management':'authority-proxy','new_listener':False}
  if op=='access.list':
   self.check(p,'access.read')
   objects=[o for o in self.all('object') if p.get('scope') is None or covers(p['scope'],o)]
   def visible(scope):return p.get('scope') is None or any(covers(scope,o) for o in objects)
   return {'devices':[{k:v for k,v in d.items() if k not in ('public_key',)}|{k:self.get('grant',d['grant_id']).get(k) for k in ('role','scope')} for d in self.all('device') if visible(self.get('grant',d['grant_id'])['scope'])], 'invitations':[{k:v for k,v in i.items() if k not in ('nonce','public_key')} for i in self.all('invitation') if visible(i['scope'])], 'objects':[self.describe(o) for o in objects],'roles':list(ROLES)}
  if op=='audit.read':
   self.check(p,'audit.read');rows=[dict(r) for r in self.db.execute('SELECT * FROM audit ORDER BY seq DESC LIMIT 200')]
   if p.get('scope'):rows=[r for r in rows if r['actor']==p['id'] or any(covers(p['scope'],o) and r['object_id']==o['id'] for o in self.all('object'))]
   return {'events':rows}
  if op=='invitations.create':
   self.check(p,'invitations.manage');self.expected(req)
   role=req.get('role');scope=scope_valid(req.get('scope'));ttl=req.get('ttl_seconds',3600)
   if role not in ROLES or role=='owner':raise Denied('Ownership cannot be shared through an invitation')
   if type(ttl) is not int or not 60<=ttl<=86400:raise ValueError('Invitation lifetime must be 1 minute to 24 hours')
   if not any(covers(scope,o) for o in self.all('object')):raise Denied('The selected scope has no owned protocol instance')
   if len(self.all('credential'))>=4096:raise ValueError('Credential capacity reached; owner maintenance is required')
   private,key=make_key();iid=token('inv-');account='rsb'+secrets.token_hex(10);c=self.get('meta','config')
   invite={'id':iid,'server_id':c['server_id'],'role':role,'scope':scope,'expires':int(self.clock())+ttl,'nonce':token(),'name':bounded_text(req.get('name','Administrator')),'account':account,'claimed_device':None,'revoked':False}
   self.put('invitation',iid,invite);self.put('credential',account,{'kind':'bootstrap','invitation_id':iid,'revoked':False});self.system.account(account,key,invite['expires']);self.bump()
   return {'invitation':{'purpose':'rookstride.admin.invitation','schema':SCHEMA,'invitation_id':iid,'server_id':c['server_id'],'endpoint':c['endpoint'],'role':role,'scope':scope,'expires':invite['expires'],'bootstrap':{'account':account,'private_key':private}},'invitation_id':iid}
  if op in ('devices.revoke','invitations.revoke','grants.update'):
   self.check(p,'grants.manage');self.expected(req)
   if op=='grants.update':
    grant=self.get('grant',ident(req.get('grant_id')))
    if not grant or grant.get('revoked'):raise Denied('Grant does not exist')
    role=req.get('role');scope=scope_valid(req.get('scope'))
    if role not in ROLES or role=='owner':raise Denied('Ownership cannot be assigned by role update')
    if not any(covers(scope,o) for o in self.all('object')):raise Denied('Scope has no current object')
    grant.update(role=role,scope=scope);self.put('grant',grant['id'],grant)
   else:
    kind='device' if op=='devices.revoke' else 'invitation';record=self.get(kind,ident(req.get(kind+'_id')))
    if not record:raise ValueError('Credential does not exist')
    record['revoked']=True;self.put(kind,record['id'],record);credential=self.get('credential',record['account']);credential['revoked']=True;self.put('credential',record['account'],credential)
    # Commit revocation before disconnecting existing sessions, including this one.
    self.bump();self.db.execute('COMMIT');self.system.revoke(record['account']);self.db.execute('BEGIN IMMEDIATE');return {'revoked':True}
   self.bump();return {'updated':True}
  if op in ('module.removal-plan','module.remove'):
   if p['id']!='@owner':raise Denied('Only the server owner can remove administration')
   import importlib.util
   path=Path(__file__).with_name('access_cleanup.py')
   spec=importlib.util.spec_from_file_location('rookstride_access_cleanup',path);cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
   credentials=[row[0] for row in self.db.execute('SELECT id FROM records WHERE kind=?',('credential',))]
   if op=='module.removal-plan':
    reviewed=cleanup.plan(credentials);value={'token':token(),'expires':int(self.clock())+300,'revision':self.revision(),'plan':reviewed};self.put('meta','removal',value)
    return {**reviewed,'token':value['token'],'expires':value['expires'],'confirmation':'REMOVE ADMINISTRATION'}
   self.expected(req);review=self.get('meta','removal',{})
   if req.get('confirmation')!='REMOVE ADMINISTRATION' or not isinstance(req.get('token'),str) or not secrets.compare_digest(req['token'],review.get('token','')) or self.clock()>=review.get('expires',0) or review.get('revision')!=self.revision():raise Denied('Review administrator removal again')
   if cleanup.plan(credentials)!=review['plan']:raise Denied('Managed account state changed; review removal again')
   config=self.get('meta','config');config['disabled']=True;self.put('meta','config',config)
   for name in credentials:
    value=self.get('credential',name);value['revoked']=True;self.put('credential',name,value)
   for kind in ('device','grant','invitation'):
    for value in self.all(kind):value['revoked']=True;self.put(kind,value['id'],value)
   self.bump();self.db.execute('COMMIT');self.db.execute('BEGIN IMMEDIATE')
   return cleanup.apply(credentials,self.system)
  if op=='inventory.refresh':
   self.check(p,'peers.manage');self.expected(req);c=self.get('meta','config');objects=discover(c['server_id'],c['deployment_id'])
   for old in self.all('object'):
    if old['server_id']==c['server_id']:self.db.execute('DELETE FROM records WHERE kind=? AND id=?',('object',old['id']))
   for obj in objects:self.put('object',obj['id'],obj)
   for peer in self.all('peer'):
    confirmed=self.system.peer(peer,{'schema':1,'operation':'peer.inspect','authority_id':c['server_id']})
    if confirmed.get('server_id')!=peer['server_id']:raise Denied('Paired node identity mismatch')
    current=confirmed.get('objects',[])
    if any(o.get('server_id')!=peer['server_id'] or o.get('deployment_id')!=c['deployment_id'] or not covers(peer['scope'],o) for o in current):raise Denied('Paired inventory is outside its fixed scope')
    for old in self.all('object'):
     if old['server_id']==peer['server_id']:self.db.execute('DELETE FROM records WHERE kind=? AND id=?',('object',old['id']))
    for obj in current:self.put('object',obj['id'],obj)
    peer['objects']=current;self.put('peer',peer['server_id'],peer)
   self.bump();return {'objects':self.all('object'),'refreshed':True}
  if op=='peers.prepare':
   self.check(p,'peers.manage');self.expected(req);scope=scope_valid(req.get('scope'))
   if scope['kind']!='deployment' or scope['users']!='all' or scope['id']!=self.get('meta','config')['deployment_id']:raise Denied('Peer authority must match this deployment')
   private,key=make_key();pid=token('peer-');account='rsp'+secrets.token_hex(10)
   self.put('credential',account,{'kind':'peer','peer_id':pid,'scope':scope,'authority_id':ident(req.get('authority_id')),'revoked':False});self.system.account(account,key);self.bump()
   return {'link':{'purpose':'rookstride.admin.peer','server_id':self.get('meta','config')['server_id'],'endpoint':self.get('meta','config')['endpoint'],'account':account,'private_key':private,'objects':self.all('object'),'scope':scope,'peer_id':pid}}
  if op=='peers.link':
   self.check(p,'peers.manage');self.expected(req);link=req.get('link')
   if not isinstance(link,dict) or link.get('purpose')!='rookstride.admin.peer':raise ValueError('Invalid paired authority link')
   sid=ident(link.get('server_id'));c=self.get('meta','config')
   if sid==c['server_id'] or scope_valid(link.get('scope'))['id']!=c['deployment_id']:raise Denied('Peer belongs to another deployment')
   # Prove possession and pinned destination before accepting any advertised objects.
   confirmed=self.system.peer(link,{'schema':1,'operation':'peer.inspect','authority_id':c['server_id']})
   if confirmed.get('server_id')!=sid:raise Denied('Paired node identity mismatch')
   self.put('peer',sid,link)
   for o in confirmed['objects']:
    if o['server_id']!=sid or o['deployment_id']!=c['deployment_id']:raise Denied('Peer object scope mismatch')
    self.put('object',o['id'],o)
   self.bump();return {'linked':True,'server_id':sid}
  if op=='enrollment.resume':return self.sync_peers(p)
  if op in ('services.review','services.apply','filtering.read','filtering.review','filtering.apply'):return self.infrastructure(p,req)
  if op in OPS:
   obj=self.get('object',ident(req.get('object_id')))
   if not obj:raise Denied('Unknown managed object')
   self.check(p,OPS[op],obj)
   parameters=req.get('parameters',{})
   if not isinstance(parameters,dict):raise ValueError('Invalid operation parameters')
   allowed={'usage.read':set(),'users.list':set(),'users.create':{'login','password','person','device'},'users.revoke':{'login'},'users.update':{'login','password','person','device'},'users.profile':{'login'},'lifecycle.inspect':set()}[op]
   if set(parameters)-allowed:raise Denied('Unexpected management parameters')
   if op not in ('users.list','usage.read','lifecycle.inspect'):bounded_text(parameters.get('login'),64)
   own=p.get('scope') and p['scope'].get('users','own')=='own'
   issued_id=obj['id']+':'+parameters.get('login','')
   if own and op in ('users.revoke','users.update','users.profile'):
    issued=self.get('issued',issued_id,{})
    if issued.get('actor')!=p['id'] or not issued.get('account_id'):raise Denied('Only accounts issued by this device are in scope')
    parameters={**parameters,'expected_account_id':issued['account_id']}
   mutation=op in ('users.create','users.revoke','users.update')
   if mutation and (op!='users.update' or 'password' in parameters) and self.describe(obj)['user_updates'][op.split('.')[1]]=='restart-review' and req.get('acknowledge_restart') is not True:raise Denied('Review the possible VPN listener restart before this account change')
   if mutation:self.expected(req)
   current_revision=self.revision()
   oid=ident(req.get('operation_id')) if mutation else None
   digest=hashlib.sha256(canonical({'op':op,'obj':obj,'parameters':parameters}).encode()).hexdigest()
   if mutation:
    previous=self.db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone()
    if previous:
     if previous['actor']!=p['id'] or previous['digest']!=digest:raise Denied('Operation identifier belongs to another request')
     if previous['state']!='complete':raise Denied('Prior request needs inspection; mutation was not replayed')
     return json.loads(previous['result'])
    pending=self.db.execute("SELECT COUNT(*) FROM operations WHERE state='running' AND actor=?",(p['id'],)).fetchone()[0]
    total=self.db.execute("SELECT COUNT(*) FROM operations WHERE state='running'").fetchone()[0]
    if pending>=32 or total>=2048:raise Denied('Unconfirmed operation limit reached; owner reconciliation is required')
    self.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',(oid,p['id'],digest,'running','{}'))
    self.db.execute('COMMIT');self.db.execute('BEGIN IMMEDIATE')
    # Revocation may occur while acquiring the durable-operation lock.
    p=self.principal(self.account);self.check(p,OPS[op],obj)
    if self.revision()!=current_revision or self.get('object',obj['id'])!=obj:raise Denied('Management state changed before the account change')
   if obj['server_id']!=self.get('meta','config')['server_id']:
    peer=self.get('peer',obj['server_id'])
    if not peer:raise Denied('Paired node is unavailable')
    result=self.system.peer(peer,{'schema':1,'operation':'peer.request','authority_id':self.get('meta','config')['server_id'],'device':self.peer_device(p),'request':req,'expected_account_id':parameters.get('expected_account_id')})
   else:result=self.execute_object(obj,op,parameters)
   if op=='users.create':self.put('issued',issued_id,{'actor':p['id'],'account_id':result.pop('_created_account_id',None)})
   if own and op=='users.list':result['users']=[u for u in result.get('users',[]) if self.get('issued',obj['id']+':'+u['login'],{}).get('actor')==p['id'] and u.get('_account_id') and self.get('issued',obj['id']+':'+u['login'],{}).get('account_id')==u.get('_account_id')]
   if own and op=='usage.read':
    for key in ('connections','monthly'):result[key]=[u for u in result.get(key,[]) if self.get('issued',obj['id']+':'+u.get('user',''),{}).get('actor')==p['id'] and result.get('_account_ids',{}).get(u.get('user')) and self.get('issued',obj['id']+':'+u.get('user',''),{}).get('account_id')==result['_account_ids'].get(u.get('user'))]
   result.pop('_account_ids',None)
   for user in result.get('users',[]):user.pop('_account_id',None)
   if mutation:
    self.bump();self.db.execute('UPDATE operations SET state=?,result=? WHERE id=?',('complete',canonical(result),oid))
    self.db.execute("DELETE FROM operations WHERE state='complete' AND id NOT IN (SELECT id FROM operations ORDER BY rowid DESC LIMIT 10000)")
   return result
  raise Denied('Unsupported management operation')
 def infrastructure(self,p,req,peer_forward=False,peer_scope=None):
  op=req['operation'];obj=self.get('object',ident(req.get('object_id')))
  if not obj:raise Denied('Unknown managed object')
  self.check(p,OPS[op],obj)
  if peer_scope and not covers(peer_scope,obj):raise Denied('Peer request is outside its fixed scope')
  # Reviews and token application happen on the machine owning the service. The
  # authority forwards only after checking the current grant on every request.
  if obj['server_id']!=self.get('meta','config')['server_id']:
   peer=self.get('peer',obj['server_id'])
   if not peer:raise Denied('Paired node is unavailable')
   return self.system.peer(peer,{'schema':1,'operation':'peer.request','authority_id':self.get('meta','config')['server_id'],'device':self.peer_device(p),'request':req})
  parameters=req.get('parameters',{})
  if not isinstance(parameters,dict):raise ValueError('Invalid operation parameters')
  group=op.split('.')[0];apply=op.endswith('.apply')
  if apply:
   if set(parameters)!={'review_token'}:raise Denied('Only the reviewed change can be applied')
   review=self.get('review',ident(parameters['review_token']))
   if not review or review.get('used') or review['actor']!=p['id'] or review['object']!=obj or review['group']!=group or review['expires']<int(self.clock()):raise Denied('Review expired, used or belongs to another administrator; review again')
   if req.get('expected_revision')!=review['revision'] or self.revision()!=review['revision']:raise Denied('Management state changed; review again')
   if review.get('grant')!={k:p.get(k) for k in ('grant_id','role','scope','authority_revision')}:raise Denied('Administrator authority changed; review again')
   self.check_affected(p,obj,review['affected'],peer_scope)
   oid=ident(req.get('operation_id'));digest=hashlib.sha256(canonical({'review':parameters['review_token'],'object':obj}).encode()).hexdigest()
   if self.db.execute('SELECT id FROM operations WHERE id=?',(oid,)).fetchone():raise Denied('This operation was already submitted; inspect the service before retrying')
   review['used']=True;self.put('review',parameters['review_token'],review)
   self.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',(oid,p['id'],digest,'running','{}'))
   self.db.execute('COMMIT');self.db.execute('BEGIN IMMEDIATE')
   if not peer_forward:
    p=self.principal(self.account);self.check(p,OPS[op],obj)
    if review.get('grant')!={k:p.get(k) for k in ('grant_id','role','scope','authority_revision')}:raise Denied('Administrator authority changed before maintenance')
   # Another authority mutation during the durable claim must invalidate work.
   if self.revision()!=review['revision']:raise Denied('Management state changed before maintenance')
   result=self.system.execute(obj,op,{'_parameters':review['parameters'],'_guard':review['guard'],'_affected':review['affected']})
   result.pop('_account_ids',None);self.bump();self.db.execute('UPDATE operations SET state=?,result=? WHERE id=?',('complete',canonical(result),oid));return result
  allowed={'services.review':{'action'},'filtering.read':set(),'filtering.review':{'enabled','level'}}[op]
  if set(parameters)-allowed:raise Denied('Unexpected maintenance parameters')
  if group=='services' and parameters.get('action') not in ('restart','repair'):raise ValueError('Choose restart or repair')
  if group=='filtering':
   if op.endswith('.review') and not parameters:raise ValueError('Choose an ad blocking change')
   if 'enabled' in parameters and type(parameters['enabled']) is not bool:raise ValueError('Expected a boolean protection setting')
   if 'level' in parameters and parameters['level'] not in ('standard','strong','strict'):raise ValueError('Unknown ad blocking level')
  result=self.system.execute(obj,op,{'_parameters':parameters});result.pop('_account_ids',None)
  if op=='filtering.read':
   self.check_affected(p,obj,result.pop('_affected',[]),peer_scope);return result
  affected=result.get('affected',[]);self.check_affected(p,obj,affected,peer_scope)
  guard=result.pop('guard');rid=token('review-');revision=self.revision();expires=int(self.clock())+300
  # Keep reviewed state private; the client receives only an opaque one-use id.
  self.put('review',rid,{'actor':p['id'],'object':obj,'group':group,'parameters':parameters,'guard':guard,'affected':affected,'revision':revision,'expires':expires,'used':False,'grant':{k:p.get(k) for k in ('grant_id','role','scope','authority_revision')}})
  for old in self.db.execute("SELECT id,value FROM records WHERE kind='review'").fetchall():
   if json.loads(old['value']).get('expires',0)<int(self.clock()):self.db.execute("DELETE FROM records WHERE kind='review' AND id=?",(old['id'],))
  return {**result,'review_token':rid,'revision':revision,'expires':expires}
 def check_affected(self,p,obj,affected,peer_scope=None):
  if not affected:raise Denied('No owned service consumers were found')
  for consumer in affected:
   candidates=[o for o in self.all('object') if o['server_id']==obj['server_id'] and o['protocol']==consumer.get('protocol') and o['instance']==consumer.get('instance')]
   if len(candidates)!=1:raise Denied('Shared service inventory changed; the owner must inspect it')
   if p.get('scope') and not covers(p['scope'],candidates[0]) or peer_scope and not covers(peer_scope,candidates[0]):raise Denied('This ad blocker is shared with a VPN outside your authority')
 def describe(self,obj):
  policy=update_policy(obj) if obj['server_id']==self.get('meta','config')['server_id'] else {'create':'live' if obj['protocol'] in ('awg','ikev2','openvpn') else 'restart-review','revoke':'live' if obj['protocol'] in ('awg','ikev2') else 'restart-review','update':'live' if obj['protocol'] in ('awg','ikev2') else 'restart-review','warning':'This change may reconnect users on the paired VPN.'}
  native=obj['protocol']!='ikev2';local=obj['server_id']==self.get('meta','config')['server_id'];paired=local and Path('/etc/rookstride-pair/manifest.json').is_file()
  maintenance={'listener':native and not paired,'filtering':native,'reason':'Double VPN listener maintenance needs the owner routing controller.' if paired else 'IKEv2 system-service maintenance stays with the owner.' if not native else ''}
  mode=installed_access_mode(obj) if local else self.peer_access_mode(obj)
  return {**obj,'user_updates':policy,'maintenance':maintenance,'access_mode':mode}
 def peer_access_mode(self,obj):
  peer=self.get('peer',obj['server_id'])
  if not peer:return 'unknown'
  cache=getattr(self,'peer_descriptions',{});self.peer_descriptions=cache
  if obj['server_id'] not in cache:
   try:
    result=self.system.peer(peer,{'schema':1,'operation':'peer.inspect','authority_id':self.get('meta','config')['server_id']})
    cache[obj['server_id']]=result if result.get('server_id')==obj['server_id'] else {}
   except (ValueError,OSError,subprocess.SubprocessError):cache[obj['server_id']]={}
  result=cache[obj['server_id']]
  if obj not in result.get('objects',[]):return 'unknown'
  for description in result.get('descriptions',[]):
   if all(description.get(key)==value for key,value in obj.items()) and description.get('access_mode') in ('password','profile'):return description['access_mode']
  return 'unknown'
 def execute_object(self,obj,op,parameters):
  if op=='lifecycle.inspect':
   path=Path('/var/lib/rookstride-lifecycle/runtime/server/lifecycle.py')
   if not path.is_file():raise ValueError('Lifecycle inspection is not installed')
   response=json.loads(run(['/usr/bin/python3',str(path)],b'{"action":"inspect"}'))
   if not response.get('ok'):raise ValueError('Lifecycle inspection failed')
   return response['result']
  return self.system.execute(obj,op,parameters)
 def peer_device(self,p):
  return {k:p.get(k) for k in ('id','public_key','role','scope','grant_id')}|{'authority_revision':self.revision()}
 def sync_peers(self,p):
  completed=[];pending=[]
  for peer in self.all('peer'):
   if p.get('scope') and not any(covers(p['scope'],o) for o in peer['objects']):continue
   try:self.system.peer(peer,{'schema':1,'operation':'peer.enroll','authority_id':self.get('meta','config')['server_id'],'device':self.peer_device(p)});completed.append(peer['server_id'])
   except (ValueError,OSError,subprocess.SubprocessError):pending.append(peer['server_id'])
  return {'device_id':p['id'],'grant_id':p['grant_id'],'role':p['role'],'scope':p.get('scope'),'completed_peers':completed,'pending_peers':pending,'enrolled':True,'account':p.get('account','')}
 def redeem(self,credential,req):
  invite=self.get('invitation',credential['invitation_id'])
  if not invite or invite['revoked'] or int(self.clock())>=invite['expires']:raise Denied('Invitation expired or was revoked')
  op=req['operation']
  if op=='enrollment.challenge':return {'invitation_id':invite['id'],'server_id':invite['server_id'],'nonce':invite['nonce'],'role':invite['role'],'scope':invite['scope'],'expires':invite['expires']}
  if op!='enrollment.accept':raise Denied('Bootstrap credentials can only enroll a device')
  key=public_key(req.get('public_key'));verify_proof(invite,key,req.get('signature'));device_id='dev-'+hashlib.sha256(key.encode()).hexdigest()[:32]
  if invite['claimed_device'] and invite['claimed_device']!=device_id:raise Denied('Invitation was already redeemed by another device')
  if not invite['claimed_device']:
   if self.get('device',device_id):raise Denied('This device is already enrolled; use its current credential')
   gid=token('grant-');account='rsd'+hashlib.sha256(key.encode()).hexdigest()[:20]
   self.put('grant',gid,{'id':gid,'role':invite['role'],'scope':invite['scope'],'revoked':False})
   self.put('device',device_id,{'id':device_id,'grant_id':gid,'public_key':key,'account':account,'name':invite['name'],'revoked':False})
   self.put('credential',account,{'kind':'device','device_id':device_id,'revoked':False});invite['claimed_device']=device_id;self.put('invitation',invite['id'],invite);self.bump()
   # Claim is durable before account creation/peer enrollment. A partial failure
   # can only resume this same proven device key, never reopen the invitation.
   self.db.execute('COMMIT');self.db.execute('BEGIN IMMEDIATE')
  device=self.get('device',device_id)
  if device['revoked'] or self.get('grant',device['grant_id'])['revoked']:raise Denied('Device access was revoked')
  self.system.account(device['account'],key)
  result=self.sync_peers(self.principal(device['account']));result['account']=device['account'];return result
 def peer_dispatch(self,credential,req):
  if req.get('authority_id')!=credential['authority_id']:raise Denied('Peer authority identity mismatch')
  if req['operation']=='peer.inspect':
   objects=[o for o in self.all('object') if covers(credential['scope'],o)]
   return {'server_id':self.get('meta','config')['server_id'],'objects':objects,'descriptions':[{**o,'access_mode':installed_access_mode(o)} for o in objects if o['server_id']==self.get('meta','config')['server_id']]}
  if req['operation'] not in ('peer.enroll','peer.request'):raise Denied('Paired credential cannot run this operation')
  d=req.get('device')
  if not isinstance(d,dict) or d.get('role') not in ROLES:raise Denied('Invalid peer device')
  if d.get('id')!='@owner':
   ident(d.get('id'));public_key(d.get('public_key'))
  old=self.get('peer_device',d['id'])
  if old and old['public_key']!=d['public_key']:raise Denied('Peer enrollment is bound to another key')
  if old and d.get('authority_revision',0)<old.get('authority_revision',0):raise Denied('Stale authority revision')
  self.put('peer_device',d['id'],d)
  if req['operation']=='peer.enroll':return {'enrolled':True,'device_id':d['id']}
  inner=req.get('request',{});op=inner.get('operation');obj=self.get('object',inner.get('object_id'))
  if op not in OPS or not obj or not covers(credential['scope'],obj):raise Denied('Peer request is outside its fixed scope')
  self.check(d,OPS[op],obj)
  if op in ('services.review','services.apply','filtering.read','filtering.review','filtering.apply'):
   self.actor=d['id'];return self.infrastructure(d,inner,peer_forward=True,peer_scope=credential['scope'])
  parameters=inner.get('parameters',{});allowed={'usage.read':set(),'users.list':set(),'users.create':{'login','password','person','device'},'users.revoke':{'login'},'users.update':{'login','password','person','device'},'users.profile':{'login'},'lifecycle.inspect':set()}[op]
  if not isinstance(parameters,dict) or set(parameters)-allowed:raise Denied('Unexpected peer parameters')
  if op not in ('users.list','usage.read','lifecycle.inspect'):bounded_text(parameters.get('login'),64)
  # Peer accounts are only held by the authority. Recipients have no direct peer
  # credential; every operation must first pass the authority's current grant.
  if op in ('users.create','users.revoke','users.update') and (op!='users.update' or 'password' in parameters) and update_policy(obj)[op.split('.')[1]]=='restart-review' and inner.get('acknowledge_restart') is not True:raise Denied('Review the paired listener restart before this change')
  if req.get('expected_account_id'):parameters={**parameters,'expected_account_id':req['expected_account_id']}
  self.actor=d['id'];return self.execute_object(obj,op,parameters)

def main():
 os.umask(0o077)
 try:
  if os.geteuid()!=0:raise Denied('Restricted administrator access is required')
  if len(sys.argv)!=1:raise Denied('Dispatcher arguments are not permitted')
  account=os.environ.get('SUDO_USER','@owner')
  if account=='root':account='@owner'
  elif account.startswith(('rsb','rsd','rsp')) and not re.fullmatch(r'rs[bdp][a-f0-9]{20}',account):raise Denied('Unknown restricted management identity')
  elif account!='@owner' and not re.fullmatch(r'rs[bdp][a-f0-9]{20}',account):account='@owner' # An independently sudo-authorized owner, never a generated account.
  import signal
  def expired(signum,frame):raise ValueError('Management request timed out before completion')
  signal.signal(signal.SIGALRM,expired);signal.alarm(15)
  raw=sys.stdin.buffer.read(MAX_REQUEST+1);signal.alarm(0)
  if len(raw)>MAX_REQUEST:raise ValueError('Request is too large')
  result=Access().request(account,json.loads(raw))
  response=canonical({'ok':True,'result':result})
  if len(response.encode())>2*1024*1024:raise ValueError('Management response is too large')
  print(response)
 except (ValueError,OSError,sqlite3.Error,subprocess.SubprocessError) as error:
  print(canonical({'ok':False,'error':str(error) if isinstance(error,ValueError) else 'Management operation failed'}));raise SystemExit(1)

if __name__=='__main__':main()
