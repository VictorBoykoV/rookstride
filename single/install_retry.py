"""Explicit, root-authorized retry of a NEW pre-publication acquisition failure.

Owner/task IDs are idempotency bindings, never administrator authority. Callers
hold management -> single locks. Detached workers acquire them only to record a
typed failure; unit liveness is checked separately before any retry dispatch.
"""
import grp,hashlib,json,os,pwd,re,stat,subprocess,uuid
from pathlib import Path
import filtering,model,runtime

SYSTEM=Path('/')
FIELDS={'schema','owner','task','request_digest','config_digest','machine','source','instance','port'}
TERMINAL={'failed','complete'}

def require(value,message):
 if not value:raise ValueError(message)

def canonical(value):
 try:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
 except (TypeError,ValueError,UnicodeError):raise ValueError('Invalid exact installation request') from None

def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def secure(path,regular=False):
 path=Path(path);require(path.is_absolute() and '..' not in path.parts,'Unexpected installation path')
 require(path==SYSTEM or SYSTEM in path.parents,'Unexpected installation root')
 current=SYSTEM
 for part in path.relative_to(SYSTEM).parts:
  current=current/part
  try:s=current.lstat()
  except FileNotFoundError:continue
  require(not stat.S_ISLNK(s.st_mode) and s.st_uid==os.geteuid() and not s.st_mode&0o022,'Installation ownership or link changed')
 if regular:
  s=path.lstat();require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=262144,'Invalid installation receipt')
 return path

def read(path):
 value=json.loads(secure(path,True).read_text());require(isinstance(value,dict),'Installation receipt is not an object');return value

def sync_directory(path):
 descriptor=os.open(secure(path),os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(descriptor)
 finally:os.close(descriptor)

def mkdir_durable(path):
 path=secure(path)
 if not path.exists():
  mkdir_durable(path.parent);path.mkdir(mode=0o700);sync_directory(path.parent)
 require(path.is_dir(),'Installation receipt parent is not a directory')
 sync_directory(path)

def durable_file(path):
 with secure(path,True).open('rb') as stream:os.fsync(stream.fileno())
 # Also covers a job directory allocated by the compatible legacy start path.
 directory=path.parent
 while directory!=SYSTEM:
  sync_directory(directory);directory=directory.parent
 sync_directory(SYSTEM)

def write_new(path,value):
 path=secure(path);mkdir_durable(path.parent)
 with path.open('x') as stream:
  os.chmod(path,0o600);json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
 sync_directory(path.parent)

def probe(args):
 result=subprocess.run(args,capture_output=True,text=True,timeout=15)
 require(result.returncode==0 and len(result.stdout)<=2*1024*1024,'Cannot prove the server has no published VPN effects')
 return result.stdout

def unpublished_effects(exclude):
 # Loaded units survive deleted unit files. Query the manager as well as disk.
 units=probe(['systemctl','list-units','--all','--plain','--no-legend','--no-pager','--full','rookstride-*','twohop-*','awg-quick@awg-exit.service','strongswan*','charon*','unbound*','adguardhome*'])
 for line in units.splitlines():
  fields=line.split();require(len(fields)>=4,'Unknown service inventory')
  name=fields[0]
  match=re.fullmatch(r'rookstride-single-install-([a-f0-9]{32})\.service',name)
  if match:
   job=match[1]
   if job in exclude:continue
   require(read(job_path(job)/'status.json').get('state') in TERMINAL,'Another loaded installer is unfinished');unit_idle(job);continue
  # OS return history may survive a verified reinstall, but not an active worker.
  match=re.fullmatch(r'rookstride-os-reinstall-([a-f0-9]{32})\.service',name)
  if match:
   status=read(SYSTEM/'var/lib/rookstride-reinstall'/match[1]/'status.json')
   require(status.get('job')==match[1] and status.get('state') in ('complete','completed','cancelled','abandoned') and fields[2]=='inactive' and fields[3]=='dead','OS worker is unfinished or unknown');continue
  match=re.fullmatch(r'rookstride-install-([a-f0-9]{32})\.service',name)
  if match:
   require(read(SYSTEM/'var/lib/rookstride/jobs'/match[1]/'status.json').get('state') in TERMINAL and fields[2] in ('inactive','failed') and fields[3] in ('dead','failed','exited'),'Another loaded installer is unfinished');continue
  if re.fullmatch(r'(strongswan[^ /]*|charon[^ /]*|unbound[^ /]*|adguardhome[^ /]*)\.service',name) and fields[2]=='inactive' and fields[3]=='dead':continue
  raise ValueError('A loaded VPN/filter/maintenance service remains; inspect it')
 for executable in ('iptables-save','ip6tables-save'):
  rules=probe([executable])
  require(not re.search(r'ROOKFILTER|ROOK_LOCAL_|RSPAIR_|RSLIFE_|SINGLEVPN_|TWOHOP_',rules),'Published VPN firewall effects remain')
 # Public download-QA fault comments are not VPN publication; only the above
 # actual product chain/comment prefixes are considered here.
 addresses=json.loads(probe(['ip','-j','address','show']))
 require(isinstance(addresses,list),'Unknown network interface inventory')
 for row in addresses:
  require(isinstance(row,dict) and isinstance(row.get('ifname'),str),'Unknown network interface')
  require(not re.match(r'^(awg-exit|rsawg|rsx|rookstride)',row['ifname']),'An owned VPN interface remains')
  require(isinstance(row.get('addr_info',[]),list),'Unknown network address inventory')
  for address in row.get('addr_info',[]):
   require(isinstance(address,dict),'Unknown network address')
   require(address.get('local') not in (*filtering.ADDRESSES,'10.66.0.1','10.249.255.253','10.249.255.254'),'A private VPN/filter address remains')
 for family in ('-4','-6'):
  rules=json.loads(probe(['ip','-j',family,'rule','show']))
  require(isinstance(rules,list) and all(isinstance(row,dict) and row.get('priority') in (0,32766,32767) and row.get('table') in ('local','main','default',253,254,255) for row in rules),'Policy routing requires separate review')
  routes=json.loads(probe(['ip','-j',family,'route','show','table','all']))
  require(isinstance(routes,list) and all(isinstance(row,dict) and row.get('table','main') in ('local','main','default',253,254,255) for row in routes),'A private routing table remains')
 for kind in ('state','policy'):
  require(probe(['ip','xfrm',kind]).strip()=='','IPsec network state remains')
 try:containers=probe(['docker','ps','--all','--format','{{json .}}'])
 except FileNotFoundError:
  require(not any((SYSTEM/p).exists() for p in ('var/lib/docker','var/lib/containerd')),'Container storage cannot be inspected');containers=''
 for line in containers.splitlines():
  row=json.loads(line);require(isinstance(row,dict) and isinstance(row.get('Names'),str) and isinstance(row.get('Labels'),str),'Unknown container inventory')
  require(not re.search(r'rookstride|twohop',row['Names'],re.I) and 'io.rookstride.' not in row['Labels'],'An owned VPN container remains')

def job_path(job):
 require(isinstance(job,str) and re.fullmatch('[a-f0-9]{32}',job),'Invalid installation job')
 return secure(runtime.STATE/'jobs'/job)

def context(req):
 value=req.get('install_context')
 if value is None:return None
 require(isinstance(value,dict) and set(value)=={'schema','owner','task'} and type(value['schema']) is int and value['schema']==1,'Invalid installation context')
 require(isinstance(value['owner'],str) and str(uuid.UUID(value['owner']))==value['owner'] and isinstance(value['task'],str) and re.fullmatch('[a-f0-9]{32}',value['task']),'Invalid installation owner/task')
 require(not req.get('filter_only') and not req.get('coexist_pair'),'This installation does not support pre-publication retry')
 return value

def original(req):
 value=req.get('request') if req.get('action')=='retry' else {k:v for k,v in req.items() if k!='install_context'}
 allowed={'action','protocol','server','sshPort','login','port','access_mode','password','sni'}
 require(isinstance(value,dict) and set(value)<=allowed and value.get('action')=='start','Exact original standalone request required')
 model.validate(value);canonical(value)
 return value

def machine():
 return hashlib.sha256(secure(SYSTEM/'etc/machine-id',True).read_bytes()).hexdigest()

def unit_state(job):
 job_path(job)
 result=subprocess.run(['systemctl','show','rookstride-single-install-'+job+'.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],capture_output=True,text=True,timeout=15)
 values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
 require(result.returncode in (0,1) and set(values)=={'LoadState','ActiveState','SubState','MainPID','ControlPID'} and values['LoadState'] in ('loaded','not-found') and values['ActiveState'] in ('inactive','failed','active','activating','deactivating') and re.fullmatch('[0-9]+',values['MainPID']) and re.fullmatch('[0-9]+',values['ControlPID']),'Installer state is unknown')
 return values

def unit_idle(job):
 values=unit_state(job)
 require(values['ActiveState'] in ('inactive','failed') and values['SubState'] in ('dead','failed','exited') and values['MainPID']==values['ControlPID']=='0','An installer is active or its state is unknown')

def observed_response(job,meta,claim=None):
 value=response(job,meta,claim)
 require(value['state'] in ('starting','running','complete','failed'),'Linked installer state is unknown')
 if value['state'] in ('starting','running'):
  require(unit_state(job)['ActiveState'] in ('active','activating','deactivating'),'Installer dispatch is uncertain; inspect its recorded claim')
 return value

def other_idle(exclude=()):
 for folder,prefix in ((runtime.STATE/'jobs','rookstride-single-install-'),(SYSTEM/'var/lib/rookstride/jobs','rookstride-install-')):
  secure(folder)
  if not folder.exists():continue
  for path in folder.iterdir():
   secure(path)
   if path.name in exclude:continue
   require(path.is_dir(),'Unknown installation job path')
   status=read(path/'status.json');require(status.get('state') in TERMINAL,'Other installation work is unfinished or unknown')
   require(not (path/'request.json').exists() and not (path/'request.json').is_symlink(),'Another installation request remains')
   if prefix=='rookstride-single-install-':
    unit_idle(path.name)
    claim_path=secure(path/'retry-claim.json')
    if claim_path.exists():
     # A durable claim with no known child remains dispatch uncertainty even
     # when another task is being reviewed. Never infer idle from its parent.
     claim=read(claim_path);meta=read(path/'meta.json');validate_meta(path.name,meta)
     require(set(claim)=={'schema','job','retry_of','nonce','failed_receipt_sha256','install_context','meta_sha256'} and claim.get('schema')==1 and claim.get('retry_of')==path.name and claim.get('install_context')==meta.get('install_context') and status.get('state')=='failed' and claim.get('failed_receipt_sha256')==sealed_receipt(path.name),'Another retry claim changed or is unresolved')
     child=job_path(claim['job']);child_meta=read(child/'meta.json')
     require(child_meta.get('retry_of')==path.name and child_meta.get('retry_nonce')==claim.get('nonce') and child_meta.get('install_context')==claim['install_context'],'Another linked retry is missing or changed')
     validate_meta(child.name,child_meta)
     if child.name not in exclude:
      require(read(child/'status.json').get('state') in TERMINAL and not (child/'request.json').exists() and not (child/'request.json').is_symlink(),'Another linked retry is unfinished or unknown');unit_idle(child.name)
   else:
    p=subprocess.run(['systemctl','is-active',prefix+path.name],capture_output=True,text=True,timeout=15)
    require(p.returncode in (3,4) and p.stdout.strip() in ('inactive','failed','unknown'),'Another installer is active or unknown')
 runtime.user_updates.ensure_no_runtime_update(destructive=True)

def absent(exclude=()):
 """No publication, not merely a missing target state.json. Never removes files."""
 for path in (filtering.ROOT,filtering.DATA,filtering.UNIT,filtering.NETWORK,
              SYSTEM/'etc/rookstride-pair',SYSTEM/'etc/single-vps-vpn',SYSTEM/'etc/ipsec.conf',
              SYSTEM/'etc/ipsec.secrets',SYSTEM/'var/lib/rookstride-public-tls',SYSTEM/'etc/twohop-vpn',
              SYSTEM/'etc/amnezia',SYSTEM/'var/lib/rookstride-pair',SYSTEM/'opt/AdGuardHome',
              SYSTEM/'var/lib/AdGuardHome',SYSTEM/'etc/swanctl/rookstride-lifecycle'):
  secure(path);require(not path.exists() and not path.is_symlink(),'VPN/filter state exists; inspect and review it')
 secure(runtime.STATE)
 if runtime.STATE.exists():
  require({p.name for p in runtime.STATE.iterdir()}<={'jobs','install-tasks'},'Protocol or unknown child state exists')
 units=SYSTEM/'etc/systemd/system';secure(units)
 for pattern in ('rookstride-single-*','rookstride-filter*','rookstride-pair*','rookstride-lifecycle-*','twohop-*','awg-quick@awg-exit*'):
  require(not list(units.glob(pattern)),'Protocol service publication exists')
 try:pwd.getpwnam('rookfilter')
 except KeyError:pass
 else:raise ValueError('A private filter account remains')
 try:grp.getgrnam('rookfilter')
 except KeyError:pass
 else:raise ValueError('A private filter group remains')
 unpublished_effects(exclude)
 for path in (SYSTEM/'var/lib/rookstride-reinstall/plan.json',):
  secure(path);require(not path.exists(),'An OS reinstall plan remains')
 require(not list((SYSTEM/'var/lib/rookstride-reinstall').glob('planned-*')),'An OS reinstall plan remains')
 for root in ('rookstride-maintenance','rookstride-engine-updates','rookstride-lifecycle/operations'):
  directory=SYSTEM/'var/lib'/root;secure(directory)
  if directory.exists():
   entries=list(directory.iterdir());require(len(entries)<=512,'Too many maintenance records to verify')
   for entry in entries:
    secure(entry);require(entry.is_dir() and re.fullmatch('[a-f0-9]{32}',entry.name),'Unknown maintenance work remains')
    paths=list(entry.rglob('*'));require(len(paths)<=4096,'Maintenance inventory requires review')
    for path in paths:secure(path)
    value=read(entry/'journal.json');require(value.get('operation')==entry.name and value.get('state') in ('accepted','rolled-back','cancelled','abandoned'),'Other maintenance work remains')
 for name in ('active.json','inventory.json'):
  path=secure(SYSTEM/'var/lib/rookstride-lifecycle'/name);require(not path.exists(),'A lifecycle route/inventory remains')
 reinstall=secure(SYSTEM/'var/lib/rookstride-reinstall');os_records={}
 if reinstall.exists():
  for path in reinstall.iterdir():
   secure(path)
   if path.name=='current.json':continue
   require(path.is_dir() and re.fullmatch('[a-f0-9]{32}',path.name),'Unknown OS work remains')
   value=read(path/'status.json');require(value.get('job')==path.name and value.get('state') in ('complete','completed','cancelled','abandoned'),'OS work is unfinished or unknown');os_records[path.name]=value
 current=SYSTEM/'var/lib/rookstride-reinstall/current.json';secure(current)
 if current.exists():
  value=read(current);returned=read(SYSTEM/'etc/rookstride-reinstall-result.json')
  status=os_records.get(value.get('job'),{})
  require(value.get('job')==returned.get('job') and status.get('state') in ('complete','completed') and returned.get('state')=='complete' and returned.get('version')==status.get('version'),'OS return is unfinished or unknown')
 other_idle(exclude)

def effective(request,port,instance):
 config=model.validate(request);config['port']=port
 return {'normalization':1,'configuration':config,'instance':instance}

def binding(request,ctx,port,instance,source):
 return {**ctx,'request_digest':digest(request),'config_digest':digest(effective(request,port,instance)),
         'machine':machine(),'source':source,'instance':instance,'port':port}

def index_path(ctx):return secure(runtime.STATE/'install-tasks'/ctx['task'])

def validate_binding(bound,request,ctx,source):
 require(isinstance(bound,dict) and set(bound)==FIELDS and all(bound.get(k)==ctx[k] for k in ('schema','owner','task')),'Installation belongs to another owner/task')
 require(bound['source']==source and bound['machine']==machine() and bound['request_digest']==digest(request) and bound['config_digest']==digest(effective(request,bound['port'],bound['instance'])),'Installation source, machine or exact configuration changed')

def validate_meta(job,meta):
 bound=meta['install_context'];actual=hashlib.sha256(secure(job_path(job)/'meta.json',True).read_bytes()).hexdigest()
 if meta.get('retry_of'):
  record=read(job_path(meta['retry_of'])/'retry-claim.json')
  require(record.get('nonce')==meta.get('retry_nonce') and record.get('install_context')==bound,'Retry parent changed')
 else:record=read(index_path(bound))
 require(record.get('job')==job and record.get('meta_sha256')==actual,'Immutable installation metadata changed')

def response(job,meta,claim=None):
 value={'job':job,'state':read(job_path(job)/'status.json')['state'],'bundle':meta['bundle'],'plan':{'port':meta['install_context']['port']},'install_context':meta['install_context']}
 if claim:value.update(retry_of=claim['retry_of'],nonce=claim['nonce'])
 return value

def existing_start(req,source):
 ctx=context(req)
 if ctx is None:return None
 request=original(req);path=index_path(ctx)
 if not path.exists():return None
 index=read(path);validate_binding(index['install_context'],request,ctx,source)
 job=index['job'];meta=read(job_path(job)/'meta.json')
 require(meta.get('install_context')==index['install_context'] and hashlib.sha256(secure(job_path(job)/'meta.json',True).read_bytes()).hexdigest()==index['meta_sha256'],'Installation acknowledgement is missing or changed; inspect it')
 return observed_response(job,meta)

def initial_meta(req,config,source,job):
 ctx=context(req)
 if ctx is None:return {}
 request=original(req);bound=binding(request,ctx,config['port'],config['instance'],source)
 try:absent((job,));fresh=True
 except (ValueError,OSError,subprocess.SubprocessError):fresh=False
 return {'install_context':bound,'normalization':1,'prefetch_retry_baseline':fresh,'execution_digest':digest(config)}

def register(req,job,meta):
 if context(req) is None:return
 for name in ('meta.json','request.json','status.json'):durable_file(job_path(job)/name)
 write_new(index_path(context(req)),{'schema':1,'job':job,'install_context':meta['install_context'],'meta_sha256':hashlib.sha256(secure(job_path(job)/'meta.json',True).read_bytes()).hexdigest()})

def failure_marker(job,error):
 if not isinstance(error,filtering.AcquisitionUnavailable):return None
 meta=read(job_path(job)/'meta.json')
 if meta.get('prefetch_retry_baseline') is not True or meta.get('normalization')!=1 or 'install_context' not in meta:return None
 validate_meta(job,meta)
 require(meta.get('execution_digest')==digest(read(job_path(job)/'request.json')),'The pending installation request changed')
 absent((job,))
 return {'schema':1,'reason':'acquisition-unavailable',**meta['install_context']}

def seal_failure(job):
 path=job_path(job);durable_file(path/'status.json')
 write_new(path/'failure-seal.json',{'schema':1,'job':job,'status_sha256':hashlib.sha256(secure(path/'status.json',True).read_bytes()).hexdigest(),'meta_sha256':hashlib.sha256(secure(path/'meta.json',True).read_bytes()).hexdigest()})

def sealed_receipt(job):
 path=job_path(job);seal=read(path/'failure-seal.json')
 receipt=hashlib.sha256(secure(path/'status.json',True).read_bytes()).hexdigest()
 require(seal=={'schema':1,'job':job,'status_sha256':receipt,'meta_sha256':hashlib.sha256(secure(path/'meta.json',True).read_bytes()).hexdigest()},'Immutable failed receipt changed or was not sealed')
 return receipt

def status_receipt(job,value):
 if value.get('state')=='failed' and isinstance(value.get('retryable'),dict):value={**value,'failed_receipt_sha256':sealed_receipt(job)}
 return value

def retry(req,source,planner,spawn,progress):
 ctx=context(req);require(ctx is not None,'Only a new bound standalone task may retry')
 request=original(req);old=req.get('job');parent=job_path(old)
 meta=read(parent/'meta.json');status=read(parent/'status.json');bound=meta.get('install_context')
 validate_binding(bound,request,ctx,source)
 validate_meta(old,meta)
 require(status.get('state')=='failed' and status.get('retryable')=={'reason':'acquisition-unavailable',**bound} and meta.get('prefetch_retry_baseline') is True and meta.get('normalization')==1,'This failure is not proven before publication')
 receipt=sealed_receipt(old)
 require(req.get('failed_receipt_sha256')==receipt and req.get('expected_config_digest')==bound['config_digest'],'The failed receipt or exact configuration differs')
 nonce=req.get('nonce');require(isinstance(nonce,str) and re.fullmatch('[a-f0-9]{32}',nonce),'Durable explicit retry nonce required')
 claim_path=parent/'retry-claim.json';secure(claim_path)
 if claim_path.exists():
  claim=read(claim_path)
  require(claim.get('nonce')==nonce and claim.get('retry_of')==old and claim.get('failed_receipt_sha256')==receipt and claim.get('install_context')==bound,'Another or changed retry claim exists')
  child=read(job_path(claim['job'])/'meta.json')
  require(child.get('retry_of')==old and child.get('retry_nonce')==nonce and child.get('install_context')==bound,'Linked retry is missing or changed; inspect dispatch')
  validate_meta(claim['job'],child)
  return observed_response(claim['job'],child,claim)
 unit_idle(old);require(not (parent/'request.json').exists() and not (parent/'request.json').is_symlink(),'The prior worker has not finished cleanup')
 absent((old,))
 forced={**request,'port':bound['port']};review=planner(forced)
 require(review['port']==bound['port'] and review['protocol']==request['protocol'],'The originally reviewed port/configuration changed')
 job=uuid.uuid4().hex
 config=model.validate(request);config['port']=bound['port'];config['instance']=bound['instance'];config['owner']='rookstride-single-v1';config['initialLogin']=config.pop('login')
 if 'password' in config:config['initialPassword']=config.pop('password')
 child={'protocol':config['protocol'],'bundle':source,'filter_only':False,'normalization':1,'prefetch_retry_baseline':True,'install_context':bound,'retry_of':old,'retry_nonce':nonce,'execution_digest':digest(config)}
 claim={'schema':1,'job':job,'retry_of':old,'nonce':nonce,'failed_receipt_sha256':receipt,'install_context':bound,'meta_sha256':hashlib.sha256(json.dumps(child,sort_keys=True).encode()).hexdigest()}
 write_new(claim_path,claim) # Before dispatch: duplicates can only reconcile.
 path=job_path(job);mkdir_durable(path)
 write_new(path/'meta.json',child);write_new(path/'request.json',config);progress(path,1,'Starting explicitly linked retry','starting')
 durable_file(path/'status.json')
 spawn(job)
 return response(job,child,claim)
