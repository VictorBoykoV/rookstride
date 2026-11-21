"""Bind engine review to accepted replacement bridges without changing topology."""
import copy,hashlib,re,shlex
from pathlib import Path
import lifecycle,pair,native_pair
FIELDS=('image_id','xray_binary','xray_sha256','worker_binary','service_sha256')
def identity(op):return lifecycle.digest({k:v for k,v in op.items() if k not in (*FIELDS,'runtime_update')})
def reviewed_anchor(manifest,wanted):
 """Derive historical anchors only through this installation's reviewed updates."""
 if wanted==lifecycle.anchor(manifest):return True
 import maintenance
 current=manifest.get('bundle')
 for item in reversed(manifest.get('helper_history',[])):
  if not isinstance(item,dict) or not re.fullmatch('[a-f0-9]{64}',str(item.get('previous',''))):raise ValueError('Reviewed helper history is incomplete')
  operation=pair.ident(item.get('operation'));record=maintenance.read(maintenance.ROOT/operation/'journal.json')
  previous=record.get('manifest',{}) if record else {}
  if not record or record.get('state') not in ('verified','accepted') or record.get('operation')!=operation or record.get('new_digest')!=current or record.get('old_digest')!=item['previous'] or previous.get('bundle')!=item['previous'] or previous.get('plan')!=manifest['plan'] or previous.get('configure_digest')!=manifest.get('configure_digest'):
   raise ValueError('Retained bridge helper history cannot be verified')
  current=item['previous']
  if wanted==lifecycle.anchor(dict(manifest,bundle=current)):return True
 return False

def records(manifest,protocols,verify_units=True):
 if not manifest or manifest['plan']['role']!='entry':return []
 result=[];active=lifecycle.route_override(manifest)
 required=active.get('operation','') if active and active.get('route',{}).get('exit_protocol') in protocols else ''
 for op in lifecycle.records():
  if op.get('state')!='accepted' or op.get('plan',{}).get('exit_protocol') not in protocols:continue
  path=native_pair.UNIT/('rookstride-lifecycle-'+pair.ident(op['operation'])+'.service')
  pair.protected(path)
  if not path.exists():
   if op['operation']==required:raise ValueError('The active replacement bridge service is missing')
   continue
  expected={k:v for k,v in manifest['plan'].items() if k not in ('exit_host','tunnel_port')}
  retained={k:v for k,v in op['plan'].items() if k not in ('exit_host','tunnel_port')}
  if op.get('deployment')!=manifest['plan']['pair'] or expected!=retained or not reviewed_anchor(manifest,op.get('anchor')):raise ValueError('Accepted bridge no longer matches this pair')
  if not path.is_file() or verify_units and path.read_text()!=lifecycle.candidate_unit(op):raise ValueError('Accepted bridge service ownership changed')
  result.append(op)
 if required and not any(op['operation']==required for op in result):raise ValueError('The active replacement bridge record is missing')
 return result

def decorate(service,op):
 service['lifecycle']={'operation':op['operation'],'identity':identity(op),'fields':{k:op[k] for k in FIELDS if k in op}}
 return service

def validate(service):
 previous=service['lifecycle'];path=lifecycle.ROOT/'operations'/pair.ident(previous['operation'])/'journal.json';op=lifecycle.read(path)
 if not op or identity(op)!=previous['identity']:raise ValueError('Accepted bridge topology changed after runtime review')
 return op,path

def docker(op,group,sha,image):
 name='rookstride-lifecycle-'+op['operation'];path=native_pair.UNIT/(name+'.service');pair.protected(path);text=path.read_text()
 if text!=lifecycle.candidate_unit(op):raise ValueError('Accepted bridge service ownership changed')
 argv=shlex.split(re.findall('^ExecStart=(.+)$',text,re.M)[0]);token='rookstride-awg:1' if group=='awg' else op['image_id'];folder=lifecycle.ROOT/'operations'/op['operation']
 files=[folder/'awg-exit.conf',folder/'bridge.sh'] if group=='awg' else [folder/'client.ovpn']
 return decorate({'kind':'bridge','name':name,'path':str(path),'text':text,'argv':argv,'configs':{str(p):sha(p) for p in files},'binary':image(token),**({'image_token':token} if group=='openvpn' else {})},op)

def update(op,rollback):
 for service in op['snapshot']['services']:
  if 'lifecycle' not in service:continue
  current,path=validate(service);previous=service['lifecycle']['fields'];group=op['group']
  if rollback:
   for key in FIELDS:
    if key in previous:current[key]=previous[key]
    else:current.pop(key,None)
  else:
   if group=='openvpn':current['image_id']=op['candidate_image']
   elif group=='xray':current.update(xray_binary=op['target'],xray_sha256=op['new_hash'])
   elif group=='routes':current['worker_binary']=op['target']
   current['service_sha256']=hashlib.sha256(Path(service['path']).read_bytes()).hexdigest()
  current['runtime_update']=op['operation'];lifecycle.write(path,current)
  if Path(service['path']).read_text()!=lifecycle.candidate_unit(current):raise ValueError('Updated bridge service does not match its retained recipe')
