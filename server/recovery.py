#!/usr/bin/env python3
"""Bounded owner recovery of native VPN identity, independent of admin grants.

Secret snapshots travel only through pinned owner SSH and are encrypted by the
phone before storage. Versioned protocol allowlists reject unknown files/state;
only complete reviewed identities can be restored.
"""
import copy,hashlib,json,os,re,sys,time,ipaddress,fcntl
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair,native_pair,lifecycle,recovery_adapters as adapters,recovery_ike
REQUIRED={'awg':['private','public','parameters','users','server','port'],
 'ikev2':['server endpoint','CA and server certificate/private key','EAP accounts','DNS and pool'],
 'openvpn':['endpoint','CA/server identity','tls-crypt key','client certificates or password hashes','transport'],
 'xray':['private','public','shortId','users','sni','server','port'],
 'xhttp':['private','public','shortId','users','sni','path','server','port'],
 'hysteria2':['endpoint','TLS identity','users','QUIC parameters'],
 'outline':['endpoint','access keys','cipher','plugin transport'],
 'shadowsocks':['endpoint','access keys','cipher','plugin transport'],
 'trusttunnel':['endpoint','TLS identity','users','transport'],
 'naive':['endpoint','TLS identity','users','transport']}

def filtering_api(endpoint,body=None):
 m=pair.load_manifest()
 if m and m['plan']['role']=='exit' and m['plan']['exit_protocol']=='ikev2':return recovery_ike.filter_api(endpoint,body)
 return native_pair.filtering.api(endpoint,body)
def filter_policy():
 status=filtering_api('filtering/status');dns=filtering_api('dns_info')
 enabled=[f for f in (status.get('filters') or []) if f.get('enabled')]
 known={v[1]:k for k,v in native_pair.filtering.FILTERS.items()}
 if len(enabled)!=1 or enabled[0].get('url') not in known or status.get('user_rules') or any(f.get('enabled') for f in (status.get('whitelist_filters') or [])):raise ValueError('Custom filtering rules require their own reviewed migration adapter')
 return {'level':known[enabled[0]['url']],'enabled':bool(dns.get('protection_enabled',True))}
def validate_policy(value):
 if not isinstance(value,dict) or set(value)!={'level','enabled'} or value['level'] not in native_pair.filtering.FILTERS or type(value['enabled']) is not bool:raise ValueError('Invalid reviewed filtering policy')
 return value
def apply_policy(value):
 validate_policy(value)
 original=native_pair.filtering.api
 try:
  m=pair.load_manifest()
  if m and m['plan']['role']=='exit' and m['plan']['exit_protocol']=='ikev2':native_pair.filtering.api=recovery_ike.filter_api
  native_pair.filtering.control(value)
 finally:native_pair.filtering.api=original
 if filter_policy()!=value:raise ValueError('Replacement filtering policy did not match the reviewed settings')
 return {'applied':True,'policy':value}

def validate(snapshot):
 if not isinstance(snapshot,dict) or set(snapshot)-{'schema','purpose','deployment','role','plan','state','created','source_anchor','usage_generation','initial_user','transport','filter_policy','identity_files','adapter'} or snapshot.get('schema') not in (1,2) or snapshot.get('purpose')!='rookstride-owner-recovery-node':raise ValueError('Expected a versioned owner recovery node')
 pair.ident(snapshot.get('deployment'));role=snapshot.get('role')
 if role not in ('entry','exit'):raise ValueError('Invalid recovery role')
 p=pair.plan(snapshot['plan']);state=snapshot.get('state')
 if not isinstance(state,dict) or p['pair']!=snapshot['deployment'] or p['role']!=role:raise ValueError('Unsupported recovery identity adapter')
 expected=p['entry_protocol'] if role=='entry' else p['exit_protocol']
 if expected!=state.get('protocol') or snapshot['schema']==1 and expected!='awg':raise ValueError('Recovery protocol does not match this pair member')
 if snapshot['schema']==2 and snapshot.get('adapter')!=expected+'-identity-v1':raise ValueError('Unsupported recovery identity adapter version')
 adapters.validate(state,role,snapshot.get('identity_files',{}))
 initial=snapshot.get('initial_user')
 if not isinstance(initial,dict) or set(initial)-{'login','password','statistics'} or initial.get('login')!=state['initialLogin']:raise ValueError('Recovery is missing matching initial-user bootstrap metadata')
 pair.username(initial.get('login'));pair.vpn_password(initial.get('password'))
 if 'statistics' in initial and type(initial['statistics']) is not bool:raise ValueError('Invalid recovery history setting')
 if state['server']!=(p['server'] if role=='entry' else p['exit_host']) or state['port']!=p['vpn_port' if role=='entry' else 'tunnel_port']:raise ValueError('Recovery endpoint does not match its owned pair role')
 if role=='entry':
  transport=snapshot.get('transport');native_pair.validate_material(p,transport)
  if state.get('pair')!=snapshot['deployment'] or state.get('pair_dns')!=transport.get('dns'):raise ValueError('Recovery DNS identity is incomplete')
 if role=='exit':validate_policy(snapshot.get('filter_policy'))
 if len(json.dumps(snapshot).encode())>1572864:raise ValueError('Owner recovery snapshot too large')
 return snapshot

def awg_fields(content):
 # Validate material first; compare fields independent of JSON parameter order.
 section='';fields={}
 for line in content.splitlines():
  line=line.strip()
  if not line or line.startswith('#'):continue
  if line.startswith('['):section=line;continue
  name,value=line.split('=',1);fields[(section,name.strip().lower())]=value.strip()
 return fields

def validate_pair(archive,plans):
 if not isinstance(archive,dict) or archive.get('schema')!=1 or archive.get('purpose')!='rookstride-owner-recovery':raise ValueError('Expected an owner recovery pair')
 deployment=pair.ident(archive.get('deployment'));nodes=archive.get('nodes')
 if not isinstance(nodes,dict) or set(nodes)!={'entry','exit'} or not isinstance(plans,dict) or set(plans)!={'entry','exit'}:raise ValueError('Recovery needs both reviewed deployment members')
 for role in ('entry','exit'):
  node=validate(nodes[role]);target=pair.plan(plans[role])
  if node['deployment']!=deployment or node['role']!=role or target!=pair.plan(node['plan']):raise ValueError('Recovery archive does not match the planned deployment endpoints, ports or protocol contract')
 entry,exit=nodes['entry'],nodes['exit'];a=pair.plan(entry['plan']);b=pair.plan(exit['plan']);a.pop('role');b.pop('role')
 if a!=b:raise ValueError('The archived members do not describe one compatible pair')
 state=exit['state'];initial=exit['initial_user']['login']
 if not any(u['login']==initial and u['enabled'] for u in state['users']):raise ValueError('Recovery is missing the enabled exit bridge bootstrap account')
 protocol=state['protocol'];actual=entry['transport']['profile'] if protocol=='ikev2' else entry['transport']['profile']['content'];matches=False
 for user in state['users']:
  if not user['enabled']:continue
  expected=adapters.client_profile(state,user['login'],exit.get('identity_files',{}))
  if protocol=='ikev2':matches=actual==expected
  elif protocol=='awg':matches=awg_fields(actual)==awg_fields(expected)
  elif isinstance(expected,dict):
   parsed=json.loads(actual)
   if state.get('access_mode')=='password':parsed.pop('certificate',None)
   matches=parsed==expected
  else:matches=actual==expected
  if matches:break
 if not matches:raise ValueError('Archived entry bridge credentials do not match the archived exit identity and users')
 return {'readiness_schema':2,'verified':True,'deployment':deployment,'entry_users':len(entry['state']['users']),'exit_users':len(state['users']),'live_restore_tested':False}

def effective_topology(m):
 plan=copy.deepcopy(m['plan']);transport=None
 inventory=lifecycle.read(lifecycle.ROOT/'inventory.json')
 if inventory:
  if inventory.get('anchor')!=lifecycle.anchor(m) or inventory.get('deployment')!=plan['pair']:raise ValueError('Recovery logical topology changed')
  if inventory.get('entry_endpoint'):plan['server']=pair.host(inventory['entry_endpoint'])
 if plan['role']=='entry':
  selected=lifecycle.route_override(m)
  if selected:
   op=lifecycle.read(lifecycle.ROOT/'operations'/pair.ident(selected.get('operation'))/'journal.json')
   if not op or op['state']!='accepted':raise ValueError('Finish the accepted exit replacement before capturing recovery')
   if op.get('deployment')!=plan['pair'] or op.get('anchor')!=lifecycle.anchor(m):raise ValueError('Replacement topology no longer matches this pair')
   for name in ('exit_host','exit_protocol','tunnel_port'):plan[name]=op['plan'][name]
   transport=copy.deepcopy(op['transport'])
  else:transport=json.loads((pair.OWN/'transport.json').read_text())
 return plan,transport

def rehearse_pair(req):
 result=validate_pair(req.get('archive'),req.get('plans'));m=pair.load_manifest()
 if not m or m['plan']['pair']!=result['deployment'] or m['plan']['role']!='entry':raise ValueError('Review recovery through the current owned entry')
 plan,_=effective_topology(m)
 if plan!=pair.plan(req['plans']['entry']):raise ValueError('Review the current accepted exit replacement topology before recovery')
 return result

def inspect():
 m=pair.load_manifest()
 if not m:return {'supported':False,'reason':'Recognized owned pair required'}
 p=m['plan'];protocol=p.get('entry_protocol','ikev2') if p['role']=='entry' else p.get('exit_protocol','awg')
 return {'schema':1,'deployment':p['pair'],'role':p['role'],'protocol':protocol,'supported':m.get('version')==2 and adapters.supported(protocol),'adapter':protocol+'-identity-v1','required_identity':REQUIRED.get(protocol,[]),'excluded':['administrator grants and invitations','SSH owner credentials','DNS query history','live sessions'],'profile_compatibility':'Only the reviewed endpoint, protocol identity and complete accounts preserve saved clients'}
def export():
 info=inspect()
 if not info['supported']:raise ValueError('This protocol has no accepted complete owner recovery adapter yet')
 m=pair.load_manifest();plan,transport=effective_topology(m);state=adapters.clean_state(recovery_ike.state(plan) if info['protocol']=='ikev2' else native_pair.runtime.load(info['protocol']))
 # Management provenance is not VPN identity and must not revive authority.
 for user in state['users']:user.pop('administration_account_id',None)
 value={'schema':2,'adapter':info['adapter'],'identity_files':adapters.files(state),'purpose':'rookstride-owner-recovery-node','deployment':info['deployment'],'role':info['role'],'plan':plan,'state':state,'created':time.time(),'source_anchor':lifecycle.anchor(m),'usage_generation':state['instance'],'initial_user':json.loads((pair.OWN/'initial-user.json').read_text()),'transport':transport}
 if info['role']=='exit':value['filter_policy']=filter_policy()
 validate(value);return value

def restored_identity(state):
 return lifecycle.digest({'state':adapters.clean_state(state),'files':{name:value['sha256'] for name,value in adapters.files(state).items()}})
def complete_restore(receipt,identity,state):
 lifecycle.write(receipt,{'snapshot':identity,'state':'complete','generation':state['instance'],'restored_identity':restored_identity(state)})
 return {'restored':True,'users':len(state['users']),'usage_generation':state['instance']}
def check_restored_service(state):
 if state['protocol']=='ikev2':native_pair.command(['systemctl','is-active','--quiet','strongswan-starter'])
 elif not native_pair.runtime.health(state)['running']:raise ValueError('Restored VPN is not running; inspect it before continuing')

def restore(req):
 snapshot=validate(req.get('snapshot'));m=pair.load_manifest()
 if not m or m.get('version')!=2 or m['plan']['pair']!=snapshot['deployment'] or m['plan']['role']!=snapshot['role']:raise ValueError('Recovery archive belongs to another deployment/member')
 if req.get('confirmation')!='RESTORE REVIEWED VPN IDENTITY':raise ValueError('Review the owner recovery identity before restoring')
 p=m['plan'];source=snapshot['plan'];state=copy.deepcopy(snapshot['state']);current=recovery_ike.state(p) if state['protocol']=='ikev2' else native_pair.runtime.load(state['protocol'])
 # Endpoint, listener and protocol trust are explicit prerequisites, not passwords.
 new_endpoint=req.get('new_endpoint')
 if new_endpoint is not None and (snapshot['role']!='entry' or pair.host(new_endpoint)!=p['server'] or req.get('endpoint_confirmation')!='ISSUE UPDATED CLIENT CONNECTIONS'):raise ValueError('Review the new client endpoint explicitly')
 for field in ('server','vpn_port','exit_host','tunnel_port','entry_protocol','exit_protocol','client_pool'):
  if p.get(field)!=source.get(field) and not (field=='server' and new_endpoint):raise ValueError('The replacement cannot retain saved profiles: endpoint or protocol contract changed')
 receipt=lifecycle.ROOT/'restores'/(snapshot['role']+'.json');identity=lifecycle.digest({'snapshot':snapshot,'new_endpoint':new_endpoint});prior=lifecycle.read(receipt)
 if prior:
  if prior['snapshot']!=identity:raise ValueError('Another recovery is already recorded on this node')
  if prior['state']=='complete':
   if current['instance']!=prior['generation'] or prior.get('restored_identity')!=restored_identity(current):raise ValueError('Restored VPN identity changed after completion; inspect this node instead of replaying recovery')
   check_restored_service(current)
   return {'restored':True,'users':len(current['users']),'usage_generation':prior['generation']}
 if current.get('pair')!=state.get('pair') or not prior and len(current.get('users',[]))>1:raise ValueError('Restore only to the reviewed fresh replacement, never over an existing user database')
 if not prior and (current['instance']==state['instance'] or m.get('activated') or snapshot['role']=='exit' and m.get('configured')):raise ValueError('Restore requires a fresh replacement that has not begun serving this pair')
 # Replacement service ports and counter generation belong to the new installation.
 state=adapters.restore_state(snapshot,current)
 if new_endpoint:
  state['server']=new_endpoint
  if state.get('tls_name')==snapshot['state']['server']:state['tls_name']=new_endpoint
 lifecycle.write(receipt,{'snapshot':identity,'state':'restoring','generation':state['instance']})
 if state['protocol']=='ikev2':
  recovery_ike.restore(state,adapters.decode_files(snapshot['state'],snapshot.get('identity_files',{})),new_endpoint=bool(new_endpoint));pair.atomic(pair.OWN/'initial-user.json',json.dumps(snapshot['initial_user']))
  if snapshot['role']=='exit':apply_policy(snapshot['filter_policy'])
  return complete_restore(receipt,identity,recovery_ike.state(p))
 if not native_pair.model.proxy_protocol(state['protocol']):
  owned=native_pair.runtime.check_container(current)
  if owned:native_pair.command(['docker','rm','-f',native_pair.runtime.container(state['protocol'])])
 adapters.install_files(state,adapters.decode_files(snapshot['state'],snapshot.get('identity_files',{})))
 native_pair.runtime.save(state)
 pair.atomic(pair.OWN/'initial-user.json',json.dumps(snapshot['initial_user']))
 previous_source=native_pair.runtime.__file__;previous_helper=native_pair.runtime.HELPER
 try:
  native_pair.runtime.__file__=str(pair.RELEASE/'single/runtime.py');native_pair.runtime.HELPER=pair.RELEASE/'single/run.py'
  if not Path(native_pair.runtime.__file__).is_file():raise ValueError('The replacement has no durable protocol recipe')
  if state['protocol'] in adapters.WORKERS:
   import routes
   # An old private leaf can be renewed from the retained CA without new client trust.
   if new_endpoint and state.get('access_mode')!='password':
    cert,_=routes.tls_paths(state,native_pair.runtime);pair.protected(cert);cert.unlink(missing_ok=True)
   routes.tls_material(state,native_pair.runtime)
  native_pair.runtime.apply_config(state,first=True)
  native_pair.runtime.save(state)
 finally:native_pair.runtime.__file__=previous_source;native_pair.runtime.HELPER=previous_helper
 if not native_pair.runtime.health(state)['running']:raise ValueError('Restored VPN did not become ready; forwarding remains guarded')
 if snapshot['role']=='exit':apply_policy(snapshot['filter_policy'])
 # No access-control files are in the exported allowlist; grants cannot resurrect.
 return complete_restore(receipt,identity,native_pair.runtime.load(state['protocol']))
def entry_bridge(req):
 m=pair.load_manifest();operation=pair.ident(req.get('operation'));protocol=m['plan']['exit_protocol'] if m else ''
 if not m or m.get('version')!=2 or m['plan']['role']!='exit' or not adapters.supported(protocol) or req.get('deployment')!=m['plan']['pair']:raise ValueError('An owned supported exit for this deployment is required')
 folder=lifecycle.ROOT/'entry-bridges';path=folder/(operation+'.json');record=lifecycle.read(path);state=recovery_ike.state(m['plan']) if protocol=='ikev2' else native_pair.runtime.load(protocol);login='migration-'+operation[:16]
 existing=next((u for u in state['users'] if u['login']==login),None)
 if record and (record.get('instance')!=state['instance'] or record.get('state')=='ready' and not existing):raise ValueError('Recorded replacement bridge changed')
 if not record and existing:raise ValueError('The reserved migration account is already used')
 previous_source=native_pair.runtime.__file__;previous_helper=native_pair.runtime.HELPER
 try:
  if protocol!='ikev2':
   # Recovery runs from a temporary upload; service units must use the owned recipe.
   native_pair.runtime.__file__=str(pair.RELEASE/'single/runtime.py');native_pair.runtime.HELPER=pair.RELEASE/'single/run.py'
   if not Path(native_pair.runtime.__file__).is_file() or not native_pair.runtime.HELPER.is_file():raise ValueError('The replacement has no durable protocol recipe')
  if not existing:
   lifecycle.write(path,{'operation':operation,'instance':state['instance'],'state':'creating'})
   if protocol=='ikev2':recovery_ike.admin.update_user({'login':login,'password':__import__('secrets').token_urlsafe(24)});state=recovery_ike.state(m['plan'])
   else:native_pair.runtime.add_user(state,login,password=__import__('secrets').token_urlsafe(24))
  elif record and record.get('state')=='creating':
   # The account file can survive a killed installer before its daemon reload.
   # Reapply that same identity before declaring the bridge ready.
   if protocol=='ikev2':recovery_ike.admin.run(['ipsec','rereadsecrets'])
   else:native_pair.runtime.apply_config(state)
 finally:native_pair.runtime.__file__=previous_source;native_pair.runtime.HELPER=previous_helper
 record={'operation':operation,'instance':state['instance'],'state':'ready'};lifecycle.write(path,record)
 # The old bridge keeps its distinct identity while the replacement is staged.
 if protocol=='ikev2':
  data=adapters.decode_files(state,adapters.files(state));profile=recovery_ike.profile(state,login,data)
  env=dict(line.split('=',1) for line in native_pair.IKE_NETWORK.read_text().splitlines() if '=' in line)
  return {'protocol':protocol,'endpoint':m['plan']['exit_host'],'profile':profile,'dns':{'address':env['DNS_IP'],'dns_port':53}}
 dns=native_pair.filtering.load()
 return {'protocol':protocol,'endpoint':m['plan']['exit_host'],'profile':native_pair.runtime.profile(state,login),'dns':{'address':dns['address'],'dns_port':53 if native_pair.model.proxy_protocol(protocol) else dns['dns_port']}}

def dispatch(req):
 if req.get('action') in ('restore','entry-bridge','apply-filter-policy'):__import__('user_updates').ensure_no_runtime_update(destructive=True)
 if req.get('action')=='inspect':return inspect()
 if req.get('action')=='entry-bridge':return entry_bridge(req)
 if req.get('action')=='export':return export()
 if req.get('action')=='filter-policy':return filter_policy()
 if req.get('action')=='apply-filter-policy':
  if req.get('confirmation')!='PRESERVE REVIEWED FILTERING':raise ValueError('Review the filtering migration')
  return apply_policy(req.get('policy'))
 if req.get('action')=='rehearse':
  snapshot=validate(req.get('snapshot'));return {'verified':True,'deployment':snapshot['deployment'],'role':snapshot['role'],'users':len(snapshot['state']['users']),'live_restore_tested':False}
 if req.get('action')=='rehearse-pair':return rehearse_pair(req)
 if req.get('action')=='restore':return restore(req)
 raise ValueError('Unsupported recovery action')
def main():
 os.umask(0o077)
 if os.geteuid()!=0:raise SystemExit('Owner access is required')
 try:
  raw=sys.stdin.buffer.read(2097153)
  if len(raw)>2097152:raise ValueError('Owner recovery request too large')
  req=json.loads(raw)
  with lifecycle.management_lock():result=dispatch(req)
  print(json.dumps({'ok':True,'result':result}))
 except Exception as exc:
  print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__}));raise SystemExit(1)
if __name__=='__main__':main()
