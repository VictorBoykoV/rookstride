#!/usr/bin/env python3
"""Owner-reviewed entry move; endpoint transfer is an explicit external checkpoint."""
import copy,fcntl,ipaddress,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair,lifecycle,native_routing,recovery

def prepare(req):
 m,info=lifecycle.owned(req);p=m['plan'];operation=pair.ident(req.get('operation'));path=lifecycle.ROOT/'operations'/operation/'journal.json';prior=lifecycle.read(path)
 if prior:
  if prior['request_digest']!=lifecycle.digest(req):raise ValueError('Entry replacement review changed')
  return public(prior)
 if not recovery.adapters.supported(p['entry_protocol']) or not recovery.adapters.supported(p['exit_protocol']):raise ValueError('This route needs a complete entry identity adapter')
 if req.get('expected_revision')!=info['revision']:raise ValueError('Deployment revision changed')
 if req.get('confirmation')!='REPLACE ENTRY AND PRESERVE VPN IDENTITY':raise ValueError('Review the entry identity and endpoint transfer first')
 if any(o['state'] not in ('accepted','rolled-back','cancelled') for o in lifecycle.records()):raise ValueError('Finish the recorded maintenance operation first')
 try:ipaddress.ip_address(p['server']);literal=True
 except ValueError:literal=False
 new_address=req.get('new_address',False)
 if type(new_address) is not bool:raise ValueError('Invalid endpoint migration mode')
 if p.get('access_mode')=='password' and not new_address:raise ValueError('This public-certificate entry needs a new-address migration. Keeping its domain before DNS transfer requires a reviewed certificate staging adapter')
 if literal and req.get('endpoint_transfer') is not True and not new_address:raise ValueError('Saved clients use the old literal IP. Transfer that exact IP or distribute new profiles; an unrelated DNS name cannot preserve them')
 snapshot=recovery.export();candidate=pair.host(req.get('candidate'));fingerprint=req.get('candidate_fingerprint','')
 if not __import__('re').fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',fingerprint):raise ValueError('Pin the replacement entry SSH identity before review')
 op=dict(schema=1,kind='replace-entry',operation=operation,deployment=p['pair'],expected_revision=info['revision'],anchor=lifecycle.anchor(m),request_digest=lifecycle.digest(req),created=time.time(),candidate=candidate,candidate_fingerprint=fingerprint,endpoint=candidate if new_address else p['server'],original_endpoint=p['server'],client_update_required=new_address,identity_digest=lifecycle.digest(snapshot['state']),state='entry-prepared',phase='Entry move reviewed; current clients and route unchanged')
 lifecycle.save(op,op['state'],op['phase']);return public(op)
def public(op):return {key:op[key] for key in ('operation','deployment','expected_revision','candidate','endpoint','client_update_required','state','phase')}
def verify_current_route(m,req):
 expected=str(ipaddress.IPv4Address(req.get('expected_exit_ip','')));blocking=req.get('filtering_enabled',True)
 if type(blocking) is not bool:raise ValueError('Invalid filtering verification policy')
 if lifecycle.route_override(m):
  plan,transport=recovery.effective_topology(m)
  native_routing.apply('refresh')
  lifecycle.verify_route({'plan':plan,'transport':transport,'expected_exit_ip':expected,'filter_policy':{'enabled':blocking}},plan['test_ip'])
  m['verified']=True;pair.write_manifest(m);native_routing.apply('activate')
 else:__import__('native_pair').verify(m['plan'],{'expected_exit_ip':expected,'filtering_enabled':blocking},True)
 return {'verified':True,'deployment':m['plan']['pair']}

def transition(req):
 operation=pair.ident(req.get('operation'));path=lifecycle.ROOT/'operations'/operation/'journal.json';op=lifecycle.read(path)
 if not op or op.get('kind')!='replace-entry' or req.get('deployment')!=op['deployment']:raise ValueError('Unknown entry migration')
 m=pair.load_manifest()
 if not m or lifecycle.anchor(m)!=op['anchor']:raise ValueError('Original entry ownership changed')
 action=req.get('action')
 if action=='status' or action=='commit' and op['state']=='accepted':return public(op)
 if action in ('candidate-ready','commit') and lifecycle.digest(recovery.export()['state'])!=op['identity_digest']:raise ValueError('Entry users or identity changed after review; keep the original entry and restage a current snapshot')
 if action=='candidate-ready':
  if op['state']=='awaiting-endpoint-switch':return public(op)
  if op['state']!='entry-prepared':raise ValueError('Unexpected entry checkpoint')
  return lifecycle.save(op,'awaiting-endpoint-switch','Candidate route verified; share and verify the updated connection' if op.get('client_update_required') else 'Candidate route verified; transfer the reviewed endpoint and verify a saved client')
 if action=='commit':
  if op['state']=='accepted':return public(op)
  if op['state'] not in ('awaiting-endpoint-switch','entry-cutover'):raise ValueError('Stage the candidate before entry cutover')
  if req.get('confirmation')!=('NEW ENDPOINT CLIENT VERIFIED' if op.get('client_update_required') else 'ENDPOINT AND SAVED CLIENT VERIFIED'):raise ValueError('Verify endpoint transfer and an unchanged saved client first')
  lifecycle.save(op,'entry-cutover','Closing old entry forwarding after verified endpoint transfer');native_routing.apply('quiesce')
  return lifecycle.save(op,'accepted','Replacement entry accepted; old server retained for reviewed cleanup')
 if action=='rollback':
  if op['state']=='accepted':raise ValueError('Accepted entry replacement requires a new reviewed migration')
  if op['state']=='rolled-back':return public(op)
  if req.get('confirmation')!='ORIGINAL ENDPOINT RESTORED':raise ValueError('Restore the original endpoint before rollback')
  verify_current_route(m,req)
  return lifecycle.save(op,'rolled-back','Original entry verified; endpoint rollback completed')
 raise ValueError('Unsupported entry migration action')
def dispatch(req):
 if req.get('action')!='status':__import__('user_updates').ensure_no_runtime_update(destructive=True)
 if req.get('action')=='prepare':return prepare(req)
 if req.get('action')=='verify-candidate':
  m=pair.load_manifest()
  if not m or m['plan']['role']!='entry' or m['plan']['pair']!=req.get('deployment'):raise ValueError('Owned candidate entry required')
  return verify_current_route(m,req)
 if req.get('action')=='record-revision':
  m=pair.load_manifest();revision=req.get('revision')
  if not m or m['plan']['pair']!=req.get('deployment') or type(revision) is not int or revision<2:raise ValueError('Invalid replacement revision')
  current=lifecycle.read(lifecycle.ROOT/'inventory.json')
  if current and current['revision'] not in (revision,revision-1):raise ValueError('Replacement already has another revision')
  endpoint=pair.host(req['entry_endpoint']) if req.get('entry_endpoint') else m['plan']['server']
  if current and current['revision']==revision and current.get('entry_endpoint',m['plan']['server'])!=endpoint:raise ValueError('Recorded replacement endpoint changed')
  lifecycle.write(lifecycle.ROOT/'inventory.json',{'schema':1,'deployment':m['plan']['pair'],'anchor':lifecycle.anchor(m),'revision':revision,'entry_operation':pair.ident(req.get('operation')),'entry_endpoint':endpoint});return {'revision':revision}
 return transition(req)
def main():
 os.umask(0o077)
 try:
  if os.geteuid()!=0:raise ValueError('Owner SSH is required')
  raw=sys.stdin.buffer.read(65537)
  if len(raw)>65536:raise ValueError('Entry migration request too large')
  with lifecycle.management_lock():result=dispatch(json.loads(raw))
  print(json.dumps({'ok':True,'result':result}))
 except Exception as exc:
  print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__}));raise SystemExit(1)
if __name__=='__main__':main()
