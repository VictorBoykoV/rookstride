"""Actual receipt/claim filesystem transitions; no services, sockets or downloads."""
import copy,hashlib,importlib.util,json,os,sys,tempfile,unittest,urllib.error,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(PROJECT/'single'))
import filtering,install_retry as retry,model,runtime
SPEC=importlib.util.spec_from_file_location('standalone_retry_api',PROJECT/'single/run.py')
api=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(api)

class StandaloneRetryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  for name in ('etc/systemd/system','var/lib','opt','run'):(self.root/name).mkdir(parents=True,exist_ok=True)
  (self.root/'etc/machine-id').write_text('local-test-machine\n')
  for module,name,value in ((retry,'SYSTEM',self.root),(runtime,'ROOT',self.root/'opt/rookstride-single'),(runtime,'STATE',self.root/'var/lib/rookstride-single'),(filtering,'ROOT',self.root/'opt/rookstride-filter'),(filtering,'DATA',self.root/'var/lib/rookstride-filter'),(filtering,'UNIT',self.root/'etc/systemd/system/rookstride-filter.service'),(filtering,'NETWORK',self.root/'etc/systemd/system/rookstride-filter-network.service'),(api,'MANAGEMENT_LOCK',self.root/'run/management.lock'),(api,'SINGLE_LOCK',self.root/'run/single.lock')):
   p=patch.object(module,name,value);p.start();self.addCleanup(p.stop)
  self.units={};self.spawned=[];self.effects={};self.commands=[]
  def command(args,**kwargs):
   self.commands.append(args)
   if tuple(args) in self.effects:
    value=self.effects[tuple(args)]
    if isinstance(value,BaseException):raise value
    return SimpleNamespace(returncode=0,stdout=value,stderr='')
   if args[0]=='iptables':return SimpleNamespace(returncode=1,stdout='',stderr='No chain/target/match by that name')
   if args[0] in ('iptables-save','ip6tables-save','docker') or args[:2]==['systemctl','list-units'] or args[:2]==['ip','xfrm']:return SimpleNamespace(returncode=0,stdout='',stderr='')
   if args[0]=='ip':return SimpleNamespace(returncode=0,stdout='[]',stderr='')
   if args[:2]==['systemctl','show']:
    job=args[2].removeprefix('rookstride-single-install-').removesuffix('.service');active=self.units.get(job,False)
    return SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState='+('active' if active else 'inactive')+'\nSubState='+('running' if active else 'dead')+'\nMainPID='+('99' if active else '0')+'\nControlPID=0\n',stderr='')
   if args[0]=='systemd-run':
    job=args[1].removeprefix('--unit=rookstride-single-install-');self.units[job]=True;self.spawned.append(job);return SimpleNamespace(returncode=0,stdout='',stderr='')
   raise AssertionError('Unexpected external command: '+repr(args))
  p=patch.object(api.subprocess,'run',side_effect=command);p.start();self.addCleanup(p.stop)
  p=patch.object(retry.pwd,'getpwnam',side_effect=KeyError);p.start();self.addCleanup(p.stop)
  p=patch.object(retry.grp,'getgrnam',side_effect=KeyError);p.start();self.addCleanup(p.stop)
  p=patch.object(api,'inspect',return_value={'compatible_os':True,'ports':[],'os':'local fixture'});p.start();self.addCleanup(p.stop)
  self.request={'action':'start','protocol':'xray','server':'vpn.example.net','sshPort':22,'login':'phone','install_context':{'schema':1,'owner':str(uuid.uuid4()),'task':uuid.uuid4().hex}}
 def read(self,p):return json.loads(p.read_text())
 def failed(self,typed=True,publish=False):
  started=api.start(copy.deepcopy(self.request));job=started['job']
  def install(state,phase):
   if publish:runtime.directory('xray').mkdir();runtime.save(state)
   raise filtering.AcquisitionUnavailable('network exhausted') if typed else ValueError('generic failure')
  with patch.object(runtime,'install',side_effect=install):api.execute(job)
  self.units[job]=False;status=api.status(job)
  return started,status
 def request_retry(self,status,nonce=None):
  return {'action':'retry','job':status['job'],'nonce':nonce or uuid.uuid4().hex,'install_context':self.request['install_context'],'request':{k:v for k,v in self.request.items() if k!='install_context'},'expected_config_digest':status['install_context']['config_digest'],'failed_receipt_sha256':status.get('failed_receipt_sha256','0'*64)}
 def tree(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}
 def refuse(self,request,pattern='.'):
  before=self.tree();count=len(self.spawned)
  with self.assertRaisesRegex((ValueError,OSError),pattern):api.retry_install(request)
  self.assertEqual(count,len(self.spawned));self.assertEqual(before,self.tree())
 def test_typed_failure_is_before_publication_and_linked_retry_preserves_receipt_and_instance(self):
  first,status=self.failed();old=retry.job_path(first['job']);original={n:(old/n).read_bytes() for n in ('meta.json','status.json')}
  self.assertEqual('acquisition-unavailable',status['retryable']['reason']);self.assertFalse((old/'request.json').exists());self.assertFalse(runtime.directory('xray').exists());self.assertFalse(filtering.DATA.exists())
  request=self.request_retry(status);child=api.retry_install(request);self.assertNotEqual(first['job'],child['job']);self.assertEqual(first['job'],child['retry_of']);self.assertEqual(first['install_context'],child['install_context'])
  config=self.read(retry.job_path(child['job'])/'request.json');self.assertEqual(first['install_context']['instance'],config['instance']);self.assertEqual(first['plan']['port'],config['port']);self.assertEqual(original,{n:(old/n).read_bytes() for n in original})
 def test_start_lost_reply_reconciles_same_running_job_without_dispatch(self):
  first=api.start(copy.deepcopy(self.request));second=api.start(copy.deepcopy(self.request));self.assertEqual(first['job'],second['job']);self.assertEqual([first['job']],self.spawned)
 def test_linked_retry_lost_reply_returns_same_running_or_complete_child_without_replay(self):
  first,status=self.failed();request=self.request_retry(status);child=api.retry_install(request)
  # A known linked child may now publish; reconciliation is read-only, not a retry.
  runtime.directory('xray').mkdir();runtime.save({'protocol':'xray','owner':'rookstride-single-v1','instance':child['install_context']['instance']})
  for state in ('running','complete'):
   api.progress(retry.job_path(child['job']),7,'observed child',state)
   again=api.retry_install(copy.deepcopy(request));self.assertEqual(child['job'],again['job']);self.assertEqual(state,again['state'])
  self.assertEqual(2,len(self.spawned));self.assertEqual('failed',self.read(retry.job_path(first['job'])/'status.json')['state'])
 def test_generic_legacy_and_postpublication_failures_never_qualify(self):
  first,status=self.failed(typed=False);self.assertNotIn('retryable',status);self.refuse(self.request_retry(status),'not proven')
  # Independently emulate a typed failure after a protocol child was saved.
  p=retry.job_path(first['job'])/'status.json';value=self.read(p);value['retryable']={'reason':'acquisition-unavailable',**first['install_context']};runtime.atomic(p,json.dumps(value));runtime.directory('xray').mkdir();self.refuse(self.request_retry({**value,'failed_receipt_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))
 def test_actual_postpublication_typed_exception_has_no_retry_marker(self):
  first,status=self.failed(publish=True);self.assertNotIn('retryable',status);self.assertTrue(runtime.directory('xray').exists());self.refuse(self.request_retry(status),'not proven')
 def test_failed_but_live_worker_or_retained_request_is_refused(self):
  first,status=self.failed();request=self.request_retry(status);self.units[first['job']]=True;self.refuse(request,'active or its state is unknown');self.units[first['job']]=False
  (retry.job_path(first['job'])/'request.json').write_text('{}');self.refuse(request,'cleanup')
 def test_foreign_job_owner_request_source_machine_and_receipt_are_refused(self):
  first,status=self.failed();base=self.request_retry(status)
  for field,value in (('nonce','bad'),('failed_receipt_sha256','f'*64),('expected_config_digest','f'*64)):
   with self.subTest(field=field):request=copy.deepcopy(base);request[field]=value;self.refuse(request)
  request=copy.deepcopy(base);request['install_context']['owner']=str(uuid.uuid4());self.refuse(request,'owner/task')
  request=copy.deepcopy(base);request['request']['login']='different';self.refuse(request,'configuration changed')
  request=copy.deepcopy(base);request['request']['port']=8443;self.refuse(request,'configuration changed')
  machine=self.root/'etc/machine-id';machine.write_text('changed\n');self.refuse(base,'configuration changed')
  machine.write_text('local-test-machine\n')
  before=self.tree()
  with self.assertRaisesRegex(ValueError,'configuration changed'):retry.retry(base,'f'*64,api.plan,lambda job:self.fail('must not dispatch'),api.progress)
  self.assertEqual(before,self.tree())
 def test_partial_filter_link_unknown_child_and_other_pending_are_refused_unchanged(self):
  first,status=self.failed();request=self.request_retry(status)
  for path in (filtering.ROOT,filtering.DATA,self.root/'etc/rookstride-pair',runtime.STATE/'unknown-child'):
   with self.subTest(path=path):path.mkdir();self.refuse(request);path.rmdir()
  target=self.root/'keep';target.write_text('unchanged');filtering.DATA.symlink_to(target);self.refuse(request,'link changed');filtering.DATA.unlink()
  second=runtime.STATE/'jobs'/('f'*32);second.mkdir();runtime.atomic(second/'status.json',json.dumps({'state':'unknown'}));self.refuse(request,'unfinished or unknown')
 def test_running_and_completed_original_jobs_cannot_retry(self):
  first,status=self.failed();request=self.request_retry(status)
  for state in ('running','complete'):
   api.progress(retry.job_path(first['job']),7,'unchanged',state);self.refuse(request,'not proven')
 def test_competing_claim_and_mutated_linked_child_refuse_without_dispatch(self):
  first,status=self.failed();request=self.request_retry(status);child=api.retry_install(request);other=copy.deepcopy(request);other['nonce']=uuid.uuid4().hex;self.refuse(other,'claim')
  meta=retry.job_path(child['job'])/'meta.json';value=self.read(meta);value['retry_of']='9'*32;runtime.atomic(meta,json.dumps(value));self.refuse(request,'changed')
 def test_unknown_claim_with_missing_child_is_not_resubmitted(self):
  first,status=self.failed();request=self.request_retry(status);parent=retry.job_path(first['job']);retry.write_new(parent/'retry-claim.json',{'schema':1,'job':'f'*32,'retry_of':first['job'],'nonce':request['nonce'],'failed_receipt_sha256':request['failed_receipt_sha256'],'install_context':first['install_context']});self.refuse(request)
 def test_start_context_mutation_and_active_other_task_do_not_allocate(self):
  first=api.start(copy.deepcopy(self.request));changed=copy.deepcopy(self.request);changed['login']='other';before=self.tree()
  with self.assertRaisesRegex(ValueError,'configuration changed'):api.start(changed)
  self.assertEqual(before,self.tree());changed=copy.deepcopy(self.request);changed['install_context']['task']=uuid.uuid4().hex
  with self.assertRaisesRegex(ValueError,'current installation'):api.start(changed)
  self.assertEqual([first['job']],self.spawned)

 def test_actual_prefetch_transport_exhaustion_is_sealed_without_publication(self):
  first=api.start(copy.deepcopy(self.request));job=first['job']
  with patch.object(filtering,'CACHE',self.root/'public-cache'),patch.object(filtering,'https_open',side_effect=urllib.error.URLError('both public origins unavailable')) as fetch,patch.object(filtering.time,'sleep'),patch.object(runtime,'command') as mutation:
   api.execute(job);mutation.assert_not_called();self.assertEqual(3,fetch.call_count)
  self.units[job]=False;status=api.status(job);self.assertIn('failed_receipt_sha256',status);self.assertFalse(runtime.directory('xray').exists());self.assertFalse(filtering.ROOT.exists());self.assertFalse(filtering.DATA.exists())
  child=api.retry_install(self.request_retry(status));self.assertEqual(job,child['retry_of']);self.assertEqual(2,len(self.spawned))

 def test_modified_failed_status_cannot_receive_a_new_accepted_receipt(self):
  first,status=self.failed();request=self.request_retry(status);path=retry.job_path(first['job'])/'status.json';value=self.read(path);value['phase']='later changed';runtime.atomic(path,json.dumps(value))
  with self.assertRaisesRegex(ValueError,'Immutable failed receipt'):api.status(first['job'])
  self.refuse(request,'Immutable failed receipt')
  request['failed_receipt_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();self.refuse(request,'Immutable failed receipt')

 def test_loaded_deleted_service_group_container_interface_and_network_effects_refuse(self):
  first,status=self.failed();request=self.request_retry(status)
  cases=[(('systemctl','list-units','--all','--plain','--no-legend','--no-pager','--full','rookstride-*','twohop-*','awg-quick@awg-exit.service','strongswan*','charon*','unbound*','adguardhome*'),'rookstride-filter.service loaded active running filter\n'),
         (('iptables-save',),'*filter\n:RSPAIR_GUARD - [0:0]\nCOMMIT\n'),(('ip6tables-save',),'*filter\n:SINGLEVPN_V6_SINK - [0:0]\nCOMMIT\n'),
         (('iptables-save',),'-A OUTPUT -m comment --comment ROOK_LOCAL_deadbeef -j REJECT\n'),(('iptables-save',),':RSLIFE_GUARD - [0:0]\n'),
         (('docker','ps','--all','--format','{{json .}}'),json.dumps({'Names':'unrelated-name','Labels':'io.rookstride.instance=example'})+'\n'),
         (('ip','-j','address','show'),json.dumps([{'ifname':'awg-exit','addr_info':[]}])),(('ip','-j','address','show'),json.dumps([{'ifname':'lo','addr_info':[{'local':'10.249.255.253'}]}])),
         (('ip','-j','-4','route','show','table','all'),json.dumps([{'table':51831,'dst':'default'}])),(('ip','-j','-4','rule','show'),json.dumps([{'priority':89,'table':51832}])),(('ip','xfrm','state'),'src 192.0.2.1 dst 192.0.2.2\n')]
  for args,output in cases:
   with self.subTest(args=args,output=output):self.effects[args]=output;self.refuse(request);self.effects.clear()
  with patch.object(retry.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=123)):self.refuse(request,'filter group')
  # A precisely owned operator download fault is not published VPN state.
  self.effects[('iptables-save',)]='-A OUTPUT -d 192.0.2.1/32 -p tcp --dport 443 -m comment --comment ROOK_DL21_test -j REJECT\n'
  self.assertEqual(first['job'],api.retry_install(request)['retry_of'])

 def test_original_auto_port_is_retained_and_busy_port_refuses(self):
  first,status=self.failed();request=self.request_retry(status);port=first['plan']['port']
  with patch.object(api,'inspect',return_value={'compatible_os':True,'ports':[{'port':port,'transport':'tcp'}],'os':'local'}):self.refuse(request,'already in use')
  child=api.retry_install(request);self.assertEqual(port,child['plan']['port'])

 def test_index_and_claim_directory_are_synced_before_dispatch_and_sync_failure_stops(self):
  synced=[];real_sync=retry.sync_directory;real_spawn=api.spawn
  def sync(path):real_sync(path);synced.append(Path(path))
  def spawn(job,release):
   path=retry.job_path(job);meta=self.read(path/'meta.json')
   expected=retry.job_path(meta['retry_of']) if meta.get('retry_of') else retry.index_path(meta['install_context']).parent
   self.assertIn(expected,synced);self.assertTrue((path/'request.json').exists());return real_spawn(job,release)
  with patch.object(retry,'sync_directory',side_effect=sync),patch.object(api,'spawn',side_effect=spawn):
   first,status=self.failed();synced.clear();request=self.request_retry(status);api.retry_install(request)
  # A crash/durability error after creating a claim must not launch or allocate
  # another child on the next exact request.
  first2=copy.deepcopy(self.request);first2['install_context']['task']=uuid.uuid4().hex
  # Separate fresh server state avoids the previous child's legitimate work.
  self.units[self.spawned[-1]]=False;api.progress(retry.job_path(self.spawned[-1]),1,'terminal','failed')
  with patch.object(retry,'sync_directory',side_effect=OSError('disk sync failed')):
   count=len(self.spawned)
   with self.assertRaises(OSError):api.start(first2)
   self.assertEqual(count,len(self.spawned))

 def test_retry_dispatch_timeout_leaves_claim_and_never_resubmits_uncertain_child(self):
  first,status=self.failed();request=self.request_retry(status);count=len(self.spawned)
  with patch.object(api,'spawn',side_effect=TimeoutError('reply lost before observed dispatch')):
   with self.assertRaises(TimeoutError):api.retry_install(request)
  self.assertEqual(count,len(self.spawned));self.refuse(request,'dispatch is uncertain')

 def test_existing_state_disables_retry_proof_without_blocking_normal_start(self):
  filtering.ROOT.mkdir();(filtering.ROOT/'preserve').write_text('existing shared module')
  first,status=self.failed();meta=self.read(retry.job_path(first['job'])/'meta.json')
  self.assertFalse(meta['prefetch_retry_baseline']);self.assertNotIn('retryable',status);self.assertEqual('existing shared module',(filtering.ROOT/'preserve').read_text());self.refuse(self.request_retry(status),'not proven')

 def test_missing_proof_tool_never_silently_qualifies_a_fresh_host(self):
  self.effects[('ip6tables-save',)]=FileNotFoundError('not installed')
  first,status=self.failed();self.assertFalse(self.read(retry.job_path(first['job'])/'meta.json')['prefetch_retry_baseline']);self.assertNotIn('retryable',status);self.assertEqual(1,len(self.spawned));self.refuse(self.request_retry(status),'not proven')

 def test_claim_sync_failure_leaves_an_uncertain_claim_and_cannot_reallocate(self):
  first,status=self.failed();request=self.request_retry(status);old=retry.job_path(first['job']);real_sync=retry.sync_directory
  def sync(path):
   real_sync(path)
   if Path(path)==old and (old/'retry-claim.json').exists():raise OSError('claim directory sync failed')
  count=len(self.spawned)
  with patch.object(retry,'sync_directory',side_effect=sync):
   with self.assertRaises(OSError):api.retry_install(request)
  self.assertEqual(count,len(self.spawned));self.assertTrue((old/'retry-claim.json').exists());self.refuse(request)

 def test_another_tasks_orphan_claim_blocks_current_retry_and_new_retry_eligibility(self):
  first,status=self.failed();request=self.request_retry(status)
  other_request=copy.deepcopy(self.request);other_request['install_context']['task']=uuid.uuid4().hex
  other=api.start(other_request)
  with patch.object(runtime,'install',side_effect=filtering.AcquisitionUnavailable('network exhausted')):api.execute(other['job'])
  self.units[other['job']]=False;other_status=api.status(other['job']);self.assertIn('retryable',other_status)
  retry.write_new(retry.job_path(other['job'])/'retry-claim.json',{'schema':1,'job':'f'*32,'retry_of':other['job'],'nonce':uuid.uuid4().hex,'failed_receipt_sha256':other_status['failed_receipt_sha256'],'install_context':other['install_context'],'meta_sha256':'e'*64})
  self.refuse(request)
  third=copy.deepcopy(self.request);third['install_context']['task']=uuid.uuid4().hex;new=api.start(third)
  self.assertFalse(self.read(retry.job_path(new['job'])/'meta.json')['prefetch_retry_baseline'])
  with patch.object(runtime,'install',side_effect=filtering.AcquisitionUnavailable('network exhausted')):api.execute(new['job'])
  self.units[new['job']]=False;self.assertNotIn('retryable',api.status(new['job']))

 def test_a_known_linked_child_may_qualify_only_after_its_own_terminal_failure(self):
  first,status=self.failed();child=api.retry_install(self.request_retry(status))
  with patch.object(runtime,'install',side_effect=filtering.AcquisitionUnavailable('network exhausted')):api.execute(child['job'])
  self.units[child['job']]=False;failed=api.status(child['job']);self.assertIn('retryable',failed)
  next_child=api.retry_install(self.request_retry(failed));self.assertEqual(child['job'],next_child['retry_of']);self.assertEqual(3,len(self.spawned));self.assertEqual('failed',api.status(first['job'])['state'])

if __name__=='__main__':unittest.main()
