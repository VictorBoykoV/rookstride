"""Private resolver boundaries and key-preserving adoption; no live hosts."""
import importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import filtering,model,runtime
spec=importlib.util.spec_from_file_location('filter_job_api',ROOT/'single/run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
class FilteringTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
  for key,value in {'CACHE':self.base/'cache','ROOT':self.base/'opt','DATA':self.base/'data','UNIT':self.base/'filter.service','NETWORK':self.base/'network.service'}.items():
   p=patch.object(filtering,key,value);p.start();self.addCleanup(p.stop)
 def state(self,**overrides):
  filtering.ROOT.mkdir(exist_ok=True);filtering.DATA.mkdir(exist_ok=True)
  value=dict(owner=filtering.OWNER,instance='fixture',address='10.253.0.1',dns_port=5354,api_port=3001,password='fixture-private-admin');value.update(overrides);filtering.save(value);return value
 def test_verified_archive_accepts_dot_prefix_and_rejects_links(self):
  import io,tarfile,hashlib
  for linked in (False,True):
   stream=io.BytesIO()
   with tarfile.open(fileobj=stream,mode='w:gz') as archive:
    member=tarfile.TarInfo('./AdGuardHome/AdGuardHome')
    if linked:member.type=tarfile.SYMTYPE;member.linkname='/outside'
    else:member.size=7
    archive.addfile(member,None if linked else io.BytesIO(b'binary!'))
   data=stream.getvalue()
   class Response(io.BytesIO):
    def __enter__(self):return self
    def __exit__(self,*args):pass
   with patch.object(filtering.platform,'machine',return_value='x86_64'),patch.dict(filtering.ASSETS,{'x86_64':('amd64',hashlib.sha256(data).hexdigest(),len(data),123)}),patch.object(filtering,'https_open',return_value=Response(data)):
    if linked:
     with self.assertRaises(ValueError):filtering.prepare_binary()
    else:self.assertEqual(filtering.prepare_binary(),b'binary!');self.assertFalse(filtering.ROOT.exists())
 def test_filter_only_reset_is_refused_when_an_installed_protocol_uses_it(self):
  with patch.object(api,'ensure_idle'),patch.object(filtering,'references',return_value=['awg']),patch.object(filtering,'reset_apply') as remove:
   with self.assertRaises(ValueError):api.action(dict(action='filter-reset-apply',token='fixture',confirmation='DELETE VPN'))
   remove.assert_not_called()
 def test_changed_owner_and_linked_state_are_rejected(self):
  self.state(owner='foreign')
  with self.assertRaises(ValueError):filtering.load()
  (filtering.DATA/'state.json').unlink();(filtering.DATA/'state.json').symlink_to(self.base/'foreign')
  with self.assertRaises(ValueError):filtering.load()
 def test_unowned_paths_precede_any_mutation(self):
  filtering.ROOT.mkdir()
  with patch.object(filtering,'command') as command:
   with self.assertRaises(ValueError):filtering.ensure()
   command.assert_not_called()
 def test_private_bind_auth_and_disabled_query_history(self):
  user=SimpleNamespace(pw_uid=123,pw_gid=123,pw_dir=str(filtering.DATA/'agh'),pw_shell='/usr/sbin/nologin')
  def cmd(args,check=True,data=None):return SimpleNamespace(returncode=1 if args[:3]==['iptables','-S',filtering.CHAIN] else 0,stdout='$2b$12$fixture-hash' if args[0]=='/usr/bin/python3' else '')
  with patch.object(filtering,'ensure_dependencies'),patch.object(filtering,'command',side_effect=cmd),patch.object(filtering.pwd,'getpwnam',side_effect=[KeyError(),user]),patch.object(filtering,'choose_address',return_value='10.253.0.1'),patch.object(filtering,'ports',return_value=set()),patch.object(filtering,'prepare_binary',return_value=b'fixture binary'),patch.object(filtering.os,'chown'),patch.object(filtering,'ready',return_value=True),patch.object(filtering,'api',return_value={'filters':[{'rules_count':42}]}):
   old=os.umask(0o077)
   try:filtering.ensure()
   finally:os.umask(old)
  config=json.loads((filtering.DATA/'agh/AdGuardHome.yaml').read_text());state=filtering.load()
  self.assertEqual(filtering.ROOT.stat().st_mode&0o777,0o755);self.assertEqual(filtering.DATA.stat().st_mode&0o777,0o755)
  self.assertEqual(config['dns']['bind_hosts'],['10.253.0.1']);self.assertEqual(config['dns']['port'],5354);self.assertEqual(config['http']['address'],'127.0.0.1:3001')
  self.assertEqual(config['dns']['fallback_dns'],['https://cloudflare-dns.com/dns-query']);self.assertEqual('parallel',config['dns']['upstream_mode']);self.assertEqual('5s',config['dns']['upstream_timeout']);self.assertEqual(2,len(config['dns']['upstream_dns']));self.assertTrue(all(x.startswith('https://') for x in config['dns']['upstream_dns']+config['dns']['fallback_dns']));self.assertFalse(config['querylog']['file_enabled']);self.assertTrue(config['users'][0]['password'].startswith('$2b$'))
  self.assertNotIn(state['password'],json.dumps(config));self.assertEqual((filtering.DATA/'state.json').stat().st_mode&0o777,0o600)
  self.assertIn('Requires=rookstride-filter-network.service',filtering.UNIT.read_text());self.assertIn('NoNewPrivileges=true',filtering.UNIT.read_text())
 def test_minimal_ubuntu_installs_missing_bcrypt_and_firewall_without_secret_arguments(self):
  calls=[]
  def cmd(args,check=True,data=None,timeout=90):
   calls.append((args,data,timeout));return SimpleNamespace(returncode=1 if args[:2]==['/usr/bin/python3','-c'] else 0)
  with patch.object(filtering,'command',side_effect=cmd),patch.object(filtering.shutil,'which',side_effect=lambda tool:None if tool=='iptables' else '/usr/bin/'+tool):
   filtering.ensure_dependencies(lambda text:None)
  self.assertEqual(calls[-1][0][-2:],['iptables','python3-bcrypt'])
  self.assertEqual(calls[-1][2],1200);self.assertTrue(all(data is None for _,data,_ in calls))
 def test_existing_dependencies_need_no_package_operation(self):
  with patch.object(filtering,'command',return_value=SimpleNamespace(returncode=0)) as command,patch.object(filtering.shutil,'which',return_value='/usr/bin/tool'):
   filtering.ensure_dependencies(lambda text:None)
  self.assertEqual(command.call_count,1)
 def test_dns_firewall_has_no_public_accept(self):
  self.state();calls=[]
  def cmd(args,check=True,data=None):
   calls.append(args);return SimpleNamespace(returncode=1 if args[:3]==['iptables','-C','INPUT'] else 0,stdout=json.dumps([{'addr_info':[{'local':'10.253.0.1'}]}]) if args[0]=='ip' else '')
  with patch.object(filtering,'command',side_effect=cmd),patch.object(filtering,'bridge',return_value=('docker0',['172.17.0.0/16'])):filtering.network_start()
  accepts=[c for c in calls if c[-1:] == ['ACCEPT']];self.assertEqual(len(accepts),4)
  for c in accepts:self.assertIn('-i',c);self.assertIn('10.253.0.1',c);self.assertIn('5354',c)
  self.assertEqual(len([c for c in calls if c[-1:]==['DROP']]),2)
 def test_local_control_disables_environment_proxies_and_omits_credentials(self):
  self.state();seen={}
  class Response:
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def read(self,n):return b'{"num_dns_queries":7}'
  class Opener:
   def open(self,req,timeout):seen['request']=req;return Response()
  def opener(handler):seen['proxy']=handler.proxies;return Opener()
  with patch.object(filtering.urllib.request,'build_opener',side_effect=opener):self.assertEqual(filtering.api('stats'),{'num_dns_queries':7})
  self.assertEqual(seen['proxy'],{});self.assertEqual(seen['request'].full_url,'http://127.0.0.1:3001/control/stats');self.assertNotIn('fixture-private-admin',seen['request'].full_url)
 def test_failed_new_list_keeps_the_previous_preset(self):
  calls=[];url=filtering.FILTERS['standard'][1]
  def request(endpoint,body=None):
   calls.append((endpoint,body))
   return {'filters':[{'url':url,'name':'Original','enabled':True,'rules_count':42}]} if endpoint=='filtering/status' else {}
  with patch.object(filtering,'api',side_effect=request),patch.object(filtering.time,'sleep'):
   with self.assertRaises(ValueError):filtering.control({'level':'strong'})
  self.assertFalse(any(body and body.get('data',{}).get('enabled') is False for _,body in calls))
 def test_reset_receipt_detects_changed_secret_before_service_changes(self):
  state=self.state();review=filtering.reset_plan();state['password']='changed-fixture';filtering.save(state)
  with patch.object(filtering,'command') as command:
   with self.assertRaises(ValueError):filtering.reset_apply({'confirmation':'DELETE VPN','token':review['token']})
   command.assert_not_called()
 def test_existing_protocol_adoption_preserves_crypto_and_uses_no_new_login(self):
  state=dict(protocol='awg',instance='existing-instance',port=51820,private='private-fixture',users=[dict(login='phone',private='peer-fixture')])
  with patch.object(runtime,'save'),patch.object(runtime,'check_container',return_value=True),patch.object(runtime,'command'),patch.object(runtime,'apply_config') as apply,patch.object(runtime,'health',return_value={'running':True}),patch.object(filtering,'ensure'),patch.object(filtering,'load',return_value={'instance':'dns-fixture'}),patch.object(filtering,'ready',return_value=True):runtime.enable_filter(state,lambda *args:None)
  self.assertEqual(state['instance'],'existing-instance');self.assertEqual(state['private'],'private-fixture');self.assertEqual(state['users'][0]['private'],'peer-fixture');apply.assert_called_once_with(state,first=True)
 def test_filter_job_keeps_the_existing_instance_and_never_serializes_keys(self):
  from types import SimpleNamespace
  state=dict(protocol='awg',instance='existing-instance',port=51820,private='private-fixture',users=[{'private':'peer-fixture'}])
  with patch.object(api,'inspect',return_value={'compatible_os':True}),patch.object(runtime,'load',return_value=state),patch.object(runtime,'ROOT',self.base/'jobs-opt'),patch.object(runtime,'STATE',self.base/'jobs-state'),patch.object(api.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
   result=api.start(dict(protocol='awg',filter_only=True));request=(self.base/'jobs-state/jobs'/result['job']/'request.json').read_text();self.assertEqual(json.loads(request)['instance'],'existing-instance');self.assertNotIn('private-fixture',request);self.assertNotIn('peer-fixture',request)
 def test_xray_captures_dns_before_private_block_without_system_fallback(self):
  state=dict(users=[],port=443,sni='www.example.net',private='private-fixture',shortId='abcd');cfg=model.xray_server(state,dict(address='10.253.0.1',dns_port=5354))
  self.assertEqual(cfg['dns']['servers'],['tcp+local://10.253.0.1:5354']);self.assertEqual(cfg['routing']['rules'][0]['outboundTag'],'filtered-dns');self.assertEqual(cfg['routing']['rules'][0]['port'],'53');self.assertEqual(cfg['routing']['rules'][1]['outboundTag'],'block')
 def test_external_dot_is_declined_only_when_filtering_is_enabled(self):
  state=dict(users=[],port=443,sni='www.example.net',private='private-fixture',shortId='abcd')
  legacy=model.xray_server(state);filtered=model.xray_server(state,dict(address='10.253.0.1',dns_port=5354))
  self.assertFalse(any(rule.get('port')=='853' for rule in legacy['routing']['rules']))
  self.assertEqual(filtered['routing']['rules'][1],dict(type='field',network='tcp,udp',port='853',outboundTag='block'))
 def test_existing_valid_filter_waits_for_transient_dns_readiness(self):
  self.state();(filtering.ROOT/'AdGuardHome').write_text('fixture binary');(filtering.ROOT/'filtering.py').write_text('fixture helper');(filtering.DATA/'agh').mkdir();(filtering.DATA/'agh/AdGuardHome.yaml').write_text('{}')
  for p in (filtering.UNIT,filtering.NETWORK):p.write_text('[Unit]\nDescription=Rookstride private DNS fixture\n')
  with patch.object(filtering,'command'),patch.object(filtering,'ready',side_effect=[False,False,True]) as ready,patch.object(filtering,'api',return_value={'filters':[{'enabled':True,'rules_count':42}]}),patch.object(filtering,'network_start') as network,patch.object(filtering.time,'sleep') as sleep:
   filtering.ensure()
  self.assertEqual(ready.call_count,3);self.assertEqual(sleep.call_count,2);network.assert_called_once()

 def test_empty_enabled_list_is_retried_and_fresh_setup_requires_rules(self):
  calls=[];loaded=False
  def api(endpoint,body=None):
   nonlocal loaded
   calls.append((endpoint,body))
   if endpoint=='filtering/refresh':loaded=True;return {}
   return dict(enabled=True,filters=[dict(enabled=True,rules_count=100 if loaded else 0)])
  with patch.object(filtering,'api',side_effect=api),patch.object(filtering,'ready',return_value=True),patch.object(filtering.time,'sleep'):
   filtering.wait_ready(lambda text:None,fresh=True)
  self.assertEqual([('filtering/refresh',dict(whitelist=False,force=True))],[x for x in calls if x[0]=='filtering/refresh'])

 def test_empty_list_retry_is_bounded_and_never_becomes_success(self):
  with patch.object(filtering,'api',return_value=dict(enabled=True,filters=[dict(enabled=True,rules_count=0)])) as api,patch.object(filtering,'ready',return_value=False),patch.object(filtering.time,'sleep'):
   with self.assertRaisesRegex(ValueError,'Check server HTTPS'):filtering.wait_ready(lambda text:None,fresh=True)
  self.assertEqual(3,len([x for x in api.call_args_list if x.args[0]=='filtering/refresh']))

 def test_paused_resolver_reuse_does_not_change_lists_or_protection(self):
  with patch.object(filtering,'ready',return_value=True),patch.object(filtering,'api') as api:
   filtering.wait_ready(lambda text:None)
  api.assert_not_called()

 def test_reuse_repairs_private_network_before_testing_dns(self):
  self.state();(filtering.ROOT/'AdGuardHome').write_text('fixture binary');(filtering.ROOT/'filtering.py').write_text('fixture helper');(filtering.DATA/'agh').mkdir();(filtering.DATA/'agh/AdGuardHome.yaml').write_text('{}')
  for p in (filtering.UNIT,filtering.NETWORK):p.write_text('[Unit]\nDescription=Rookstride private DNS fixture\n')
  events=[]
  with patch.object(filtering,'command'),patch.object(filtering,'network_start',side_effect=lambda:events.append('repair')),patch.object(filtering,'ready',side_effect=lambda:events.append('dns') or True):filtering.ensure()
  self.assertEqual(events,['repair','dns'])
 def test_paused_protection_remains_a_resolver_and_can_be_reenabled(self):
  with patch.object(filtering,'command',return_value=SimpleNamespace(returncode=0)),patch.object(filtering,'api',return_value={'protection_enabled':False}),patch.object(filtering,'query',side_effect=[0,0]):self.assertTrue(filtering.ready())
  with patch.object(filtering,'command',return_value=SimpleNamespace(returncode=0)),patch.object(filtering,'api',return_value={'protection_enabled':True}),patch.object(filtering,'query',side_effect=[0,0]):self.assertFalse(filtering.ready())
 def test_protection_api_accepts_only_boolean_and_returns_no_admin_secret(self):
  with patch.object(filtering,'api',side_effect=[{},dict(num_dns_queries=7,num_blocked_filtering=3),dict(filters=[]),dict(protection_enabled=False)]) as api:
   result=filtering.control({'enabled':False});self.assertFalse(result['protection_enabled']);self.assertEqual(result['blocked'],3);self.assertEqual(api.call_args_list[0].args,('protection',dict(enabled=False,duration=0)))
  with patch.object(filtering,'api') as api:
   with self.assertRaises(ValueError):filtering.control({'enabled':'false'})
   api.assert_not_called()

class PublicComponentCache(unittest.TestCase):
 def test_verified_cache_is_rechecked_and_needs_no_network(self):
  import hashlib
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering,'https_open') as fetch:
   filtering.CACHE.mkdir();data=b'public component';digest=hashlib.sha256(data).hexdigest();(filtering.CACHE/digest).write_bytes(data)
   self.assertEqual(data,filtering.pinned_download('https://example.net/component',digest,100));fetch.assert_not_called()
   (filtering.CACHE/digest).write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'checksum'):filtering.pinned_download('https://example.net/component',digest,100)
 def test_transient_download_retries_but_never_caches_a_failed_body(self):
  import hashlib,io,urllib.error
  data=b'verified public component';digest=hashlib.sha256(data).hexdigest()
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering.time,'sleep'),patch.object(filtering,'https_open',side_effect=[urllib.error.URLError('temporary'),io.BytesIO(data)]) as fetch:
   self.assertEqual(data,filtering.pinned_download('https://example.net/component',digest,100,len(data)));self.assertEqual(2,fetch.call_count);self.assertEqual(data,(filtering.CACHE/digest).read_bytes())
 def test_missing_release_is_not_retried_or_accepted(self):
  import urllib.error
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering,'https_open',side_effect=urllib.error.HTTPError('https://example.net',404,'missing',{},None)) as fetch:
   with self.assertRaisesRegex(ValueError,'rejected'):filtering.pinned_download('https://example.net','a'*64,100)
   self.assertEqual(1,fetch.call_count);self.assertEqual([],list(filtering.CACHE.iterdir()))
 def test_bad_download_and_cache_links_never_run_or_replace_public_files(self):
  import io
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering,'https_open',return_value=io.BytesIO(b'tampered')):
   with self.assertRaisesRegex(ValueError,'checksum'):filtering.pinned_download('https://example.net','a'*64,100)
   target=Path(d)/'unrelated';target.write_bytes(b'keep');(filtering.CACHE/('a'*64)).symlink_to(target)
   with self.assertRaisesRegex(ValueError,'link'):filtering.pinned_download('https://example.net','a'*64,100)
   self.assertEqual(b'keep',target.read_bytes())
 def test_bounded_download_retries_stop_and_leave_no_cache(self):
  import urllib.error
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering.time,'sleep'),patch.object(filtering,'https_open',side_effect=urllib.error.URLError('unreachable')) as fetch:
   with self.assertRaisesRegex(ValueError,'three attempts'):filtering.pinned_download('https://example.net','a'*64,100)
   self.assertEqual(3,fetch.call_count);self.assertEqual([],list(filtering.CACHE.iterdir()))
