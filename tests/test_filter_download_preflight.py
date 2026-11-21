"""Failure/retry boundaries for fresh installs; all downloads and services are local fakes."""
import contextlib,hashlib,http.client,io,json,ssl,sys,tarfile,tempfile,unittest,urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import filtering,model,routes,runtime


def archive_bytes(kind=tarfile.REGTYPE):
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w:gz') as archive:
  item=tarfile.TarInfo('./AdGuardHome/AdGuardHome');item.type=kind;item.size=7 if kind==tarfile.REGTYPE else 0;item.linkname='/foreign'
  archive.addfile(item,io.BytesIO(b'binary!') if item.size else None)
 return stream.getvalue()


class FilterDownloadPreflight(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
  for module,key,value in [(filtering,'CACHE',self.base/'cache'),(filtering,'ROOT',self.base/'opt-filter'),(filtering,'DATA',self.base/'filter-data'),(filtering,'UNIT',self.base/'filter.service'),(filtering,'NETWORK',self.base/'network.service'),(runtime,'STATE',self.base/'protocols')]:
   p=patch.object(module,key,value);p.start();self.addCleanup(p.stop)
  self.raw=archive_bytes();p=patch.dict(filtering.ASSETS,{'x86_64':('amd64',hashlib.sha256(self.raw).hexdigest(),len(self.raw),705629752)});p.start();self.addCleanup(p.stop)
  p=patch.object(filtering.platform,'machine',return_value='x86_64');p.start();self.addCleanup(p.stop)

 def assert_unpublished(self,protocol=None):
  for p in (filtering.ROOT,filtering.DATA,filtering.UNIT,filtering.NETWORK):self.assertFalse(p.exists(),str(p))
  if protocol:self.assertFalse(runtime.directory(protocol).exists())

 def test_filter_download_failure_leaves_no_owned_state_and_retry_completes(self):
  with patch.object(filtering,'https_open',side_effect=urllib.error.URLError('offline')),patch.object(filtering.time,'sleep'),patch.object(filtering,'ensure_dependencies') as dependencies,patch.object(filtering,'command') as command:
   with self.assertRaisesRegex(ValueError,'three attempts'):filtering.ensure()
   self.assert_unpublished();dependencies.assert_not_called();command.assert_not_called()
  # A later retry can prepare the verified binary without recovering/resetting state.
  with patch.object(filtering,'https_open',return_value=io.BytesIO(self.raw)):
   self.assertEqual(b'binary!',filtering.prepare_binary())
  self.assert_unpublished();self.assertEqual(self.raw,(filtering.CACHE/hashlib.sha256(self.raw).hexdigest()).read_bytes())

 def test_both_adapter_families_retry_after_failed_download_without_child_stub(self):
  for protocol in ('awg','hysteria2'):
   with self.subTest(protocol=protocol):
    state=dict(protocol=protocol,owner='rookstride-single-v1',instance='new-'+protocol,initialLogin='phone',port=51820 if protocol=='awg' else 443,server='vpn.example.net')
    with patch.object(filtering,'https_open',side_effect=urllib.error.URLError('offline')),patch.object(filtering.time,'sleep'),patch.object(runtime,'command') as command,patch.object(routes,'worker') as worker:
     with self.assertRaisesRegex(ValueError,'three attempts'):runtime.install(state,lambda *args:None)
     self.assert_unpublished(protocol);command.assert_not_called();worker.assert_not_called();self.assertNotIn('users',state)
    user=SimpleNamespace(pw_uid=123,pw_gid=123,pw_dir=str(filtering.DATA/'agh'),pw_shell='/usr/sbin/nologin')
    def cmd(args,check=True,data=None):return SimpleNamespace(returncode=1 if args[:3]==['iptables','-S',filtering.CHAIN] else 0,stdout='$2b$12$fixture-hash' if args[0]=='/usr/bin/python3' else '')
    with contextlib.ExitStack() as stack:
     for target,name,kw in [(filtering,'https_open',dict(return_value=io.BytesIO(self.raw))), (filtering,'command',dict(side_effect=cmd)), (filtering,'ensure_dependencies',{}), (filtering.pwd,'getpwnam',dict(side_effect=[KeyError(),user])), (filtering,'choose_address',dict(return_value='10.253.0.1')), (filtering,'ports',dict(return_value=set())), (filtering.os,'chown',{}), (filtering,'wait_ready',{}), (filtering,'ready',dict(return_value=True)), (runtime,'docker_ready',{}), (runtime,'command',dict(return_value='')), (runtime,'awg_key',dict(return_value='fixture-key')), (runtime,'apply_config',{}), (runtime,'health',dict(return_value={'running':True})), (runtime,'add_user',dict(side_effect=lambda s,*a,**k:s['users'].append({'login':'phone'}))), (routes,'worker',{}), (routes,'tls_material',{}), (routes,'port',dict(return_value=24000)), (routes,'new_user',dict(return_value={'login':'phone'})), (routes,'apply',{}), (routes,'health',dict(return_value={'running':True})), (routes,'statistics',dict(return_value=True)), (routes,'verify_connection',{})]:stack.enter_context(patch.object(target,name,**kw))
     runtime.install(state,lambda *args:None)
    self.assertEqual('phone',runtime.load(protocol)['users'][0]['login']);self.assertEqual(filtering.load()['instance'],runtime.load(protocol)['filtering'])
    # Each subtest represents a different cold server.
    import shutil
    for p in (filtering.ROOT,filtering.DATA,filtering.CACHE,runtime.STATE):shutil.rmtree(p)
    for p in (filtering.UNIT,filtering.NETWORK):p.unlink()

 def test_complete_shared_module_needs_no_download_and_preserves_identity_preferences(self):
  filtering.ROOT.mkdir();(filtering.DATA/'agh').mkdir(parents=True)
  state=dict(owner=filtering.OWNER,instance='existing-shared',address='10.255.253.1',dns_port=5357,api_port=3007,password='original-secret',docker=True)
  filtering.save(state)
  for p,value in [(filtering.ROOT/'AdGuardHome','old installed binary'),(filtering.ROOT/'filtering.py','old helper'),(filtering.DATA/'agh/AdGuardHome.yaml','{"filtering":{"protection_enabled":false}}'),(filtering.UNIT,'[Unit]\nDescription=Rookstride private DNS filter\n'),(filtering.NETWORK,'[Unit]\nDescription=Rookstride private DNS network\n')]:p.write_text(value)
  before={p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
  with patch.object(filtering,'https_open') as fetch,patch.object(filtering,'network_start'),patch.object(filtering,'command'),patch.object(filtering,'wait_ready'):
   self.assertIsNone(filtering.prepare_binary());filtering.ensure(docker=True);fetch.assert_not_called()
  self.assertEqual(before,{p:p.read_bytes() for p in self.base.rglob('*') if p.is_file()});self.assertEqual(state,filtering.load());self.assertFalse(filtering.CACHE.exists())

 def test_unknown_and_partial_states_are_refused_without_download_or_changes(self):
  # Even the exact legacy pre-user stub is deliberately left for reviewed recovery.
  values=[dict(owner=filtering.OWNER,instance='legacy',address='10.253.0.1',dns_port=5354,api_port=3001,password='old-secret',docker=False),dict(owner='foreign',address='10.253.0.1',dns_port=5354,api_port=3001),dict(owner=filtering.OWNER,address='203.0.113.1',dns_port=5354,api_port=3001)]
  for value in values:
   filtering.ROOT.mkdir(exist_ok=True);filtering.DATA.mkdir(exist_ok=True);filtering.save(value)
   before=(filtering.DATA/'state.json').read_bytes()
   with patch.object(filtering,'https_open') as fetch,patch.object(filtering,'command') as command,patch.object(filtering,'references',return_value=['openvpn']):
    with self.assertRaises(ValueError):filtering.ensure()
    fetch.assert_not_called();command.assert_not_called()
   self.assertEqual(before,(filtering.DATA/'state.json').read_bytes());self.assertEqual([],list(filtering.ROOT.iterdir()))

 def test_linked_filter_paths_never_fetch_or_follow_a_target(self):
  target=self.base/'foreign';target.mkdir();sentinel=target/'keep';sentinel.write_text('unchanged')
  for path in (filtering.ROOT,filtering.DATA,filtering.UNIT,filtering.NETWORK):
   with self.subTest(path=path):
    path.symlink_to(target)
    with patch.object(filtering,'https_open') as fetch:
     with self.assertRaises(ValueError):filtering.prepare_binary()
     fetch.assert_not_called()
    path.unlink();self.assertEqual('unchanged',sentinel.read_text())

 def test_pair_entry_dns_keeps_the_existing_no_local_filter_path(self):
  for protocol in ('awg','hysteria2'):
   state=dict(protocol=protocol,owner='rookstride-single-v1',instance='entry',initialLogin='phone',port=443,pair_dns={'address':'10.253.0.1','dns_port':5354})
   with patch.object(filtering,'prepare_binary') as prepare,patch.object(runtime,'docker_ready',side_effect=ValueError('runtime stage')),patch.object(routes,'worker',side_effect=ValueError('runtime stage')):
    with self.assertRaisesRegex(ValueError,'runtime stage'):runtime.install(state,lambda *args:None)
    prepare.assert_not_called();self.assertEqual([],runtime.load(protocol)['users'])


class PinnedAlternateOrigin(unittest.TestCase):
 def test_first_transport_or_http_failure_uses_fixed_api_before_retrying(self):
  raw=b'pinned public bytes';digest=hashlib.sha256(raw).hexdigest();api='https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/assets/705629752'
  for error in (urllib.error.URLError('offline'),urllib.error.HTTPError('https://github.com',404,'not accessible',{},None),TimeoutError('timed out'),http.client.IncompleteRead(b'partial'),ssl.SSLEOFError('peer closed TLS'),urllib.error.URLError(ssl.SSLEOFError('peer closed TLS'))):
   with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering.time,'sleep') as sleep,patch.object(filtering,'https_open',side_effect=[error,io.BytesIO(raw)]) as fetch:
    self.assertEqual(raw,filtering.pinned_download('https://github.com/fixed/v0.107.80',digest,100,len(raw),((api,{'Accept':'application/octet-stream'}),)))
    self.assertEqual(api,fetch.call_args_list[1].args[0].full_url);self.assertEqual('application/octet-stream',fetch.call_args_list[1].args[0].get_header('Accept'));self.assertEqual(2,fetch.call_count);sleep.assert_not_called()

 def test_bad_cached_or_downloaded_bytes_do_not_try_a_different_origin(self):
  raw=b'correct';digest=hashlib.sha256(raw).hexdigest();fallback=(('https://api.github.com/pinned',{'Accept':'application/octet-stream'}),)
  for cached in (False,True):
   with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering,'https_open',return_value=io.BytesIO(b'tampered')) as fetch:
    if cached:filtering.CACHE.mkdir();(filtering.CACHE/digest).write_bytes(b'corrupt')
    with self.assertRaisesRegex(ValueError,'checksum'):filtering.pinned_download('https://github.com/fixed',digest,100,len(raw),fallback)
    self.assertEqual(0 if cached else 1,fetch.call_count)
    if cached:self.assertEqual(b'corrupt',(filtering.CACHE/digest).read_bytes())
    else:self.assertEqual([],list(filtering.CACHE.iterdir()))

 def test_wrapped_certificate_and_ssl_validation_failures_are_not_retryable_acquisition(self):
  for error in (ssl.SSLCertVerificationError('untrusted certificate'),urllib.error.URLError(ssl.SSLCertVerificationError('untrusted certificate')),urllib.error.URLError(ssl.SSLError('TLS policy failure'))):
   with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering,'https_open',side_effect=error) as fetch,patch.object(filtering.time,'sleep') as sleep:
    with self.assertRaisesRegex(ValueError,'TLS validation') as raised:filtering.pinned_download('https://github.com/fixed','0'*64,100,10,(('https://api.github.com/pinned',{}),))
    self.assertNotIsInstance(raised.exception,filtering.AcquisitionUnavailable);self.assertEqual(1,fetch.call_count);sleep.assert_not_called();self.assertEqual([],list(filtering.CACHE.iterdir()))
