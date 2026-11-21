"""Pinned artifact transport and installer retry boundaries; no external network or hosts."""
import email.message,hashlib,io,json,os,re,shlex,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import filtering


class HTTPSDownloads(unittest.TestCase):
 def test_https_redirect_is_followed_but_downgrade_and_other_schemes_are_refused(self):
  for target,allowed in [('https://release-assets.githubusercontent.com/fixed',True),('http://release-assets.githubusercontent.com/fixed',False),('ftp://example.invalid/fixed',False)]:
   with self.subTest(target=target):
    handler=filtering.HTTPSOnlyRedirect();handler.parent=SimpleNamespace(open=Mock(return_value='https-response'))
    headers=email.message.Message();headers['Location']=target
    request=filtering.urllib.request.Request('https://github.com/fixed');request.timeout=45
    if allowed:
     self.assertEqual('https-response',handler.http_error_302(request,io.BytesIO(b''),302,'Found',headers));self.assertEqual(target,handler.parent.open.call_args.args[0].full_url)
    else:
     with self.assertRaisesRegex(ValueError,'HTTPS'):handler.http_error_302(request,io.BytesIO(b''),302,'Found',headers)
     handler.parent.open.assert_not_called()

 def test_non_https_initial_download_never_opens_a_connection(self):
  with patch.object(filtering.urllib.request,'build_opener') as opener:
   with self.assertRaisesRegex(ValueError,'HTTPS'):filtering.https_open(filtering.urllib.request.Request('http://example.invalid/artifact'),45)
   opener.assert_not_called()

 def test_non_https_final_response_is_closed_and_never_cached(self):
  raw=b'public component';response=io.BytesIO(raw);response.geturl=lambda:'http://example.invalid/downgraded';opener=SimpleNamespace(open=Mock(return_value=response))
  with tempfile.TemporaryDirectory() as d,patch.object(filtering,'CACHE',Path(d)/'cache'),patch.object(filtering.urllib.request,'build_opener',return_value=opener) as build:
   with self.assertRaisesRegex(ValueError,'HTTPS'):filtering.pinned_download('https://github.com/fixed',hashlib.sha256(raw).hexdigest(),100,len(raw))
   self.assertTrue(response.closed);self.assertEqual([],list(filtering.CACHE.iterdir()));self.assertIsInstance(build.call_args.args[0],filtering.HTTPSOnlyRedirect)


class ClassicInstallerPreflight(unittest.TestCase):
 def run_stage(self,mode):
  # Execute the production package/download stage through its first owned-directory
  # publication boundary. Only archive pins are injected with local fixture values.
  source=(ROOT/'gateway/scripts/install.sh').read_text();stage=source[source.index('apt-get update -qq\n'):source.index('install -d -m 700 /etc/single-vps-vpn')]
  stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w:gz') as archive:
   item=tarfile.TarInfo('./AdGuardHome/AdGuardHome');item.size=7;archive.addfile(item,io.BytesIO(b'binary!'))
  raw=stream.getvalue();stage=re.sub(r'checksum=[a-f0-9]{64}','checksum='+hashlib.sha256(raw).hexdigest(),stage);stage=re.sub(r'size=\d+','size='+str(len(raw)),stage)
  with tempfile.TemporaryDirectory() as d:
   base=Path(d);binary=base/'bin';binary.mkdir();(base/'gateway/scripts').mkdir(parents=True);(base/'server').mkdir();(base/'archive').write_bytes(raw)
   # Exercise the actual cache reader in an isolated namespace, never host /var/cache.
   cache=base/'cache';cache.mkdir(mode=0o700)
   helper=(ROOT/'gateway/scripts/public-artifact-cache.py').read_text()
   wrapper="import os,sys\nfrom pathlib import Path\nns={'__name__':'cache_reader'}\nexec(compile("+repr(helper)+",'public-artifact-cache.py','exec'),ns)\nraise SystemExit(0 if ns['copy_cached'](sys.argv[1],int(sys.argv[2]),sys.argv[3],Path("+repr(str(cache))+"),os.getuid(),Path("+repr(str(base))+")) else 10)\n"
   (base/'gateway/scripts/public-artifact-cache.py').write_text(wrapper)
   if mode in ('cache-hit','cache-corrupt'):
    cached=cache/hashlib.sha256(raw).hexdigest();cached.write_bytes(raw if mode=='cache-hit' else b'corrupt');cached.chmod(0o600)
   common="import json,os,sys\nfrom pathlib import Path\ndef log(command,args):\n with Path(os.environ['STAGE_LOG']).open('a') as f:f.write(json.dumps({'command':command,'args':args})+'\\n')\n"
   scripts={
    'apt-get':common+"log('apt-get',sys.argv[1:])\n",
    'uname':"print('x86_64')\n",
    'stat':"import os,sys\nprint(os.stat(sys.argv[-1]).st_size)\n",
    'sha256sum':"import hashlib,sys\nfrom pathlib import Path\nline=sys.stdin.read().strip();expected,path=line.split(None,1)\nraise SystemExit(0 if hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected else 1)\n",
    'curl':common+"log('curl',sys.argv[1:]);args=sys.argv[1:]\nif any(flag not in args or args[args.index(flag)+1]!='=https' for flag in ('--proto','--proto-redir')):raise SystemExit(97)\nmode=os.environ['STAGE_MODE'];url=args[-1]\nif mode in ('network-failure','downgrade') or url.startswith('https://github.com/'):raise SystemExit(1)\nPath(args[args.index('-o')+1]).write_bytes(Path(os.environ['STAGE_ARCHIVE']).read_bytes())\n",
   }
   for name,body in scripts.items():p=binary/name;p.write_text('#!'+sys.executable+'\n'+body);p.chmod(0o755)
   (base/'server/ike_packages.py').write_text(common+"log('vpn-dns-packages',sys.argv[1:])\n")
   completed=base/'completed';script=base/'stage.sh';script.write_text('set -Eeuo pipefail\nROOT_DIR='+shlex.quote(str(base/'gateway'))+'\nPAIR_ENTRY=NO\n'+stage+'\nprintf ready > '+shlex.quote(str(completed))+'\n')
   env={**os.environ,'PATH':str(binary)+os.pathsep+os.environ['PATH'],'STAGE_LOG':str(base/'events'),'STAGE_MODE':mode,'STAGE_ARCHIVE':str(base/'archive')}
   result=subprocess.run(['bash',str(script)],capture_output=True,text=True,env=env,timeout=20)
   events=[json.loads(line) for line in (base/'events').read_text().splitlines()]
   return result,events,completed.exists()

 def test_failed_download_never_installs_vpn_or_dns_packages(self):
  result,events,completed=self.run_stage('network-failure');self.assertNotEqual(0,result.returncode);self.assertFalse(completed)
  self.assertFalse(any(e['command']=='vpn-dns-packages' for e in events))
  for event in events:
   if event['command']=='apt-get' and 'install' in event['args']:
    self.assertEqual(['ca-certificates','curl'],event['args'][-2:]);self.assertIn('--no-remove',event['args'])

 def test_refused_downgrade_never_reaches_vpn_or_dns_installation(self):
  result,events,completed=self.run_stage('downgrade');self.assertNotEqual(0,result.returncode);self.assertFalse(completed);self.assertFalse(any(e['command']=='vpn-dns-packages' for e in events))
  downloads=[e for e in events if e['command']=='curl'];self.assertEqual(2,len(downloads))
  for event in downloads:
   for flag in ('--proto','--proto-redir'):self.assertEqual('=https',event['args'][event['args'].index(flag)+1])

 def test_later_successful_retry_verifies_artifact_before_daemon_packages(self):
  failed,_,_=self.run_stage('network-failure');self.assertNotEqual(0,failed.returncode)
  result,events,completed=self.run_stage('success');self.assertEqual(0,result.returncode,result.stderr);self.assertTrue(completed)
  downloads=[i for i,e in enumerate(events) if e['command']=='curl'];install=[i for i,e in enumerate(events) if e['command']=='vpn-dns-packages'];self.assertEqual(2,len(downloads));self.assertEqual(1,len(install));self.assertGreater(install[0],downloads[-1])
  self.assertIn('strongswan-starter',events[install[0]]['args']);self.assertIn('unbound',events[install[0]]['args'])

 def test_app_prepared_cache_is_consumed_without_any_curl(self):
  result,events,completed=self.run_stage('cache-hit');self.assertEqual(0,result.returncode,result.stderr);self.assertTrue(completed)
  self.assertFalse(any(e['command']=='curl' for e in events));self.assertEqual(1,len([e for e in events if e['command']=='vpn-dns-packages']))

 def test_corrupt_existing_cache_refuses_before_download_or_daemon_install(self):
  result,events,completed=self.run_stage('cache-corrupt');self.assertNotEqual(0,result.returncode);self.assertFalse(completed)
  self.assertFalse(any(e['command'] in ('curl','vpn-dns-packages') for e in events))
