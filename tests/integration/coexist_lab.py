#!/usr/bin/env python3
"""Disposable four-protocol cycles: both install orders, independent reset and full cleanup."""
import hashlib,importlib.util,json,os,socket,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'single'));sys.path.insert(0,str(ROOT/'server'));sys.path.insert(0,str(Path(__file__).parent))
import runtime,run as api,deploy,filtering,inspect_server
from rookstride import admin
from single_ike_lab import probe
assert os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')=='yes' and os.geteuid()==0
order=sys.argv[1];assert order in ('ike-first','ike-last')
BASE_NATIVE_PROTOCOLS=('awg','xray','openvpn')
report={'environment':'disposable Ubuntu 24.04 GitHub runner','order':order,'cycles':[]}
sentinel=Path('/var/tmp/rookstride-unrelated-site');sentinel.write_text('keep this unrelated application')
os_identity=Path('/etc/os-release').read_bytes()
root_identity=next(v for v in Path('/etc/shadow').read_text().splitlines() if v.startswith('root:'))
# Ubuntu's second local resolver must not block the phone's preflight after reset.
resolver_fixture=None
if not any(v['address']=='127.0.0.54' and v['port']==53 and v['transport']=='udp' for v in inspect_server.listeners()):
 resolver_fixture=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);resolver_fixture.bind(('127.0.0.54',53))

def wait(fetch):
 deadline=time.monotonic()+1800
 while time.monotonic()<deadline:
  s=fetch()
  if s['state']=='complete':return
  if s['state'] in ('failed','paused'):raise AssertionError('Installation stopped: '+s.get('phase','unknown'))
  time.sleep(2)
 raise AssertionError('Installation deadline')

def install_ike(password):
 assert inspect_server.inspect()['ikev2_ready'],'The phone preflight must permit this install/reinstall'
 job=deploy.start(dict(mode='install',server='vpn.example.net',login='lab-ike',password=password,statistics=False))['job']
 try:wait(lambda:deploy.status(job))
 except Exception:
  log=deploy.JOBS/job/'install.log'
  if log.is_file():print('Disposable IKE installer diagnostic:\n'+log.read_text()[-8000:],flush=True)
  raise

def install_protocol(protocol):
 result=api.action(dict(action='start',protocol=protocol,server='172.17.0.1',login='lab-phone'));wait(lambda:api.status(result['job']))

def adapters():
 for protocol in BASE_NATIVE_PROTOCOLS:
  subprocess.run([sys.executable,str(Path(__file__).parent/'single_protocol_lab.py'),protocol,'--existing','--keep-installed'],check=True,timeout=600)

for number,password in enumerate(('abcdefgh','12345678'),1):
 if order=='ike-first':install_ike(password)
 for protocol in BASE_NATIVE_PROTOCOLS:install_protocol(protocol)
 if order=='ike-last':install_ike(password)
 assert set(api.action(dict(action='inspect'))['installed_protocols'])==set(BASE_NATIVE_PROTOCOLS)
 assert all(api.action(dict(action='status',protocol=p))['running'] for p in BASE_NATIVE_PROTOCOLS)
 ike=probe('lab-ike',password);assert all(ike.values());adapters()
 # A single-protocol reset must preserve real traffic through the others.
 old_public=runtime.load('awg')['public'];review=api.action(dict(action='reset-plan',protocol='awg'));api.action(dict(action='reset-apply',protocol='awg',token=review['token'],confirmation='DELETE VPN'))
 assert all(api.action(dict(action='status',protocol=p))['running'] for p in ('xray','openvpn'));assert all(probe('lab-ike',password).values())
 install_protocol('awg');assert runtime.load('awg')['public']!=old_public
 # Prove the replacement's fresh credentials carry traffic, not only a running service.
 subprocess.run([sys.executable,str(Path(__file__).parent/'single_protocol_lab.py'),'awg','--existing','--keep-installed'],check=True,timeout=600)
 # Exercise actual MSCHAPv2 with punctuation, quotes and backslashes too.
 special='Letters-"\\123';admin.update_user(dict(login='lab-ike',password=special,replace=True));assert all(probe('lab-ike',special).values())
 review=api.action(dict(action='reset-server-plan'));assert set(review['protocols'])=={'ikev2','awg','xray','openvpn'}
 result=api.action(dict(action='reset-server-apply',token=review['token'],confirmation='DELETE ALL VPNS'));assert set(result['removed_protocols'])==set(review['protocols']);assert review['filtering'];assert 'filtering' in result['removed_components'];assert not filtering.exists();assert not filtering.ROOT.exists();assert not filtering.UNIT.exists();assert not filtering.NETWORK.exists()
 assert not Path('/etc/ipsec.conf').exists();assert not any((runtime.directory(p)/'state.json').exists() for p in runtime.model.PROTOCOLS)
 assert inspect_server.inspect()['ikev2_ready'],'Cleanup must leave the phone able to install IKEv2 again'
 assert sentinel.read_text()=='keep this unrelated application';assert Path('/etc/os-release').read_bytes()==os_identity
 assert next(v for v in Path('/etc/shadow').read_text().splitlines() if v.startswith('root:'))==root_identity
 report['cycles'].append({'cycle':number,'all_four_installed':True,'real_clients_https':True,'ike_vpn_and_ad_dns':True,'independent_reset_and_new_awg_keys':True,'letters_digits_and_escaped_password_auth':True,'all_protocol_reset':True,'shared_filter_reset_and_reinstall':True,'native_ad_dns_and_outage':True,'os_root_credentials_and_unrelated_data_preserved':True})
if resolver_fixture:resolver_fixture.close()
report['ubuntu_loopback_proxy_preflight_and_reinstall']=True
report['status']='PASS';print(json.dumps(report,indent=2));(ROOT/'.build').mkdir(exist_ok=True);(ROOT/'.build'/('coexist-'+order+'.json')).write_text(json.dumps(report,indent=2))
