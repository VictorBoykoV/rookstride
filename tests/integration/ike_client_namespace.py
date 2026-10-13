#!/usr/bin/env python3
"""Opt-in root QA client on an owned EXIT, never a server installer.

JSON stdin: pair, server, server_id, port, login, password, ca, expected_exit.
An external runner stops/restarts the entry bridge and sets control='down'/'up'
in the private directory recorded in /run/rookstride-provider-client.json.
Network and mount namespaces isolate the client's IPsec state and configuration.
Its veth firewall permits only outer IKE; plaintext VIP fallback is rejected.
See https://docs.strongswan.org/docs/latest/howtos/nameSpaces.html.
"""
import fcntl,ipaddress,json,os,re,shutil,signal,subprocess,sys,tempfile,time,uuid
from pathlib import Path
MARKER=Path('/run/rookstride-provider-client.json')
CHILD=r'''
import sys,os,json,subprocess,time,ipaddress,socket
from pathlib import Path
d=Path(sys.argv[1]);c=json.loads((d/'request.json').read_text());os.umask(0o077)
def cmd(a,timeout=45):return subprocess.run(a,capture_output=True,text=True,timeout=timeout,check=True).stdout.strip()
def state(phase,checks):
 p=d/'status.tmp';p.write_text(json.dumps({'phase':phase,'checks':checks}));p.replace(d/'status.json')
def control(value):
 for _ in range(150):
  if (d/'control').exists() and (d/'control').read_text().strip()==value:return
  time.sleep(1)
 raise RuntimeError('External QA control timed out')
checks={}
try:
 for source,target in [('run','/run'),('ipsec.d','/etc/ipsec.d'),('ipsec.conf','/etc/ipsec.conf'),('ipsec.secrets','/etc/ipsec.secrets'),('strongswan.conf','/etc/strongswan.conf')]:cmd(['mount','--bind',str(d/source),target])
 with (d/'ike-private.log').open('w') as log:
  starter=subprocess.Popen(['ipsec','start','--nofork'],stdout=log,stderr=log)
  try:
   for _ in range(30):
    if Path('/run/charon.ctl').exists():break
    if starter.poll() is not None:raise RuntimeError('Isolated starter stopped')
    time.sleep(1)
   cmd(['ipsec','up','qa'],timeout=75)
   report=cmd(['ipsec','statusall','qa']);checks['ike_eap_established']='ESTABLISHED' in report and 'INSTALLED' in report
   assert checks['ike_eap_established']
   addresses=json.loads(cmd(['ip','-j','-4','addr','show']));vip=next(a['local'] for n in addresses for a in n.get('addr_info',[]) if ipaddress.ip_address(a['local']) in ipaddress.ip_network('10.250.0.0/16'))
   def dig(domain):return cmd(['dig','+time=4','+tries=1','+short','-b',vip,'@10.253.0.1',domain,'A'])
   def tcp():
    s=socket.socket();s.settimeout(4)
    try:s.bind((vip,0));s.connect(('1.1.1.1',443));return True
    except OSError:return False
    finally:s.close()
   def https():
    values=dig('api.ipify.org').splitlines();address=next(v for v in values if re_ip(v))
    return cmd(['curl','-4','--interface',vip,'--resolve','api.ipify.org:443:'+address,'--connect-timeout','8','--max-time','20','-fsS','https://api.ipify.org'])
   def re_ip(value):
    try:return ipaddress.ip_address(value).version==4
    except ValueError:return False
   checks['https_exit_matches']=https()==c['expected_exit'];checks['ad_dns_blocked']=dig('doubleclick.net')=='0.0.0.0';checks['literal_tcp_baseline']=tcp();assert all(checks.values());state('connected',checks)
   control('down');checks['ike_remains_during_bridge_outage']='ESTABLISHED' in cmd(['ipsec','statusall','qa']);checks['bridge_down_blocks_tcp']=not tcp();assert all(checks.values());state('blocked',checks)
   control('up');checks['bridge_restart_https']=https()==c['expected_exit'];checks['bridge_restart_dns']=dig('doubleclick.net')=='0.0.0.0';assert all(checks.values());state('done',checks)
  finally:
   subprocess.run(['ipsec','stop'],capture_output=True,timeout=20)
   try:starter.wait(timeout=10)
   except subprocess.TimeoutExpired:starter.kill();starter.wait()
except BaseException as exc:
 state('failed',dict(checks,error=type(exc).__name__));raise
'''
def run(args,check=True):return subprocess.run(args,capture_output=True,text=True,timeout=30,check=check).stdout.strip()
def main():
 os.umask(0o077)
 if os.geteuid()!=0:raise PermissionError('Root QA access is required')
 c=json.loads(sys.stdin.buffer.read(65536));m=json.loads(Path('/etc/rookstride-pair/manifest.json').read_text())
 if not re.fullmatch('[a-f0-9]{32}',c['pair']) or m['plan']['pair']!=c['pair'] or m['plan']['role']!='exit':raise ValueError('Use only the explicitly selected owned exit')
 for key in ['server','server_id','expected_exit']:ipaddress.IPv4Address(c[key])
 if not 1<=c['port']<=65535 or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',c['login']) or not re.fullmatch('[A-Za-z0-9_-]{16,128}',c['password']):raise ValueError('Invalid QA connection input')
 if not c['ca'].startswith('-----BEGIN CERTIFICATE-----'):raise ValueError('Pinned public CA is required')
 if MARKER.exists():raise ValueError('Another QA client marker exists')
 for name in ['/etc/ipsec.conf','/etc/ipsec.secrets']:
  if Path(name).exists():raise ValueError('Exit has unexpected IKE configuration; no overwrite allowed')
 if not Path('/etc/ipsec.d').is_dir() or not Path('/etc/strongswan.conf').is_file():raise ValueError('Retained strongSwan client packages are needed')
 # Refuse a test subnet collision; do not alter a provider's own addresses.
 subnet=ipaddress.ip_network('198.18.254.0/30')
 for route in json.loads(run(['ip','-j','-4','route','show','table','main'])):
  if route.get('dst','default')!='default' and subnet.overlaps(ipaddress.ip_network(route['dst'])):raise ValueError('QA subnet overlaps a host route')
 with Path('/run/rookstride-pair.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  resolver_before=Path('/etc/resolv.conf').read_bytes()
  d=Path(tempfile.mkdtemp(prefix='rookstride-client-',dir='/root'));name='rkqa'+uuid.uuid4().hex[:8];host=name+'h';peer=name+'n';chain='RKQA_'+uuid.uuid4().hex[:8];created=[];p=None;result=None
  try:
   for folder in ['run','ipsec.d/cacerts']:(d/folder).mkdir(parents=True)
   (d/'ipsec.d/cacerts/qa.pem').write_text(c['ca']);(d/'request.json').write_text(json.dumps(c));(d/'child.py').write_text(CHILD)
   # DNS is probed explicitly through the VIP. Never ask resolvconf to edit host DNS.
   (d/'strongswan.conf').write_text('charon {\n load_modular = yes\n plugins {\n include /etc/strongswan.d/charon/*.conf\n resolve { load = no }\n }\n}\n')
   (d/'ipsec.conf').write_text('config setup\n uniqueids=never\nca qa\n cacert=/etc/ipsec.d/cacerts/qa.pem\n auto=add\nconn qa\n keyexchange=ikev2\n left=%defaultroute\n leftauth=eap-mschapv2\n leftid='+c['login']+'\n eap_identity='+c['login']+'\n leftsourceip=%config\n leftikeport=4500\n right='+c['server']+'\n rightid='+c['server_id']+'\n rightauth=pubkey\n rightsubnet=0.0.0.0/0\n rightikeport='+str(c['port'])+'\n auto=add\n')
   (d/'ipsec.secrets').write_text(c['login']+' : EAP "'+c['password']+'"\n')
   for file in ['/etc/ipsec.conf','/etc/ipsec.secrets']:Path(file).touch(mode=0o600,exist_ok=False);created.append(Path(file))
   run(['ip','netns','add',name]);run(['ip','link','add',host,'type','veth','peer','name',peer]);run(['ip','link','set',peer,'netns',name]);run(['ip','addr','add','198.18.254.1/30','dev',host]);run(['ip','link','set',host,'up'])
   for args in [['ip','link','set','lo','up'],['ip','addr','add','198.18.254.2/30','dev',peer],['ip','link','set',peer,'up'],['ip','route','add','default','via','198.18.254.1']]:run(['ip','netns','exec',name]+args)
   for table,parent in [('filter','FORWARD'),('nat','POSTROUTING')]:run(['iptables','-t',table,'-N',chain]);run(['iptables','-t',table,'-I',parent,'1','-j',chain])
   ports=str(c['port']) if c['port']!=500 else '500,4500'
   run(['iptables','-A',chain,'-i',host,'-s','198.18.254.2/32','-d',c['server'],'-p','udp','-m','multiport','--dports',ports,'-j','ACCEPT'])
   run(['iptables','-A',chain,'-o',host,'-d','198.18.254.2/32','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'])
   for flag in ['-i','-o']:run(['iptables','-A',chain,flag,host,'-j','DROP'])
   run(['iptables','-t','nat','-A',chain,'-s','198.18.254.2/32','-d',c['server'],'-p','udp','-m','multiport','--dports',ports,'-j','MASQUERADE'])
   MARKER.write_text(json.dumps({'path':str(d),'namespace':name}));(d/'status.json').write_text('{"phase":"starting","checks":{}}')
   with (d/'child-private.log').open('w') as log:
    p=subprocess.Popen(['ip','netns','exec',name,'unshare','--mount','--propagation','private','python3',str(d/'child.py'),str(d)],stdout=log,stderr=log)
    try:p.wait(timeout=450)
    except subprocess.TimeoutExpired:p.kill();p.wait()
   result=json.loads((d/'status.json').read_text());result['ok']=p.returncode==0 and result['phase']=='done'
   if not result['ok']:result['private_diagnostic']=(d/'child-private.log').read_text()[-4000:]+'\n'+((d/'ike-private.log').read_text()[-9000:] if (d/'ike-private.log').exists() else '')
  finally:
   if p and p.poll() is None:p.terminate();p.wait(timeout=10)
   for pid in run(['ip','netns','pids',name],check=False).split():
    try:os.kill(int(pid),signal.SIGTERM)
    except ProcessLookupError:pass
   time.sleep(1)
   for pid in run(['ip','netns','pids',name],check=False).split():
    try:os.kill(int(pid),signal.SIGKILL)
    except ProcessLookupError:pass
   run(['ip','netns','del',name],check=False);run(['ip','link','del',host],check=False)
   for table,parent in [('filter','FORWARD'),('nat','POSTROUTING')]:
    run(['iptables','-t',table,'-D',parent,'-j',chain],check=False);run(['iptables','-t',table,'-F',chain],check=False);run(['iptables','-t',table,'-X',chain],check=False)
   for file in created:
    if file.is_file() and not file.is_symlink() and file.stat().st_size==0:file.unlink()
   MARKER.unlink(missing_ok=True);shutil.rmtree(d)
  if result is not None:
   result['checks']['host_resolver_unchanged']=Path('/etc/resolv.conf').read_bytes()==resolver_before
   result['checks']['qa_namespace_removed']=name not in run(['ip','netns','list'])
   result['checks']['qa_chains_removed']=chain not in run(['iptables-save'])
   result['checks']['temporary_ike_files_removed']=all(not file.exists() for file in created)
   result['ok']=result['ok'] and all(result['checks'].values())
   print(json.dumps(result))
if __name__=='__main__':main()
