#!/usr/bin/env python3
"""Disposable-only IKEv2 namespace client for the single-server coexistence lab."""
import json,os,subprocess,sys,tempfile
from pathlib import Path

CHILD=r'''
import ipaddress,json,subprocess,sys,time
from pathlib import Path
p=Path(sys.argv[1])
def command(args,timeout=60):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=timeout).stdout.strip()
command(['mount','--make-rprivate','/'])
for name,target in [('run','/run'),('ipsec.d','/etc/ipsec.d'),('ipsec.conf','/etc/ipsec.conf'),('ipsec.secrets','/etc/ipsec.secrets'),('strongswan.conf','/etc/strongswan.conf')]:command(['mount','--bind',str(p/name),target])
log=(p/'private-client.log').open('w');starter=subprocess.Popen(['ipsec','start','--nofork'],stdout=log,stderr=log)
try:
 for _ in range(50):
  if Path('/run/charon.ctl').exists():break
  if starter.poll() is not None:raise RuntimeError('Client daemon stopped')
  time.sleep(.2)
 command(['ipsec','up','coexist'],timeout=60)
 status=command(['ipsec','statusall','coexist']);assert 'ESTABLISHED' in status and 'INSTALLED' in status
 vip=next(a['local'] for n in json.loads(command(['ip','-j','-4','addr'])) for a in n.get('addr_info',[]) if ipaddress.ip_address(a['local']) in ipaddress.ip_network('10.252.0.0/24'))
 def dig(name):return command(['dig','+short','+time=5','+tries=1','-b',vip,'@10.254.0.1',name,'A'])
 address=next(v for v in dig('example.com').splitlines() if v.count('.')==3)
 body=command(['curl','-4','--interface',vip,'--resolve','example.com:443:'+address,'--max-time','35','-fsS','https://example.com/']);assert 'Example Domain' in body
 blocked=dig('doubleclick.net');assert blocked=='0.0.0.0'
 print(json.dumps({'ike_eap':True,'vpn_dns':True,'https':True,'ad_dns':True}))
finally:
 subprocess.run(['ipsec','stop'],capture_output=True,timeout=20)
 try:starter.wait(timeout=10)
 except subprocess.TimeoutExpired:starter.kill();starter.wait()
'''

def probe(login,password):
 assert os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')=='yes' and os.geteuid()==0
 network='rs-coexist-ike';host='rs-ike-host';peer='rs-ike-peer'
 def command(args,check=True,timeout=120):
  p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  if check and p.returncode:raise RuntimeError('IKE lab operation failed: '+args[0])
  return p.stdout.strip()
 # The lab owns these names and refuses preexisting namespaces/interfaces.
 assert network not in command(['ip','netns','list']).split()
 assert not any(v.get('ifname')==host for v in json.loads(command(['ip','-j','link'])))
 with tempfile.TemporaryDirectory(prefix='rook-ike-lab-') as directory:
  p=Path(directory);p.chmod(0o700);(p/'run').mkdir();(p/'ipsec.d/cacerts').mkdir(parents=True)
  (p/'ipsec.d/cacerts/ca.pem').write_bytes(Path('/etc/ipsec.d/cacerts/single-vps-ca.pem').read_bytes())
  (p/'strongswan.conf').write_text('charon { load_modular = yes\n plugins { include /etc/strongswan.d/charon/*.conf\n resolve { load = no }\n }\n}\n')
  (p/'ipsec.conf').write_text('config setup\nconn coexist\n auto=add\n keyexchange=ikev2\n left=%defaultroute\n leftsourceip=%config\n leftauth=eap-mschapv2\n eap_identity='+login+'\n right=198.18.253.1\n rightid=@vpn.example.net\n rightauth=pubkey\n rightsubnet=0.0.0.0/0\n fragmentation=yes\n forceencaps=yes\n')
  escaped=password.replace('\\','\\\\').replace('"','\\"');(p/'ipsec.secrets').write_text(login+' : EAP "'+escaped+'"\n');(p/'ipsec.secrets').chmod(0o600)
  (p/'client.py').write_text(CHILD)
  try:
   command(['ip','netns','add',network]);command(['ip','link','add',host,'type','veth','peer','name',peer]);command(['ip','link','set',peer,'netns',network])
   command(['ip','addr','add','198.18.253.1/30','dev',host]);command(['ip','link','set',host,'up'])
   command(['ip','netns','exec',network,'ip','addr','add','198.18.253.2/30','dev',peer]);command(['ip','netns','exec',network,'ip','link','set',peer,'up']);command(['ip','netns','exec',network,'ip','link','set','lo','up'])
   command(['ip','netns','exec',network,'ip','route','add','default','via','198.18.253.1'])
   result=command(['ip','netns','exec',network,'unshare','--mount','--fork',sys.executable,str(p/'client.py'),str(p)],timeout=150)
   return json.loads(result.splitlines()[-1])
  finally:
   command(['ip','netns','delete',network],check=False);command(['ip','link','delete',host],check=False)
