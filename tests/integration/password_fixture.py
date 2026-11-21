#!/usr/bin/env python3
"""Opt-in local CA/ACME stand-in. Never a public certificate issuance claim.

Use only inside disposable machines. Its trusted root and private keys remain
inside the lab, outside Rookstride's owned removal paths. Product recipes remain
unmodified. A separate public ACME test is required for issuer/Internet proof.
"""
import json,os,subprocess,sys
from pathlib import Path
BASE=Path('/root/rook-signin-lab')
def run(args,**kw):return subprocess.run([str(x) for x in args],check=True,capture_output=True,**kw)
def setup(names):
 if os.geteuid()!=0 or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes':raise PermissionError('Disposable root lab required')
 import ipaddress
 for name in names:
  try:ip=ipaddress.ip_address(name)
  except ValueError:
   if not name.endswith('.test'):raise ValueError('Only private lab IPs or .test domains are accepted')
  else:
   if ip.is_global:raise ValueError('Never install synthetic issuance on a public VPS')
 os.umask(0o077);BASE.mkdir(mode=0o700,exist_ok=True)
 if not (BASE/'root.key').exists():run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',BASE/'root.key','-out',BASE/'root.pem','-days','30','-subj','/CN=Rookstride disposable integration authority','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
 import shutil
 shutil.copy2(BASE/'root.pem','/usr/local/share/ca-certificates/rook-signin-lab.crt');run(['update-ca-certificates'])
 allowed=[]
 for name in names:
  allowed.append(name)
  try:ipaddress.IPv4Address(name);allowed.append(name.replace('.','-')+'.sslip.io')
  except ValueError:pass
 (BASE/'names.json').write_text(json.dumps(allowed));source=Path(__file__).read_text();(BASE/'issuer.py').write_text(source)
 for venv in (Path('/opt/rookstride-public-tls/venv'),Path('/opt/rookstride/ike-acme-venv')):
  (venv/'bin').mkdir(mode=0o700,parents=True,exist_ok=True);tool=venv/'bin/certbot';tool.write_text('#!/bin/sh\nexec /usr/bin/python3 /root/rook-signin-lab/issuer.py issue "$@"\n');tool.chmod(0o700)
 # Seed a verified identity cache, using a CA trusted only in these disposable
 # systems. Fresh private-address public issuance remains prohibited in product.
 sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'single'));import public_tls,hashlib
 public_tls.initialize()
 for value in names:
  name=public_tls.tls_name(value);folder=public_tls.BASE/hashlib.sha256(name.encode()).hexdigest()
  issue(['certonly','--cert-name','rookstride','--config-dir',str(folder/'config'),'-d',name])
 return {'synthetic_ca_fixture':True,'allowed_names':len(allowed)}
def issue(args):
 if args==['--version']:print('certbot 5.9.0');return
 if not BASE.is_dir() or os.geteuid()!=0:raise PermissionError('No disposable issuer fixture')
 import ipaddress
 name=args[args.index('--cert-name')+1];config=Path(args[args.index('--config-dir')+1]);folder=config/'live'/name;folder.mkdir(mode=0o700,parents=True,exist_ok=True)
 identities=[args[i+1] for i,v in enumerate(args) if v in ('-d','--ip-address')]
 if not identities:
  identities=json.loads((folder/'identities.json').read_text())
 if not identities or not set(identities).issubset(json.loads((BASE/'names.json').read_text())):raise ValueError('Not an allowed lab identity')
 sans=[]
 for value in identities:
  try:ipaddress.ip_address(value);kind='IP'
  except ValueError:kind='DNS'
  sans.append(kind+':'+value)
 run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-keyout',folder/'privkey.pem','-out',folder/'request.pem','-subj','/CN='+identities[0]])
 (folder/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\nsubjectAltName='+','.join(sans)+'\n')
 run(['openssl','x509','-req','-in',folder/'request.pem','-CA',BASE/'root.pem','-CAkey',BASE/'root.key','-CAcreateserial','-days','7','-out',folder/'cert.pem','-extfile',folder/'extensions'])
 (folder/'chain.pem').write_bytes((BASE/'root.pem').read_bytes());(folder/'fullchain.pem').write_bytes((folder/'cert.pem').read_bytes()+(BASE/'root.pem').read_bytes());(folder/'identities.json').write_text(json.dumps(identities));print('Disposable synthetic certificate prepared')
if __name__=='__main__':
 if sys.argv[1:2]==['issue']:issue(sys.argv[2:])
 else:print(json.dumps(setup(sys.argv[1:])))
