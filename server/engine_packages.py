"""Exact-version strongSwan transactions using the host's authenticated APT index.

No distribution upgrade, dependency churn, daemon switch or foreign package is
allowed. Both old and candidate .deb sets must be retrievable and hash-verified
before the first mutation; otherwise this host cannot promise package rollback.
"""
import hashlib,json,os,re,subprocess
from pathlib import Path
import pair,runtime,lifecycle,native_pair,ike_packages
ALLOWED={'strongswan','strongswan-starter','strongswan-charon','charon-systemd','strongswan-swanctl','strongswan-pki','libstrongswan','libstrongswan-standard-plugins','libstrongswan-extra-plugins','libcharon-extra-plugins','libcharon-extauth-plugins'}

def run(args,cwd=None,timeout=120):
 p=subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',DEBIAN_FRONTEND='noninteractive'))
 if p.returncode:raise ValueError('Exact IKE package operation failed: '+Path(args[0]).name)
 if len(p.stdout)>2*1024*1024:raise ValueError('Unexpected package response size')
 return p.stdout

def installed():
 raw=run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${source:Package}\t${db:Status-Status}\n'])
 result={}
 for line in raw.splitlines():
  fields=line.split('\t')
  if len(fields)!=4:continue
  name,version,source,status=fields;name=name.split(':')[0]
  if status=='installed' and source=='strongswan':
   if name not in ALLOWED:raise ValueError('This strongSwan package layout needs a reviewed adapter')
   if not re.fullmatch('[A-Za-z0-9.+:~_-]{1,100}',version):raise ValueError('Unexpected IKE package version')
   result[name]=version
 if not result:raise ValueError('IKEv2 system packages are not installed')
 return result

def snapshot(manifest,sha,additional=()):
 services=list(additional)
 if Path('/etc/single-vps-vpn/network.env').is_file():
  if not manifest:__import__('reset').inspect()
  services.append('strongswan-starter')
 if manifest and manifest['plan']['role']=='entry' and manifest['plan']['exit_protocol']=='ikev2':services.append(native_pair.BRIDGE)
 if not services:raise ValueError('No recognized IKEv2 service is installed')
 packages=installed();files={}
 roots=[Path('/etc/ipsec.conf'),Path('/etc/ipsec.secrets'),Path('/etc/ipsec.d'),Path('/etc/strongswan.conf'),Path('/etc/strongswan.d'),Path('/etc/swanctl'),Path('/etc/single-vps-vpn/network.env'),Path('/var/lib/rookstride/users.json')]
 for root in roots:
  pair.protected(root)
  for file in sorted(root.rglob('*')) if root.is_dir() else [root]:
   if file.is_file():files[str(file)]=sha(file)
 return [{'kind':'packages','name':service,'configs':files,'packages':packages,'binary':lifecycle.digest(packages)} for service in services]

def candidate(name):
 text=run(['apt-cache','policy',name]);found=re.findall(r'^\s*Candidate:\s*(\S+)',text,re.M)
 if len(found)!=1 or found[0]=='(none)' or not re.fullmatch('[A-Za-z0-9.+:~_-]{1,100}',found[0]):raise ValueError('The signed package repository has no candidate for '+name)
 return found[0]

def metadata(name,version):
 raw=run(['apt-cache','show',name+'='+version]);records=[]
 for paragraph in raw.split('\n\n'):
  fields=dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
  if fields.get('Package')==name and fields.get('Version')==version and re.fullmatch('[a-f0-9]{64}',fields.get('SHA256','')):records.append(fields)
 if not records:raise ValueError('The previous IKE package is no longer retrievable from the authenticated repository; rollback cannot be prepared')
 fingerprints={(r['SHA256'],r.get('Size')) for r in records}
 if len(fingerprints)!=1:raise ValueError('Ambiguous IKE package metadata')
 digest,size=next(iter(fingerprints))
 if not size or not size.isdigit() or not 0<int(size)<128*1024*1024:raise ValueError('Unexpected package size')
 return digest,int(size)

def download(name,version,folder):
 digest,size=metadata(name,version);target=folder/name;target.mkdir(parents=True,mode=0o700,exist_ok=True)
 run(['apt-get','-o','Acquire::Retries=3','download',name+'='+version],cwd=target,timeout=180)
 files=list(target.glob('*.deb'))
 if len(files)!=1 or files[0].stat().st_size!=size or hashlib.sha256(files[0].read_bytes()).hexdigest()!=digest:raise ValueError('IKE package integrity check failed')
 return {'path':str(files[0]),'sha256':digest,'version':version}

def plan(paths,allowed):
 args=['apt-get','-s','--no-remove','--allow-downgrades','--no-install-recommends','install',*paths]
 text=run(args)
 if re.search('^Remv ',text,re.M):raise ValueError('The IKE update would remove another package')
 changed=set(re.findall(r'^Inst\s+([^ :]+)',text,re.M))
 if changed-set(allowed):raise ValueError('The IKE update needs unreviewed system dependencies')
 return text

def stage(op,folder):
 if run(['dpkg','--audit']).strip():raise ValueError('Finish the existing package repair before updating IKEv2')
 run(['apt-get','-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=3','update'],timeout=600)
 old=op['snapshot']['services'][0]['packages'];new={name:candidate(name) for name in old}
 # Upstream major transitions need new configuration compatibility evidence.
 if any(re.sub(r'^\d+:','',old[n]).split('.')[0]!=re.sub(r'^\d+:','',new[n]).split('.')[0] for n in old):raise ValueError('A new strongSwan major version needs app compatibility review')
 op['prior_packages']={name:download(name,version,folder/'prior-packages') for name,version in old.items()}
 op['candidate_packages']={name:download(name,version,folder/'candidate-packages') for name,version in new.items()}
 plan([v['path'] for v in op['candidate_packages'].values()],old)
 op['candidate_versions']=new;op['new_hash']=lifecycle.digest(new);op['target']='exact-ike-packages';op['available']=old!=new
 return op

def same_identity(op,sha):
 old=op['snapshot']['services'][0]['packages'];current=installed()
 if set(current)!=set(old) or any(current[n] not in (old[n],op['candidate_versions'][n]) for n in old):raise ValueError('IKE package versions changed outside this operation')
 for service in op['snapshot']['services']:
  for path,digest in service['configs'].items():
   if sha(Path(path))!=digest:raise ValueError('IKE identity or configuration changed after review')
 for group in ('prior_packages','candidate_packages'):
  for value in op[group].values():
   if sha(Path(value['path']))!=value['sha256']:raise ValueError('Retained IKE package integrity failed')

def mutate(op,rollback):
 packages=op['prior_packages' if rollback else 'candidate_packages'];paths=[value['path'] for value in packages.values()]
 plan(paths,packages)
 run(['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Dpkg::Options::=--force-confold','--no-download','--no-remove','--allow-downgrades','--no-install-recommends','-y','install',*paths],timeout=1200)
 if installed()!={name:value['version'] for name,value in packages.items()}:raise ValueError('IKE package versions did not match the reviewed set')
 for service in op['snapshot']['services']:runtime.command(['systemctl','restart',service['name']],timeout=45)
