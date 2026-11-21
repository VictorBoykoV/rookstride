"""Switch only owned, inactive, unmodified mutually exclusive IKE daemon packages.

Ownership metadata survives managed VPN removal because downloaded packages do.
It contains no users, keys or credentials. An unowned daemon is never removed.
"""
import hashlib,json,os,re,subprocess,sys,uuid
from pathlib import Path
MARKER=Path('/var/lib/rookstride-ike-packages.json')
PACKAGES={'starter':'strongswan-starter','systemd':'charon-systemd'}

def run(args,check=True,timeout=120):
    return subprocess.run(args,capture_output=True,text=True,check=check,timeout=timeout,env=dict(os.environ,LC_ALL='C'))

def installed(package):
    try:p=run(['dpkg-query','-W','-f=${db:Status-Status}',package],check=False)
    except FileNotFoundError:return False
    return p.returncode==0 and p.stdout.strip()=='installed'

def secure(path):
    for p in (path,*path.parents):
        if p.is_symlink() or p.exists() and (p.stat().st_uid!=0 or p.stat().st_mode&0o022):raise ValueError('IKE package ownership changed')
    return path

def ownership():
    path=secure(MARKER)
    if not path.exists():
        return {'owner':'rookstride-ike-packages-v1','packages':[]}
    value=json.loads(path.read_text())
    if not isinstance(value,dict) or set(value)!={'owner','packages'} or value.get('owner')!='rookstride-ike-packages-v1' or not isinstance(value.get('packages'),list) or any(p not in PACKAGES.values() for p in value['packages']):raise ValueError('IKE package ownership changed')
    return value

def remember_owned(target):
    package=PACKAGES[target]
    if not installed(package):return
    value=ownership();value['packages']=sorted(set(value['packages'])|{package})
    temporary=MARKER.with_name('.rookstride-ike-packages-'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w') as out:json.dump(value,out)
        temporary.replace(MARKER)
    finally:temporary.unlink(missing_ok=True)

def unmodified_config(target):
    package='strongswan-swanctl' if target=='systemd' else 'strongswan-starter'
    raw=run(['dpkg-query','-W','-f=${Conffiles}',package],check=False).stdout
    known={name:digest for name,digest in re.findall(r'^\s*(/\S+)\s+([a-f0-9]{32})(?:\s|$)',raw,re.M)}
    folder=Path('/etc/swanctl')
    if target=='systemd' and folder.is_symlink():raise ValueError('Existing IKE configuration needs review before switching daemons')
    files=list(folder.rglob('*')) if target=='systemd' and folder.exists() else [Path('/etc/ipsec.conf'),Path('/etc/ipsec.secrets')] if target=='starter' else []
    for p in files:
        if p.is_symlink():raise ValueError('Existing IKE configuration needs review before switching daemons')
        if p.is_file() and (str(p) not in known or hashlib.md5(p.read_bytes()).hexdigest()!=known[str(p)]):raise ValueError('Existing IKE configuration needs review before switching daemons')

def install(target,packages):
    if target not in PACKAGES or any(not re.fullmatch('[a-z0-9][a-z0-9+.-]*',p) for p in packages):raise ValueError('Invalid IKE package selection')
    conflict='systemd' if target=='starter' else 'starter';other=PACKAGES[conflict];switch=False
    apt=['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3']
    requested=list(dict.fromkeys([*packages,PACKAGES[target]]))
    if installed(other):
        # Older distributions permit both wrappers. Never remove one merely
        # because it is installed; inspect the distribution's actual plan.
        preview=run([*apt,'-s','install','--no-auto-remove','-y',*requested])
        removals=set(re.findall(r'^Remv\s+(\S+)',preview.stdout,re.M))
        if removals-{other}:raise ValueError('IKE package switching would remove another application; review this server')
        switch=other in removals
    if switch:
        if other not in ownership()['packages']:raise ValueError('An existing IKE daemon is not owned by Rookstride. Review it before replacing it.')
        for service in ('strongswan','strongswan-starter'):
            if run(['systemctl','is-active','--quiet',service],check=False).returncode==0:raise ValueError('Stop and remove the recognized VPN before switching its IKE daemon')
        unmodified_config(conflict)
        requested.append(other+'-')
    run([*apt,'install','--no-auto-remove',*([] if switch else ['--no-remove']),'-y','-qq',*requested],timeout=1200)
    remember_owned(target)

if __name__=='__main__':
    if os.geteuid()!=0:raise PermissionError('Root access required')
    install(sys.argv[1],sys.argv[2:])
