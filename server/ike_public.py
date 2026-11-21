#!/usr/bin/env python3
"""Owned single-server IKEv2 public certificates; validation remains mandatory.

Certbot state and its virtual environment live inside existing Rookstride trees.
Only an idle port80 and the gateway's own firewall chain are used. No web service
is stopped. Existing private deployments change only through explicit enable.
"""
import contextlib,datetime,fcntl,hashlib,ipaddress,json,math,os,re,shutil,signal,socket,ssl,subprocess,sys,uuid
from pathlib import Path

BASE=Path('/etc/single-vps-vpn')
MARKER=BASE/'public-certificate.json'
ACME=BASE/'acme'
VENV=Path('/opt/rookstride/ike-acme-venv')
CERT=Path('/etc/ipsec.d/certs/single-vps-server-cert.pem')
KEY=Path('/etc/ipsec.d/private/single-vps-server-key.pem')
ISSUERS=tuple(Path('/etc/ipsec.d/cacerts/single-vps-public-issuer-'+str(i)+'.pem') for i in range(4))
UNIT=Path('/etc/systemd/system/rookstride-ike-cert-renew.service')
TIMER=Path('/etc/systemd/system/rookstride-ike-cert-renew.timer')
CERTBOT_VERSION='5.9.0'
COMMENT='rookstride-ike-acme'
RULE=['-p','tcp','--dport','80','-m','comment','--comment',COMMENT,'-j','ACCEPT']

def run(args,timeout=180,check=True):
    return subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=timeout,check=check)

def atomic(path,data,mode=0o600):
    path=Path(path)
    if path.is_symlink():raise ValueError('Unexpected certificate path link')
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data.encode() if isinstance(data,str) else data)
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)

def eligible(identity):
    if not isinstance(identity,str):return False
    try:return ipaddress.ip_address(identity).version==4 and ipaddress.ip_address(identity).is_global
    except ValueError:
        name=identity.lower().rstrip('.')
        forbidden=('example.com','example.net','example.org','localhost')
        if any(name==x or name.endswith('.'+x) for x in forbidden):return False
        return bool(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',name)) and not name.endswith(('.test','.invalid','.local','.internal','.private','.example'))

def aliases(values):
    if not isinstance(values,list) or len(values)>10:raise ValueError('Use up to five certificate hostnames')
    result=[]
    for name in values:
        if not eligible(name) or ':' in name:raise ValueError('Invalid certificate hostname')
        try:ipaddress.ip_address(name)
        except ValueError:pass
        else:raise ValueError('Aliases must be hostnames')
        name=name.lower().rstrip('.')
        if name not in result:result.append(name)
    if len(result)>5:raise ValueError('Use up to five certificate hostnames')
    return result

def status():
    try:
        if MARKER.is_symlink() or not MARKER.is_file() or CERT.is_symlink():return None
        value=json.loads(MARKER.read_text())
        if not isinstance(value,dict):return None
        if value.get('version')!=1 or not eligible(value.get('identity')) or not re.fullmatch(r'[a-f0-9]{32}',value.get('instance','')):return None
        if type(value.get('expires')) not in (int,float) or not math.isfinite(value['expires']) or value['expires']<=0:return None
        aliases(value.get('aliases',[]))
        if hashlib.sha256(CERT.read_bytes()).hexdigest()!=value.get('certificate_sha256'):return None
        prior=BASE/'previous-identity'/CERT.name
        if not value.get('previous_instance') and prior.is_file() and not prior.is_symlink():value['previous_instance']=hashlib.sha256(prior.read_bytes()).hexdigest()
        return value
    except (OSError,ValueError,TypeError):return None

def pair_scope():
    path=Path('/etc/rookstride-pair/manifest.json')
    if path.is_symlink():raise ValueError('Unexpected pair ownership link')
    if not path.exists():return None
    value=json.loads(path.read_text());p=value.get('plan',{})
    if value.get('version')!=2 or p.get('role')!='entry' or p.get('entry_protocol')!='ikev2' or p.get('access_mode')!='password':
        raise ValueError('Public sign-in is available only on this route’s IKEv2 entry')
    return p['pair']

def identity():
    conf=Path('/etc/ipsec.conf')
    if not (BASE/'network.env').is_file():raise ValueError('Choose a Rookstride IKEv2 server')
    pair_scope()
    values=re.findall(r'^\s*leftid\s*=\s*(\S+)',conf.read_text(),re.M)
    if len(values)!=1 or not eligible(values[0].lstrip('@')):raise ValueError('Public sign-in needs a public IPv4 address or hostname')
    return values[0].lstrip('@')

@contextlib.contextmanager
def challenge_port():
    # Refuse a busy HTTP port. Never stop an unrelated website to issue a certificate.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.bind(('0.0.0.0',80))
    # Pair input guards also precede the single gateway chain. Open only this
    # temporary, tagged HTTP challenge ahead of those guards, never base policy.
    chain='INPUT' if pair_scope() else 'SINGLEVPN_INPUT'
    run(['iptables','-L',chain])
    for _ in range(8):
        if run(['iptables','-C',chain,*RULE],check=False).returncode:break
        run(['iptables','-D',chain,*RULE])
    run(['iptables','-I',chain,'1',*RULE])
    try:yield
    finally:run(['iptables','-D',chain,*RULE],check=False)

def client():
    for path in (BASE,ACME,VENV):
        if path.is_symlink() or path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode&0o022):raise ValueError('Certificate client directory ownership changed')
    binary=VENV/'bin/certbot'
    if not binary.is_file():
        run(['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3','install','--no-remove','-y','-qq','python3-venv'],timeout=1200)
        run(['/usr/bin/python3','-m','venv',VENV])
        run([VENV/'bin/pip','install','--disable-pip-version-check','certbot=='+CERTBOT_VERSION,'acme=='+CERTBOT_VERSION],timeout=600)
    if 'certbot '+CERTBOT_VERSION not in run([binary,'--version']).stdout:raise ValueError('Unexpected ACME client version')
    return binary

def options():return ['--config-dir',ACME/'config','--work-dir',ACME/'work','--logs-dir',ACME/'logs']

def obtain(name,renew=False,names=()):
    binary=client()
    if renew:command=[binary,'renew','--cert-name','rookstride-ike','--non-interactive','--no-random-sleep-on-renew','--preferred-chain','ISRG Root X1',*options()]
    else:
        command=[binary,'certonly','--non-interactive','--agree-tos','--register-unsafely-without-email','--standalone','--preferred-challenges','http','--key-type','rsa','--rsa-key-size','3072','--preferred-chain','ISRG Root X1','--cert-name','rookstride-ike',*options()]
        try:ipaddress.ip_address(name);command+=['--ip-address',name,'--preferred-profile','shortlived']
        except ValueError:command+=['-d',name]
        for alias in aliases(list(names)):
            if alias!=name:command+=['-d',alias]
        command+=['--expand']
    with challenge_port():run(command,timeout=600)
    return ACME/'config/live/rookstride-ike'

def material(directory,name,names=()):
    cert=directory/'cert.pem';key=directory/'privkey.pem';chain=directory/'chain.pem'
    # Certbot's own live symlinks are confined to its private managed directory.
    for item in (cert,key,chain):
        if not item.resolve().is_relative_to(ACME.resolve()):raise ValueError('Certificate escaped its managed directory')
    run(['openssl','verify','-purpose','sslserver','-CApath','/etc/ssl/certs','-untrusted',chain,cert])
    try:ipaddress.ip_address(name);flag='-checkip'
    except ValueError:flag='-checkhost'
    run(['openssl','x509','-in',cert,'-noout',flag,name])
    for alias in aliases(list(names)):run(['openssl','x509','-in',cert,'-noout','-checkhost',alias])
    public=run(['openssl','x509','-in',cert,'-pubkey','-noout']).stdout
    if public!=run(['openssl','pkey','-in',key,'-pubout']).stdout:raise ValueError('Certificate and private key differ')
    pieces=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',chain.read_text(),re.S)
    if not 1<=len(pieces)<=len(ISSUERS):raise ValueError('Unsupported issuer chain length')
    expiry=run(['openssl','x509','-in',cert,'-noout','-enddate']).stdout.strip().split('=',1)[1]
    expires=datetime.datetime.strptime(expiry,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp()
    if expires<datetime.datetime.now(datetime.timezone.utc).timestamp()+3600:raise ValueError('Certificate expires too soon')
    return cert.read_bytes(),key.read_bytes(),[x+'\n' for x in pieces],expires

def activate(directory,name,names=()):
    scope=pair_scope();cert,key,chain,expires=material(directory,name,names);old=status()
    if old and old.get('pair')!=scope:raise ValueError('IKEv2 certificate ownership changed')
    if old and old['certificate_sha256']==hashlib.sha256(cert).hexdigest():return old
    paths=(CERT,KEY,*ISSUERS,MARKER)
    for path in paths:
        if path.is_symlink():raise ValueError('Unexpected managed certificate link')
    if not old and any(p.exists() for p in ISSUERS):raise ValueError('Public issuer files already exist; review their ownership')
    if not CERT.is_file() or not KEY.is_file():raise ValueError('Existing IKEv2 identity is incomplete')
    before={p:p.read_bytes() if p.exists() else None for p in paths}
    backup=BASE/'previous-identity';backup.mkdir(mode=0o700,exist_ok=True)
    if not old:
        for path in (CERT,KEY):atomic(backup/path.name,before[path])
    try:
        atomic(CERT,cert,0o644);atomic(KEY,key)
        for i,path in enumerate(ISSUERS):
            if i<len(chain):atomic(path,chain[i],0o644)
            else:path.unlink(missing_ok=True)
        run(['ipsec','rereadall']);run(['ipsec','reload'])
        value={'version':1,'identity':name,'instance':old['instance'] if old else uuid.uuid4().hex,'certificate_sha256':hashlib.sha256(cert).hexdigest(),'expires':expires,'aliases':aliases(list(names)),'previous_instance':(old or {}).get('previous_instance',hashlib.sha256((backup/CERT.name).read_bytes()).hexdigest())}
        scope=pair_scope()
        if scope:value['pair']=scope
        atomic(MARKER,json.dumps(value))
        if scope:update_pair_hashes()
        return value
    except Exception:
        for path,data in before.items():
            if data is None:path.unlink(missing_ok=True)
            else:atomic(path,data,0o644 if path==CERT or path in ISSUERS else 0o600)
        run(['ipsec','rereadall'],check=False);run(['ipsec','reload'],check=False)
        raise

def update_pair_hashes():
    """Advance only the two identity files changed by this verified activation.

    User edits to configuration/secrets retain their old checksums and still fail
    the immutable pair resume check. Never rewrite a broad directory manifest.
    """
    path=Path('/etc/rookstride-pair/ike-files.sha256')
    if path.is_symlink() or not path.is_file():raise ValueError('Missing IKEv2 ownership record')
    lines=path.read_text().splitlines();result=[];seen=set()
    for line in lines:
        digest,filename=line.split('  ',1)
        if filename in (str(CERT),str(KEY)):
            digest=hashlib.sha256(Path(filename).read_bytes()).hexdigest();seen.add(filename)
        result.append(digest+'  '+filename)
    if seen!={str(CERT),str(KEY)}:raise ValueError('Incomplete IKEv2 identity ownership record')
    atomic(path,'\n'.join(result)+'\n')

def timer():
    for path in (UNIT,TIMER):
        if path.is_symlink() or path.exists() and 'Description=Rookstride IKEv2 certificate renewal' not in path.read_text():raise ValueError('Certificate renewal unit ownership changed')
    atomic(UNIT,'[Unit]\nDescription=Rookstride IKEv2 certificate renewal\nAfter=network-online.target\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=1200\nExecStart=/usr/bin/python3 /opt/rookstride/server/ike_public.py renew\n',0o644)
    atomic(TIMER,'[Unit]\nDescription=Rookstride IKEv2 certificate renewal timer\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=4h\nRandomizedDelaySec=10min\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',TIMER.name])

def enable(names=()):
    name=identity();old=status();names=aliases(list(names)+(old or {}).get("aliases",[]));directory=obtain(name,names=names)
    # Renewal must be scheduled before the new short-lived identity is advertised.
    timer()
    try:return activate(directory,name,names)
    except Exception:
        if not old:
            run(['systemctl','disable','--now',TIMER.name],check=False)
            run(['systemctl','stop',UNIT.name],check=False)
            UNIT.unlink(missing_ok=True);TIMER.unlink(missing_ok=True)
            run(['systemctl','daemon-reload'],check=False)
        raise

def renew():
    old=status()
    if not old:raise ValueError('No recognized public certificate setup')
    if pair_scope()!=old.get('pair'):raise ValueError('IKEv2 certificate ownership changed')
    name=identity()
    if name!=old['identity']:raise ValueError('IKEv2 identity changed')
    return activate(obtain(name,True),name,old.get("aliases",[]))

def main():
    os.umask(0o077)
    def interrupted(signum,frame):raise SystemExit(128+signum)
    signal.signal(signal.SIGTERM,interrupted)
    if os.geteuid()!=0:raise PermissionError('Administrator access required')
    with Path('/run/rookstride-management.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if len(sys.argv)<2 or sys.argv[1] not in ('enable','renew'):raise ValueError('Choose enable or renew')
        if sys.argv[1]=='renew' and len(sys.argv)!=2:raise ValueError('Renew uses its saved certificate names')
        values=sys.argv[2:];names=[]
        while values:
            if len(values)<2 or values[0]!='--alias':raise ValueError('Expected a certificate hostname')
            names.append(values[1]);values=values[2:]
        value=enable(aliases(names)) if sys.argv[1]=='enable' else renew()
    print(json.dumps({'public_certificate':True,'expires':value['expires']}))

if __name__=='__main__':main()
