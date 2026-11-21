"""Shared, owned public TLS identities. Consumers retain their own renewal units.

Only public IP/DNS identities are eligible. No TLS verification bypass, webserver
shutdown or user-supplied command is accepted. An identity is cached across a
single protocol removal; whole-server managed cleanup removes this shared cache.
"""
import contextlib,datetime,fcntl,hashlib,ipaddress,json,os,re,shutil,signal,socket,subprocess,time
from pathlib import Path

BASE=Path('/var/lib/rookstride-public-tls')
VENV=Path('/opt/rookstride-public-tls/venv')
LOCK=Path('/run/rookstride-public-tls.lock')
CERTBOT_VERSION='5.9.0'
AUTO_DOMAIN='sslip.io'
RULE=['-p','tcp','--dport','80','-m','comment','--comment','rookstride-public-tls','-j','ACCEPT']

def run(args,timeout=120,check=True):
    return subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=timeout,check=check)

def tls_name(value):
    try:return str(ipaddress.IPv4Address(value)).replace('.','-')+'.'+AUTO_DOMAIN
    except ValueError:return value.lower().rstrip('.')

def identity(value):
    if not isinstance(value,str):raise ValueError('Enter the public VPN IP address or domain')
    try:
        ip=ipaddress.ip_address(value)
        if ip.version!=4 or not ip.is_global:raise ValueError('Reusable sign-in needs a public IPv4 address or domain')
        return str(ip)
    except ValueError:
        name=value.lower().rstrip('.')
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',name) or any(name==v or name.endswith('.'+v) for v in ('example.com','example.net','example.org','localhost','invalid','test','local','internal','example')):
            raise ValueError('Reusable sign-in needs a public IPv4 address or domain')
        return name

def owned(path):
    for p in (path,*path.parents):
        if p.is_symlink() or p.exists() and (p.stat().st_uid!=0 or p.stat().st_mode&0o022):
            raise ValueError('Public certificate directory ownership changed')
        if p==Path('/'):break
    return path

@contextlib.contextmanager
def http_challenge():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:probe.bind(('0.0.0.0',80))
    # A precise temporary owned rule precedes entry-node input guards as well.
    for _ in range(8):
        if run(['iptables','-C','INPUT',*RULE],check=False).returncode:break
        run(['iptables','-D','INPUT',*RULE])
    def interrupted(signum,frame):raise SystemExit(128+signum)
    previous=signal.signal(signal.SIGTERM,interrupted)
    try:
        run(['iptables','-I','INPUT','1',*RULE])
        try:yield
        finally:run(['iptables','-D','INPUT',*RULE],check=False)
    finally:signal.signal(signal.SIGTERM,previous)

def client():
    owned(VENV)
    binary=VENV/'bin/certbot'
    if not binary.exists():
        run(['apt-get','-o','DPkg::Lock::Timeout=1200','-o','Acquire::Retries=3','install','--no-remove','-y','python3-venv'],timeout=1200)
        run(['/usr/bin/python3','-m','venv',VENV])
        run([VENV/'bin/pip','install','--disable-pip-version-check','certbot=='+CERTBOT_VERSION,'acme=='+CERTBOT_VERSION],timeout=600)
    if 'certbot '+CERTBOT_VERSION not in run([binary,'--version']).stdout:raise ValueError('Unexpected public certificate client version')
    return binary

def dates(cert):
    raw=run(['openssl','x509','-in',cert,'-noout','-startdate','-enddate']).stdout
    values=[datetime.datetime.strptime(line.split('=',1)[1].strip(),'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp() for line in raw.splitlines()]
    if len(values)!=2:raise ValueError('Invalid public certificate dates')
    return values

def material(folder,name):
    live=folder/'config/live/rookstride'
    cert,key,chain,full=[live/n for n in ('cert.pem','privkey.pem','chain.pem','fullchain.pem')]
    for p in (cert,key,chain,full):
        if not p.resolve().is_relative_to(folder.resolve()):raise ValueError('Certificate escaped its owned directory')
        owned(p.resolve())
    if key.stat().st_mode&0o077:raise ValueError('Private certificate key permissions changed')
    run(['openssl','verify','-purpose','sslserver','-CApath','/etc/ssl/certs','-untrusted',chain,cert])
    try:ipaddress.ip_address(name);flag='-checkip'
    except ValueError:flag='-checkhost'
    run(['openssl','x509','-in',cert,'-noout',flag,name])
    if run(['openssl','x509','-in',cert,'-pubkey','-noout']).stdout!=run(['openssl','pkey','-in',key,'-pubout']).stdout:raise ValueError('Public certificate key does not match')
    start,expires=dates(cert)
    if expires<time.time()+3600:raise ValueError('Public certificate expires too soon')
    subject=run(['openssl','x509','-in',cert,'-noout','-subject','-nameopt','RFC2253']).stdout.strip()
    common=re.search(r'(?:^|,)CN=([^,]+)',subject.split('=',1)[-1])
    return {'identity':name,'common_name':common.group(1) if common else '','certificate':str(full),'key':str(key),'expires':expires,'renew_after':expires-(expires-start)/3,'sha256':hashlib.sha256(cert.read_bytes()).hexdigest()}

def ensure(value):
    name=tls_name(value)
    initialize()
    folder=BASE/hashlib.sha256(name.encode()).hexdigest();owned(folder);folder.mkdir(mode=0o700,exist_ok=True)
    with LOCK.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            current=material(folder,name)
            if current['renew_after']>time.time():return current
        except (OSError,ValueError,subprocess.SubprocessError):pass
        identity(value);identity(name)
        command=[client(),'certonly','--non-interactive','--agree-tos','--register-unsafely-without-email','--standalone','--preferred-challenges','http','--key-type','rsa','--rsa-key-size','3072','--preferred-chain','ISRG Root X1','--cert-name','rookstride','--keep-until-expiring','--config-dir',folder/'config','--work-dir',folder/'work','--logs-dir',folder/'logs']
        try:ipaddress.ip_address(name);command+=['--ip-address',name,'--preferred-profile','shortlived']
        except ValueError:command+=['-d',name,'--required-profile','classic']
        try:
            with http_challenge():run(command,timeout=600)
            return material(folder,name)
        except (OSError,subprocess.SubprocessError) as e:
            detail=str(getattr(e,'stderr',''))
            if 'rateLimited' in detail or 'too many certificates' in detail.lower():raise ValueError('The certificate provider is temporarily limiting requests. Try again later, or set up this VPN with a domain you own. Other VPNs are unchanged.') from e
            raise ValueError('Could not verify the public VPN address. Check that the domain points to this VPS and HTTP port 80 can be reached, then retry. Existing websites are preserved.') from e

def roots():
    # A public trust store, never the current server leaf or a private authority.
    value=Path('/etc/ssl/certs/ca-certificates.crt').read_text()
    if not 0<len(value.encode())<=450000:raise ValueError('Unexpected public trust store size')
    return value


def initialize():
    owned(BASE);marker=BASE/'owner.json'
    if BASE.exists() and (not marker.is_file() or marker.read_text()!='{"owner":"rookstride-public-tls-v1"}\n'):
        raise ValueError('Public certificate cache ownership changed')
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not marker.exists():
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:out.write('{"owner":"rookstride-public-tls-v1"}\n')

def fingerprint():
    if not BASE.exists():return None
    initialize();h=hashlib.sha256()
    for path in sorted(BASE.rglob('*')):
        if path.is_symlink() and not path.resolve().is_relative_to(BASE.resolve()):raise ValueError('Certificate cache link escaped its directory')
        if path.is_file() and 'logs' not in path.relative_to(BASE).parts and 'work' not in path.relative_to(BASE).parts:
            owned(path.resolve())
            h.update(str(path.relative_to(BASE)).encode()+path.read_bytes())
    return h.hexdigest()

def cleanup(expected):
    if fingerprint()!=expected:raise ValueError('Certificate cache changed. Review removal again.')
    if expected is not None:
        for _ in range(8):
            if run(['iptables','-C','INPUT',*RULE],check=False).returncode:break
            run(['iptables','-D','INPUT',*RULE])
        shutil.rmtree(owned(BASE))
    # Packages/client binaries remain, as they do for other downloaded engines.
