#!/usr/bin/env python3
"""Detached, inspectable installation jobs for eligible Ubuntu gateways."""
import contextlib
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from rookstride.admin import atomic, username, label
from rookstride.passwords import validate as vpn_password
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'gateway/scripts'))
from ubuntu_support import require as require_ubuntu

ROOT=Path('/opt/rookstride')
STATE=Path('/var/lib/rookstride')
JOBS=STATE/'jobs'


def state(job,value):
    value['updated']=time.time()
    atomic(job/'status.json',json.dumps(value))


def validate(req,enroll=False):
    if os.geteuid()!=0: raise ValueError('Root or passwordless sudo access is required')
    require_ubuntu()
    if enroll:
        if not Path('/etc/single-vps-vpn/network.env').exists():
            raise ValueError('Existing server is not a supported single VPS gateway')
    else:
        for p in ('/etc/ipsec.conf','/etc/ipsec.secrets','/etc/single-vps-vpn','/var/lib/AdGuardHome','/opt/AdGuardHome'):
            if Path(p).exists(): raise ValueError('Existing VPN/DNS configuration detected. Use enrollment for a compatible gateway or a fresh VPS.')
        username(req.get('login'))
        password=req.get('password','')
        vpn_password(password)
        address=req.get('server','')
        if not isinstance(address,str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',address):
            raise ValueError('Invalid VPN server address')
    import ike_public
    if req.get('access_mode','auto') not in ('auto','profile','password'):raise ValueError('Invalid sign-in mode')
    if req.get('access_mode')=='password' and not ike_public.eligible(req.get('server')):raise ValueError('Username/password sign-in needs a public IP address or domain')
    ike_public.aliases(req.get('aliases',[]))
    if not isinstance(req.get('statistics',False),bool): raise ValueError('Invalid statistics option')


def start(req):
    enroll=req.get('mode')=='enroll'
    if req.get('mode') not in ('install','enroll'): raise ValueError('Invalid deployment mode')
    validate(req,enroll)
    JOBS.mkdir(mode=0o700,parents=True,exist_ok=True)
    with Path('/run/rookstride-management.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for p in list(JOBS.glob('*/status.json'))+list(Path('/var/lib/rookstride-single/jobs').glob('*/status.json')):
            previous=json.loads(p.read_text())
            if previous.get('state') in ('starting','running'):
                raise ValueError('An installation is already recorded as running. Check its status first.')
        ident=uuid.uuid4().hex
        job=JOBS/ident; job.mkdir(mode=0o700)
        source=Path(__file__).resolve().parent.parent
        release=ROOT/'releases'/'0.1.0'
        release.mkdir(mode=0o700,parents=True,exist_ok=True)
        for name in ('server','gateway'):
            for p in (source/name).rglob('*'):
                if p.is_symlink(): raise ValueError('Unexpected symbolic link in deployment package')
            shutil.copytree(source/name,release/name,dirs_exist_ok=True)
        # Python ZIP extraction drops executable bits. Restore only known bundled scripts
        # in the private root-owned release before the installer calls its verifier.
        for script in (release/'gateway/scripts').glob('*.sh'):
            script.chmod(0o700)
        (release/'server/enroll.sh').chmod(0o700)
        atomic(job/'config.json',json.dumps(req))
        state(job,{'state':'starting','phase':'Starting installation','job':ident})
        p=subprocess.run(['systemd-run','--unit=rookstride-install-'+ident,'--collect',
                          '--property=UMask=0077','--property=StandardOutput=journal',
                          '/usr/bin/python3',str(release/'server/deploy.py'),'run',ident],
                          capture_output=True,text=True)
        if p.returncode:
            (job/'config.json').unlink(missing_ok=True)
            state(job,{'state':'failed','phase':'Could not start the installation service','job':ident})
            raise ValueError('Could not launch installation; check systemd on the VPS')
        return {'job':ident,'state':'starting'}


def public_certificate(log,aliases=()):
    command=['/usr/bin/python3',str(ROOT/'server/ike_public.py'),'enable']
    import ike_public
    for name in ike_public.aliases(list(aliases)):command+=['--alias',name]
    worker=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
    try:
        code=worker.wait(timeout=1200)
        if code:raise subprocess.CalledProcessError(code,command)
    except subprocess.TimeoutExpired:
        # Stop the entire ACME process group: no child may activate an identity
        # after the deployment has already reported its fallback result.
        with contextlib.suppress(ProcessLookupError):os.killpg(worker.pid,signal.SIGTERM)
        try:worker.wait(timeout=15)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):os.killpg(worker.pid,signal.SIGKILL)
            worker.wait(timeout=15)
        raise


def verify_gateway(source,log):
    """Keep diagnostic output private and return only known, actionable errors."""
    try:
        result=subprocess.run(['bash',str(source/'gateway/scripts/verify.sh')],
                              capture_output=True,text=True,timeout=360)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('VPN and DNS checks timed out. The existing setup is retained; check this server before installing again.') from exc
    log.write(result.stdout or '')
    log.write(result.stderr or '')
    log.flush()
    if result.returncode:
        output=(result.stdout or '')+'\n'+(result.stderr or '')
        if 'The ad-block list did not finish downloading.' in output or 'The ad-block list could not be downloaded.' in output:
            raise ValueError('Ad blocking did not finish downloading its list. The VPN setup is retained. Check the server’s internet access before trying again.')
        if 'AdGuard did not finish loading its block list.' in output:
            raise ValueError('Ad blocking could not finish loading. The VPN setup is retained. Check the server’s DNS and internet access before trying again.')
        raise ValueError('The VPN or DNS checks did not pass. The existing setup is retained; inspect this server before installing again.')


def execute(ident):
    if not re.fullmatch(r'[a-f0-9]{32}',ident): raise ValueError('Invalid job identifier')
    job=JOBS/ident
    req=json.loads((job/'config.json').read_text())
    source=Path(__file__).resolve().parent.parent
    try:
        with (job/'install.log').open('a') as log:
            if req['mode']=='install':
                state(job,{'state':'running','phase':'Installing StrongSwan, DNS and AdGuard Home','job':ident})
                atomic(job/'vpn-password',req['password']+'\n')
                env=dict(os.environ,SERVER_ID=req['server'],VPN_USER=req['login'],VPN_PASSWORD_FILE=str(job/'vpn-password'),ROOKSTRIDE_VERIFY_SEPARATELY='YES')
                subprocess.run(['bash',str(source/'gateway/scripts/install.sh')],env=env,
                               stdout=log,stderr=log,check=True,timeout=1800)
                state(job,{'state':'running','phase':'Checking VPN, DNS and ad blocking','job':ident})
                verify_gateway(source,log)
            state(job,{'state':'running','phase':'Adding management and monitoring','job':ident})
            env=dict(os.environ,ROOKSTRIDE_STATS=str(req.get('statistics',False)).lower())
            subprocess.run(['bash',str(source/'server/enroll.sh')],env=env,
                           stdout=log,stderr=log,check=True,timeout=600)
        public_ready=False
        if req.get('access_mode')=='password' or req['mode']=='install' and req.get('access_mode')!='profile':
            import ike_public
            if ike_public.eligible(req['server']):
                state(job,{'state':'running','phase':'Preparing trusted IKEv2 sign-in','job':ident})
                with (job/'install.log').open('a') as log:
                    try:
                        names=list(req.get('aliases') or [])
                        if req['mode']=='enroll':
                            try:__import__('ipaddress').ip_address(req['server'])
                            except ValueError:names.append(req['server'])
                        public_certificate(log,names)
                        public_ready=True
                    except (OSError,subprocess.SubprocessError):
                        if req.get('access_mode')=='password':raise ValueError('Trusted sign-in could not be prepared. Check the domain DNS and that HTTP port 80 is reachable, then use Enable username/password sign-in to retry. Your VPN users are retained.')
                        log.write('Public certificate unavailable. Secure pinned-profile sign-in remains available.\n')
        state(job,{'state':'complete','phase':'Gateway ready','job':ident,'public_certificate':public_ready})
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        state(job,{'state':'failed','phase':str(exc) if isinstance(exc,ValueError) else 'Installation stopped. Open the installation guide before retrying.',
                   'error':type(exc).__name__,'job':ident})
    finally:
        (job/'config.json').unlink(missing_ok=True)
        (job/'vpn-password').unlink(missing_ok=True)


def status(ident):
    if not re.fullmatch(r'[a-f0-9]{32}',ident): raise ValueError('Invalid job identifier')
    job=JOBS/ident
    result=json.loads((job/'status.json').read_text())
    if result['state'] in ('starting','running'):
        active=subprocess.run(['systemctl','is-active','--quiet','rookstride-install-'+ident]).returncode==0
        if not active and time.time()-result['updated']>15:
            result.update(state='failed',phase='Installation was interrupted on the VPS. Inspect it before starting again.')
            state(job,result)
    # Logs remain root-only on the VPS. Do not copy package-manager output into public telemetry.
    return result


def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0: raise ValueError('Administrator access is required')
        action=sys.argv[1]
        if action=='start':
            raw=sys.stdin.buffer.read(65537)
            if len(raw)>65536: raise ValueError('Request is too large')
            req=json.loads(raw)
            if not isinstance(req,dict): raise ValueError('Expected a JSON object')
            result=start(req)
        elif action=='run':
            execute(sys.argv[2]); return
        elif action=='status': result=status(sys.argv[2])
        else: raise ValueError('Unsupported deployment action')
        print(json.dumps({'ok':True,'result':result}))
    except (ValueError,OSError,KeyError,IndexError) as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__}))
        raise SystemExit(1)


if __name__=='__main__': main()
