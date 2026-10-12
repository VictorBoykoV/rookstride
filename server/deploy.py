#!/usr/bin/env python3
"""Detached, inspectable installation jobs for fresh Ubuntu 24.04 gateways."""
import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from rookstride.admin import atomic, username, label

ROOT=Path('/opt/rookstride')
STATE=Path('/var/lib/rookstride')
JOBS=STATE/'jobs'


def state(job,value):
    value['updated']=time.time()
    atomic(job/'status.json',json.dumps(value))


def validate(req,enroll=False):
    if os.geteuid()!=0: raise ValueError('Root or passwordless sudo access is required')
    osrelease=dict(l.split('=',1) for l in Path('/etc/os-release').read_text().splitlines() if '=' in l)
    if osrelease.get('ID','').strip('"')!='ubuntu' or osrelease.get('VERSION_ID','').strip('"')!='24.04':
        raise ValueError('This version supports Ubuntu 24.04')
    if enroll:
        if not Path('/etc/single-vps-vpn/network.env').exists():
            raise ValueError('Existing server is not a supported single VPS gateway')
    else:
        for p in ('/etc/ipsec.conf','/etc/ipsec.secrets','/etc/single-vps-vpn','/var/lib/AdGuardHome','/opt/AdGuardHome'):
            if Path(p).exists(): raise ValueError('Existing VPN/DNS configuration detected. Use enrollment for a compatible gateway or a fresh VPS.')
        username(req.get('login'))
        password=req.get('password','')
        if not isinstance(password,str) or not 16<=len(password)<=512 or any(c in password for c in ('\n','\r','\0')):
            raise ValueError('VPN password must be a single line of 16–512 characters')
        address=req.get('server','')
        if not isinstance(address,str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',address):
            raise ValueError('Invalid VPN server address')
    if not isinstance(req.get('statistics',False),bool): raise ValueError('Invalid statistics option')


def start(req):
    enroll=req.get('mode')=='enroll'
    if req.get('mode') not in ('install','enroll'): raise ValueError('Invalid deployment mode')
    validate(req,enroll)
    JOBS.mkdir(mode=0o700,parents=True,exist_ok=True)
    with Path('/run/rookstride-management.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for p in JOBS.glob('*/status.json'):
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
                env=dict(os.environ,SERVER_ID=req['server'],VPN_USER=req['login'],VPN_PASSWORD_FILE=str(job/'vpn-password'))
                subprocess.run(['bash',str(source/'gateway/scripts/install.sh')],env=env,
                               stdout=log,stderr=log,check=True,timeout=1800)
            state(job,{'state':'running','phase':'Adding management and monitoring','job':ident})
            env=dict(os.environ,ROOKSTRIDE_STATS=str(req.get('statistics',False)).lower())
            subprocess.run(['bash',str(source/'server/enroll.sh')],env=env,
                           stdout=log,stderr=log,check=True,timeout=600)
        state(job,{'state':'complete','phase':'Gateway ready','job':ident})
    except (OSError,subprocess.SubprocessError) as exc:
        state(job,{'state':'failed','phase':'Installation stopped. Open the installation guide before retrying.',
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
