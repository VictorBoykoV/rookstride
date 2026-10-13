#!/usr/bin/env python3
"""Owned, resumable per-node jobs for the IKEv2 -> AWG pair. SSH JSON stdin only."""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from rookstride.admin import atomic, username

OWN=Path('/etc/rookstride-pair')
STATE=Path('/var/lib/rookstride-pair')
RELEASE=Path('/opt/rookstride-pair')
LOCK=Path('/run/rookstride-pair.lock')
DEFAULTS={'client_pool':'10.250.0.0/16','test_ip':'10.249.255.254','entry_address':'10.253.0.2/30','exit_address':'10.253.0.1/30','tunnel_port':443,'route_table':51831,'vpn_port':500}
ACTIONS={'bootstrap','configure','verify','activate'}


def ident(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value): raise ValueError('Invalid pair or job identifier')
    return value


def host(value):
    if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',value): raise ValueError('Invalid server address')
    return value


def key(value):
    try:
        if not isinstance(value,str) or len(base64.b64decode(value,validate=True))!=32: raise ValueError()
    except (ValueError,TypeError): raise ValueError('Invalid tunnel key')
    return value


def plan(req):
    if not isinstance(req,dict): raise ValueError('Expected a JSON object')
    result={k:req.get(k,v) for k,v in DEFAULTS.items()}
    result.update(pair=ident(req.get('pair')),role=req.get('role'),server=host(req.get('server')),exit_host=host(req.get('exit_host')))
    if result['role'] not in ('entry','exit'): raise ValueError('Invalid node role')
    for k in ('tunnel_port','vpn_port','route_table'):
        n=result[k]
        if type(n) is not int or not 1<=n<=(2147483647 if k=='route_table' else 65535): raise ValueError('Invalid port or routing table')
    pool=ipaddress.ip_network(result['client_pool'],strict=True)
    test=ipaddress.ip_address(result['test_ip'])
    entry=ipaddress.ip_interface(result['entry_address']); exit=ipaddress.ip_interface(result['exit_address'])
    if any(v.version!=4 for v in (pool,test,entry,exit)): raise ValueError('IPv4 addresses are required')
    if entry.network!=exit.network or entry.ip==exit.ip or entry.ip in (entry.network.network_address,entry.network.broadcast_address) or exit.ip in (exit.network.network_address,exit.network.broadcast_address): raise ValueError('Use distinct usable tunnel addresses')
    if pool.overlaps(entry.network) or test in pool or test in entry.network: raise ValueError('Address ranges overlap')
    return result


def protected(path):
    p=Path(path)
    for part in (p,*p.parents):
        if part.is_symlink(): raise ValueError('A managed path is a symbolic link')
        if part.exists() and part.stat().st_uid!=0: raise ValueError('A managed path is not root-owned')
    return p


def load_manifest():
    protected(OWN)
    p=OWN/'manifest.json'
    return json.loads(p.read_text()) if p.exists() else None


def require_owner(p):
    m=load_manifest()
    if not m or m['plan']!=p: raise ValueError('This node belongs to another pair or installation plan')
    return m


def fresh(p):
    d=dict(l.split('=',1) for l in Path('/etc/os-release').read_text().splitlines() if '=' in l)
    if d.get('ID','').strip('"')!='ubuntu' or d.get('VERSION_ID','').strip('"')!='24.04': raise ValueError('Use fresh Ubuntu 24.04')
    for name in ('/etc/ipsec.conf','/etc/ipsec.secrets','/etc/single-vps-vpn','/etc/twohop-vpn','/etc/amnezia','/etc/wireguard','/opt/AdGuardHome','/var/lib/AdGuardHome'):
        if Path(name).exists(): raise ValueError('Existing VPN/DNS configuration detected; use a fresh node')
    for route in json.loads(command_output(['ip','-j','-4','route','show','table','main'])):
        destination=route.get('dst','default')
        if destination!='default':
            network=ipaddress.ip_network(destination,strict=False)
            if network.overlaps(ipaddress.ip_network(p['client_pool'])) or network.overlaps(ipaddress.ip_interface(p['entry_address']).network):raise ValueError('Proposed pools overlap an existing host route')
    for name in ('strongswan-starter','adguardhome','unbound'):
        if subprocess.run(['systemctl','is-active','--quiet',name],capture_output=True).returncode==0: raise ValueError('Existing VPN/DNS service detected')


def write_manifest(m): atomic(OWN/'manifest.json',json.dumps(m))


def job_state(job,**values):
    old=json.loads((job/'status.json').read_text()) if (job/'status.json').exists() else {}
    old.update(values,updated=time.time(),job=job.name)
    atomic(job/'status.json',json.dumps(old))


def source_digest(source):
    h=hashlib.sha256()
    for folder in ('server','twohop','gateway'):
        for path in sorted((source/folder).rglob('*'),key=lambda path:path.relative_to(source).as_posix()):
            if path.is_symlink(): raise ValueError('Bundle contains a symbolic link')
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':
                h.update(str(path.relative_to(source)).encode());h.update(path.read_bytes())
    return h.hexdigest()


def start(req):
    p=plan(req); action=req.get('action')
    if action not in ACTIONS: raise ValueError('Unsupported pair action')
    source=Path(__file__).resolve().parent.parent
    digest=source_digest(source)
    m=load_manifest()
    if m:
        m=require_owner(p)
        if m['bundle']!=digest: raise ValueError('Bundle changed; review an explicit upgrade instead of resuming')
    else:
        if action!='bootstrap': raise ValueError('Bootstrap this node first')
        fresh(p)
        if p['role']=='entry':
            username(req.get('login'))
            pw=req.get('password')
            if not isinstance(pw,str) or not 16<=len(pw)<=512 or any(c in pw for c in '\n\r\0'): raise ValueError('Use a single-line VPN password of 16–512 characters')
            if type(req.get('statistics',False)) is not bool: raise ValueError('Invalid history setting')
        for directory in (OWN,STATE,RELEASE): protected(directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        # The checked source is immutable for this pair; jobs and boot recovery use it.
        for folder in ('server','twohop','gateway'):
            shutil.copytree(source/folder,RELEASE/folder,dirs_exist_ok=True)
        for script in RELEASE.rglob('*.sh'): script.chmod(0o700)
        m={'plan':p,'bundle':digest,'jobs':{},'configured':False,'verified':False,'activated':False,'version':1}
        write_manifest(m)
        if p['role']=='entry': atomic(OWN/'initial-user.json',json.dumps({'login':req['login'],'password':req['password'],'statistics':req.get('statistics',False)}))
    protected(STATE)
    previous=m['jobs'].get(action)
    for recorded in m['jobs'].values():
        if recorded!=previous and status(recorded)['state'] in ('starting','running','awaiting-reboot'):
            raise ValueError('Finish or resume the recorded job before another step')
    if action=='configure':
        key(req.get('peer_key'))
        if p['role']=='entry':validate_shared(req.get('shared'))
        config_hash=hashlib.sha256(json.dumps({'peer':req['peer_key'],'shared':req.get('shared')},sort_keys=True).encode()).hexdigest()
        if m.get('configure_digest') and m['configure_digest']!=config_hash:raise ValueError('Peer configuration changed')
        m['configure_digest']=config_hash;write_manifest(m)
    if previous and status(previous)['state']=='complete' and action in ('verify','activate') and req.get('repeat') is True:
        previous=None
    if previous:
        job=STATE/previous; s=status(previous)
        old_req=json.loads((job/'request.json').read_text()) if (job/'request.json').exists() else None
        # Configure requests contain peer authentication material; an interrupted job is immutable.
        if old_req is not None and plan(old_req)!=p: raise ValueError('Recorded job plan changed')
        if s['state'] in ('complete','starting','running','awaiting-reboot'): return s
        if not req.get('resume'): raise ValueError('The previous step failed or was interrupted. Use Resume after reviewing it.')
    else:
        if action!='bootstrap' and not m['jobs'].get('bootstrap'): raise ValueError('Bootstrap is required')
        if action=='configure':
            key(req.get('peer_key'))
            if p['role']=='entry': validate_shared(req.get('shared'))
        if action in ('verify','activate') and (p['role']!='entry' or not m['configured']): raise ValueError('Configure the entry first')
        if action=='activate' and not m['verified']: raise ValueError('A successful staged verification is required')
        ident_=uuid.uuid4().hex; job=STATE/ident_;job.mkdir(mode=0o700)
        atomic(job/'request.json',json.dumps(req))
        m['jobs'][action]=ident_;write_manifest(m)
    job_state(job,state='starting',phase='Starting '+action,action=action)
    unit='rookstride-pair-job-'+job.name
    unitfile=Path('/etc/systemd/system')/(unit+'.service')
    protected(unitfile)
    atomic(unitfile,f'''[Unit]\nDescription=Rookstride owned pair job\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nUMask=0077\nExecStart=/usr/bin/python3 {RELEASE}/server/pair.py run {job.name}\nTimeoutStartSec=45min\n[Install]\nWantedBy=multi-user.target\n''')
    unitfile.chmod(0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable',unit]);run(['systemctl','start','--no-block',unit])
    return status(job.name)


def run(args,**kwargs):
    return subprocess.run(args,check=True,timeout=kwargs.pop('timeout',1800),**kwargs)


def validate_shared(shared):
    if not isinstance(shared,dict) or set(shared)!={'psk','header_key','headers'}: raise ValueError('Invalid shared tunnel parameters')
    key(shared['psk']);key(shared['header_key'])
    if not isinstance(shared['headers'],list) or len(shared['headers'])!=4 or len(set(shared['headers']))!=4 or any(type(n) is not int or not 1<=n<=4294967295 for n in shared['headers']): raise ValueError('Invalid protocol headers')
    return shared


def command_output(args):
    return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL,timeout=30).strip()


def install_helper(entry=False,history=False):
    target=Path('/opt/rookstride')
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for folder in ('server','gateway'): shutil.copytree(RELEASE/folder,target/folder,dirs_exist_ok=True)
    atomic('/usr/local/sbin/rookstride-admin','#!/bin/sh\ncd /opt/rookstride/server\nexec /usr/bin/python3 -m rookstride.admin\n')
    Path('/usr/local/sbin/rookstride-admin').chmod(0o700)
    if entry:
        run(['bash',str(RELEASE/'server/enroll.sh')],env=dict(os.environ,ROOKSTRIDE_STATS=str(history).lower()))


def prepare_guard(p):
    d=Path('/etc/twohop-vpn');d.mkdir(mode=0o700,exist_ok=True)
    atomic(d/'entry.env',f"AWG_INTERFACE=awg-exit\nCLIENT_POOL={p['client_pool']}\nTEST_SOURCE_IP={p['test_ip']}\nROUTE_TABLE={p['route_table']}\n")
    helper=Path('/usr/local/sbin/twohop-vpn-entry-routing')
    shutil.copyfile(RELEASE/'twohop/scripts/remote/twohop-vpn-entry-routing',helper);helper.chmod(0o700)
    # Tools are needed before the guard; no VPN credentials/profile exist yet.
    run(['apt-get','update','-qq']);run(['apt-get','install','-y','-qq','iproute2','iptables'])
    run([str(helper),'quiesce'])
    atomic('/etc/systemd/system/twohop-vpn-entry-routing.service','''[Unit]\nAfter=network-online.target\nWants=network-online.target\nBefore=strongswan-starter.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/twohop-vpn-entry-routing boot\n[Install]\nWantedBy=multi-user.target\n''')
    Path('/etc/systemd/system/twohop-vpn-entry-routing.service').chmod(0o644)
    drop=Path('/etc/systemd/system/strongswan-starter.service.d');drop.mkdir(exist_ok=True)
    atomic(drop/'rookstride-pair.conf','[Unit]\nRequires=twohop-vpn-entry-routing.service\nAfter=twohop-vpn-entry-routing.service\n')
    run(['systemctl','daemon-reload']);run(['systemctl','enable','twohop-vpn-entry-routing'])


def bootstrap(p,job,log):
    if p['role']=='entry': prepare_guard(p)
    result=subprocess.run(['bash','scripts/install-amneziawg.sh','ingress' if p['role']=='entry' else 'egress'],cwd=RELEASE/'twohop',stdout=log,stderr=log,timeout=1800,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    if result.returncode==194:
        job_state(job,state='awaiting-reboot',phase='A matching kernel was installed; reboot this node to continue',boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        return False
    result.check_returncode()
    if not (OWN/'material.json').exists():
        private=command_output(['awg','genkey'])
        public=subprocess.check_output(['awg','pubkey'],input=private+'\n',text=True).strip()
        value={'private_key':private,'public_key':public}
        if p['role']=='exit': value['shared']={'psk':command_output(['awg','genpsk']),'header_key':command_output(['awg','genkey']),'headers':secrets.SystemRandom().sample(range(100000000,2000000000),4)}
        atomic(OWN/'material.json',json.dumps(value))
    return True


def config_text(p,material,peer,shared):
    role=p['role'];address=p['entry_address'] if role=='entry' else p['exit_address']
    h=shared['headers']
    text=f'''[Interface]\nAddress = {address}\nMTU = 1280\nTable = off\nPrivateKey = {material['private_key']}\nJc = 5\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = {h[0]}\nH2 = {h[1]}\nH3 = {h[2]}\nH4 = {h[3]}\nI1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>\nHeaderProtectionKey = {shared['header_key']}\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\nRandomTrailers = on\nDisableCookies = on\n'''
    if role=='exit': text+=f"ListenPort = {p['tunnel_port']}\nPostUp = /usr/local/sbin/twohop-vpn-exit-firewall apply\n"
    else: text+='PostUp = /usr/local/sbin/twohop-vpn-entry-routing tunnel-up\nPostDown = /usr/local/sbin/twohop-vpn-entry-routing tunnel-down\n'
    text+=f"\n[Peer]\nPublicKey = {peer}\nPresharedKey = {shared['psk']}\n"
    if role=='entry': text+=f"AllowedIPs = 0.0.0.0/0\nEndpoint = {p['exit_host']}:{p['tunnel_port']}\nPersistentKeepalive = 25\n"
    else: text+=f"AllowedIPs = {ipaddress.ip_interface(p['entry_address']).ip}/32, {p['client_pool']}, {p['test_ip']}/32\n"
    return text


def check_partial_ike():
    checkpoint=OWN/'ike-files.sha256'
    if checkpoint.exists():
        run(['sha256sum','--check','--status',str(checkpoint)])
    elif Path('/etc/ipsec.conf').exists():
        # apt may create its commented sample before the owned installer renders a connection.
        active=[line.strip() for line in Path('/etc/ipsec.conf').read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if any(line.startswith(('conn ','include ')) for line in active):
            raise ValueError('Unrecognized IKE configuration appeared during installation; refusing replacement')


def configure(p,req,job,log):
    m=require_owner(p)
    if m['configured']:
        if hashlib.sha256(Path('/etc/amnezia/amneziawg/awg-exit.conf').read_bytes()).hexdigest()!=m['awg_hash']:raise ValueError('Owned tunnel configuration changed')
        return
    material=json.loads((OWN/'material.json').read_text())
    shared=validate_shared(req.get('shared')) if p['role']=='entry' else material['shared']
    cfg=job/'awg.conf';atomic(cfg,config_text(p,material,key(req.get('peer_key')),shared))
    env=dict(os.environ,CLIENT_POOL=p['client_pool'],TEST_SOURCE_IP=p['test_ip'],TUNNEL_EXIT_IP=str(ipaddress.ip_interface(p['exit_address']).ip),TUNNEL_PORT=str(p['tunnel_port']),ROUTE_TABLE=str(p['route_table']),DEBIAN_FRONTEND='noninteractive',MANAGE_UNBOUND='NO')
    script='stage-ingress.sh' if p['role']=='entry' else 'apply-egress.sh'
    run(['bash','scripts/'+script,str(cfg)],cwd=RELEASE/'twohop',env=env,stdout=log,stderr=log)
    # Both the parser and the loaded module must retain version-3.1 features.
    actual=command_output(['awg','showconf','awg-exit'])
    fields={line.split('=',1)[0].strip().lower() for line in actual.splitlines() if '=' in line}
    if not {'headerprotectionkey','contentpaddingaddition','s4'}<=fields: raise ValueError('Loaded AWG module does not retain the required 3.1 parameters')
    if p['role']=='exit':
        run(['bash',str(RELEASE/'server/install-pair-dns.sh')],env=env,stdout=log,stderr=log)
        install_helper()
        drop=Path('/etc/systemd/system/awg-quick@awg-exit.service.d');drop.mkdir(exist_ok=True)
        atomic(drop/'rookstride-pair.conf','[Unit]\nWants=unbound.service adguardhome.service twohop-vpn-exit-firewall.service\n')
        run(['systemctl','daemon-reload'])
    else:
        initial=json.loads((OWN/'initial-user.json').read_text())
        if not (OWN/'ike-installed').exists():
            check_partial_ike()
            pw=job/'vpn-password';atomic(pw,initial['password']+'\n')
            env.update(SERVER_ID=p['server'],VPN_USER=initial['login'],VPN_PASSWORD_FILE=str(pw),DNS_SERVERS=str(ipaddress.ip_interface(p['exit_address']).ip),ALT_IKE_PORT=str(p['vpn_port']) if p['vpn_port'] not in (500,4500) else '',ALLOW_REPLACE='YES',IKE_OWNER_HASH_FILE=str(OWN/'ike-files.sha256'))
            run(['bash','scripts/install-strongswan-ikev2.sh'],cwd=RELEASE/'twohop',env=env,stdout=log,stderr=log)
            atomic(OWN/'ike-installed','owned\n');pw.unlink(missing_ok=True)
        install_helper(entry=True,history=initial['statistics'])
        (OWN/'initial-user.json').unlink(missing_ok=True)
    cfg.unlink(missing_ok=True)
    m['configured']=True;m['awg_hash']=hashlib.sha256(Path('/etc/amnezia/amneziawg/awg-exit.conf').read_bytes()).hexdigest();write_manifest(m)


def execute(jobid):
    job=STATE/ident(jobid);s=json.loads((job/'status.json').read_text())
    if s['state']=='complete': return
    req=json.loads((job/'request.json').read_text());p=plan(req);m=require_owner(p)
    if s['state']=='awaiting-reboot' and s.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip(): return
    action=req['action'];job_state(job,state='running',phase=action.capitalize()+' '+p['role'])
    try:
        with (job/'private-install.log').open('a') as log:
            if action=='bootstrap' and not bootstrap(p,job,log): return
            if action=='configure': configure(p,req,job,log)
            if action in ('verify','activate'):
                if hashlib.sha256(Path('/etc/amnezia/amneziawg/awg-exit.conf').read_bytes()).hexdigest()!=m['awg_hash']:raise ValueError('Owned tunnel configuration changed')
                expected=ipaddress.ip_address(req.get('expected_exit_ip',''))
                if expected.version!=4: raise ValueError('Expected an IPv4 exit address')
                # Activation always repeats staging: a persisted verified flag is not sufficient.
                run(['bash','scripts/verify-staged-egress.sh'],cwd=RELEASE/'twohop',env=dict(os.environ,EXPECTED_EXIT_IP=str(expected),TEST_SOURCE_IP=p['test_ip']),stdout=log,stderr=log,timeout=240)
                m=require_owner(p);m['verified']=True;write_manifest(m)
                if action=='activate':
                    run(['bash','scripts/activate-ingress.sh','apply'],cwd=RELEASE/'twohop',stdout=log,stderr=log)
                    m['activated']=True;write_manifest(m)
        job_state(job,state='complete',phase=action.capitalize()+' complete')
        (job/'request.json').unlink(missing_ok=True)
        run(['systemctl','disable','rookstride-pair-job-'+jobid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except Exception as exc:
        if p['role']=='entry' and Path('/usr/local/sbin/twohop-vpn-entry-routing').exists():
            subprocess.run(['/usr/local/sbin/twohop-vpn-entry-routing','quiesce'],capture_output=True)
        job_state(job,state='failed',phase='Step stopped; forwarding stays closed. Review and resume.',error=type(exc).__name__,detail=str(exc) if isinstance(exc,ValueError) else 'Server command failed; the private job log stays on this node')
        raise


def status(jobid):
    job=STATE/ident(jobid);s=json.loads((job/'status.json').read_text())
    if s['state'] in ('starting','running') and time.time()-s['updated']>20:
        try:
            active=command_output(['systemctl','show','-p','ActiveState','--value','rookstride-pair-job-'+jobid]) in ('active','activating','reloading')
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
            # Package installation may briefly reload/reexecute systemd. An unreadable
            # state is not proof that a detached job stopped; keep polling safely.
            return dict(s,status_unavailable=True)
        if not active: job_state(job,state='paused',phase='Interrupted job; resume the recorded step');s=json.loads((job/'status.json').read_text())
    return s


def dispatch(req):
    action=req.get('command')
    if action=='start': return start(req)
    if action=='status': return status(req.get('job'))
    m=load_manifest()
    if not m or ident(req.get('pair'))!=m['plan']['pair']: raise ValueError('Unknown pair owner')
    if action=='material':
        v=json.loads((OWN/'material.json').read_text());return {k:v[k] for k in ('public_key','shared') if k in v}
    if action=='overview':
        return {'role':m['plan']['role'],'configured':m['configured'],'activated':Path('/etc/twohop-vpn/activation').read_text().strip()=='active' if Path('/etc/twohop-vpn/activation').exists() else False,'jobs':{k:status(v) for k,v in m['jobs'].items()},'exit_ip':command_output(['curl','-4','--connect-timeout','10','--max-time','20','-fsS','https://api.ipify.org']) if m['plan']['role']=='exit' and m['configured'] else ''}
    if action=='pause' and m['plan']['role']=='entry':
        if any(status(j)['state'] in ('starting','running') for j in m['jobs'].values()):raise ValueError('Wait for the installation step before pausing')
        run(['/usr/local/sbin/twohop-vpn-entry-routing','quiesce']);return {'paused':True}
    if action=='reboot':
        waiting=[status(j) for j in m['jobs'].values() if status(j)['state']=='awaiting-reboot']
        if not waiting: raise ValueError('No owned job is awaiting a reboot')
        run(['systemd-run','--on-active=3s','/usr/bin/systemctl','reboot'],capture_output=True);return {'rebooting':True}
    raise ValueError('Unsupported pair command')


def main():
    os.umask(0o077)
    if os.geteuid()!=0: raise SystemExit('Root or passwordless sudo is required')
    if len(sys.argv)>1 and sys.argv[1]=='run':
        execute(ident(sys.argv[2]));return
    try:
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536: raise ValueError('Request too large')
        req=json.loads(raw)
        LOCK.parent.mkdir(exist_ok=True)
        with LOCK.open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX);result=dispatch(req)
        print(json.dumps({'ok':True,'result':result}))
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__}));raise SystemExit(1)


if __name__=='__main__':main()
