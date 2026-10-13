#!/usr/bin/env python3
"""Explicit removal of a recognized gateway; never a general operating-system wipe."""
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

MARKER=Path('/etc/single-vps-vpn/network.env')
CONFIG=Path('/etc/ipsec.conf')
STATE=Path('/var/lib/rookstride')
PATHS=tuple(Path(p) for p in (
 '/etc/ipsec.conf','/etc/ipsec.secrets','/etc/single-vps-vpn','/root/single-vps-vpn',
 '/etc/ipsec.d/cacerts/single-vps-ca.pem','/etc/ipsec.d/certs/single-vps-server-cert.pem',
 '/etc/ipsec.d/private/single-vps-server-key.pem','/etc/unbound/unbound.conf.d/single-vps-vpn.conf',
 '/etc/sysctl.d/90-single-vps-vpn.conf','/etc/systemd/system/single-vps-vpn-dns-address.service',
 '/etc/systemd/system/single-vps-vpn-firewall.service','/etc/systemd/system/adguardhome.service',
 '/etc/systemd/system/rookstride-stats.service','/usr/local/sbin/single-vps-vpn-firewall',
 '/usr/local/sbin/rookstride-admin','/var/lib/AdGuardHome','/opt/AdGuardHome',
 '/opt/rookstride','/var/lib/rookstride','/run/charon.vici'))
SERVICES=('rookstride-stats','strongswan-starter','adguardhome','unbound',
          'single-vps-vpn-firewall','single-vps-vpn-dns-address')
CHAINS=(('iptables','filter','INPUT','SINGLEVPN_INPUT'),
        ('iptables','filter','FORWARD','SINGLEVPN_FWD'),
        ('iptables','nat','POSTROUTING','SINGLEVPN_NAT'),
        ('ip6tables','filter','FORWARD','SINGLEVPN_V6_SINK'))

def execute(args,check=True):
    p=subprocess.run(args,capture_output=True,timeout=30)
    if check and p.returncode: raise RuntimeError('Could not complete gateway removal; inspect the server before retrying')
    return p.returncode

def inspect():
    if not MARKER.is_file() or MARKER.is_symlink():
        raise ValueError('Only a recognized single VPS gateway can be reset. Use the hosting provider to rebuild an arbitrary VPS.')
    config=CONFIG
    if not config.is_file() or config.is_symlink(): raise ValueError('Gateway configuration cannot be safely identified')
    if re.findall(r'^\s*conn\s+(\S+)',config.read_text(),re.M)!=['ikev2-vpn']:
        raise ValueError('Additional VPN configuration detected; review it manually before removing this gateway')
    if any(p.is_symlink() for p in PATHS): raise ValueError('Unexpected symbolic link in managed paths; manual review required')
    # Stable configuration identity; active counters/logs may change during review.
    digest=hashlib.sha256(MARKER.read_bytes()+config.read_bytes()).hexdigest()
    return {'files':[str(p) for p in PATHS if p.exists()], 'services':list(SERVICES),
            'configuration':digest,'scope':'VPN accounts, certificates, DNS filtering data, managed firewall rules and usage history. Ubuntu and SSH remain installed.'}

def plan():
    value=inspect();STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    token=secrets.token_hex(32)
    record={'token':token,'expires':time.time()+300,'plan':value}
    temporary=STATE/'reset-plan.tmp'
    temporary.write_text(json.dumps(record));temporary.chmod(0o600);temporary.replace(STATE/'reset-plan.json')
    return dict(value,token=token,expires=record['expires'])

def apply(req):
    if req.get('confirmation')!='DELETE VPN': raise ValueError('Type DELETE VPN to confirm removal')
    record=json.loads((STATE/'reset-plan.json').read_text())
    if not isinstance(req.get('token'),str) or not re.fullmatch(r'[a-f0-9]{64}',req['token']) or not secrets.compare_digest(req['token'],record['token']) or time.time()>record['expires']:
        raise ValueError('The reset review expired or does not match. Review a new plan.')
    current=inspect()
    if current['configuration']!=record['plan']['configuration'] or current['files']!=record['plan']['files']:
        raise ValueError('Gateway configuration changed; review a new reset plan')
    # Refuse while a detached installation is running.
    for p in (STATE/'jobs').glob('*/status.json'):
        if json.loads(p.read_text()).get('state') in ('starting','running'):
            raise ValueError('An installation is recorded as running; check it before resetting')
    for service in SERVICES:
        execute(['systemctl','disable','--now',service],check=False)
        if execute(['systemctl','is-active','--quiet',service],check=False)==0:
            raise RuntimeError('A managed service could not be stopped; no files were removed')
    # Remove only the installation's own jump rules and chains; never flush base chains.
    for tool,table,parent,chain in CHAINS:
        if execute([tool,'-t',table,'-L',chain],check=False)!=0: continue
        for _ in range(100):
            if execute([tool,'-t',table,'-C',parent,'-j',chain],check=False)!=0: break
            execute([tool,'-t',table,'-D',parent,'-j',chain])
        execute([tool,'-t',table,'-F',chain]);execute([tool,'-t',table,'-X',chain])
    # This service's ExecStop removes the private loopback DNS address.
    removed=[]
    for p in PATHS:
        if p.is_symlink(): raise RuntimeError('A managed path changed; removal stopped')
        if p.is_dir(): shutil.rmtree(p)
        elif p.exists(): p.unlink()
        removed.append(str(p))
    execute(['systemctl','daemon-reload'])
    return {'removed':removed,'reset':True,'message':'Gateway data removed. Ubuntu, SSH and installed package binaries remain. You can install a fresh gateway.'}

def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0: raise PermissionError('Root or passwordless sudo access is required')
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536: raise ValueError('Request is too large')
        req=json.loads(raw)
        if not isinstance(req,dict): raise ValueError('Expected an object')
        if req.get('mode') in ('pair-plan','pair-apply'):
            import pair_reset
            with Path('/run/rookstride-pair.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                result=pair_reset.plan(req) if req['mode']=='pair-plan' else pair_reset.apply(req)
            print(json.dumps({'ok':True,'result':result}));return
        # Separate lock remains outside the directory being removed.
        with Path('/run/rookstride-management.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if req.get('mode')=='plan': result=plan()
            elif req.get('mode')=='apply': result=apply(req)
            else: raise ValueError('Unsupported reset action')
        print(json.dumps({'ok':True,'result':result}))
    except (ValueError,PermissionError,RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,(ValueError,PermissionError,RuntimeError)) else type(exc).__name__}))
        raise SystemExit(1)

if __name__=='__main__': main()
