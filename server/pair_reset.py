#!/usr/bin/env python3
"""Reviewed removal of an owned pair node. Keeps Ubuntu, SSH and unrelated data."""
import hashlib
import json
import pwd
import re
import secrets
import shutil
import time
from pathlib import Path

import pair

REVIEWS=Path('/var/lib/rookstride-reset')
ADGUARD_STATE=Path('/var/lib/AdGuardHome')
COMMON=tuple(Path(p) for p in (
 '/etc/amnezia','/etc/twohop-vpn','/etc/sysctl.d/90-twohop-vpn-entry.conf',
 '/etc/sysctl.d/90-twohop-vpn-exit.conf','/etc/systemd/system/awg-quick@awg-exit.service.d',
 '/usr/local/sbin/twohop-vpn-entry-routing','/usr/local/sbin/twohop-vpn-exit-firewall',
 '/etc/systemd/system/twohop-vpn-entry-routing.service','/etc/systemd/system/twohop-vpn-exit-firewall.service',
 '/usr/local/sbin/rookstride-admin','/opt/rookstride','/var/lib/rookstride'))
ENTRY=tuple(Path(p) for p in (
 '/etc/ipsec.conf','/etc/ipsec.secrets','/etc/ipsec.d/cacerts/twohop-ca-cert.pem',
 '/etc/ipsec.d/certs/twohop-server-cert.pem','/etc/ipsec.d/private/twohop-server-key.pem',
 '/root/twohop-vpn-ca','/root/twohop-vpn-client','/etc/sysctl.d/90-twohop-vpn-ikev2.conf',
 '/etc/systemd/system/twohop-vpn-ikev2-firewall.service','/usr/local/sbin/twohop-vpn-ikev2-firewall',
 '/etc/systemd/system/strongswan-starter.service.d/rookstride-pair.conf',
 '/etc/systemd/system/rookstride-stats.service','/run/charon.vici'))
EXIT=tuple(Path(p) for p in (
 '/etc/unbound/unbound.conf.d/twohop-vpn.conf','/etc/systemd/system/unbound.service.d/twohop-vpn.conf',
 '/etc/systemd/system/adguardhome.service','/var/lib/AdGuardHome','/opt/AdGuardHome','/root/rookstride-pair'))
CHAINS=(('iptables','filter','FORWARD','TWOHOP_ENTRY'),('iptables','filter','FORWARD','TWOHOP_GUARD'),
 ('iptables','mangle','FORWARD','TWOHOP_MSS'),('iptables','filter','INPUT','TWOHOP_IKEV2_INPUT'),
 ('iptables','filter','FORWARD','TWOHOP_IKEV2_FWD'),('iptables','nat','POSTROUTING','TWOHOP_IKEV2_NAT'),
 ('iptables','nat','PREROUTING','TWOHOP_IKEV2_ALT'),('ip6tables','filter','FORWARD','TWOHOP_IKEV2_V6_SINK'),
 ('iptables','filter','INPUT','TWOHOP_EXIT_INPUT'),('iptables','filter','FORWARD','TWOHOP_EXIT_FWD'),
 ('iptables','filter','DOCKER-USER','TWOHOP_EXIT_FWD'),('iptables','nat','PREROUTING','TWOHOP_DNS'),
 ('iptables','nat','POSTROUTING','TWOHOP_SNAT'))

def removal_path(path):
    p=Path(path)
    if p!=ADGUARD_STATE:return pair.protected(p)
    # AdGuard deliberately owns its state directory; every ancestor stays root-owned.
    pair.protected(p.parent)
    if p.is_symlink():raise ValueError('A managed path is a symbolic link')
    if p.exists():
        allowed={0,pwd.getpwnam('adguard').pw_uid}
        if p.stat().st_uid not in allowed:raise ValueError('Unexpected DNS state owner')
        if any(q.is_symlink() or q.stat().st_uid not in allowed for q in p.rglob('*')):
            raise ValueError('Unexpected DNS state path or owner')
    return p

def inspect(req):
    expected=pair.plan(req)
    m=pair.load_manifest()
    if not m:
        pair.fresh(expected)
        return {'role':expected['role'],'pair':expected['pair'],'already_fresh':True,'files':[],
                'services':[],'configuration':'fresh','scope':'Already fresh; nothing to delete.'}
    if m.get('version')!=1 or m.get('plan')!=expected:
        raise ValueError('Node ownership or role changed; reset the saved pair before swapping its roles')
    for ident in m['jobs'].values():
        pair.ident(ident)
        if (pair.STATE/ident/'status.json').exists() and pair.status(ident)['state'] in ('starting','running'):
            raise ValueError('An owned installation job is running; wait or resume before resetting')
    conf=Path('/etc/amnezia/amneziawg/awg-exit.conf')
    if m.get('awg_hash') and ((not conf.is_file() and not m.get('resetting')) or (conf.is_file() and hashlib.sha256(conf.read_bytes()).hexdigest()!=m['awg_hash'])):
        raise ValueError('Owned tunnel configuration changed; review it before resetting')
    directory=Path('/etc/amnezia')
    if directory.exists() and any(p.is_file() and p!=conf for p in directory.rglob('*')):
        raise ValueError('Additional Amnezia configuration found; no blanket directory removal is allowed')
    role=expected['role']
    if role=='entry' and Path('/etc/ipsec.conf').exists():
        names=re.findall(r'^\s*conn\s+(\S+)',Path('/etc/ipsec.conf').read_text(),re.M)
        if names not in ([],['ikev2-vpn']):raise ValueError('Additional IKE configuration found')
    paths=list(COMMON+(ENTRY if role=='entry' else EXIT))
    for ident in m['jobs'].values():paths.append(Path('/etc/systemd/system')/('rookstride-pair-job-'+ident+'.service'))
    # Ownership is removed last, so a partial removal can still be reviewed and continued.
    paths.extend([pair.RELEASE,pair.STATE,pair.OWN])
    for p in paths:
        removal_path(p)
        if p.is_dir() and any(q.is_symlink() for q in p.rglob('*')):raise ValueError('Unexpected managed symbolic link')
    services=['awg-quick@awg-exit','twohop-vpn-entry-routing','twohop-vpn-exit-firewall']
    services+=['strongswan-starter','twohop-vpn-ikev2-firewall','rookstride-stats'] if role=='entry' else ['adguardhome','unbound']
    services+=['rookstride-pair-job-'+ident for ident in m['jobs'].values()]
    frozen=hashlib.sha256(json.dumps(m,sort_keys=True).encode())
    for p in [Path('/etc/ipsec.conf'),conf]:
        if p.is_file():frozen.update(p.read_bytes())
    return {'role':role,'pair':expected['pair'],'already_fresh':False,
            'files':[str(p) for p in paths if p.exists()],'services':services,'configuration':frozen.hexdigest(),
            'scope':'This node’s owned VPN accounts, certificates, tunnel keys, DNS data, firewall rules and history. Ubuntu, SSH and unrelated files stay installed.'}

def review_path(req):return REVIEWS/(pair.ident(req['pair'])+'-'+pair.plan(req)['role']+'.json')

def plan(req):
    value=inspect(req);pair.protected(REVIEWS);REVIEWS.mkdir(mode=0o700,parents=True,exist_ok=True)
    record={'token':secrets.token_hex(32),'expires':time.time()+300,'plan':value}
    pair.atomic(review_path(req),json.dumps(record))
    return dict(value,token=record['token'],expires=record['expires'])

def apply(req):
    from reset import execute
    if req.get('confirmation')!='DELETE PAIR':raise ValueError('Type DELETE PAIR to confirm removal')
    record=json.loads(review_path(req).read_text());token=req.get('token')
    if not isinstance(token,str) or not re.fullmatch('[a-f0-9]{64}',token) or not secrets.compare_digest(token,record['token']) or time.time()>record['expires']:
        raise ValueError('Reset review expired or does not match')
    value=inspect(req)
    if value!=record['plan']:raise ValueError('Node configuration changed; review a new reset plan')
    if value['already_fresh']:return {'reset':True,'already_fresh':True,'role':value['role']}
    m=pair.load_manifest();p=m['plan']
    m['resetting']=True;pair.write_manifest(m)
    if p['role']=='entry' and Path('/usr/local/sbin/twohop-vpn-entry-routing').exists():
        execute(['/usr/local/sbin/twohop-vpn-entry-routing','quiesce'])
    # Stop IKE first; removing guards must never expose a running VPN client pool.
    ordered=sorted(value['services'],key=lambda s:0 if s=='strongswan-starter' else 1)
    for service in ordered:
        execute(['systemctl','disable','--now',service],check=False)
        if execute(['systemctl','is-active','--quiet',service],check=False)==0:
            raise RuntimeError('Could not stop an owned service; forwarding remains guarded')
    for tool,table,parent,chain in CHAINS:
        if execute([tool,'-t',table,'-L',chain],check=False)!=0:continue
        for _ in range(100):
            if execute([tool,'-t',table,'-C',parent,'-j',chain],check=False)!=0:break
            execute([tool,'-t',table,'-D',parent,'-j',chain])
    # FWD and DOCKER-USER may reference the same chain. Flush/delete only after all jumps are gone.
    for tool,table,chain in sorted({(t,tab,c) for t,tab,_,c in CHAINS}):
        if execute([tool,'-t',table,'-L',chain],check=False)==0:
            execute([tool,'-t',table,'-F',chain]);execute([tool,'-t',table,'-X',chain])
    # The exact rule is matched by priority, source and table, never a broad rule flush.
    for priority,source in [(100,p['client_pool']),(90,p['test_ip']+'/32')]:
        for _ in range(100):
            if execute(['ip','rule','del','priority',str(priority),'from',source,'lookup',str(p['route_table'])],check=False)!=0:break
    if p['role']=='entry':execute(['ip','route','flush','table',str(p['route_table'])],check=False)
    for name in value['files']:
        path=removal_path(name)
        if path.is_dir():shutil.rmtree(path)
        elif path.exists():path.unlink()
    execute(['systemctl','daemon-reload'])
    review_path(req).unlink(missing_ok=True)
    return {'reset':True,'role':p['role'],'message':'Owned pair data removed. Ubuntu, SSH and packages remain; either role can be installed next.'}
