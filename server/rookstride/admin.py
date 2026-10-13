"""Root-only JSON commands over SSH stdin. No shell interpolation of inputs."""
import base64
import contextlib
import fcntl
import json
import ipaddress
import os
import re
import shlex
import ssl
import subprocess
import tempfile
import time
import urllib.request
import urllib.parse
import uuid
from pathlib import Path
from . import VERSION
from .vici import Vici, sessions, connections
from .usage import Ledger

ROOT=Path('/opt/rookstride')
STATE=Path('/var/lib/rookstride')
SECRETS=Path('/etc/ipsec.secrets')
USERNAME=re.compile(r'[A-Za-z0-9_.@-]{1,64}')


def username(value):
    if not isinstance(value,str) or not USERNAME.fullmatch(value):
        raise ValueError('Use 1–64 letters, numbers, dots, underscores, @ or hyphens for the login')
    return value


def label(value):
    if not isinstance(value,str) or not 1 <= len(value) <= 80 or any(ord(c)<32 for c in value):
        raise ValueError('Use a name of 1–80 printable characters')
    return value


def atomic(path,data):
    path=Path(path); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.rookstride-')
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def catalog():
    p=STATE/'users.json'
    return json.loads(p.read_text()) if p.exists() else {}


def user_inventory():
    names=[]
    if SECRETS.exists():
        for line in SECRETS.read_text().splitlines():
            try:
                parts=shlex.split(line,comments=True)
            except ValueError:
                continue
            if len(parts)>=4 and parts[1:3]==[':','EAP']:
                names.append(parts[0])
    info=catalog()
    return [{'login':n,'person':info.get(n,{}).get('person',n),
             'device':info.get(n,{}).get('device','Shared login'),
             'kind':info.get(n,{}).get('kind','shared')} for n in names]


def run(command,timeout=20):
    p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError('Server command failed: '+Path(command[0]).name)
    return p.stdout


def health():
    service={s:subprocess.run(['systemctl','is-active','--quiet',s]).returncode==0
             for s in ('strongswan-starter','adguardhome','unbound','rookstride-stats')}
    result={'version':VERSION,'services':service,'monitoring_available':Path('/var/run/charon.vici').exists(),
            'users':user_inventory(),'statistics_enabled':service['rookstride-stats']}
    try:
        result['connections']=connections(sessions()) if result['monitoring_available'] else []
    except (OSError,ValueError,RuntimeError):
        result['connections']=[]; result['monitoring_available']=False
        result['monitoring_error']='The local VPN monitoring interface is unavailable'
    if (STATE/'usage.db').exists():
        ledger=Ledger(STATE/'usage.db')
        try:
            result['monthly']=ledger.totals(); result['accounting']=ledger.metadata(); result['history']=ledger.history()
        finally: ledger.close()
    else:
        result['monthly']=[]; result['accounting']={}; result['history']=[]
    return result


def update_user(req,remove=False):
    login=username(req.get('login'))
    if not SECRETS.exists(): raise ValueError('No compatible VPN configuration found')
    lines=SECRETS.read_text().splitlines()
    def is_user(line):
        try:
            p=shlex.split(line,comments=True)
            return len(p)>=3 and p[0]==login and p[1:3]==[':','EAP']
        except ValueError: return False
    exists=any(is_user(l) for l in lines)
    if remove and not exists: raise ValueError('User does not exist')
    if not remove:
        pw=req.get('password','')
        if not isinstance(pw,str) or not 16<=len(pw)<=512 or '\n' in pw or '\r' in pw or '\0' in pw:
            raise ValueError('Use a single-line password of 16–512 characters')
        if exists and not req.get('replace'): raise ValueError('Login already exists')
    info=catalog()
    if remove: info.pop(login,None)
    else:
        person=label(req.get('person',login)); device=label(req.get('device','Shared login'))
        if req.get('kind','shared') not in ('shared','device'): raise ValueError('Invalid login kind')
        info[login]={'person':person,'device':device,'kind':req.get('kind','shared')}
    new=[l for l in lines if not is_user(l)]
    if not remove:
        quoted=pw.replace('\\','\\\\').replace('"','\\"')
        new.append(f'{login} : EAP "{quoted}"')
    original=SECRETS.read_text()
    atomic(SECRETS,'\n'.join(new)+'\n')
    try: run(['ipsec','rereadsecrets'])
    except Exception:
        atomic(SECRETS,original); run(['ipsec','rereadsecrets']); raise
    atomic(STATE/'users.json',json.dumps(info))
    disconnected=0
    failures=0
    if remove:
        # Revocation prevents new logins and closes every current session for this login.
        try:
            for c in connections(sessions()):
                if c['user']==login:
                    try:
                        with Vici() as v: v.request('terminate',{'ike-id':c['id'],'timeout':'5000'})
                        disconnected+=1
                    except (OSError,RuntimeError): failures+=1
        except (OSError,RuntimeError): failures+=1
    return {'login':login,'removed':remove,'disconnected':disconnected,
            'warning':'Login revoked; check Sessions because an active connection could not be closed' if failures else ''}


def profile(req):
    login=username(req.get('login'))
    if login not in [u['login'] for u in user_inventory()]: raise ValueError('Unknown login')
    config=Path('/etc/ipsec.conf').read_text()
    match=re.search(r'^\s*leftid\s*=\s*([^\s#]+)',config,re.M)
    if not match: raise ValueError('Missing server identity')
    identity=match.group(1).lstrip('@')
    certmatch=re.search(r'^\s*leftcert\s*=\s*([^\s#]+)',config,re.M)
    if not certmatch or '/' in certmatch.group(1): raise ValueError('Unsupported server certificate path')
    cert=ssl.PEM_cert_to_DER_cert((Path('/etc/ipsec.d/certs')/certmatch.group(1)).read_text())
    mtu=req.get('mtu',1280)
    if not isinstance(mtu,int) or not 1280<=mtu<=1500: raise ValueError('MTU must be 1280–1500')
    remote={'addr':identity,'id':identity,'cert':base64.b64encode(cert).decode(),'certreq':False}
    pair=Path('/etc/rookstride-pair/manifest.json')
    if pair.exists():
        pair_plan=json.loads(pair.read_text())['plan']
        if pair_plan['role']!='entry':raise ValueError('Export profiles from the entry node')
        if pair_plan.get('vpn_port',500)!=500:remote['port']=pair_plan['vpn_port']
    return {'uuid':str(uuid.uuid4()),'name':label(req.get('name','Rookstride VPN')),'type':'ikev2-eap',
            'remote':remote,
            'local':{'eap_id':login},'mtu':mtu,
            'split-tunneling':{'block-ipv4':True,'block-ipv6':True}}


FILTERS={
 'standard':('AdGuard DNS filter','https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt'),
 'strong':('HaGeZi Multi PRO','https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt'),
 'strict':('HaGeZi Multi PRO++','https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt')}


def adguard(req):
    # Only the private gateway dashboard is accessed, with credentials never returned to the app.
    login=Path('/root/rookstride-pair/adguard-login.txt') if Path('/etc/rookstride-pair/manifest.json').exists() else Path('/root/single-vps-vpn/adguard-login.txt')
    if not login.exists(): raise ValueError('AdGuard login file is missing; this gateway needs manual enrollment')
    creds=dict(l.split(': ',1) for l in login.read_text().splitlines() if ': ' in l)
    address=creds['Dashboard']
    parsed=urllib.parse.urlparse(address)
    try: private=ipaddress.ip_address(parsed.hostname).is_private
    except (ValueError, TypeError): private=False
    if not private or parsed.scheme!='http' or parsed.port!=3000 or parsed.username or parsed.path not in ('','/'):
        raise ValueError('Unexpected AdGuard dashboard address')
    auth=base64.b64encode((creds['Username']+':'+creds['Password']).encode()).decode()
    def call(endpoint,data=None):
        body=json.dumps(data).encode() if data is not None else None
        r=urllib.request.Request(address+'/control/'+endpoint,data=body,
            headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        with urllib.request.urlopen(r,timeout=60 if endpoint=='filtering/add_url' else 15) as response:
            value=response.read()
            return json.loads(value) if value.startswith(b'{') else {}
    if req.get('level'):
        level=req['level']
        if level not in FILTERS: raise ValueError('Unknown filter strength')
        status=call('filtering/status')
        if not any(f['url']==FILTERS[level][1] for f in status.get('filters',[])):
            name,url=FILTERS[level]; call('filtering/add_url',{'name':name,'url':url,'whitelist':False})
        name,url=FILTERS[level]
        call('filtering/set_url',{'url':url,'data':{'url':url,'name':name,'enabled':True}})
        # Keep the previous preset enabled until the new list is actually loaded.
        for attempt in range(10):
            loaded=call('filtering/status')
            if any(f['url']==url and f.get('enabled') and f.get('rules_count',0)>0 for f in loaded.get('filters',[])):break
            time.sleep(1)
        else:raise ValueError('The selected filter has no loaded rules yet. Previous filters remain enabled; retry after checking its download.')
        for f in status.get('filters',[]):
            if f['url'] in [v[1] for v in FILTERS.values()] and f['url']!=url:
                call('filtering/set_url',{'url':f['url'],'data':{'url':f['url'],'name':f['name'],'enabled':False}})
    data=call('stats'); status=call('filtering/status')
    return {'queries':data.get('num_dns_queries',0),'blocked':data.get('num_blocked_filtering',0),
            'filters':[{'name':f['name'],'enabled':f['enabled'],'rules':f.get('rules_count',0)} for f in status.get('filters',[])]}


def dispatch(req):
    action=req.get('action')
    if action=='status': return health()
    if action=='add-user': return update_user(req)
    if action=='remove-user': return update_user(req,remove=True)
    if action=='profile': return profile(req)
    if action=='adguard': return adguard(req)
    if action=='disconnect':
        ident=req.get('session')
        if not isinstance(ident,str) or not re.fullmatch(r'[0-9]{1,12}',ident): raise ValueError('Invalid session')
        with Vici() as v: return v.request('terminate',{'ike-id':ident,'timeout':'5000'})
    if action=='stats-toggle':
        if not isinstance(req.get('enabled'),bool): raise ValueError('Expected a boolean')
        # A deliberate pause must not charge traffic accumulated while collection was off.
        if not req['enabled']:
            run(['systemctl','disable','--now','rookstride-stats'])
            ledger=Ledger(STATE/'usage.db')
            try:
                with ledger.db:
                    ledger.db.execute("INSERT OR REPLACE INTO meta VALUES('rebase','yes')")
            finally: ledger.close()
            return {'enabled':False}
        run(['systemctl','enable' if req['enabled'] else 'disable','--now','rookstride-stats'])
        return {'enabled':req['enabled']}
    raise ValueError('Unsupported management action')


def main():
    import sys
    os.umask(0o077)
    try:
        if os.geteuid()!=0: raise PermissionError('Administrator access is required')
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536: raise ValueError('Request is too large')
        req=json.loads(raw)
        if not isinstance(req,dict): raise ValueError('Expected a JSON object')
        STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
        with Path('/run/rookstride-management.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            result=dispatch(req)
        print(json.dumps({'ok':True,'result':result}))
    except (ValueError,PermissionError,RuntimeError,OSError,subprocess.TimeoutExpired) as e:
        # Errors contain our messages, never a request dump or password.
        print(json.dumps({'ok':False,'error':str(e) if isinstance(e,(ValueError,PermissionError,RuntimeError)) else type(e).__name__}))
        raise SystemExit(1)


if __name__=='__main__': main()
