"""Per-operation account impact and bounded root-local OpenVPN management.

A live add is not evidence of live revocation. Capabilities describe expected
impact; mutation receipts describe what actually happened. No public management
listener or generic command facility is exposed.
"""
import os,socket,stat,time,json
from pathlib import Path
import access,model

LIMIT=65536

def impact(state):
    protocol=state['protocol'];password=access.reusable(state)
    result={'schema':1,'metadata':'live','add':'restart','revoke':'restart',
            'password':'restart' if password else 'not-applicable',
            'restart_fallback':True}
    if protocol=='awg':result.update(add='live',revoke='live',restart_fallback=False)
    elif protocol=='openvpn':
        result.update(add='live',revoke='targeted-or-restart',password='targeted-or-restart' if password else 'not-applicable')
    elif protocol in ('xray','xhttp'):result['add']='live-or-restart'
    return result

def result(restarted=False,kind=None):
    return {'listener_restarted':bool(restarted),'update':kind or ('restart' if restarted else 'live')}

def merge(*values):
    usable=[value for value in values if isinstance(value,dict) and 'listener_restarted' in value]
    return result(any(value['listener_restarted'] for value in usable)) if usable else {}

def _line(control,pending,deadline,total):
    while b'\n' not in pending:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise OSError('OpenVPN management response timed out')
        control.settimeout(remaining)
        data=control.recv(min(4096,LIMIT-total))
        if not data:raise OSError('OpenVPN management connection ended')
        pending+=data;total+=len(data)
        if total>=LIMIT:raise OSError('OpenVPN management response exceeded the limit')
    line,pending=pending.split(b'\n',1)
    return line.rstrip(b'\r'),pending,total

def terminate(state,login,runtime):
    """End only this common name; reject unsafe/missing management endpoints.

    Caller decides whether to restart on failure. New authentication must already
    be disabled before calling this, so an inconclusive command cannot reinstate it.
    """
    (access.login if access.reusable(state) else model.label)(login)
    folder=runtime.directory('openvpn')/'runtime';path=folder/'management.sock';config=folder/'server.conf'
    if folder.is_symlink() or path.is_symlink() or config.is_symlink():raise OSError('OpenVPN management ownership changed')
    socket_info=path.stat()
    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=os.geteuid():raise OSError('Unexpected OpenVPN management endpoint')
    if 'management /vpn/management.sock unix' not in config.read_text().splitlines():raise OSError('This OpenVPN needs a reviewed management upgrade')
    deadline=time.monotonic()+3;total=0;pending=b''
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as control:
        control.settimeout(3);control.connect(str(path))
        line,pending,total=_line(control,pending,deadline,total)
        if not line.startswith(b'>INFO:'):raise OSError('Unexpected OpenVPN management greeting')
        control.sendall(('kill '+login+'\n').encode('ascii'))
        while True:
            line,pending,total=_line(control,pending,deadline,total)
            if line.startswith(b'>'):continue
            if line.startswith(b'SUCCESS:'):return result()
            if line.startswith(b'ERROR:') and b'common name' in line.lower() and b'not found' in line.lower():return result()
            raise OSError('OpenVPN did not confirm targeted session termination')


def ensure_no_runtime_update(root=Path('/var/lib/rookstride-engine-updates'),destructive=False):
    """Do not invalidate a pending rollback with another management mutation."""
    if root.is_symlink():raise ValueError('Unexpected runtime operation directory')
    for path in root.glob('*/journal.json'):
        if path.is_symlink() or path.parent.is_symlink() or path.stat().st_uid!=os.geteuid() or path.stat().st_size>2*1024*1024:raise ValueError('Runtime operation ownership cannot be verified')
        value=json.loads(path.read_text())
        if value.get('state') in ('applying','apply-failed','verified','rolling-back','rollback-failed') or destructive and value.get('state') not in ('accepted','rolled-back','cancelled','abandoned'):
            raise ValueError('Finish or roll back the reviewed runtime update before changing VPN users or settings')

def remove_retained_containers(protocol,command,root=Path('/var/lib/rookstride-engine-updates')):
    """Managed protocol removal also removes its stopped engine rollback container."""
    ensure_no_runtime_update(root,destructive=True)
    if protocol not in ('awg','openvpn'):return
    import re,subprocess
    for path in root.glob('*/journal.json'):
        value=json.loads(path.read_text());ident=value.get('operation','')
        if value.get('group')!=protocol:continue
        if not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('Invalid retained runtime operation')
        expected=next((s.get('original_id') for s in value.get('snapshot',{}).get('services',[]) if s.get('kind')=='container' and s.get('name')=='rookstride-single-'+protocol),None)
        name='rookstride-prior-'+ident+'-'+protocol
        probe=subprocess.run(['docker','container','inspect',name],capture_output=True,text=True,timeout=20)
        if probe.returncode:
            if 'no such' in probe.stderr.lower():continue
            raise ValueError('Could not inspect retained runtime container')
        containers=json.loads(probe.stdout)
        if len(containers)!=1 or not expected or containers[0].get('Id')!=expected or containers[0].get('State',{}).get('Running'):raise ValueError('Retained runtime container changed; inspect it before removal')
        command(['docker','rm',name])
