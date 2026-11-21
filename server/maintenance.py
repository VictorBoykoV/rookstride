#!/usr/bin/env python3
"""Reviewed helper updates, with durable rollback. Never upgrades VPN engines.

The app supplies a verified source bundle; review binds its digest and the exact
installed deployment. Accounts, endpoint keys and protocol configuration are not
part of the helper tree and are never replaced by this operation.
"""
import contextlib, copy, fcntl, hashlib, ipaddress, json, os, shutil, sys, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair, lifecycle

ROOT=Path('/var/lib/rookstride-maintenance')
SOURCE=Path(__file__).resolve().parent.parent
LOCK=Path('/run/rookstride-management.lock')
TERMINAL=('accepted','rolled-back','cancelled')

def ensure_no_pending_update():
    """Runtime transactions must not invalidate an outstanding helper rollback."""
    pair.protected(ROOT)
    for path in ROOT.glob('*/journal.json'):
        if read(path).get('state') not in TERMINAL:
            raise ValueError('Finish or roll back the reviewed helper update before changing VPN runtimes')

def runtime_idle():
    import engine_updates,native_pair
    native_pair.runtime.user_updates.ensure_no_runtime_update(engine_updates.ROOT,destructive=True)

def read(path):
    if not path.exists() and not path.is_symlink():return None
    pair.protected(path)
    return json.loads(path.read_text())

def write(path,value):
    pair.protected(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    pair.atomic(path,json.dumps(value,sort_keys=True))
    fd=os.open(str(path.parent),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def record(op,state,phase):
    op.update(state=state,phase=phase,updated=time.time());write(ROOT/op['operation']/'journal.json',op)
    return public(op)

def public(op):
    return {k:op[k] for k in ('operation','state','phase','old_digest','new_digest','created','updated','preserves','interruption') if k in op}

def check_idle(m):
    if m.get('resetting'):raise ValueError('Finish the recorded reset before updating helpers')
    for job in m.get('jobs',{}).values():
        if pair.status(job)['state'] in ('starting','running','awaiting-reboot'):raise ValueError('Finish the recorded installation before updating helpers')
    if any(op['state'] not in TERMINAL for op in lifecycle.records()):raise ValueError('Finish or roll back the lifecycle operation before updating helpers')

def logical_revision():
    # Helper reanchoring changes only code anchors; a completed topology change
    # between review and apply must invalidate the old maintenance snapshot.
    result={}
    for name in ('inventory.json','active.json'):
        value=read(lifecycle.ROOT/name)
        result[name]=None if value is None else {key:item for key,item in value.items() if key not in ('anchor','helper_anchors')}
    return lifecycle.digest(result)

def current_installation(op):
    """Validate the live identity before any routing or directory mutation.

    A resumable rename can leave either reviewed helper digest (or a temporarily
    absent release directory), but never permits restoring an older deployment
    over a reset/replacement that happened after this review.
    """
    runtime_idle()
    current=pair.load_manifest();reviewed=op['manifest']
    if not current or current.get('version')!=reviewed.get('version') or current.get('plan')!=reviewed.get('plan') or current.get('configure_digest')!=reviewed.get('configure_digest'):
        raise ValueError('The deployment or peer identity changed; this helper operation cannot change the current installation')
    check_idle(current)
    if any(current.get(key)!=reviewed.get(key) for key in ('file_hashes','unit_hashes','configured')) or op.get('logical_revision')!=logical_revision():
        raise ValueError('The reviewed service or lifecycle revision changed; inspect before updating helpers')
    if op['state']=='prepared' and current.get('activated')!=reviewed.get('activated'):raise ValueError('The reviewed forwarding state changed; inspect before updating helpers')
    runtime=(lifecycle.ROOT/'runtime').exists();had_runtime=(ROOT/op['operation']/'previous-runtime').exists()
    if had_runtime!=op.get('runtime_present') or runtime!=had_runtime and not (had_runtime and op['state'] in ('applying','rolling-back') and (ROOT/op['operation']/'runtime-displaced').exists()):
        raise ValueError('The lifecycle runtime changed outside this recorded update')
    allowed=(op['old_digest'],) if op['state']=='prepared' else (op['old_digest'],op['new_digest'])
    if current.get('bundle') not in allowed:raise ValueError('The installed helper revision changed outside this operation')
    if pair.RELEASE.exists():
        pair.protected(pair.RELEASE)
        if pair.source_digest(pair.RELEASE) not in allowed:raise ValueError('Installed helper integrity changed during this operation')
    elif op['state'] not in ('applying','rolling-back'):
        raise ValueError('The installed helper is missing outside a recorded directory swap')
    # Owned service/configuration changes require a fresh review. Do not call
    # inspect() here: its logical anchor can legitimately be one rename ahead.
    import native_pair
    for path,expected in [(Path(path),value) for path,value in current.get('file_hashes',{}).items()]+[(native_pair.UNIT/(name+'.service'),value) for name,value in current.get('unit_hashes',{}).items()]:
        pair.protected(path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Owned VPN files changed; inspect before updating helpers')
    return current

def review():
    m=pair.load_manifest()
    if not m:return {'supported':False,'reason':'This reviewed adapter requires an existing native Double VPN','engine_updates':False}
    if m.get('version')!=2:return {'supported':False,'reason':'This older deployment must be migrated before a helper update','engine_updates':False}
    check_idle(m)
    if pair.source_digest(pair.RELEASE)!=m['bundle']:raise ValueError('Installed helper integrity changed; recover its verified copy first')
    info=lifecycle.inspect()
    if info.get('read_only'):raise ValueError('The installed services must pass ownership checks before updating helpers')
    old=m['bundle'];new=pair.source_digest(SOURCE)
    return {'supported':True,'deployment':m['plan']['pair'],'role':m['plan']['role'],'old_digest':old,'new_digest':new,'available':old!=new,'anchor':lifecycle.anchor(m),'preserves':['VPN accounts and passwords','client keys and certificates','installed protocols','server settings','saved phone profiles'],'interruption':'Entry forwarding closes while its helper is checked; the exit listener remains running','engine_updates':False}

def prepare(req):
    runtime_idle()
    operation=pair.ident(req.get('operation'));folder=ROOT/operation
    old=read(folder/'journal.json')
    if old:
        if old.get('request_digest')!=lifecycle.digest(req):raise ValueError('Recorded update review changed')
        return public(old)
    plan=review()
    if not plan.get('supported') or not plan.get('available'):raise ValueError('No reviewed helper update is available')
    if req.get('confirmation')!='UPDATE HELPERS AND KEEP VPN USERS':raise ValueError('Review the brief interruption before updating')
    if any(req.get(k)!=plan[k] for k in ('deployment','old_digest','new_digest','anchor')):raise ValueError('The installation changed; review the update again')
    for path in ROOT.glob('*/journal.json') if ROOT.exists() else []:
        if read(path)['state'] not in TERMINAL:raise ValueError('Resume or roll back the existing helper update')
    m=pair.load_manifest();op=dict(plan,operation=operation,request_digest=lifecycle.digest(req),created=time.time(),manifest=copy.deepcopy(m),was_active=bool(m.get('activated')),logical_revision=logical_revision(),runtime_present=(lifecycle.ROOT/'runtime').exists())
    pair.protected(folder);folder.mkdir(parents=True,mode=0o700)
    stage=folder/'new'
    if stage.exists():raise ValueError('Unexpected staging directory')
    stage.mkdir(mode=0o700)
    for name in ('server','single','gateway','twohop'):
        shutil.copytree(SOURCE/name,stage/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    if pair.source_digest(stage)!=plan['new_digest']:raise ValueError('Source changed while staging the update')
    for script in stage.rglob('*.sh'):script.chmod(0o700)
    if (lifecycle.ROOT/'runtime').exists():shutil.copytree(lifecycle.ROOT/'runtime',folder/'previous-runtime',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    return record(op,'prepared','Helper update reviewed; VPN unchanged')

def routing(mode):
    import native_routing
    native_routing.apply(mode)

def verify(op):
    m=pair.load_manifest()
    import native_pair
    if m['plan']['role']=='entry':
        active=lifecycle.route_override(m)
        if active:
            candidate=read(lifecycle.ROOT/'operations'/active['operation']/'journal.json')
            lifecycle.verify_route(candidate,m['plan']['test_ip'])
        else:native_pair.verify(m['plan'],{'expected_exit_ip':op['expected_exit_ip']},False)
        if op['was_active']:routing('activate')
    else:
        result=native_pair.dispatch({'command':'health'},m)
        # Health adapters raise for invalid configuration; additionally reject an
        # explicit service/DNS failure without treating a false optional flag as one.
        if result.get('healthy') is False or result.get('running') is False or result.get('services',{}).get('adguard') is False:raise ValueError('Exit service or DNS did not pass its health check')

def swap_runtime(op,rollback=False):
    folder=ROOT/op['operation'];target=lifecycle.ROOT/'runtime'
    if not (folder/'previous-runtime').exists():return
    candidate=folder/'runtime-next'
    if candidate.exists():shutil.rmtree(candidate)
    if rollback:shutil.copytree(folder/'previous-runtime',candidate)
    else:
        candidate.mkdir(mode=0o700)
        for name in ('server','single'):shutil.copytree(pair.RELEASE/name,candidate/name)
    previous=folder/'runtime-displaced'
    if previous.exists():shutil.rmtree(previous)
    if target.exists():os.rename(target,previous)
    os.rename(candidate,target)

def transition(req):
    operation=pair.ident(req.get('operation'));folder=ROOT/operation;op=read(folder/'journal.json')
    action=req.get('action')
    if not op:
        if action=='status':return {'operation':operation,'state':'not-started'}
        raise ValueError('Unknown helper update')
    if action=='status':return public(op)
    if action=='accept':
        if op['state']=='accepted':return public(op)
        if op['state']!='verified' or req.get('confirmation')!='CLIENT TRAFFIC VERIFIED':raise ValueError('Verify a saved client connection before accepting')
        current=current_installation(op)
        if current['bundle']!=op['new_digest'] or pair.source_digest(pair.RELEASE)!=op['new_digest']:raise ValueError('The verified helper is no longer installed')
        return record(op,'accepted','Helper update accepted; previous helper retained for recovery')
    if action not in ('apply','rollback'):raise ValueError('Unsupported helper update action')
    if action=='rollback' and op['state']=='prepared':
        # Preparing only copied a staged helper. Cancelling it must not interrupt
        # the untouched route or require an exit address that was never probed.
        # Even a stale review can be discarded: it never mutated the live tree.
        # Strict identity validation still applies after an applying checkpoint.
        return record(op,'cancelled','Reviewed helper update cancelled; VPN unchanged')
    if action=='rollback' and op['state']=='cancelled':return public(op)
    if action=='apply' and op['state'] in ('verified','accepted'):return public(op)
    if action=='rollback' and op['state']=='rolled-back':return public(op)
    if op['state'] in TERMINAL:raise ValueError('Start a new reviewed update for this completed operation')
    current=current_installation(op)
    if action=='apply':
        if op['state'] not in ('prepared','applying'):raise ValueError('This update cannot be applied')
        expected=str(ipaddress.IPv4Address(req.get('expected_exit_ip','')))
        if op.get('expected_exit_ip') not in (None,expected):raise ValueError('Reviewed exit address changed')
        op['expected_exit_ip']=expected;record(op,'applying','Closing entry forwarding and updating verified helpers')
    else:record(op,'rolling-back','Closing entry forwarding and restoring the previous helper')
    if op['manifest']['plan']['role']=='entry':routing('quiesce')
    previous=folder/'previous'
    try:
        if action=='apply':
            # A durable journal precedes each rename; a retry reconciles both
            # trees before changing the manifest, including death between renames.
            if pair.RELEASE.exists() and pair.source_digest(pair.RELEASE)==op['old_digest']:
                if previous.exists():raise ValueError('Unexpected previous helper directory')
                os.rename(pair.RELEASE,previous)
            if not pair.RELEASE.exists():os.rename(folder/'new',pair.RELEASE)
            if pair.source_digest(pair.RELEASE)!=op['new_digest']:raise ValueError('New helper integrity failed')
            new=copy.deepcopy(current);new['bundle']=op['new_digest'];new['activated']=False;history=new.setdefault('helper_history',[])
            if not any(item.get('operation')==operation for item in history):history.append({'operation':operation,'previous':op['old_digest']})
            lifecycle.reanchor(op['manifest'],new)
            pair.write_manifest(new);swap_runtime(op)
        else:
            if pair.RELEASE.exists() and pair.source_digest(pair.RELEASE)==op['new_digest']:
                displaced=folder/'rejected'
                if displaced.exists():raise ValueError('Unexpected rejected helper directory')
                os.rename(pair.RELEASE,displaced)
            if not pair.RELEASE.exists():os.rename(previous,pair.RELEASE)
            if pair.source_digest(pair.RELEASE)!=op['old_digest']:raise ValueError('Rollback helper integrity failed')
            restored=copy.deepcopy(op['manifest']);restored['activated']=False
            reviewed_new=copy.deepcopy(op['manifest']);reviewed_new['bundle']=op['new_digest']
            lifecycle.reanchor(reviewed_new,restored)
            pair.write_manifest(restored);swap_runtime(op,True)
        if op['manifest']['plan']['role']=='entry':
            # The watch daemon retains imported Python code across directory
            # swaps; restart only this guard, never the user-facing listener.
            import native_pair
            native_pair.command(['systemctl','restart','rookstride-pair-watch'])
            routing('refresh')
        verify(op)
        return record(op,'verified' if action=='apply' else 'rolled-back','Helper and route verified; check a saved client' if action=='apply' else 'Previous helper and route restored')
    except Exception:
        if op['manifest']['plan']['role']=='entry':
            with contextlib.suppress(Exception):routing('quiesce')
        record(op,op['state'],'Update paused safely; resume or roll back')
        raise

def dispatch(req):
    if not isinstance(req,dict):raise ValueError('Expected a JSON object')
    if req.get('action')=='review':return review()
    if req.get('action')=='prepare':return prepare(req)
    return transition(req)

def main():
    os.umask(0o077)
    try:
        if os.geteuid()!=0:raise ValueError('Owner SSH access is required')
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('Request is too large')
        # Keep the documented global order: management → lifecycle → pair.
        with contextlib.ExitStack() as stack:
            for path in (LOCK,lifecycle.LOCK,pair.LOCK):
                stream=stack.enter_context(open(path,'a'));fcntl.flock(stream,fcntl.LOCK_EX)
            result=dispatch(json.loads(raw))
        print(json.dumps({'ok':True,'result':result}))
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e) if isinstance(e,ValueError) else type(e).__name__}));sys.exit(1)

if __name__=='__main__':main()
