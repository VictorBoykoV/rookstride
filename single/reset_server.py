"""Reviewable removal of recognized single-server VPNs; never an OS reinstall."""
import hashlib,importlib.util,json,secrets,shutil,time
from pathlib import Path
import model,runtime,filtering,public_tls

spec=importlib.util.spec_from_file_location('rookstride_ike_reset',Path(__file__).resolve().parents[1]/'server/reset.py')
ike=importlib.util.module_from_spec(spec);spec.loader.exec_module(ike)
PAIR=Path('/etc/rookstride-pair')
CONFIRMATION='DELETE ALL VPNS'

def inventory():
    if PAIR.exists() or PAIR.is_symlink():raise ValueError('Use the two-server reset for this node')
    protocols={}
    if ike.MARKER.exists() or ike.MARKER.is_symlink():protocols['ikev2']=ike.inspect()
    for protocol in model.PROTOCOLS:
        path=runtime.directory(protocol)
        if path.exists() or path.is_symlink():
            state=runtime.load(protocol)
            if not model.proxy_protocol(protocol):runtime.check_container(state)
            else:
                for suffix in (['','-endpoint'] if protocol=='trusttunnel' else ['']):
                    unit=Path('/etc/systemd/system/rookstride-single-'+protocol+suffix+'.service')
                    expected={'xray':'Description=Rookstride Xray VPN','xhttp':'Description=Rookstride XHTTP VPN'}.get(protocol,'Description=Rookstride managed '+protocol+' VPN'+suffix)
                    if (unit.exists() or unit.is_symlink()) and (not unit.is_file() or unit.is_symlink() or expected not in unit.read_text()):raise ValueError('Service ownership changed')
            protocols[protocol]={'configuration':hashlib.sha256(json.dumps(state,sort_keys=True).encode()).hexdigest()}
    if filtering.exists():protocols['filtering']={'configuration':filtering.fingerprint()}
    cached=public_tls.fingerprint()
    if cached:protocols['public-tls']={'configuration':cached}
    return protocols

def configuration(protocols):return hashlib.sha256(json.dumps(protocols,sort_keys=True).encode()).hexdigest()

def plan(prepare_protocol):
    protocols=inventory();plans={}
    for protocol in protocols:
        if protocol=='public-tls':continue
        plans[protocol]=filtering.reset_plan() if protocol=='filtering' else ike.plan() if protocol=='ikev2' else prepare_protocol(protocol)
    record={'token':secrets.token_hex(32),'expires':time.time()+300,'configuration':configuration(protocols),'plans':plans,'public_tls':protocols.get('public-tls',{}).get('configuration')}
    runtime.atomic(runtime.STATE/'reset-server.json',json.dumps(record))
    return {'token':record['token'],'expires':record['expires'],'protocols':[p for p in protocols if p not in ('filtering','public-tls')],'filtering':'filtering' in protocols,
            'confirmation':CONFIRMATION,'os_reinstall':False,'already_empty':not protocols,'scope':'Remove all recognized Rookstride VPNs, accounts and keys on this server. Ubuntu, SSH, administrator credentials, downloaded packages and unrelated applications stay.'}

def apply(req,remove_protocol):
    path=runtime.STATE/'reset-server.json'
    if path.is_symlink():raise ValueError('Unexpected reset review link')
    record=json.loads(path.read_text())
    if req.get('confirmation')!=CONFIRMATION or not isinstance(req.get('token'),str) or not secrets.compare_digest(req['token'],record['token']) or time.time()>record['expires']:raise ValueError('Review all VPN removals again')
    if configuration(inventory())!=record['configuration']:raise ValueError('The server changed. Review all VPN removals again.')
    removed=[]
    # Remove adapters first. The IKEv2 helper has a separate owned subtree.
    for protocol in sorted(record['plans'],key=lambda p:(2 if p=='filtering' else 1 if p=='ikev2' else 0,p)):
        review=record['plans'][protocol]
        request={'protocol':protocol,'confirmation':'DELETE VPN','token':review['token']}
        try:
            if protocol=='filtering':filtering.reset_apply(request)
            elif protocol=='ikev2':ike.apply(request)
            else:remove_protocol(request)
            removed.append(protocol)
        except Exception as e:
            raise ValueError('Reset stopped after removing '+(', '.join(removed) or 'nothing')+'. Inspect the server and review the remaining VPNs again.') from e
    public_tls.cleanup(record.get('public_tls'))
    path.unlink(missing_ok=True)
    return {'reset':True,'removed_protocols':[p for p in removed if p!='filtering'],'removed_components':['filtering'] if 'filtering' in removed else [],'already_empty':not removed,'os_reinstall':False,'message':'No Rookstride VPN setups remain. Ubuntu, SSH and other applications are retained.' if not removed else 'Rookstride VPNs removed. Ubuntu and SSH retained. You can install again.'}
