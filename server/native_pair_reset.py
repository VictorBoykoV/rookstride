"""Review either owned native-pair node without needing its partner or old phone record."""
import hashlib,json,secrets,shutil,time
from pathlib import Path
import pair,native_pair,lifecycle
import reset as ike_reset
import public_tls,ike_packages

REVIEWS=Path('/var/lib/rookstride-reset')
SERVICES=('rookstride-pair-watch','rookstride-pair-entry','rookstride-pair-bridge','rookstride-pair-routing')
def inspect(req):
    p=pair.plan(req);m=pair.require_owner(p)
    if m.get('version')!=2:raise ValueError('Unsupported node ownership')
    for job in m['jobs'].values():
        if pair.status(job)['state'] in ('starting','running'):raise ValueError('Wait for the owned installation job before removing this node')
    protocol=p['entry_protocol'] if p['role']=='entry' else p['exit_protocol']
    units=[]
    for name in SERVICES:
        path=native_pair.UNIT/(name+'.service')
        if path.exists():
            pair.protected(path)
            if hashlib.sha256(path.read_bytes()).hexdigest()!=m.get('unit_hashes',{}).get(name):raise ValueError('Owned route service changed')
            units.append(path)
    files=units+[pair.RELEASE,pair.STATE,pair.OWN]
    if p['role']=='entry' and p['exit_protocol']=='ikev2':files=units+[native_pair.IKE_CREDENTIALS,native_pair.IKE_SOCKET,pair.RELEASE,pair.STATE,pair.OWN]
    for path in (native_pair.IKE_SHARED,native_pair.IKE_DROP):
        if path.exists():
            pair.protected(path)
            if hashlib.sha256(path.read_bytes()).hexdigest()!=m.get('file_hashes',{}).get(str(path)):raise ValueError('Owned IKEv2 route configuration changed')
            files.insert(0,path)
    for job in m['jobs'].values():files.insert(0,native_pair.UNIT/('rookstride-pair-job-'+job+'.service'))
    for path in files:
        pair.protected(path)
        if path.is_dir() and any(x.is_symlink() for x in path.rglob('*')):raise ValueError('Unexpected symbolic link in route data')
    configuration=hashlib.sha256(json.dumps(m,sort_keys=True).encode())
    child_exists=(native_pair.runtime.directory(protocol)/'state.json').is_file() if protocol!='ikev2' else ike_reset.MARKER.is_file()
    if protocol!='ikev2' and child_exists:
        state=native_pair.runtime.load(protocol)
        if not native_pair.model.proxy_protocol(protocol):native_pair.runtime.check_container(state)
        configuration.update(json.dumps(state,sort_keys=True).encode())
    elif protocol=='ikev2' and child_exists:configuration.update(json.dumps(ike_reset.inspect(),sort_keys=True).encode())
    elif protocol=='ikev2' and ike_reset.CONFIG.exists():raise ValueError('Unrecognized partial IKEv2 files need review before removal')
    if p['role']=='exit' and protocol!='ikev2' and native_pair.filtering.exists():configuration.update(native_pair.filtering.fingerprint().encode())
    for path in (native_pair.IKE_SHARED,native_pair.IKE_DROP):
        if path.exists():configuration.update(path.read_bytes())
    for path in units:configuration.update(path.read_bytes())
    if p['role']=='entry' and p['exit_protocol']=='ikev2' and native_pair.IKE_CREDENTIALS.exists():
        for path in sorted(native_pair.IKE_CREDENTIALS.rglob('*')):
            if path.is_file():configuration.update(str(path).encode()+path.read_bytes())
    lifecycle_review=lifecycle.cleanup_review(m);files.extend(Path(name) for name in lifecycle_review['files']);configuration.update(lifecycle_review['fingerprint'].encode())
    cached=public_tls.fingerprint()
    if cached:configuration.update(cached.encode())
    return {'lifecycle':lifecycle_review,'public_tls':cached,'role':p['role'],'pair':p['pair'],'already_fresh':False,'files':[str(x) for x in files if x.exists()],'services':[x.stem for x in units],'protocols':[protocol],'child_exists':child_exists,'filtering':p['role']=='exit','configuration':configuration.hexdigest(),'scope':'This server’s owned VPN, bridge, accounts, keys and filtering. The other server, Ubuntu, SSH and unrelated files remain.'}
def path(req):return REVIEWS/(pair.ident(req['pair'])+'-'+pair.plan(req)['role']+'-native.json')
def plan(req):
    value=inspect(req);p=pair.plan(req);protocol=value['protocols'][0]
    import importlib.util
    spec=importlib.util.spec_from_file_location('native_single_api',Path(native_pair.runtime.__file__).parent/'run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
    child=(api.reset_plan(protocol) if protocol!='ikev2' else ike_reset.plan()) if value['child_exists'] else None
    filter_plan=native_pair.filtering.reset_plan() if p['role']=='exit' and protocol!='ikev2' and native_pair.filtering.exists() else None
    # A partial IKE install may not yet have a management directory. Preparing
    # its child review creates that directory; snapshot the final stable scope.
    value=inspect(req)
    record={'token':secrets.token_hex(32),'expires':time.time()+300,'review':value,'child':child,'filter':filter_plan}
    pair.protected(REVIEWS);REVIEWS.mkdir(mode=0o700,parents=True,exist_ok=True);pair.atomic(path(req),json.dumps(record))
    return dict(value,token=record['token'],expires=record['expires'])
def apply(req):
    if req.get('confirmation')!='DELETE PAIR':raise ValueError('Confirm the reviewed route removal')
    record=json.loads(path(req).read_text());token=req.get('token')
    if not isinstance(token,str) or not secrets.compare_digest(token,record['token']) or time.time()>record['expires']:raise ValueError('Review this removal again')
    if inspect(req)!=record['review']:raise ValueError('The node changed. Review its removal again.')
    m=pair.load_manifest();p=m['plan'];m['resetting']=True;pair.write_manifest(m)
    if p['role']=='entry' and p['exit_protocol']=='ikev2' and p['entry_protocol']!='ikev2' and native_pair.IKE_CREDENTIALS.exists():ike_packages.remember_owned('systemd')
    if p['role']=='entry':native_pair.network('quiesce')
    for name in ('rookstride-pair-watch','rookstride-pair-entry','rookstride-pair-bridge'):
        native_pair.command(['systemctl','disable','--now',name]) if (native_pair.UNIT/(name+'.service')).exists() else None
    lifecycle.cleanup_network(record['review'].get('lifecycle',{'files':[],'services':[],'interfaces':[]}))
    protocol=record['review']['protocols'][0]
    child={'protocol':protocol,'confirmation':'DELETE VPN','token':record['child']['token']} if record['child'] else None
    if protocol!='ikev2' and child:
        import importlib.util
        spec=importlib.util.spec_from_file_location('native_single_api',Path(native_pair.runtime.__file__).parent/'run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api);api.reset_apply(child)
    elif child:ike_reset.apply(child)
    if record['filter']:native_pair.filtering.reset_apply({'confirmation':'DELETE VPN','token':record['filter']['token']})
    # Remove policy only after the entry listener and forwarding have stopped.
    if p['role']=='entry':
        from native_routing import run,ipt,GUARD,FORWARD,INPUT,NAT,MSS,OUTPUT,OUTPUT_GUARD,ADMIN
        for table,parent,chain in [('filter','FORWARD',GUARD),('filter','FORWARD',FORWARD),('filter','INPUT',INPUT),('filter','OUTPUT',ADMIN),('filter','OUTPUT',OUTPUT_GUARD),('filter','OUTPUT',OUTPUT),('nat','POSTROUTING',NAT),('mangle','FORWARD',MSS)]:
            while ipt(table,'-C',parent,'-j',chain,check=False).returncode==0:ipt(table,'-D',parent,'-j',chain)
            ipt(table,'-F',chain,check=False);ipt(table,'-X',chain,check=False)
        for priority,source in [(100,p['client_pool']),(90,p['test_ip']+'/32')]:
            while run(['ip','rule','del','priority',str(priority),'from',source,'lookup',str(p['route_table'])],False).returncode==0:pass
        run(['ip','route','flush','table',str(p['route_table'])],False);run(['ip','route','del',p['client_pool'],'dev','docker0'],False);run(['ip','address','del',p['test_ip']+'/32','dev','lo'],False);run(['ip','address','del','10.66.0.1/32','dev','lo'],False) if native_pair.model.proxy_protocol(p['entry_protocol']) else None;run(['ip','link','del','awg-exit'],False)
    if (native_pair.UNIT/'rookstride-pair-routing.service').exists():native_pair.command(['systemctl','disable','--now','rookstride-pair-routing'])
    for name in record['review']['files']:
        item=pair.protected(name)
        if item.is_dir():shutil.rmtree(item)
        else:item.unlink(missing_ok=True)
    public_tls.cleanup(record['review'].get('public_tls'))
    native_pair.command(['systemctl','daemon-reload']);path(req).unlink(missing_ok=True)
    return {'reset':True,'role':p['role'],'message':'Owned two-server VPN removed from this node. Ubuntu and SSH remain. It can now host a single-server VPN or either two-server role.'}
