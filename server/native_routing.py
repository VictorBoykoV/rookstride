#!/usr/bin/env python3
"""Fail-closed forwarding for the owned native-entry pair; never changes main default."""
import ipaddress,json,subprocess,sys,time,shutil
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pair

GUARD='RSPAIR_GUARD';FORWARD='RSPAIR_FORWARD';INPUT='RSPAIR_INPUT';NAT='RSPAIR_NAT';MSS='RSPAIR_MSS';OUTPUT='RSPAIR_OUTPUT';OUTPUT_GUARD='RSPAIR_OUT_GUARD';ADMIN='RSPAIR_ADMIN';INTERFACE='awg-exit'
def run(args,check=True):
    result=subprocess.run(args,text=True,capture_output=True,timeout=30)
    if check and result.returncode:raise ValueError('Could not update the owned two-server route')
    return result
def ipt(table,*args,check=True):return run(['iptables','-w','10','-t',table,*args],check)
def ssh_ports():
    sshd=shutil.which('sshd')
    if not sshd:return []
    result=run([sshd,'-T'],False)
    if result.returncode:return []
    return sorted({int(line.split()[1]) for line in result.stdout.splitlines() if line.startswith('port ') and line.split()[1].isdigit() and 0<int(line.split()[1])<65536})
def chain(table,name):ipt(table,'-N',name,check=False)
def jump(table,parent,name):
    if ipt(table,'-C',parent,'-j',name,check=False).returncode:ipt(table,'-I',parent,'1','-j',name)
def rule(priority,source,table):
    rules=json.loads(run(['ip','-j','-4','rule','show']).stdout)
    matches=[r for r in rules if r.get('priority')==priority]
    def network(value):
        address=value.get('src','all')
        if address=='all':return None
        try:return ipaddress.IPv4Network(address if '/' in address else address+'/'+str(value.get('srclen',32)),strict=False)
        except ValueError:return None
    if any(network(r)!=ipaddress.IPv4Network(source,strict=False) or str(r.get('table'))!=str(table) or set(r)-{'priority','src','srclen','table','protocol'} for r in matches):raise ValueError('The dedicated policy-rule priority is already used')
    if not matches:run(['ip','rule','add','priority',str(priority),'from',source,'lookup',str(table)])
def container_route(p):
    if p.get('entry_protocol') not in ('awg','openvpn'):return
    if not shutil.which('docker') or run(['systemctl','is-active','--quiet','docker'],False).returncode:return
    protocol=p['entry_protocol'];value=run(['docker','inspect','rookstride-single-'+protocol],False)
    if value.returncode:return
    container=json.loads(value.stdout)[0]
    if container['Config'].get('Labels',{}).get('io.rookstride.instance')!=__import__('native_pair').runtime.load(protocol)['instance']:raise ValueError('Entry container ownership changed')
    address=container['NetworkSettings']['Networks']['bridge']['IPAddress']
    if address:run(['ip','route','replace',p['client_pool'],'via',str(ipaddress.IPv4Address(address)),'dev','docker0'])
def routes(p):
    rule(100,p['client_pool'],p['route_table']);rule(90,p['test_ip']+'/32',p['route_table'])
    if 'blackhole default' not in run(['ip','route','show','table',str(p['route_table'])],False).stdout:run(['ip','route','add','blackhole','default','metric','42760','table',str(p['route_table'])])
    if run(['ip','link','show',INTERFACE],False).returncode==0:run(['ip','route','replace','default','dev',INTERFACE,'metric','10','table',str(p['route_table'])])
    assigned=json.loads(run(['ip','-j','address','show','dev','lo']).stdout)
    if not any(a.get('local')==p['test_ip'] for row in assigned for a in row.get('addr_info',[])):run(['ip','address','add',p['test_ip']+'/32','dev','lo'])
    if p.get('entry_protocol') not in ('ikev2','awg','openvpn'):run(['ip','address','replace','10.66.0.1/32','dev','lo'])
    container_route(p)
def guard(p):
    chain('filter',GUARD)
    if ipt('filter','-C',GUARD,'-s',p['client_pool'],'-j','REJECT',check=False).returncode:ipt('filter','-A',GUARD,'-s',p['client_pool'],'-j','REJECT')
    jump('filter','FORWARD',GUARD)
    chain('filter',OUTPUT_GUARD)
    if ipt('filter','-C',OUTPUT_GUARD,'-s',p['client_pool'],'-j','REJECT',check=False).returncode:ipt('filter','-A',OUTPUT_GUARD,'-s',p['client_pool'],'-j','REJECT')
    jump('filter','OUTPUT',OUTPUT_GUARD)
def save_manifest(m):
    selected=__import__('lifecycle').route_override(m)
    if selected:
        original=pair.load_manifest()
        if 'bridge_ip' in original:m['bridge_ip']=original['bridge_ip']
    pair.write_manifest(m)
def apply(action):
    global INTERFACE
    INTERFACE='awg-exit'
    m=pair.load_manifest()
    if not m or m.get('version')!=2 or m['plan']['role']!='entry':raise ValueError('Owned native-entry pair required')
    p=dict(m['plan'])
    try:
        import lifecycle
        selected=lifecycle.route_override(m)
        if selected:
            route=selected['route'];INTERFACE=route['interface'];p.update(exit_host=route['exit_host'],exit_protocol=route['exit_protocol']);m['bridge_ip']=route['bridge_ip']
    except (ValueError, OSError, KeyError):
        guard(p)
        if action=='quiesce':m['activated']=False;pair.write_manifest(m);return
        raise
    if action=='ike-load':
        from native_pair import IKE_CREDENTIALS,IKE_SOCKET
        folder=IKE_CREDENTIALS
        for _ in range(100):
            if IKE_SOCKET.exists():
                loaded=run(['/usr/sbin/swanctl','--load-all','--file',str(folder/'swanctl.conf'),'--uri','unix://'+str(IKE_SOCKET)],False)
                if loaded.returncode==0:
                    # Reloading an identical VICI connection need not repeat
                    # start_action. Explicit initiation makes Resume reliable.
                    ready=run(['/usr/sbin/swanctl','--initiate','--child','route-exit','--timeout','20','--uri','unix://'+str(IKE_SOCKET)],False)
                    if ready.returncode:raise ValueError('The entry could not establish its IKEv2 exit. Check reachability and resume.')
                    return
            time.sleep(.2)
        raise ValueError('The private IKEv2 client configuration could not be loaded')
    if action=='xfrm':
        if run(['ip','link','show',INTERFACE],False).returncode:run(['ip','link','add',INTERFACE,'type','xfrm','if_id','42'])
        run(['ip','link','set',INTERFACE,'mtu','1280','up']);return
    if action=='watch':
        while True:
            try:
                current=pair.load_manifest()
                if not current or current.get('resetting'):return
                selected=lifecycle.route_override(current)
                if selected:
                    INTERFACE=selected['route']['interface'];current['bridge_ip']=selected['route']['bridge_ip'];p.update(exit_protocol=selected['route']['exit_protocol'])
                else:
                    INTERFACE='awg-exit';p=dict(current['plan'])
                if selected:
                    # Read the selected sidecar, not an arbitrary SA or the old
                    # global tunnel. Its changing VIP never edits the pair recipe.
                    import lifecycle_transport
                    operation=lifecycle.read(lifecycle.ROOT/'operations'/selected['operation']/'journal.json')
                    vip=lifecycle_transport.ready(operation) if p['exit_protocol']!='awg' else selected['route']['bridge_ip']
                    if vip and vip!=selected['route']['bridge_ip']:
                        selected['route']['bridge_ip']=vip;operation['bridge_ip']=vip
                        lifecycle.write(lifecycle.ROOT/'operations'/operation['operation']/'journal.json',operation);lifecycle.write(lifecycle.ACTIVE,selected);apply('boot')
                elif p['exit_protocol']=='ikev2':
                    vip=__import__('native_pair').ike_vip()
                    if vip and vip!=current.get('bridge_ip'):
                        current['bridge_ip']=vip;pair.write_manifest(current);apply('boot')
                elif p['exit_protocol'] in ('xray','xhttp') and run(['ip','link','show',INTERFACE],False).returncode==0:
                    run(['ip','address','replace','10.69.0.2/32','dev',INTERFACE]);run(['ip','link','set',INTERFACE,'mtu','1280','up'])
                elif p['exit_protocol']=='openvpn':
                    vip=__import__('native_pair').interface_vip()
                    if vip and vip!=current.get('bridge_ip'):
                        current['bridge_ip']=vip;pair.write_manifest(current);apply('boot')
                routes(p)
            except (ValueError,OSError,RuntimeError,subprocess.SubprocessError):pass
            time.sleep(5)
    active=action=='activate' or action in ('boot','refresh') and m.get('activated',False)
    if action not in ('activate','boot','refresh','quiesce'):raise ValueError('Unsupported route action')
    if action=='activate' and not m.get('verified'):raise ValueError('Verify the complete route before opening forwarding')
    guard(p);chain('filter',INPUT)
    # Administrators may use another VPN client. Allow authenticated SSH to the
    # entry itself before the local-service guard, without opening DNS or internet.
    ports=ssh_ports()
    for port in ports:
        args=['-s',p['client_pool'],'-p','tcp','--dport',str(port),'-j','ACCEPT']
        if ipt('filter','-C',INPUT,*args,check=False).returncode:ipt('filter','-I',INPUT,'1',*args)
    if ipt('filter','-C',INPUT,'-s',p['client_pool'],'-j','REJECT',check=False).returncode:ipt('filter','-A',INPUT,'-s',p['client_pool'],'-j','REJECT')
    jump('filter','INPUT',INPUT);routes(p)
    run(['sysctl','-w','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=2','net.ipv4.conf.default.rp_filter=2'])
    # Xray creates local sockets, so its source-bound traffic needs an OUTPUT
    # guard in addition to the packet-client FORWARD guard.
    chain('filter',OUTPUT);ipt('filter','-F',OUTPUT)
    if active:ipt('filter','-A',OUTPUT,'-s',p['client_pool'],'-o',INTERFACE,'-j','ACCEPT')
    ipt('filter','-A',OUTPUT,'-s',p['client_pool'],'-j','REJECT');jump('filter','OUTPUT',OUTPUT)
    # Keep the temporary block ahead of the rebuilt local-socket chain.
    while ipt('filter','-C','OUTPUT','-j',OUTPUT_GUARD,check=False).returncode==0:ipt('filter','-D','OUTPUT','-j',OUTPUT_GUARD)
    jump('filter','OUTPUT',OUTPUT_GUARD)
    # Proxy entries originate client sockets locally. Permit only SSH destined
    # to this entry, ahead of both fail-closed OUTPUT chains, even during repair.
    # A LOCAL destination cannot escape to the internet or the exit node.
    chain('filter',ADMIN);ipt('filter','-F',ADMIN)
    for port in ports:ipt('filter','-A',ADMIN,'-s',p['client_pool'],'-m','addrtype','--dst-type','LOCAL','-p','tcp','--dport',str(port),'-j','ACCEPT')
    while ipt('filter','-C','OUTPUT','-j',ADMIN,check=False).returncode==0:ipt('filter','-D','OUTPUT','-j',ADMIN)
    jump('filter','OUTPUT',ADMIN)
    if action=='quiesce':m['activated']=False;save_manifest(m);return
    chain('filter',FORWARD);ipt('filter','-F',FORWARD)
    incoming=['-i','docker0'] if p['entry_protocol'] in ('awg','openvpn') else ['-m','policy','--dir','in','--pol','ipsec','--proto','esp'] if p['entry_protocol']=='ikev2' else None
    if incoming:ipt('filter','-A',FORWARD,*incoming,'-s',p['client_pool'],'-o',INTERFACE,'-j','ACCEPT')
    ipt('filter','-A',FORWARD,'-i',INTERFACE,'-d',p['client_pool'],'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ipt('filter','-A',FORWARD,'-s',p['client_pool'],'-j','REJECT')
    jump('filter','FORWARD',FORWARD)
    # The temporary guard must be before the rebuilt forward chain.
    while ipt('filter','-C','FORWARD','-j',GUARD,check=False).returncode==0:ipt('filter','-D','FORWARD','-j',GUARD)
    jump('filter','FORWARD',GUARD)
    if m.get('bridge_ip'):
        vip=str(ipaddress.IPv4Address(m['bridge_ip']));chain('nat',NAT);ipt('nat','-F',NAT)
        for source in (p['client_pool'],p['test_ip']+'/32'):ipt('nat','-A',NAT,'-s',source,'-o',INTERFACE,'-j','SNAT','--to-source',vip)
        jump('nat','POSTROUTING',NAT)
    chain('mangle',MSS);ipt('mangle','-F',MSS)
    ipt('mangle','-A',MSS,'-s',p['client_pool'],'-o',INTERFACE,'-p','tcp','--tcp-flags','SYN,RST','SYN','-j','TCPMSS','--set-mss','1160');jump('mangle','FORWARD',MSS)
    m['activated']=bool(active);save_manifest(m)
    if active:
        ipt('filter','-F',GUARD)
        ipt('filter','-F',OUTPUT_GUARD)
        if action=='activate' and not m.get('first_activated_at'):m['first_activated_at']=time.time();save_manifest(m)

if __name__=='__main__':apply(sys.argv[1])
