"""Read-only inventory. A nonempty server is not automatically an unsafe server."""
import ipaddress,json
import sys
from pathlib import Path
from ubuntu_support import assess

IKE_PATHS=('/etc/ipsec.conf','/etc/ipsec.secrets','/etc/single-vps-vpn','/opt/AdGuardHome','/var/lib/AdGuardHome')
def listeners(root=Path('/')):
    result=[];seen=0
    for name,transport in [('tcp','tcp'),('tcp6','tcp'),('udp','udp'),('udp6','udp')]:
        path=root/'proc/net'/name
        if not path.exists():continue
        seen+=1
        for line in path.read_text().splitlines()[1:]:
            fields=line.split()
            if len(fields)<4:raise ValueError('Cannot read server ports')
            if transport=='tcp' and fields[3]!='0A':continue
            raw,port=fields[1].split(':');port=int(port,16)
            # /proc stores addresses as native-endian 32-bit words, including IPv6.
            packed=b''.join(int(raw[i:i+8],16).to_bytes(4,sys.byteorder) for i in range(0,len(raw),8))
            address=ipaddress.ip_address(packed)
            loopback=address.is_loopback or bool(getattr(address,'ipv4_mapped',None) and address.ipv4_mapped.is_loopback)
            result.append({'transport':transport,'port':port,'address':str(address),'wildcard':address.is_unspecified,'loopback':loopback})
    if seen<2:raise ValueError("Cannot inspect server ports; /proc must be available")
    return result

def inspect(root=Path('/')):
    release=dict(line.split('=',1) for line in (root/'etc/os-release').read_text().splitlines() if '=' in line)
    assessment=assess(root);ubuntu=assessment['eligible']
    owned=(root/'etc/single-vps-vpn/network.env').is_file()
    paths=[p for p in IKE_PATHS if (root/p.lstrip('/')).exists()]
    ports=listeners(root)
    ike_ports=[v['port'] for v in ports if v['transport']=='udp' and v['port'] in (500,4500)]
    dns_busy=any(v['port']==53 and not v['loopback'] for v in ports)
    conflicts=assessment['errors']+['Existing configuration: '+p for p in paths]
    conflicts+=['UDP port '+str(p)+' is in use' for p in sorted(set(ike_ports))]
    conflicts+=['DNS port 53 is in use on '+v['address'] for v in ports if v['port']==53 and not v['loopback']]
    pair_info={};manifest=root/'etc/rookstride-pair/manifest.json'
    if manifest.is_file() and not manifest.is_symlink():
        try:
            m=json.loads(manifest.read_text());p=m.get('plan',{})
            if m.get('version') in (1,2) and p.get('role') in ('entry','exit'):
                pair_info={'role':p['role'],'entry_protocol':p.get('entry_protocol','ikev2'),'exit_protocol':p.get('exit_protocol','awg')}
        except (OSError,ValueError,TypeError):pass
    return {'compatible_os':ubuntu,'os_assessment':assessment,'os':release.get('PRETTY_NAME','').strip('"'),'owned_ikev2':owned,
            'conflicting_paths':paths,'ports':ports,'ikev2_conflicts':list(dict.fromkeys(conflicts)),'ikev2_ready':ubuntu and not paths and not ike_ports and not dns_busy,
            'pair_node':(root/'etc/rookstride-pair').exists(),'pair':pair_info,'os_reinstall':False,'ssh_preserved':True}
