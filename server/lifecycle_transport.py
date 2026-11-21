"""Isolated exit-migration transports. Never replaces a listener or main route."""
import base64,hashlib,ipaddress,json,os,re,ssl,subprocess,sys,time
from pathlib import Path
import pair,native_pair
SUPPORTED={'awg','ikev2',*native_pair.model.PROTOCOLS}

def connection(op):return 'rsx-'+pair.ident(op['operation'])
def if_id(op):return 1000+int(pair.ident(op['operation'])[:7],16)
def directory(op):return __import__('lifecycle').ROOT/'operations'/pair.ident(op['operation'])
def runtime():return __import__('lifecycle').ROOT/'runtime'/'server'/'lifecycle_transport.py'
def fixed_vip(op):
 # Independent /32 addresses avoid connected-subnet collisions between retained
 # and staged TUNs. The full operation identity contributes to the choice.
 offset=int(hashlib.sha256(pair.ident(op['operation']).encode()).hexdigest()[:12],16)%2097151
 return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('10.128.0.0'))+offset*4+2))
def reserve_vip(op):
 value=subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,check=True)
 if any(a.get('local')==fixed_vip(op) and row.get('ifname')!=op['interface'] for row in json.loads(value.stdout) for a in row.get('addr_info',[])):raise ValueError('Candidate private address is already assigned; choose a new reviewed operation')
def socket_path(op):return native_pair.IKE_SOCKET if op.get('ike_shared') else Path('/run/rookstride-lifecycle-'+op['operation']+'.vici')
def ike_folder(op):return Path('/etc/swanctl/rookstride-lifecycle')/pair.ident(op['operation'])
def unit(op):
 folder=directory(op);name='rookstride-lifecycle-'+op['operation'];protocol=op['plan']['exit_protocol']
 head='[Unit]\nDescription=Rookstride staged '+protocol+' replacement exit\nAfter=network-online.target\n[Service]\nUMask=0077\n'
 tail='Restart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n'
 if protocol=='openvpn':
  return head.replace('After=network-online.target','After=docker.service network-online.target\nRequires=docker.service')+f'ExecStartPre=-/usr/bin/docker rm -f {name}\nExecStart=/usr/bin/docker run --rm --name {name} --label io.rookstride.lifecycle={op["operation"]} --network host --cap-add NET_ADMIN --device /dev/net/tun --mount type=bind,source={folder},target=/vpn,readonly --entrypoint /usr/sbin/openvpn {op["image_id"]} --config /vpn/client.ovpn\nExecStop=/usr/bin/docker stop {name}\n'+tail
 if protocol in ('xray','xhttp'):return head+f'ExecStart={op["xray_binary"]} run -config {folder}/client.json\n'+tail
 if protocol=='ikev2':
  helper=str(runtime());prefix=f'ExecStartPre=/usr/bin/python3 {helper} xfrm {op["operation"]}\n';uri='unix://'+str(socket_path(op));stop=f'ExecStop=-/usr/sbin/swanctl --terminate --ike {connection(op)} --timeout 5 --uri {uri}\n'
  if op.get('ike_shared'):
   dependency='strongswan-starter.service' if op['plan']['entry_protocol']=='ikev2' else 'rookstride-pair-bridge.service'
   return head.replace('After=network-online.target','After=network-online.target '+dependency+'\nRequires='+dependency+'\nPartOf='+dependency)+f'Type=oneshot\nRemainAfterExit=yes\n'+prefix+f'ExecStart=/usr/bin/python3 {helper} ike-load {op["operation"]}\n'+stop+'[Install]\nWantedBy=multi-user.target '+dependency+'\n'
  return head+f'Environment=STRONGSWAN_CONF={ike_folder(op)}/strongswan.conf\n'+prefix+f'ExecStart={op["ike_daemon"]}\nExecStartPost=/usr/bin/python3 {helper} ike-load {op["operation"]}\n'+stop+tail
 return head+f'ExecStart={op["worker_binary"]} run {folder}/worker.json\n'+tail

def write_owned(path,content):
 pair.protected(path)
 if path.exists() and path.read_text()!=content:raise ValueError('Staged transport configuration changed; review the recorded operation')
 pair.atomic(path,content)

def ike_config(op):
 value=op['transport']['profile'];name=connection(op);folder=ike_folder(op);number=if_id(op)
 # Input fields have already passed native_pair.validate_material. String values
 # remain data, never commands, and password is JSON-quoted for strongSwan.
 return f'''connections {{
 {name} {{
  version = 2
  remote_addrs = {value['server']}
  vips = 0.0.0.0
  proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048
  encap = yes
  dpd_delay = 20s
  local {{
   auth = eap-mschapv2
   id = {value['login']}
   eap_id = {value['login']}
  }}
  remote {{
   auth = pubkey
   id = {value['identity']}
   certs = {folder}/exit.pem
  }}
  children {{
   {name} {{
    remote_ts = 0.0.0.0/0
    if_id_in = {number}
    if_id_out = {number}
    start_action = none
    dpd_action = restart
    close_action = start
    esp_proposals = aes256gcm16,aes256-sha256
   }}
  }}
 }}
}}
secrets {{
 eap-{name} {{
  id = {value['login']}
  secret = {json.dumps(value['password'],ensure_ascii=False)}
 }}
}}
'''

def prepare(op):
 protocol=op['plan']['exit_protocol'];folder=directory(op)
 if protocol not in ('awg','ikev2','openvpn'):reserve_vip(op)
 if protocol=='openvpn':
  image=native_pair.command(['docker','image','inspect','--format','{{.Id}}','rookstride-openvpn:1'])
  if not re.fullmatch(r'sha256:[a-f0-9]{64}',image):raise ValueError('The current OpenVPN runtime identity is unavailable')
  if op.get('image_id') and op['image_id']!=image:raise ValueError('The reviewed OpenVPN runtime changed')
  op['image_id']=image
  content=native_pair.openvpn_profile(op['plan'],op['transport']['profile']).replace('dev '+native_pair.INTERFACE+'\n','dev '+op['interface']+'\n')
  write_owned(folder/'client.ovpn',content)
 elif protocol in ('xray','xhttp'):
  source=native_pair.runtime.ROOT/'bin/xray';pair.protected(source)
  if not source.is_file() or not 0<source.stat().st_size<100*1024*1024:raise ValueError('The current Xray runtime is unavailable')
  data=source.read_bytes();digest=hashlib.sha256(data).hexdigest();binary=folder/'xray';pair.protected(binary)
  if op.get('xray_sha256') and op['xray_sha256']!=digest or binary.exists() and hashlib.sha256(binary.read_bytes()).hexdigest()!=digest:raise ValueError('The reviewed Xray runtime changed')
  if not binary.exists():
   fd=os.open(binary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)
   with os.fdopen(fd,'wb') as stream:stream.write(data)
  op['xray_binary']=str(binary);op['xray_sha256']=digest;outbound=native_pair.xray_outbound(op['plan'],op['transport']['profile'])
  config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'bridge','protocol':'tun','settings':{'name':op['interface'],'MTU':1280}}],'outbounds':[{'tag':'blocked','protocol':'blackhole'},outbound],'routing':{'rules':[{'type':'field','inboundTag':['bridge'],'network':'tcp,udp','outboundTag':'exit'}]}}
  write_owned(folder/'client.json',json.dumps(config));native_pair.command([str(binary),'run','-test','-config',str(folder/'client.json')]);op['bridge_ip']=fixed_vip(op)
 elif protocol=='ikev2':
  original=pair.load_manifest()['plan'];op['ike_shared']=original['entry_protocol']=='ikev2' or original['exit_protocol']=='ikev2'
  native_pair.command(['apt-get','update'],timeout=600);native_pair.ike_packages.install('starter' if original['entry_protocol']=='ikev2' else 'systemd',['strongswan-swanctl','libcharon-extra-plugins','libstrongswan-extra-plugins'])
  folder=ike_folder(op);pair.protected(folder);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
  write_owned(folder/'exit.pem',ssl.DER_cert_to_PEM_cert(base64.b64decode(op['transport']['profile']['certificate'],validate=True)));write_owned(folder/'swanctl.conf',ike_config(op))
  if not op['ike_shared']:
   # No installed IKE listener or old IKE bridge exists on this entry. Refuse to
   # stop any unexpected daemon; a foreign service is an ownership conflict.
   for service in ('strongswan','strongswan-starter','strongswan-swanctl'):
    if subprocess.run(['systemctl','is-active','--quiet',service],capture_output=True).returncode==0:raise ValueError('An unrelated IKE daemon is active; the candidate did not change it')
   binaries=[p for p in native_pair.command(['dpkg-query','-L','charon-systemd']).splitlines() if p.startswith('/usr/') and Path(p).name=='charon-systemd' and Path(p).is_file() and os.access(p,os.X_OK)]
   if len(binaries)!=1:raise ValueError('Packaged IKE runtime could not be identified')
   op['ike_daemon']=binaries[0]
   write_owned(folder/'strongswan.conf','charon-systemd {\n load_modular = yes\n install_routes = no\n plugins {\n include /etc/strongswan.d/charon/*.conf\n resolve { load = no }\n vici { socket = unix://'+str(socket_path(op))+' }\n }\n}\n')
 else:
  import routes
  config=routes.client_config(json.loads(op['transport']['profile']['content']),0);config['box']['inbounds']=[{'type':'tun','tag':'bridge','interface_name':op['interface'],'address':[fixed_vip(op)+'/32'],'mtu':1280,'auto_route':False,'stack':'gvisor'}]
  op['worker_binary']=str(routes.worker());features=json.loads(native_pair.command([op['worker_binary'],'features']))
  if features.get('schema')!=1 or features.get('tun_gvisor') is not True:raise ValueError('The transferred runtime lacks its packet engine')
  write_owned(folder/'worker.json',json.dumps(config));op['bridge_ip']=fixed_vip(op)
 return unit(op)

def vip(op):
 if op['plan']['exit_protocol']=='ikev2':
  from rookstride.vici import Vici
  with Vici(str(socket_path(op))) as connection_socket:
   for event in connection_socket.request('list-sas',event='list-sa'):
    for name,sa in event.items():
     if name!=connection(op) or not isinstance(sa,dict) or sa.get('state')!='ESTABLISHED':continue
     if not any(child.get('state')=='INSTALLED' for child in sa.get('child-sas',{}).values()):continue
     return next((str(ipaddress.IPv4Address(v)) for v in sa.get('local-vips',[]) if ipaddress.ip_address(v).version==4),'')
  return ''
 value=subprocess.run(['ip','-j','-4','address','show','dev',op['interface']],capture_output=True,text=True)
 if value.returncode:return ''
 return next((a['local'] for row in json.loads(value.stdout) if 'UP' in row.get('flags',[]) for a in row.get('addr_info',[]) if a.get('family')=='inet'),'')

def ready(op):
 if op['plan']['exit_protocol'] in ('xray','xhttp') and subprocess.run(['ip','link','show',op['interface']],capture_output=True).returncode==0:
  native_pair.command(['ip','address','replace',fixed_vip(op)+'/32','dev',op['interface']]);native_pair.command(['ip','link','set',op['interface'],'mtu','1280','up'])
 address=vip(op)
 if address:
  if op['plan']['exit_protocol'] in ('xray','xhttp',*native_pair.model.ADDITIONAL) and address!=fixed_vip(op):raise ValueError('Candidate private address changed')
  return address
 return ''

def main():
 import lifecycle
 operation=pair.ident(sys.argv[2]);op=lifecycle.read(directory({'operation':operation})/'journal.json')
 if not op or op['operation']!=operation or op['plan']['exit_protocol']!='ikev2':raise ValueError('Unknown owned IKE bridge')
 if sys.argv[1]=='xfrm':
  existing=subprocess.run(['ip','-j','-d','link','show',op['interface']],capture_output=True,text=True)
  if existing.returncode:native_pair.command(['ip','link','add',op['interface'],'type','xfrm','if_id',str(if_id(op))])
  else:
   link=json.loads(existing.stdout)[0];info=link.get('linkinfo',{})
   if info.get('info_kind')!='xfrm' or info.get('info_data',{}).get('if_id')!=if_id(op):raise ValueError('Candidate XFRM interface ownership changed')
  native_pair.command(['ip','link','set',op['interface'],'mtu','1280','up']);return
 if sys.argv[1]!='ike-load':raise ValueError('Unknown staged transport command')
 for _ in range(100):
  if socket_path(op).exists():
   native_pair.command(['/usr/sbin/swanctl','--load-all','--file',str(ike_folder(op)/'swanctl.conf'),'--uri','unix://'+str(socket_path(op))]);native_pair.command(['/usr/sbin/swanctl','--initiate','--child',connection(op),'--timeout','30','--uri','unix://'+str(socket_path(op))]);return
  time.sleep(.2)
 raise ValueError('Candidate IKE socket did not become ready')
if __name__=='__main__':main()
