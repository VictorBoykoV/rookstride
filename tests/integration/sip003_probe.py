#!/usr/bin/env python3
"""Official v2ray-plugin TCP interoperability; no claim of generic-plugin UDP."""
import argparse,hashlib,io,json,os,subprocess,sys,tarfile,tempfile,time,urllib.request
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--profile',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--xray',type=Path,required=True);args=p.parse_args()
sys.path.insert(0,str(args.source/'single'));import runtime
profile=json.loads(json.loads(args.profile.read_text())['content'])
url='https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.4.0/v2ray-plugin-linux-amd64-v1.4.0.tar.gz';expected='31dfb5a13d7f7ce401a2fa044168d4c7a67b271b382db4e4faf7a8c07b02e756'
with urllib.request.urlopen(url,timeout=60) as r:raw=r.read(5266244)
assert len(raw)==5266243 and hashlib.sha256(raw).hexdigest()==expected
with tempfile.TemporaryDirectory(prefix='rookstride-sip003-') as folder:
 os.chmod(folder,0o700);d=Path(folder)
 with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
  members=[m for m in archive.getmembers() if m.isfile() and Path(m.name).name.startswith('v2ray-plugin') and not Path(m.name).suffix in ('.md','.txt')];assert len(members)==1;binary=d/'v2ray-plugin';binary.write_bytes(archive.extractfile(members[0]).read());binary.chmod(0o700)
 ca=d/'ca.pem';ca.write_text(profile['certificate']);ca.chmod(0o600)
 env=dict(os.environ,SS_REMOTE_HOST=profile['server'],SS_REMOTE_PORT=str(profile['port']),SS_LOCAL_HOST='127.0.0.1',SS_LOCAL_PORT='18882',SS_PLUGIN_OPTIONS='tls;host='+profile['server_name']+';path='+profile['path']+'/tcp;mux=0',SSL_CERT_FILE=str(ca))
 config={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':18881,'protocol':'socks','settings':{}}],'outbounds':[{'protocol':'shadowsocks','settings':{'servers':[{'address':'127.0.0.1','port':18882,'method':profile['method'],'password':profile['password']}]}}]}
 path=d/'xray.json';path.write_text(json.dumps(config));path.chmod(0o600)
 with (d/'private.log').open('w') as log:
  plugin=subprocess.Popen([str(binary)],env=env,stdout=log,stderr=log);client=None
  try:
   time.sleep(.5);assert plugin.poll() is None,'Official plugin did not start';client=subprocess.Popen([str(args.xray),'run','-config',str(path)],stdout=log,stderr=log);time.sleep(.5)
   assert any(runtime.socks_https_ready(18881,h) for h in ('example.com','www.cloudflare.com')),'Official SIP003 TCP client did not pass the encrypted HTTPS test'
   print(json.dumps(dict(official_plugin='v1.4.0',plugin_sha256=expected,independent_shadowsocks_client='Xray 26.3.27',encrypted_https=True,tcp_interoperability=True,generic_plugin_udp_tested=False)))
  except Exception:
   log.flush();data=(d/'private.log').read_text()
   for key in ('password','path'):
    if profile.get(key):data=data.replace(profile[key],'[redacted]')
   print(data[-5000:],file=sys.stderr);raise
  finally:
   for process in (client,plugin):
    if process:
     process.terminate()
     try:process.wait(timeout=5)
     except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
