#!/usr/bin/env python3
"""Real OpenVPN username/password traffic probe, only on an owned disposable host.

JSON stdin carries {content, login, password, reject?}; no operator credentials.
The client is isolated in a container, so default routes never change on the host.
"""
import json,os,subprocess,sys,tempfile,time
from pathlib import Path
assert os.geteuid()==0 and os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')=='yes'
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'single'));import access
req=json.load(sys.stdin);access.login(req['login']);access.password(req['password']);name='rook-signin-openvpn-client'
def run(args,**kw):return subprocess.run(args,capture_output=True,text=True,timeout=kw.pop('timeout',60),**kw)
assert run(['docker','inspect',name]).returncode!=0,'Existing lab client requires cleanup'
with tempfile.TemporaryDirectory(prefix='rook-password-client-') as folder:
 p=Path(folder);p.chmod(0o700);(p/'client.ovpn').write_text(req['content']);(p/'password').write_text(req['login']+'\n'+req['password']+'\n');(p/'password').chmod(0o600)
 try:
  q=run(['docker','run','-d','--name',name,'--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv6.conf.all.disable_ipv6=0','--mount','type=bind,source='+folder+',target=/profile,readonly','--entrypoint','/usr/sbin/openvpn','rookstride-openvpn:1','--config','/profile/client.ovpn','--auth-user-pass','/profile/password','--auth-retry','none','--connect-retry-max','1','--connect-timeout','10'])
  assert q.returncode==0,q.stderr[-400:];end=time.monotonic()+45;log=''
  while time.monotonic()<end:
   log=run(['docker','logs',name]).stdout+run(['docker','logs',name]).stderr
   if 'Initialization Sequence Completed' in log or 'AUTH_FAILED' in log:break
   time.sleep(.3)
  if req.get('reject'):
   assert 'AUTH_FAILED' in log,'Wrong password must reach and fail authentication, not merely time out'
   print(json.dumps({'wrong_password_rejected':True}));raise SystemExit(0)
  assert 'Initialization Sequence Completed' in log,log[-1500:]
  pid=run(['docker','inspect','--format','{{.State.Pid}}',name]).stdout.strip()
  def client(args):
   q=run(['nsenter','-t',pid,'-n',*args],timeout=45);assert q.returncode==0,q.stderr[-300:];return q.stdout.strip()
  dns=client(['dig','+short','+time=5','+tries=1','@1.1.1.1','example.com','A']);address=next(v for v in dns.splitlines() if v.count('.')==3)
  body=client(['curl','--curves','X25519','-4','--fail','--silent','--show-error','--max-time','30','--resolve','example.com:443:'+address,'https://example.com/']);assert 'Example Domain' in body
  blocked=client(['dig','+noall','+comments','+answer','+time=5','+tries=1','@1.1.1.1','doubleclick.net','A']);assert 'status: NXDOMAIN' in blocked or 'status: NOERROR' in blocked and '0.0.0.0' in blocked,blocked
  import runtime
  live=[]
  for _ in range(18):
   live=runtime.health(runtime.load('openvpn'))['connections']
   if any(c.get('user')==req['login'] for c in live):break
   time.sleep(.4)
  assert any(c.get('user')==req['login'] for c in live),'Authenticated user missing from live statistics'
  print(json.dumps({'live_user_statistics':True,'password_authentication':True,'https':True,'dns_through_vpn':True,'ad_dns_blocked':True}))
 finally:run(['docker','rm','-f',name])
