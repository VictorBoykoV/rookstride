#!/usr/bin/env python3
"""Repair an enabled but empty AdGuard list after a transient startup download.
Runs locally as root; dashboard credentials never leave the loopback service.
"""
import base64,ipaddress,json,os,re,subprocess,sys,time,urllib.request
from pathlib import Path
CREDENTIALS=Path('/root/single-vps-vpn/adguard-login.txt')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('Unexpected AdGuard redirect')
def ensure(call,clock=time.monotonic,sleep=time.sleep):
 deadline=clock()+240
 # A first filter download can take over two minutes on a small VPS. The
 # former forty two-second polls ended before even the old 120-second budget.
 # Keep both a real deadline and a finite guard for a broken/stalled clock.
 for attempt in range(121):
  status=call('filtering/status');filters=[f for f in status.get('filters',[]) if f.get('enabled')]
  if not status.get('enabled') or not filters:raise ValueError('Ad blocking has no enabled filter')
  if all(f.get('rules_count',0)>0 for f in filters):return
  if clock()>=deadline:break
  if attempt in (0,10,20):
   try:call('filtering/refresh',{'whitelist':False,'force':True})
   except (ValueError,OSError):pass  # A recovered resolver can complete the next bounded attempt.
  # Give an asynchronous download and a recovering resolver time to finish.
  # Repeating three refreshes in six seconds can exhaust all retries too early.
  sleep(2)
 raise ValueError('The ad-block list did not finish downloading. Check server HTTPS access; the existing VPN setup has been retained.')
def main():
 if os.geteuid()!=0:raise PermissionError('Root access is required')
 address=ipaddress.IPv4Address(sys.argv[1])
 if not address.is_private or address.is_unspecified or address.is_multicast:raise ValueError('Private DNS address required')
 loopback=json.loads(subprocess.check_output(['ip','-j','-4','address','show','dev','lo'],text=True))
 if not any(a.get('local')==str(address) for row in loopback for a in row.get('addr_info',[])):raise ValueError('The owned DNS address is not on loopback')
 if CREDENTIALS.is_symlink():raise ValueError('AdGuard credential path changed')
 text=CREDENTIALS.read_text();username=re.search(r'^Username: (.+)$',text,re.M);password=re.search(r'^Password: (.+)$',text,re.M)
 if not username or not password:raise ValueError('Owned AdGuard sign-in was not found')
 auth=base64.b64encode((username[1]+':'+password[1]).encode()).decode()
 local=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def call(endpoint,data=None):
  payload=None if data is None else json.dumps(data).encode()
  request=urllib.request.Request('http://'+str(address)+':3000/control/'+endpoint,data=payload,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
  try:
   with local.open(request,timeout=20 if data is not None else 10) as response:
    raw=response.read(1024*1024+1)
    if len(raw)>1024*1024:raise ValueError('Unexpected AdGuard response size')
    return json.loads(raw) if raw else {}
  except Exception as exc:raise ValueError('AdGuard did not finish loading its block list. Check server DNS/HTTPS access, then check and resume.') from None
 ensure(call);print('Enabled ad-block list is loaded.')
if __name__=='__main__':
 try:main()
 except (ValueError,OSError) as exc:print(str(exc),file=sys.stderr);raise SystemExit(1)
