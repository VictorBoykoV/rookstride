#!/usr/bin/env python3
"""Explicit owner-only installation; never installs or restarts a VPN listener."""
import hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
import scoped_access as access

PACKAGE=Path(__file__).resolve().parent

def endpoint(value):
 if not isinstance(value,dict):raise ValueError('A pinned server endpoint is required')
 host=value.get('host');port=value.get('port',22);pin=value.get('fingerprint')
 if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}',host) or type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid SSH endpoint')
 if not isinstance(pin,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',pin):raise ValueError('SSH must be pinned before enabling administration')
 for path in Path('/etc/ssh').glob('ssh_host_*_key.pub'):
  key=' '.join(path.read_text().split()[:2])
  if access.fingerprint(key)==pin:return {'host':host,'port':port,'fingerprint':pin,'host_key':key}
 raise ValueError('Pinned SSH identity does not match this server')

def install(req):
 if os.geteuid()!=0:raise ValueError('The owner must enable administration')
 if req.get('schema')!=1 or req.get('operation')!='enable':raise ValueError('Unsupported owner installation request')
 target=Path('/opt/rookstride-access');root=access.ROOT
 if target.is_symlink() or root.is_symlink():raise ValueError('Unexpected management directory link')
 ep=endpoint(req.get('endpoint'));server_id=access.ident(req.get('server_id'));deployment_id=access.ident(req.get('deployment_id'))
 existing=access.Access() if (root/'authority.sqlite').exists() else None
 if existing:
  c=existing.get('meta','config')
  if c and (c['server_id']!=server_id or c['deployment_id']!=deployment_id):raise ValueError('Administration identity differs; existing grants were preserved')
 objects=access.discover(server_id,deployment_id)
 if not objects:raise ValueError('No compatible owned protocol helper is installed; inspect or install the owner helper first')
 for executable in ('/usr/bin/sudo','/usr/sbin/sshd','/usr/sbin/useradd','/usr/bin/ssh-keygen','/usr/bin/openssl','/usr/bin/ssh'):
  if not Path(executable).is_file():raise ValueError('Required local SSH administration component is missing')
 # Managed names must never overwrite an unrelated administrator configuration.
 marker='# Rookstride scoped administration v1\n'
 sshpath=Path('/etc/ssh/sshd_config.d/80-rookstride-access.conf');sudopath=Path('/etc/sudoers.d/rookstride-access')
 for path in (sshpath,sudopath):
  if path.exists() and (path.is_symlink() or not path.read_text().startswith(marker)):raise ValueError('Unrecognized existing management configuration')
 import grp
 try:grp.getgrnam('rookstride-access')
 except KeyError:access.run(['/usr/sbin/groupadd','--system','rookstride-access'])
 target.mkdir(mode=0o755,parents=True,exist_ok=True);root.mkdir(mode=0o700,parents=True,exist_ok=True)
 target.chmod(0o755);os.chown(target,0,0)
 system=access.System()
 original_module=(target/'scoped_access.py').read_text() if (target/'scoped_access.py').exists() else None
 original_helper=Path(access.HELPER).read_text() if Path(access.HELPER).exists() else None
 original_cleanup=(target/'access_cleanup.py').read_text() if (target/'access_cleanup.py').exists() else None
 cleanup_source=(PACKAGE/'access_cleanup.py').read_text();compile(cleanup_source,'access_cleanup.py','exec')
 module_source=(PACKAGE/'scoped_access.py').read_text();compile(module_source,'scoped_access.py','exec')
 ssh=marker+'''Match Group rookstride-access
    AuthorizedKeysFile /var/lib/rookstride-access-accounts/%u/authorized_keys
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    PermitUserRC no
    AllowAgentForwarding no
    X11Forwarding no
    DisableForwarding yes
    ForceCommand /usr/bin/sudo -n /usr/local/sbin/rookstride-access
Match all
'''
 sudo=marker+'Defaults:%rookstride-access env_reset\n%rookstride-access ALL=(root) NOPASSWD: /usr/local/sbin/rookstride-access ""\n'
 original_ssh=sshpath.read_text() if sshpath.exists() else None
 original_sudo=sudopath.read_text() if sudopath.exists() else None
 try:
  system.atomic(target/'scoped_access.py',module_source,0o644)
  system.atomic(target/'access_cleanup.py',cleanup_source,0o644)
  system.atomic(Path(access.HELPER),'#!/bin/sh\nexec /usr/bin/python3 -I /opt/rookstride-access/scoped_access.py\n',0o755)
  system.atomic(sudopath,sudo,0o440);access.run(['/usr/sbin/visudo','-cf',str(sudopath)])
  system.atomic(sshpath,ssh,0o644);access.run(['/usr/sbin/sshd','-t'])
  # Validate effective restrictions; Include ordering cannot silently weaken them.
  effective=access.run(['/usr/sbin/sshd','-T','-C','user=rsb00000000000000000000,host=localhost,addr=127.0.0.1']).decode()
  # sshd cannot resolve a not-yet-created user's group; check actual enrolled
  # credentials in live acceptance after their creation, plus static Match here.
  db=access.Access()
  if db.get('meta','config'):
   c=db.get('meta','config')
   if c['server_id']!=server_id or c['deployment_id']!=deployment_id:raise ValueError('Administration identity differs; existing grants were preserved')
   if c.get('disabled'):
    c['disabled']=False;c['revision']+=1;db.put('meta','config',c) # All old credentials/grants stay revoked.
   result={'schema':1,'revision':db.revision(),'objects':db.all('object'),'already_enabled':True}
  else:result=db.initialize(server_id,deployment_id,ep,objects)
  access.run(['/usr/bin/systemctl','reload','ssh'])
  return result
 except Exception:
  for path,original,mode in ((sshpath,original_ssh,0o644),(sudopath,original_sudo,0o440),(target/'scoped_access.py',original_module,0o644),(Path(access.HELPER),original_helper,0o755),(target/'access_cleanup.py',original_cleanup,0o644)):
   if original is None:path.unlink(missing_ok=True)
   else:system.atomic(path,original,mode)
  raise

def main():
 os.umask(0o077)
 try:
  raw=sys.stdin.buffer.read(access.MAX_REQUEST+1)
  if len(raw)>access.MAX_REQUEST:raise ValueError('Request is too large')
  print(access.canonical({'ok':True,'result':install(json.loads(raw))}))
 except (ValueError,OSError,subprocess.SubprocessError) as e:
  print(access.canonical({'ok':False,'error':str(e) if isinstance(e,ValueError) else 'Administration installation failed'}));raise SystemExit(1)
if __name__=='__main__':main()
