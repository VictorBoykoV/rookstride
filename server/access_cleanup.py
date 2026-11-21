#!/usr/bin/env python3
"""Owner-reviewed removal of only scoped SSH credentials/configuration.

The disabled root-only database is retained as revocation tombstones. No VPN,
root SSH credentials, unrelated Unix account or downloaded protocol is removed.
"""
import grp,json,os,pwd,re,subprocess
from pathlib import Path

MARKER='# Rookstride scoped administration v1\n'
ACCOUNTS=Path('/var/lib/rookstride-access-accounts')
CONFIGS=(Path('/etc/ssh/sshd_config.d/80-rookstride-access.conf'),Path('/etc/sudoers.d/rookstride-access'))

def plan(credentials):
 accounts=[]
 for name in sorted(credentials):
  if not re.fullmatch(r'rs[bdp][a-f0-9]{20}',name):raise ValueError('Unexpected credential identity; removal stopped')
  try:entry=pwd.getpwnam(name)
  except KeyError:entry=None
  if entry:
   if entry.pw_uid==0 or entry.pw_dir!=str(ACCOUNTS/name) or entry.pw_shell!='/bin/sh' or entry.pw_gid!=grp.getgrnam('rookstride-access').gr_gid:raise ValueError('Credential account ownership changed; removal stopped')
  home=ACCOUNTS/name
  if home.is_symlink() or (home.exists() and (home.stat().st_uid!=0 or home.stat().st_mode & 0o022)):raise ValueError('Credential directory ownership changed; removal stopped')
  if home.exists():
   children=list(home.iterdir())
   if any(p.name!='authorized_keys' or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 for p in children):raise ValueError('Unrecognized files in credential directory; removal stopped')
  accounts.append(name)
 for p in CONFIGS:
  if p.exists() and (p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or not p.read_text().startswith(MARKER)):raise ValueError('Management configuration ownership changed; removal stopped')
 return {'accounts':accounts,'files':[str(p) for p in CONFIGS if p.exists()],'vpn_credentials_preserved':True,'owner_ssh_preserved':True,'revocation_tombstones_retained':True}

def apply(credentials,system):
 inspected=plan(credentials)
 # The caller has committed disabled/revoked authority before OS side effects.
 for name in inspected['accounts']:
  system.revoke(name)
  try:pwd.getpwnam(name)
  except KeyError:pass
  else:
   result=subprocess.run(['/usr/sbin/userdel',name],capture_output=True,timeout=30)
   if result.returncode:raise ValueError('A restricted account remains; it is revoked. Review cleanup again.')
  home=ACCOUNTS/name
  if home.exists():
   key=home/'authorized_keys'
   if key.exists():key.unlink()
   home.rmdir()
 saved={path:path.read_text() for path in CONFIGS if path.exists()}
 try:
  for path in saved:path.unlink()
  result=subprocess.run(['/usr/sbin/sshd','-t'],capture_output=True,timeout=30)
  if result.returncode:raise ValueError('SSH configuration needs owner review')
  result=subprocess.run(['/usr/bin/systemctl','reload','ssh'],capture_output=True,timeout=30)
  if result.returncode:raise ValueError('SSH configuration reload needs owner review')
 except Exception:
  for path,text in saved.items():system.atomic(path,text,0o440 if 'sudoers' in str(path) else 0o644)
  raise
 return {'disabled':True,'removed_accounts':len(inspected['accounts']),'vpn_credentials_preserved':True,'owner_ssh_preserved':True,'revocation_tombstones_retained':True}
