import importlib.util,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('access_cleanup',ROOT/'server/access_cleanup.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class AccessCleanupTest(unittest.TestCase):
 def test_unrelated_unix_accounts_are_never_removal_candidates(self):
  for name in ('root','ubuntu','rsdshort','../../root','other'):
   with self.assertRaises(ValueError):c.plan([name])
 def test_changed_home_or_group_refuses_managed_account_removal(self):
  account='rsd'+'a'*20
  for entry in (SimpleNamespace(pw_uid=0,pw_dir=str(c.ACCOUNTS/account),pw_shell='/bin/sh',pw_gid=900),SimpleNamespace(pw_uid=900,pw_dir='/home/unrelated',pw_shell='/bin/sh',pw_gid=900),SimpleNamespace(pw_uid=900,pw_dir=str(c.ACCOUNTS/account),pw_shell='/bin/sh',pw_gid=901)):
   with patch.object(c.pwd,'getpwnam',return_value=entry),patch.object(c.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=900)):
    with self.assertRaises(ValueError):c.plan([account])
 def test_already_absent_owned_accounts_are_safe_to_review(self):
  with tempfile.TemporaryDirectory() as temp,patch.object(c,'ACCOUNTS',Path(temp)/'accounts'),patch.object(c,'CONFIGS',()),patch.object(c.pwd,'getpwnam',side_effect=KeyError):
   review=c.plan(['rsd'+'a'*20]);self.assertTrue(review['vpn_credentials_preserved']);self.assertTrue(review['owner_ssh_preserved']);self.assertEqual(1,len(review['accounts']))
if __name__=='__main__':unittest.main()
