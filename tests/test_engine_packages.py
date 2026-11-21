import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1];sys.path[:0]=[str(BASE/'server'),str(BASE/'single')]
import engine_packages as p
class Packages(unittest.TestCase):
 def test_only_owned_source_package_family_is_accepted(self):
  good='libstrongswan\t5.9.13-2\tstrongswan\tinstalled\nopenssh-server\t1\topenssh\tinstalled\n'
  with patch.object(p,'run',return_value=good):self.assertEqual({'libstrongswan':'5.9.13-2'},p.installed())
  with patch.object(p,'run',return_value='unreviewed-plugin\t1\tstrongswan\tinstalled\n'):
   with self.assertRaisesRegex(ValueError,'layout'):p.installed()
 def test_rollback_package_must_exist_with_repository_hash(self):
  with patch.object(p,'run',return_value='Package: libstrongswan\nVersion: 5.9.13-2\nStatus: installed\n'):
   with self.assertRaisesRegex(ValueError,'retrievable'):p.metadata('libstrongswan','5.9.13-2')
  raw='Package: libstrongswan\nVersion: 5.9.13-2\nSHA256: '+'a'*64+'\nSize: 42\n'
  with patch.object(p,'run',return_value=raw):self.assertEqual(('a'*64,42),p.metadata('libstrongswan','5.9.13-2'))
 def test_simulated_plan_blocks_foreign_dependencies_and_removal(self):
  for response in ('Inst libc6 [1] (2 Ubuntu)\n','Remv openssh-server [1]\n'):
   with patch.object(p,'run',return_value=response):
    with self.assertRaises(ValueError):p.plan(['/private/pkg.deb'],{'libstrongswan'})
  with patch.object(p,'run',return_value='Inst libstrongswan [1] (2 Ubuntu)\n'):p.plan(['/private/pkg.deb'],{'libstrongswan'})
 def test_external_package_edit_or_package_tamper_invalidates_operation(self):
  op={'snapshot':{'services':[{'packages':{'libstrongswan':'1'},'configs':{'/private/config':'config'}}]},'candidate_versions':{'libstrongswan':'2'},'prior_packages':{'libstrongswan':{'path':'/private/old','sha256':'old'}},'candidate_packages':{'libstrongswan':{'path':'/private/new','sha256':'new'}}}
  with patch.object(p,'installed',return_value={'libstrongswan':'3'}):
   with self.assertRaisesRegex(ValueError,'outside'):p.same_identity(op,lambda path:'')
  with patch.object(p,'installed',return_value={'libstrongswan':'1'}):
   with self.assertRaisesRegex(ValueError,'integrity'):p.same_identity(op,lambda path:'config' if str(path).endswith('config') else 'tampered')
 def test_partial_package_transaction_can_resume_exact_reviewed_versions(self):
  op={'snapshot':{'services':[{'packages':{'libstrongswan':'1','strongswan':'1'},'configs':{}}]},'candidate_versions':{'libstrongswan':'2','strongswan':'2'},'prior_packages':{},'candidate_packages':{}}
  with patch.object(p,'installed',return_value={'libstrongswan':'2','strongswan':'1'}):p.same_identity(op,lambda path:'')
if __name__=='__main__':unittest.main()
