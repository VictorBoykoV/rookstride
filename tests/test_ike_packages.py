import importlib.util,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('ike_packages',Path(__file__).parents[1]/'server/ike_packages.py');packages=importlib.util.module_from_spec(spec);spec.loader.exec_module(packages)

class IkePackageTransitions(unittest.TestCase):
 def test_fresh_install_still_forbids_package_removals(self):
  with patch.object(packages,'installed',return_value=False),patch.object(packages,'run') as run,patch.object(packages,'remember_owned'):
   packages.install('starter',['curl']);self.assertIn('--no-remove',run.call_args.args[0]);self.assertIn('--no-auto-remove',run.call_args.args[0])
 def test_owned_inactive_daemon_switch_has_an_exact_removal_preview(self):
  with patch.object(packages,'installed',return_value=True),patch.object(packages,'ownership',return_value={'packages':['charon-systemd']}),patch.object(packages,'unmodified_config'),patch.object(packages,'remember_owned') as remember,patch.object(packages,'run',return_value=SimpleNamespace(returncode=1,stdout='Remv charon-systemd [1]\n')) as run:
   packages.install('starter',['curl']);actual=run.call_args.args[0];self.assertIn('charon-systemd-',actual);self.assertNotIn('--no-remove',actual);self.assertIn('--no-auto-remove',actual);remember.assert_called_once_with('starter')
 def test_unowned_daemon_is_never_removed(self):
  with patch.object(packages,'installed',return_value=True),patch.object(packages,'ownership',return_value={'packages':[]}),patch.object(packages,'run',return_value=SimpleNamespace(returncode=0,stdout='Remv charon-systemd [1]\n')) as run:
   with self.assertRaisesRegex(ValueError,'not owned'):packages.install('starter',[])
   self.assertFalse(any('-qq' in call.args[0] for call in run.call_args_list))
 def test_distribution_coexistence_does_not_remove_an_unowned_package(self):
  with patch.object(packages,'installed',return_value=True),patch.object(packages,'ownership') as owner,patch.object(packages,'run',return_value=SimpleNamespace(returncode=0,stdout='')),patch.object(packages,'remember_owned') as remember:
   packages.install('starter',[]);owner.assert_not_called();remember.assert_called_once_with('starter')
 def test_active_daemon_or_unrelated_removal_is_refused(self):
  for active,extra in ((True,False),(False,True)):
   def response(args,**kw):return SimpleNamespace(returncode=0 if active else 1,stdout='Remv charon-systemd [1]\n'+('Remv unrelated-application [2]\n' if extra else ''))
   with patch.object(packages,'installed',return_value=True),patch.object(packages,'ownership',return_value={'packages':['charon-systemd']}),patch.object(packages,'unmodified_config'),patch.object(packages,'remember_owned') as remember,patch.object(packages,'run',side_effect=response) as run:
    with self.assertRaises(ValueError):packages.install('starter',[])
    remember.assert_not_called();self.assertFalse(any('-qq' in call.args[0] for call in run.call_args_list))
 def test_custom_swanctl_configuration_is_preserved(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder)/'swanctl.conf';p.write_text('connections { custom { } }')
   with patch.object(packages,'run',return_value=SimpleNamespace(stdout='')),patch.object(packages,'Path',side_effect=lambda value:Path(folder) if value=='/etc/swanctl' else Path(value)):
    with self.assertRaisesRegex(ValueError,'configuration needs review'):packages.unmodified_config('systemd')
   self.assertIn('custom',p.read_text())
 def test_nonsecret_ownership_marker_survives_reset_and_rejects_wrong_owner(self):
  with tempfile.TemporaryDirectory() as folder:
   marker=Path(folder)/'packages.json'
   with patch.object(packages,'MARKER',marker),patch.object(packages,'secure',side_effect=lambda value:value),patch.object(packages,'installed',return_value=True):
    packages.remember_owned('systemd');packages.remember_owned('starter');self.assertEqual(sorted(packages.PACKAGES.values()),packages.ownership()['packages']);marker.write_text('{"owner":"someone-else","packages":[]}')
    with self.assertRaises(ValueError):packages.ownership()
