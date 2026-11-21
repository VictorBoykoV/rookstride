import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'single'))
import runtime,filtering
spec=importlib.util.spec_from_file_location('pair_coexist_api',ROOT/'single/run.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
class PairCoexistenceTests(unittest.TestCase):
 def test_only_explicit_disjoint_openvpn_on_active_native_awg_entry_is_allowed(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);manifest=root/'manifest.json';m=dict(version=2,activated=True,plan=dict(pair='a'*32,role='entry',entry_protocol='awg',client_pool='10.66.0.0/24'),jobs={});manifest.write_text(json.dumps(m));original=Path.stat
   def stat(path,*a,**kw):return SimpleNamespace(st_uid=0) if path==manifest else original(path,*a,**kw)
   inventory=dict(compatible_os=True,os='Ubuntu 24.04',ports=[],pair_node=True)
   with patch.object(api,'PAIR_MANIFEST',manifest),patch.object(api,'inspect',return_value=inventory),patch.object(runtime,'directory',return_value=root/'absent'),patch.object(Path,'stat',stat):
    req=dict(protocol='openvpn',server='entry.example.net',coexist_pair='a'*32);self.assertEqual('openvpn',api.plan(req)['protocol'])
    for change in ({'coexist_pair':'b'*32},{'coexist_pair':None},{'protocol':'awg'},{'protocol':'xray'}):
     with self.assertRaises(ValueError):api.plan(dict(req,**change))
    for changed in [dict(m,activated=False),dict(m,version=1),dict(m,plan=dict(m['plan'],role='exit')),dict(m,plan=dict(m['plan'],entry_protocol='openvpn'))]:
     manifest.write_text(json.dumps(changed))
     with self.assertRaises(ValueError):api.plan(req)
 def test_local_single_dns_never_shadows_the_pair_exit_resolver(self):
  with tempfile.TemporaryDirectory() as directory:
   transport=Path(directory)/'transport.json';transport.write_text(json.dumps({'dns':{'address':'10.253.0.1'}}))
   with patch.object(filtering,'PAIR_TRANSPORT',transport),patch.object(filtering,'command',return_value=SimpleNamespace(stdout='[]')):self.assertEqual('10.255.253.1',filtering.choose_address())
if __name__=='__main__':unittest.main()
