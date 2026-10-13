"""A failed blocking-list download must not silently remove existing protection."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from rookstride import admin

class FilterSwitchTests(unittest.TestCase):
 def switch(self,loaded):
  with tempfile.TemporaryDirectory() as directory:
   login=Path(directory)/'login';login.write_text('Dashboard: http://10.253.0.1:3000\nUsername: admin\nPassword: test-only\n')
   original=admin.FILTERS['standard'][1];target=admin.FILTERS['strong'][1]
   filters=[dict(url=original,name='Current',enabled=True,rules_count=200),dict(url=target,name='New',enabled=False,rules_count=0)]
   disabled=[]
   class Response:
    def __init__(self,value):self.value=value
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self):return json.dumps(self.value).encode()
   def urlopen(req,timeout):
    endpoint=req.full_url.rsplit('/',1)[-1]
    if endpoint=='status':return Response({'filters':copy.deepcopy(filters)})
    if endpoint=='set_url':
     data=json.loads(req.data)
     for f in filters:
      if f['url']==data['url']:
       f['enabled']=data['data']['enabled']
       if f['url']==target and loaded:f['rules_count']=1234
       if not f['enabled']:disabled.append(f['url'])
    return Response({})
   actual=Path
   def path(value):return login if str(value).endswith('adguard-login.txt') else actual(directory)/'absent'
   with patch.object(admin,'Path',side_effect=path),patch.object(admin.urllib.request,'urlopen',side_effect=urlopen),patch.object(admin.time,'sleep'):
    if loaded:
     result=admin.adguard({'level':'strong'});self.assertTrue(any(f['enabled'] and f['rules']==1234 for f in result['filters']));self.assertEqual([original],disabled)
    else:
     with self.assertRaisesRegex(ValueError,'Previous filters remain enabled'):admin.adguard({'level':'strong'})
     self.assertEqual([],disabled);self.assertTrue(filters[0]['enabled'])
 def test_unloaded_target_keeps_existing_filter(self):self.switch(False)
 def test_loaded_target_allows_switch(self):self.switch(True)

if __name__=='__main__':unittest.main()
