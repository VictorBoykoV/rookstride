"""Server authority and review contract for bounded infrastructure changes."""
import json, unittest, subprocess, sys
from pathlib import Path
from unittest.mock import patch
import test_scoped_access as fixture
Effects=fixture.Effects
a=fixture.a

class MaintenanceEffects(Effects):
 def __init__(self):
  super().__init__();self.guard='state-1';self.affected=[];self.changed=0
 def execute(self,obj,op,params):
  if not op.startswith(('services.','filtering.')):return super().execute(obj,op,params)
  self.calls.append((obj['id'],op,dict(params)))
  affected=self.affected or [{'protocol':obj['protocol'],'instance':obj['instance']}]
  if op=='filtering.read':return {'protection_enabled':True,'_affected':affected}
  if op.endswith('.review'):return {'guard':self.guard,'affected':affected,'message':'Reviewed listener change'}
  if params['_guard']!=self.guard:raise a.Denied('Service state changed')
  if params['_affected']!=affected:raise a.Denied('Shared consumers changed')
  self.changed+=1;return {'changed':True,'running':True}

class InfrastructureTest(unittest.TestCase):
 setUpClass=classmethod(fixture.ScopedAccessTest.setUpClass.__func__)
 call=fixture.ScopedAccessTest.call
 invite=fixture.ScopedAccessTest.invite
 proof=fixture.ScopedAccessTest.proof
 enroll=fixture.ScopedAccessTest.enroll
 mutate=fixture.ScopedAccessTest.mutate
 setup_peer=fixture.ScopedAccessTest.setup_peer
 def setUp(self):
  fixture.ScopedAccessTest.setUp(self);self.effects=MaintenanceEffects();self.db.system=self.effects
 def tearDown(self):fixture.ScopedAccessTest.tearDown(self)
 def review(self,account,group='services',parameters=None):
  return self.call(group+'.review',account,object_id=self.obj['id'],parameters=parameters if parameters is not None else {'action':'restart'})
 def apply(self,account,review,group='services',**overrides):
  req={'object_id':self.obj['id'],'parameters':{'review_token':review['review_token']},'expected_revision':review['revision'],'operation_id':a.token('op-')};req.update(overrides)
  return self.call(group+'.apply',account,**req)
 def test_infrastructure_can_review_apply_and_replay_is_denied(self):
  _,user=self.enroll('infrastructure');review=self.review(user['account'])
  self.assertNotIn('guard',review);self.assertEqual(0,self.effects.changed)
  self.assertTrue(self.apply(user['account'],review)['changed'])
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  self.assertEqual(1,self.effects.changed)
 def test_user_manager_and_viewer_cannot_perform_service_actions(self):
  for role in ('viewer','user_manager'):
   invite=self.invite(role);user=self.call('enrollment.accept',invite['bootstrap']['account'],**self.proof(invite,self.key1 if role=='viewer' else self.key2))
   with self.assertRaises(a.Denied):self.review(user['account'])
  self.assertFalse(self.effects.calls)
 def test_review_cannot_be_used_for_another_object_or_action(self):
  _,user=self.enroll('infrastructure',{'kind':'server','id':'server-first','users':'all'});review=self.review(user['account'])
  with self.assertRaises(a.Denied):self.apply(user['account'],review,object_id=self.obj2['id'])
  with self.assertRaises(a.Denied):self.apply(user['account'],review,'filtering')
  with self.assertRaises(a.Denied):self.apply(user['account'],review,parameters={'review_token':review['review_token'],'action':'repair'})
  self.assertEqual(0,self.effects.changed)
 def test_shared_filter_requires_every_consumers_scope(self):
  self.effects.affected=[{'protocol':self.obj['protocol'],'instance':self.obj['instance']},{'protocol':self.obj2['protocol'],'instance':self.obj2['instance']}]
  _,user=self.enroll('infrastructure')
  with self.assertRaises(a.Denied):self.review(user['account'],'filtering',{'enabled':False})
  with self.assertRaises(a.Denied):self.call('filtering.read',user['account'],object_id=self.obj['id'],parameters={})
  self.call('grants.update',grant_id=user['grant_id'],role='infrastructure',scope={'kind':'server','id':'server-first','users':'all'},expected_revision=self.db.revision())
  review=self.review(user['account'],'filtering',{'level':'strong'});self.assertTrue(self.apply(user['account'],review,'filtering')['changed'])
 def test_unknown_consumer_denied_not_silently_ignored(self):
  self.effects.affected=[{'protocol':'xray','instance':'unregistered'}];_,user=self.enroll('infrastructure',{'kind':'server','id':'server-first','users':'all'})
  with self.assertRaises(a.Denied):self.review(user['account'],'filtering',{'enabled':True})
 def test_current_revision_and_revocation_invalidate_review(self):
  _,user=self.enroll('infrastructure');review=self.review(user['account'])
  self.db.bump()
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  review=self.review(user['account']);self.call('devices.revoke',device_id=user['device_id'],expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  self.assertEqual(0,self.effects.changed)
 def test_changed_install_instance_and_expiry_invalidate_review(self):
  _,user=self.enroll('infrastructure');review=self.review(user['account']);replacement={**self.obj,'instance':'replacement'};self.db.put('object',replacement['id'],replacement)
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  self.db.put('object',self.obj['id'],self.obj);review=self.review(user['account']);self.now+=301
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
 def test_adapter_state_change_consumes_review_without_replaying_failed_action(self):
  _,user=self.enroll('infrastructure');review=self.review(user['account']);self.effects.guard='changed'
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  self.effects.guard='state-1'
  with self.assertRaises(a.Denied):self.apply(user['account'],review)
  self.assertEqual(0,self.effects.changed)
 def test_client_cannot_supply_command_service_or_private_scope(self):
  _,user=self.enroll('infrastructure')
  for params in ({'action':'restart','command':'id'},{'action':'restart','service':'sshd'},{'action':'wipe'},{'_affected':[]},{'enabled':'true'},{'level':'private-url'}):
   with self.assertRaises(ValueError):self.review(user['account'],'filtering' if 'enabled' in params or 'level' in params else 'services',params)
  self.assertFalse(self.effects.calls)
 def test_owner_inventory_refresh_tracks_peer_replacement_without_rebinding_protocol_grant(self):
  peer,effects,obj,link=self.setup_peer();_,user=self.enroll('infrastructure',{'kind':'protocol','id':obj['id'],'users':'all'})
  replacement={**obj,'id':'vpn-new-peer','instance':'new-peer-instance'};peer.db.execute("DELETE FROM records WHERE kind='object' AND id=?",(obj['id'],));peer.put('object',replacement['id'],replacement)
  with patch.object(a,'discover',return_value=[self.obj,self.obj2]):report=self.call('inventory.refresh',expected_revision=self.db.revision())
  self.assertIn(replacement['id'],[o['id'] for o in report['objects']]);self.assertNotIn(obj['id'],[o['id'] for o in report['objects']])
  self.assertEqual([],self.call('capabilities',user['account'])['objects'])
  with self.assertRaises(a.Denied):self.call('inventory.refresh',user['account'],expected_revision=self.db.revision())
 def test_real_helper_checks_service_digest_under_the_protocol_lock(self):
  folder=Path(self.temp.name)/'real-service';folder.mkdir();state=folder/'state.json';state.write_text(json.dumps({'protocol':'awg','instance':'instance-first','users':[]}))
  (folder/'run.py').write_text("import json\nfrom pathlib import Path\nfrom types import SimpleNamespace\nfolder=Path(__file__).parent\ndef load(protocol):return json.loads((folder/'state.json').read_text())\ndef command(args):\n (folder/'effect').write_text(json.dumps(args))\n return ''\ndef ensure_no_runtime_update():\n if (folder/'pending-runtime').exists():raise ValueError('Finish the runtime update first')\nruntime=SimpleNamespace(user_updates=SimpleNamespace(ensure_no_runtime_update=ensure_no_runtime_update),load=load,directory=lambda protocol:folder,check_container=lambda state:{'Id':'container-id','Config':{},'HostConfig':{}},container=lambda protocol:'rookstride-single-'+protocol,command=command,health=lambda state:{'running':True})\n")
  code=a.ADAPTER_RUNNER.replace('/run/rookstride-management.lock',str(folder/'manage.lock')).replace('/run/rookstride-single.lock',str(folder/'single.lock'))
  def invoke(req):
   completed=subprocess.run([sys.executable,'-I','-c',code,str(folder/'run.py'),'single'],input=json.dumps(req).encode(),capture_output=True,timeout=10)
   return json.loads(completed.stdout)
  req={'action':'scoped-infrastructure','protocol':'awg','expected_instance':'instance-first','_operation':'services.review','_parameters':{'action':'restart'}}
  review=invoke(req)['result'];self.assertFalse((folder/'effect').exists())
  state.write_text(json.dumps({'protocol':'awg','instance':'instance-first','users':[{'login':'new-account'}]}))
  result=invoke({**req,'_operation':'services.apply','_guard':review['guard'],'_affected':review['affected']});self.assertFalse(result['ok']);self.assertFalse((folder/'effect').exists())
  review=invoke(req)['result'];(folder/'pending-runtime').touch()
  blocked=invoke({**req,'_operation':'services.apply','_guard':review['guard'],'_affected':review['affected']});self.assertFalse(blocked['ok']);self.assertFalse((folder/'effect').exists())
  (folder/'pending-runtime').unlink();result=invoke({**req,'_operation':'services.apply','_guard':review['guard'],'_affected':review['affected']})
  self.assertTrue(result['ok']);self.assertEqual(['docker','restart','rookstride-single-awg'],json.loads((folder/'effect').read_text()))
 def test_peer_review_uses_target_revision_and_current_authority_role(self):
  peer,_,obj,link=self.setup_peer();remote=MaintenanceEffects();peer.system=remote;_,user=self.enroll('infrastructure',{'kind':'deployment','id':'deployment','users':'all'})
  review=self.call('services.review',user['account'],object_id=obj['id'],parameters={'action':'restart'})
  result=self.call('services.apply',user['account'],object_id=obj['id'],parameters={'review_token':review['review_token']},expected_revision=review['revision'],operation_id='peer-maintenance')
  self.assertTrue(result['changed']);self.assertEqual(1,remote.changed)
  review=self.call('services.review',user['account'],object_id=obj['id'],parameters={'action':'restart'})
  self.call('grants.update',grant_id=user['grant_id'],role='viewer',scope={'kind':'deployment','id':'deployment','users':'all'},expected_revision=self.db.revision())
  with self.assertRaises(a.Denied):self.call('services.apply',user['account'],object_id=obj['id'],parameters={'review_token':review['review_token']},expected_revision=review['revision'],operation_id='rejected-peer-maintenance')
  self.assertEqual(1,remote.changed)

if __name__=='__main__':unittest.main()
