import copy,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1];sys.path[:0]=[str(BASE/'server'),str(BASE/'single')]
import engine_lifecycle as e
import maintenance
class AcceptedBridgeUpdates(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.path=self.root/'bridge.service';self.path.write_text('old unit')
  self.record={'operation':'a'*32,'state':'accepted','deployment':'pair','plan':{'exit_protocol':'xray'},'transport':{'dns':{'address':'10.90.0.1'}},'xray_binary':'old','xray_sha256':'oldhash','service_sha256':'oldunit'}
  self.service=e.decorate({'path':str(self.path),'name':'bridge'},self.record)
  self.op={'operation':'b'*32,'group':'xray','target':'new','new_hash':'newhash','snapshot':{'services':[self.service]}}
 def tearDown(self):self.temp.cleanup()
 def test_engine_fields_do_not_change_logical_identity_but_transport_does(self):
  changed=copy.deepcopy(self.record);changed.update(xray_binary='new',xray_sha256='newhash');self.assertEqual(e.identity(self.record),e.identity(changed))
  changed['transport']['dns']['address']='10.91.0.1';self.assertNotEqual(e.identity(self.record),e.identity(changed))
 def test_update_rebinds_recipe_and_hash_without_mutating_topology(self):
  self.path.write_text('new unit');writes=[]
  with patch.object(e.lifecycle,'read',return_value=copy.deepcopy(self.record)),patch.object(e.lifecycle,'write',side_effect=lambda path,value:writes.append(value)),patch.object(e.lifecycle,'candidate_unit',return_value='new unit'):
   e.update(self.op,False)
  self.assertEqual('new',writes[0]['xray_binary']);self.assertEqual('newhash',writes[0]['xray_sha256']);self.assertEqual(self.record['transport'],writes[0]['transport'])
 def test_rollback_restores_original_engine_fields(self):
  changed=dict(self.record,xray_binary='new',xray_sha256='newhash');writes=[]
  with patch.object(e.lifecycle,'read',return_value=changed),patch.object(e.lifecycle,'write',side_effect=lambda path,value:writes.append(value)),patch.object(e.lifecycle,'candidate_unit',return_value='old unit'):
   e.update(self.op,True)
  self.assertEqual('old',writes[0]['xray_binary']);self.assertEqual('oldhash',writes[0]['xray_sha256'])
 def test_topology_change_prevents_engine_update(self):
  changed=copy.deepcopy(self.record);changed['plan']['exit_protocol']='openvpn'
  with patch.object(e.lifecycle,'read',return_value=changed):
   with self.assertRaisesRegex(ValueError,'topology changed'):e.validate(self.service)
class RetainedBridgeHistory(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.units=self.root/'units';self.units.mkdir()
  self.patches=[patch.object(e.pair,'protected',side_effect=Path),patch.object(e.lifecycle,'ROOT',self.root/'lifecycle'),patch.object(e.lifecycle,'ACTIVE',self.root/'lifecycle/active.json'),patch.object(e.native_pair,'UNIT',self.units),patch.object(maintenance,'ROOT',self.root/'helpers')]
  for p in self.patches:p.start()
  plan={'pair':'a'*32,'role':'entry','entry_protocol':'awg','exit_protocol':'awg','server':'192.0.2.1','exit_host':'192.0.2.2','tunnel_port':443,'pool':'10.88.0.0/24','dns':'10.88.0.1'}
  self.manifest={'plan':plan,'bundle':'c'*64,'configure_digest':'d'*64,'helper_history':[{'operation':'e'*32,'previous':'a'*64},{'operation':'f'*32,'previous':'b'*64}]}
  for operation,old,new in [('e'*32,'a'*64,'b'*64),('f'*32,'b'*64,'c'*64)]:
   maintenance.write(maintenance.ROOT/operation/'journal.json',{'operation':operation,'state':'accepted','old_digest':old,'new_digest':new,'manifest':dict(self.manifest,bundle=old)})
  self.old={'operation':'1'*32,'state':'accepted','deployment':plan['pair'],'plan':dict(plan,exit_host='192.0.2.3',tunnel_port=8443),'anchor':e.lifecycle.anchor(dict(self.manifest,bundle='a'*64))}
  self.active=dict(copy.deepcopy(self.old),operation='2'*32,anchor=e.lifecycle.anchor(self.manifest))
  self.store(self.old);self.store(self.active)
  e.lifecycle.write(e.lifecycle.ACTIVE,{'schema':1,'operation':self.active['operation'],'deployment':plan['pair'],'anchor':e.lifecycle.anchor(self.manifest),'route':{'interface':'rsx'+'2'*10,'bridge_ip':'10.90.0.2','exit_host':'192.0.2.3','exit_protocol':'awg'}})
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def path(self,op):return self.units/('rookstride-lifecycle-'+op['operation']+'.service')
 def store(self,op):
  e.lifecycle.write(e.lifecycle.ROOT/'operations'/op['operation']/'journal.json',op);self.path(op).write_text(e.lifecycle.candidate_unit(op))
 def test_two_reviewed_helper_changes_include_both_real_retained_units(self):
  records=e.records(self.manifest,['awg']);self.assertEqual([self.old,self.active],records)
 def test_absent_superseded_unit_is_ignored_before_stale_anchor_check(self):
  self.old['anchor']='unrelated';self.store(self.old);self.path(self.old).unlink()
  self.assertEqual([self.active],e.records(self.manifest,['awg']))
 def test_absent_active_service_or_journal_is_never_ignored(self):
  self.path(self.active).unlink()
  with self.assertRaisesRegex(ValueError,'active replacement bridge service'):e.records(self.manifest,['awg'])
  self.store(self.active);(e.lifecycle.ROOT/'operations'/self.active['operation']/'journal.json').unlink()
  with self.assertRaisesRegex(ValueError,'active replacement bridge record'):e.records(self.manifest,['awg'])
 def test_existing_unit_requires_exact_owned_recipe(self):
  self.path(self.old).write_text(self.path(self.old).read_text()+'ExecStartPost=/bin/true\n')
  with self.assertRaisesRegex(ValueError,'ownership changed'):e.records(self.manifest,['awg'])
  # Only the transactional resume path delegates old/new text validation to its
  # captured per-service snapshot; plan and helper checks remain mandatory.
  self.assertEqual(2,len(e.records(self.manifest,['awg'],verify_units=False)))
  self.old['deployment']='b'*32;e.lifecycle.write(e.lifecycle.ROOT/'operations'/self.old['operation']/'journal.json',self.old)
  with self.assertRaisesRegex(ValueError,'no longer matches'):e.records(self.manifest,['awg'],verify_units=False)
 def test_foreign_deployment_unreviewed_anchor_and_changed_entry_are_rejected(self):
  original=copy.deepcopy(self.old)
  for key,value in [('deployment','b'*32),('anchor','9'*64),('plan',dict(original['plan'],server='192.0.2.4')),('plan',dict(original['plan'],pool='10.89.0.0/24')),('plan',dict(original['plan'],entry_protocol='ikev2')),('plan',dict(original['plan'],dns='10.90.0.1'))]:
   with self.subTest(key=key,value=value):
    changed=copy.deepcopy(original);changed[key]=value;self.store(changed)
    with self.assertRaisesRegex(ValueError,'no longer matches'):e.records(self.manifest,['awg'])
 def test_each_historical_helper_link_needs_its_exact_reviewed_journal(self):
  path=maintenance.ROOT/('e'*32)/'journal.json';original=maintenance.read(path)
  for changed in [dict(original,state='prepared'),dict(original,new_digest='9'*64),dict(original,old_digest='8'*64),dict(original,manifest=dict(original['manifest'],configure_digest='7'*64)),dict(original,manifest=dict(original['manifest'],plan=dict(original['manifest']['plan'],server='192.0.2.9')))]:
   with self.subTest(changed=changed):
    maintenance.write(path,changed)
    with self.assertRaisesRegex(ValueError,'history cannot be verified'):e.records(self.manifest,['awg'])
  path.unlink()
  with self.assertRaisesRegex(ValueError,'history cannot be verified'):e.records(self.manifest,['awg'])
 def test_untrusted_anchor_lists_do_not_authorize_a_retained_consumer(self):
  self.old['anchor']='7'*64;self.old['helper_anchors']=['7'*64];self.store(self.old)
  value=e.lifecycle.read(e.lifecycle.ACTIVE);value['helper_anchors']=['7'*64];e.lifecycle.write(e.lifecycle.ACTIVE,value)
  with self.assertRaisesRegex(ValueError,'no longer matches'):e.records(self.manifest,['awg'])

if __name__=='__main__':unittest.main()
