"""Real status-v3 boundary: sessions, restart/reconnect generations and no endpoints."""
import copy,datetime,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
import openvpn_metrics as metrics,runtime
FIELDS=['Common Name','Real Address','Virtual Address','Virtual IPv6 Address','Bytes Received','Bytes Sent','Connected Since','Connected Since (time_t)','Username','Client ID','Peer ID','Data Channel Cipher']
NOW=1792713600
DAEMON=datetime.datetime.fromtimestamp(NOW-100,datetime.timezone.utc).isoformat().replace('+00:00','Z')
STATE=dict(protocol='openvpn',instance='fixture-instance',users=[dict(login='phone'),dict(login='unused'),dict(login='revoked',enabled=False)])
def report(rows=None,fields=None,stamp=NOW,end=True):
 fields=fields or FIELDS
 rows=rows if rows is not None else [dict(zip(FIELDS,['phone','198.51.100.7:1234','10.68.0.2','', '123','456','ignored display time',str(NOW-20),'UNDEF','1','0','AES-256-GCM']))]
 return '\n'.join(['TITLE\tOpenVPN fixture','TIME\tignored\t'+str(stamp),'HEADER\tCLIENT_LIST\t'+'\t'.join(fields),*['CLIENT_LIST\t'+'\t'.join(r.get(f,'future-value') for f in fields) for r in rows],*(['END'] if end else [])])+'\n'
class OpenVpnMetrics(unittest.TestCase):
 def test_docker_nanosecond_precision_is_supported_on_older_python(self):
  base='2026-11-02T17:00:00'
  for fraction in ('','1','12','123','1234','12345','123456','1234567','12345678','123456789'):
   stamp=base+('.'+fraction if fraction else '')+'Z'
   expected=datetime.datetime(2026,11,2,17,0,0,int(fraction.ljust(6,'0')[:6]) if fraction else 0,tzinfo=datetime.timezone.utc).timestamp()
   self.assertEqual(expected,metrics.daemon_time(stamp))
 def test_docker_generation_rejects_malformed_or_ambiguous_timestamps(self):
  for stamp in (None,0,'2026-11-02T17:00:00','2026-11-02T17:00:00+01:00','2026-11-02T17:00:00.1234567890Z','2026-11-02T17:00:00.Z','2026-99-02T17:00:00Z'):
   with self.assertRaises(ValueError):metrics.daemon_time(stamp)

 def test_named_columns_and_future_extensions_preserve_direction_and_hide_endpoints(self):
  base=metrics.parse(STATE,report(),DAEMON,NOW)
  extended=list(reversed(FIELDS))+['Future Extension']
  self.assertEqual(base,metrics.parse(STATE,report(fields=extended),DAEMON,NOW));self.assertEqual(123,base[0]['upload']);self.assertEqual(456,base[0]['download']);self.assertEqual(1,base[0]['sessions']);self.assertTrue(base[0]['recent']);self.assertEqual(0,base[1]['sessions'])
  self.assertNotIn('198.51.100',json.dumps(base));self.assertNotIn('revoked',json.dumps(base))
 def test_shared_login_sums_current_sessions_and_ignores_revoked_or_unknown(self):
  a=dict(zip(FIELDS,['phone','private-endpoint','10.68.0.2','','10','20','display',str(NOW-20),'UNDEF','1','0','AES']))
  b=dict(a,**{'Client ID':'2','Bytes Received':'30','Bytes Sent':'40'})
  data=metrics.parse(STATE,report([a,b,dict(a,**{'Common Name':'revoked'}),dict(a,**{'Common Name':'unknown'})]),DAEMON,NOW)
  self.assertEqual((40,60,2),(data[0]['upload'],data[0]['download'],data[0]['sessions']))
 def test_empty_complete_snapshot_is_zero_but_missing_or_stale_is_not(self):
  self.assertTrue(all(x['sessions']==0 for x in metrics.parse(STATE,report([]),DAEMON,NOW)))
  for text in [report(end=False),report(stamp=NOW-46),report(stamp=NOW+11),report().replace('Bytes Sent','Renamed Counter'),report().replace('\t123\t','\t-1\t'),report().replace('\t456\t','\t9223372036854775808\t')]:
   with self.subTest(text=text[:25]),self.assertRaises(ValueError):metrics.parse(STATE,text,DAEMON,NOW)
 def test_generation_changes_on_session_reconnect_or_daemon_restart_not_poll(self):
  first=metrics.parse(STATE,report(),DAEMON,NOW)[0]['generation']
  self.assertEqual(first,metrics.parse(STATE,report(stamp=NOW+1),DAEMON,NOW+1)[0]['generation'])
  self.assertNotEqual(first,metrics.parse(STATE,report().replace('\t1\t0\t','\t2\t0\t'),DAEMON,NOW)[0]['generation'])
  restarted=datetime.datetime.fromtimestamp(NOW-1,datetime.timezone.utc).isoformat().replace('+00:00','Z')
  self.assertNotEqual(first,metrics.parse(STATE,report(),restarted,NOW)[0]['generation'])
 def test_duplicate_session_identity_and_rows_from_before_the_daemon_are_rejected(self):
  raw=report();line=next(x for x in raw.splitlines() if x.startswith('CLIENT_LIST'))
  with self.assertRaises(ValueError):metrics.parse(STATE,raw.replace('END',line+'\nEND'),DAEMON,NOW)
  with self.assertRaises(ValueError):metrics.parse(STATE,report(stamp=NOW-30),datetime.datetime.fromtimestamp(NOW-10,datetime.timezone.utc).isoformat().replace('+00:00','Z'),NOW)
 def test_reader_rejects_links_fifos_oversize_and_old_daemon_files(self):
  with tempfile.TemporaryDirectory() as temp,patch.object(runtime,'STATE',Path(temp)):
   root=runtime.directory('openvpn')/'runtime';root.mkdir(parents=True);path=root/'status.csv';path.write_text(report());os.utime(path,(NOW,NOW));state=copy.deepcopy(STATE);container={'State':{'StartedAt':DAEMON}}
   with patch.object(metrics.time,'time',return_value=NOW):self.assertEqual(1,metrics.read(state,container,runtime)[0]['sessions'])
   path.unlink();outside=Path(temp)/'elsewhere';outside.write_text(report());path.symlink_to(outside)
   with self.assertRaises(OSError):metrics.read(state,container,runtime)
   path.unlink();os.mkfifo(path)
   with self.assertRaises(ValueError):metrics.read(state,container,runtime)
   path.unlink();path.write_bytes(b'x'*(metrics.LIMIT+1))
   with self.assertRaises(ValueError):metrics.read(state,container,runtime)
   path.write_text(report());os.utime(path,(NOW-200,NOW-200))
   with self.assertRaises(ValueError):metrics.read(state,container,runtime)
 def test_health_uses_session_scope_and_never_invents_zero_on_read_failure(self):
  container={'State':{'Running':True,'StartedAt':DAEMON}}
  with patch.object(runtime,'check_container',return_value=container),patch.object(metrics,'read',return_value=metrics.parse(STATE,report(),DAEMON,NOW)):
   value=runtime.health(STATE);self.assertTrue(value['monitoring_available']);self.assertEqual('sessions',value['statistics_kind']);self.assertEqual('active-sessions',value['statistics_scope'])
  with patch.object(runtime,'check_container',return_value=container),patch.object(metrics,'read',side_effect=ValueError('stale')):
   value=runtime.health(STATE);self.assertFalse(value['monitoring_available']);self.assertEqual([],value['connections'])
if __name__=='__main__':unittest.main()
