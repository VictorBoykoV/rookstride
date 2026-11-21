"""Account-scoped live metrics; keys and endpoint identifiers must not escape."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'single'))
import runtime
class AwgMetricsTests(unittest.TestCase):
 def test_recent_stale_never_connected_unknown_and_disabled_peers(self):
  state={'users':[dict(login='recent',public='pub-one',address='10.67.0.2'),dict(login='stale',public='pub-two',address='10.67.0.3'),dict(login='unused',public='pub-three',address='10.67.0.4'),dict(login='revoked',public='pub-four',address='10.67.0.5',enabled=False)]}
  rows=['secret-server\tpublic\t51820\toff']
  for key,when in [('pub-one',990),('pub-two',100),('pub-three',0),('pub-four',999),('unknown',999)]:rows.append(f'{key}\tsecret-psk\t198.51.100.3:1234\t10.67.0.2/32\t{when}\t123\t456\t25')
  result=runtime.awg_connections(state,'\n'.join(rows),now=1000)
  self.assertEqual([r['user'] for r in result],['recent','stale','unused']);self.assertEqual([r['recent'] for r in result],[True,False,False])
  self.assertEqual(result[0]['upload'],123);self.assertEqual(result[0]['download'],456)
  for secret in ['pub-one','secret','198.51.100']:self.assertNotIn(secret,str(result))
 def test_bad_negative_and_future_handshakes_are_not_online(self):
  state={'users':[dict(login='a',public='key',address='10.67.0.2')]}
  for payload in ['key\tpsk\tendpoint\tip\tbad\t1\t2\t25','key\tpsk\tendpoint\tip\t90\t-1\t2\t25','truncated']:
   self.assertEqual(runtime.awg_connections(state,'header\n'+payload,now=100),[])
  result=runtime.awg_connections(state,'header\nkey\tpsk\tendpoint\tip\t200\t0\t0\t25',now=100)
  self.assertFalse(result[0]['recent'])

class AwgGenerationTests(unittest.TestCase):
 def test_daemon_restart_changes_generation_without_exposing_container_identity(self):
  from unittest.mock import patch
  state={'protocol':'awg','instance':'fixture','users':[dict(login='phone',public='key',address='10.67.0.2')]}
  generations=[]
  for started in ['2026-10-23T00:00:00Z','2026-10-23T00:01:00Z']:
   with patch.object(runtime,'check_container',return_value={'State':{'Running':True,'StartedAt':started}}),patch.object(runtime,'command',side_effect=['51820','key','private\tpublic\t51820\toff\nkey\tsecret\tendpoint\tip\t1\t20\t30\t25']):
    status=runtime.health(state);self.assertTrue(status['monitoring_available']);generations.append(status['connections'][0]['generation']);self.assertNotIn(started,str(status))
  self.assertNotEqual(generations[0],generations[1])
