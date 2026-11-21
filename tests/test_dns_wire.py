import ipaddress,struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'integration'))
import dns_wire

class DnsWireAcceptance(unittest.TestCase):
 def packet(self,address=None,rcode=0):
  question=b'\x07example\x03com\x00\x00\x01\x00\x01';answer=b''
  if address:answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+ipaddress.IPv4Address(address).packed
  return struct.pack('!6H',42,0x8180|rcode,1,int(address is not None),0,0)+question+answer
 def test_each_supported_adguard_blocking_reply_is_recognized(self):
  for packet in (self.packet(rcode=3),self.packet(),self.packet('0.0.0.0'),self.packet('127.0.0.1')):
   value=dns_wire.response(packet,42);self.assertTrue(dns_wire.blocked(value));self.assertFalse(dns_wire.allowed(value))
 def test_real_address_is_not_falsely_accepted_as_ad_blocking(self):
  value=dns_wire.response(self.packet('1.1.1.1'),42);self.assertTrue(dns_wire.allowed(value));self.assertFalse(dns_wire.blocked(value))
 def test_wrong_identity_and_truncated_records_fail(self):
  packet=self.packet('1.1.1.1')
  for data,ident in ((packet,43),(packet[:-1],42),(packet[:11],42)):
   with self.assertRaises(ValueError):dns_wire.response(data,ident)
