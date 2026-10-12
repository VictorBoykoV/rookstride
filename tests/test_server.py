import copy
import json
import shlex
import sys
import tempfile
import unittest
import socket
import struct
from collections import deque
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from rookstride import admin
from rookstride.usage import Ledger
from rookstride.vici import encode,decode,connections,Vici


def connection(user='alice',ike='1',child='1',upload=100,download=200):
    return {'id':ike,'user':user,'endpoint':'192.0.2.10','port':4500,
            'vpn_addresses':['10.252.0.2'],'age':5,
            'children':[{'id':child,'upload':upload,'download':download}]}


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'usage.db'
        self.ledger=Ledger(self.path)
    def tearDown(self):
        self.ledger.close(); self.tmp.cleanup()
    def total(self):
        return self.ledger.db.execute('SELECT SUM(upload),SUM(download) FROM daily').fetchone()
    def test_repeat_poll_and_final_event_do_not_double_count(self):
        c=connection()
        self.ledger.sample('boot',[c],now=100)
        self.ledger.sample('boot',[c],now=110)
        self.ledger.disconnect('boot',c,now=120)
        self.assertEqual(self.total(),(100,200))
        self.assertFalse(self.ledger.history()[0]['active'])
    def test_shared_login_sums_distinct_sessions(self):
        self.ledger.sample('boot',[connection(),connection(ike='2',child='2',upload=400)],now=100)
        self.assertEqual(self.total(),(500,400))
        self.assertEqual(len(self.ledger.history()),2)
    def test_reconnect_rekey_and_daemon_restart_have_distinct_generations(self):
        self.ledger.sample('boot',[connection()],now=100)
        self.ledger.sample('boot',[connection(child='2',upload=10,download=20)],now=110)
        self.ledger.sample('new-boot',[connection(upload=30,download=40)],now=120)
        self.assertEqual(self.total(),(140,260))
    def test_restart_of_collector_preserves_counters(self):
        self.ledger.sample('boot',[connection()],now=100)
        self.ledger.close(); self.ledger=Ledger(self.path)
        self.ledger.sample('boot',[connection(upload=110,download=250)],now=110)
        self.assertEqual(self.total(),(110,250))
    def test_initial_baseline_does_not_invent_past_usage(self):
        self.ledger.sample('boot',[connection()],now=100,baseline=True)
        self.assertEqual(self.total(),(None,None))
        self.ledger.sample('boot',[connection(upload=110,download=250)],now=110)
        self.assertEqual(self.total(),(10,50))
    def test_deliberate_pause_rebases_existing_session(self):
        self.ledger.sample('boot',[connection()],now=100)
        self.ledger.sample('boot',[connection(upload=900,download=900)],now=200,baseline=True)
        self.ledger.sample('boot',[connection(upload=910,download=940)],now=210)
        self.assertEqual(self.total(),(110,240))
    def test_lower_counter_records_gap_without_huge_wraparound(self):
        self.ledger.sample('boot',[connection()],now=100)
        self.ledger.sample('boot',[connection(upload=10,download=20)],now=110)
        self.assertEqual(self.total(),(100,200))
        self.assertIn('counter_reset',self.ledger.metadata())
    def test_owner_change_is_rejected(self):
        self.ledger.sample('boot',[connection()],now=100)
        with self.assertRaises(ValueError):
            self.ledger.sample('boot',[connection(user='bob')],now=110)
        self.assertEqual(self.total(),(100,200))
    def test_retention_keeps_daily_totals_after_session_cleanup(self):
        self.ledger.sample('boot',[connection()],now=100)
        self.ledger.sample('boot',[],now=110)
        self.ledger.prune(now=31*86400)
        self.assertEqual(self.ledger.history(),[])
        self.assertEqual(self.total(),(100,200))


class ProtocolTests(unittest.TestCase):
    def test_event_arriving_before_registration_confirmation_is_preserved(self):
        local,remote=socket.socketpair()
        client=Vici.__new__(Vici);client.sock=local;client.pending=deque()
        local.settimeout(1)
        try:
            event=b'\x07\x0cchild-updown'+encode({'up':'yes'})
            remote.sendall(struct.pack('!I',len(event))+event+b'\0\0\0\x01\x05')
            client.register('child-rekey')
            self.assertEqual(client.receive(),(7,'child-updown',{'up':'yes'}))
        finally: local.close();remote.close()
    def test_nested_vici_roundtrip(self):
        m={'vpn':{'remote-eap-id':'alice','remote-vips':['10.252.0.2','fd42:252::2'],
                  'child-sas':{'vpn-1':{'uniqueid':'1','bytes-in':'42','state':'INSTALLED'}}}}
        self.assertEqual(decode(encode(m)),m)
        self.assertEqual(connections([m])[0]['upload'],42)
    def test_truncated_unbalanced_and_oversized_fields(self):
        for value in (b'\x01\x03ab',b'\x02',b'\x05\0\x01x',b'\x01\x01x',b'\x03\x01x\0\x05a'):
            with self.assertRaises(ValueError): decode(value)


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.secrets=self.root/'secrets'; self.secrets.write_text('vpn.example.net : RSA "server-key.pem"\nalice : EAP "old-password-long"\n')
        self.paths=patch.multiple(admin,STATE=self.root,SECRETS=self.secrets)
        self.paths.start()
    def tearDown(self):
        self.paths.stop(); self.tmp.cleanup()
    def test_shell_characters_and_invalid_labels_rejected(self):
        for value in ('alice;id','$(id)','a\nroot','a b','../root'):
            with self.assertRaises(ValueError): admin.username(value)
        with self.assertRaises(ValueError): admin.label('a\nname')
    def test_password_quotes_and_slashes_roundtrip(self):
        pw='A-long-password-"\\withquotes'
        with patch.object(admin,'run'):
            admin.update_user({'login':'bob','password':pw,'person':'Bob','device':'Phone','kind':'device'})
        row=next(x for x in self.secrets.read_text().splitlines() if x.startswith('bob '))
        self.assertEqual(shlex.split(row)[3],pw)
        self.assertEqual(self.secrets.stat().st_mode&0o777,0o600)
        self.assertNotIn(pw,(self.root/'users.json').read_text())
    def test_failed_reload_restores_existing_credentials(self):
        original=self.secrets.read_text()
        with patch.object(admin,'run',side_effect=[RuntimeError('failure'),None]):
            with self.assertRaises(RuntimeError):
                admin.update_user({'login':'bob','password':'a-valid-password-long'})
        self.assertEqual(self.secrets.read_text(),original)
    def test_duplicate_login_cannot_silently_overwrite(self):
        with self.assertRaises(ValueError):
            admin.update_user({'login':'alice','password':'a-valid-password-long'})
    def test_request_dispatch_rejects_unknown_commands(self):
        with self.assertRaises(ValueError): admin.dispatch({'action':'run-shell','command':'id'})


if __name__=='__main__': unittest.main()
