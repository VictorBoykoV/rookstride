#!/usr/bin/env python3
"""Exercise actual Linux packet filters in a disposable network namespace.
This proves the local SSH exception, not a complete VPN or phone connection.
Run with ROOKSTRIDE_DISPOSABLE_LAB=yes as root in a disposable Linux VM.
"""
import os,sys,socket,subprocess,threading,secrets
from pathlib import Path

def command(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
def inside():
    from unittest.mock import patch
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'server'))
    import pair,native_routing as routing
    identity=subprocess.check_output(['ip','netns','identify'],text=True).strip()
    if not identity.startswith('rook-admin-fixture-'):raise SystemExit('Refusing to change host routing')
    command('ip','link','set','lo','up')
    for address in ('198.18.7.1/32','10.66.0.1/32'):command('ip','address','add',address,'dev','lo')
    servers=[]
    for port in (2222,2223):
        listener=socket.socket();listener.bind(('198.18.7.1',port));listener.listen();servers.append(listener)
        def serve(s=listener):
            while True:
                try:
                    c,_=s.accept();c.sendall(b'ok');c.close()
                except OSError:return
        threading.Thread(target=serve,daemon=True).start()
    p=pair.plan(dict(pair='a'*32,role='entry',exit_host='198.51.100.20',entry_protocol='xray',exit_protocol='awg',server='192.0.2.10',vpn_port=443))
    m={'version':2,'plan':p,'activated':False,'verified':True}
    def probe(address,port):
        with socket.socket() as s:
            s.settimeout(1);s.bind(('10.66.0.1',0))
            try:s.connect((address,port));return s.recv(2)==b'ok'
            except OSError:return False
    try:
        with patch.object(pair,'load_manifest',return_value=m),patch.object(pair,'write_manifest'),patch.object(routing,'ssh_ports',return_value=[2222]):
            for state in ('quiesce','activate','quiesce'):
                routing.apply(state)
                assert probe('198.18.7.1',2222),state+': local administrator access failed'
                assert not probe('198.18.7.1',2223),state+': other local service bypassed the guard'
                assert not probe('198.18.9.9',2222),state+': administrator exception bypassed the exit route'
                print('PASS '+state+': local SSH allowed; other local service and external SSH blocked',flush=True)
    finally:
        for s in servers:s.close()
if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes':raise SystemExit('Use an explicitly disposable root Linux lab')
    if '--inside' in sys.argv:inside()
    else:
        name='rook-admin-fixture-'+secrets.token_hex(4);command('ip','netns','add',name)
        try:subprocess.run(['ip','netns','exec',name,sys.executable,str(Path(__file__).resolve()),'--inside'],check=True)
        finally:command('ip','netns','del',name)
