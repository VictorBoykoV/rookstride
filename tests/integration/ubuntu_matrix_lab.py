#!/usr/bin/env python3
"""All single-server methods in an explicitly owned Lima VM; never a live VPS."""
import hashlib,json,os,platform,runpy,socket,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
if os.geteuid()!=0 or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes' or not socket.gethostname().startswith('lima-rook-ubuntu'):
    raise SystemExit('Use an explicitly disposable rook-ubuntu Lima VM, not a provider node.')
os.umask(0o077)
sys.path.insert(0,str(ROOT/'single'));sys.path.insert(1,str(ROOT/'server'))
import run as api,runtime,routes,filtering,ubuntu_support,reset_server,deploy
ubuntu_support.require()
protocols=sys.argv[1:] or ['awg','openvpn','xray','xhttp','hysteria2','outline','shadowsocks','trusttunnel','naive','ikev2']
assert all(p in (*runtime.model.PROTOCOLS,'ikev2') for p in protocols)
assert not any(runtime.directory(p).exists() for p in runtime.model.PROTOCOLS) and not filtering.exists() and not Path('/etc/single-vps-vpn').exists(),'Review owned cleanup before starting this matrix.'
report={'ubuntu':ubuntu_support.assess()['version'],'architecture':platform.machine(),'single_source':api.digest(ROOT/'single'),'rounds':[]}
output=ROOT/'.build/ubuntu-matrix.json';output.parent.mkdir(exist_ok=True)
sentinel=Path('/srv/rook-matrix-unrelated');sentinel.mkdir(exist_ok=True);(sentinel/'check').write_text('preserve unrelated data')
def persist():output.write_text(json.dumps(report,indent=2))
def clean():
    review=api.action(dict(action='reset-server-plan'))
    api.action(dict(action='reset-server-apply',token=review['token'],confirmation='DELETE ALL VPNS'))
    assert not filtering.exists() and not Path('/etc/single-vps-vpn').exists()
    assert (sentinel/'check').read_text()=='preserve unrelated data'
def wait_job(started,ike=False):
    deadline=time.monotonic()+1800;previous=''
    while True:
        state=deploy.status(started['job']) if ike else api.action(dict(action='job',job=started['job']))
        if state['phase']!=previous:previous=state['phase'];print(previous,flush=True)
        if state['state']=='complete':return
        if state['state']=='failed' or time.monotonic()>deadline:raise AssertionError(previous)
        time.sleep(2)
for protocol in protocols:
    for cycle in (1,2):
        try:
            print('START',report['ubuntu'],protocol,cycle,flush=True)
            if protocol in ('awg','openvpn','xray'):
                old=sys.argv;sys.argv=[str(ROOT/'tests/integration/single_protocol_lab.py'),protocol]
                try:runpy.run_path(sys.argv[0],run_name='__main__')
                finally:sys.argv=old
                child=json.loads((ROOT/'.build'/('single-'+protocol+'-lab.json')).read_text());assert child['status']=='PASS'
                clean();checks=child['checks']
            elif protocol=='ikev2':
                wait_job(deploy.start(dict(mode='install',server='vpn.example.net',login='lab-user',password='LabSample123',statistics=True)),True)
                import single_ike_lab
                checks=single_ike_lab.probe('lab-user','LabSample123');assert all(checks.values())
                clean()
            else:
                wait_job(api.action(dict(action='start',protocol=protocol,server='127.0.0.1',login='this-phone')))
                api.action(dict(action='add-user',protocol=protocol,login='second-device'))
                profile=ROOT/'.build/client-private.json';profile.write_text(json.dumps(api.action(dict(action='profile',protocol=protocol,login='second-device'))))
                command=[sys.executable,str(ROOT/'tests/integration/routes_probe.py'),'--source',str(ROOT),'--worker',str(routes.worker()),'--xray',str(runtime.ROOT/'bin/xray'),'--profile',str(profile)]
                probe=subprocess.run(command,capture_output=True,text=True,timeout=150)
                if probe.returncode:raise AssertionError(protocol+' traffic probe failed: '+probe.stderr[-300:])
                health=api.action(dict(action='status',protocol=protocol))
                assert health['running'] and health['filtering']['running'] and health['monitoring_available']
                assert sum(v['upload'] for v in health['connections'])>0 and sum(v['download'] for v in health['connections'])>0
                api.action(dict(action='remove-user',protocol=protocol,login='second-device'))
                assert subprocess.run(command,capture_output=True,timeout=90).returncode!=0,'Revoked user accepted'
                profile.unlink();clean();checks={'encrypted_https':True,'filtered_tcp_udp_dns':True,'usage':True,'create_export_revoke':True}
            row=dict(protocol=protocol,round=cycle,status='PASS',checks=checks,owned_reset=True,unrelated_data_preserved=True)
            report['rounds'].append(row);persist();print('PASS',protocol,cycle,flush=True)
        except Exception as error:
            report['rounds'].append(dict(protocol=protocol,round=cycle,status='FAIL',type=type(error).__name__,message=str(error)[-400:]))
            persist();print('FAIL',protocol,cycle,type(error).__name__,flush=True)
            clean()
sentinel.joinpath('check').unlink();sentinel.rmdir()
report['all_passed']=all(row['status']=='PASS' for row in report['rounds']);persist()
print('MATRIX_RESULT '+json.dumps(report),flush=True)
raise SystemExit(0 if report['all_passed'] else 1)
