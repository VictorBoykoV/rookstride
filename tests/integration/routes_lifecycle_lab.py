#!/usr/bin/env python3
"""Two lifecycle rounds on an explicitly disposable, empty GitHub Ubuntu runner."""
import hashlib,json,os,platform,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ROOKSTRIDE_DISPOSABLE_LAB')!='yes':
    raise SystemExit('Only an explicitly disposable GitHub runner is allowed.')
os.umask(0o077)
sys.path.insert(0,str(ROOT/'single'))
import runtime,run as api,routes,filtering

pins=json.loads((ROOT/'single/routes-pins.json').read_text())
asset=pins['assets'][platform.machine()]
source=ROOT/'.tools/native-engines/output/routes/linux'/platform.machine()
target=routes.WORKER/asset['sha256'];target.mkdir(mode=0o700,parents=True,exist_ok=True)
for name,key in (('rook-routes','sha256'),('libcronet.so','library_sha256')):
    raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==asset[key]
    temporary=target/(name+'.new');temporary.write_bytes(raw);temporary.chmod(0o700);temporary.replace(target/name)
private=Path('/var/tmp/rookstride-routes-lab');private.mkdir(mode=0o700,exist_ok=True)
sentinel=private/'unrelated';sentinel.write_text('preserve unrelated application')
results=[]
for protocol in ('xhttp','hysteria2','outline','shadowsocks','trusttunnel','naive'):
    for round in (1,2):
        started=api.action(dict(action='start',protocol=protocol,server='127.0.0.1',login='this-phone'));job=started['job']
        deadline=time.monotonic()+1200;last=''
        while True:
            status=api.action(dict(action='job',job=job))
            if status['phase']!=last:last=status['phase'];print(protocol,round,last,flush=True)
            if status['state']=='complete':break
            if status['state']=='failed' or time.monotonic()>deadline:raise AssertionError('Detached installation did not complete: '+last)
            time.sleep(2)
        api.action(dict(action='add-user',protocol=protocol,login='second-device'))
        revoked=api.action(dict(action='profile',protocol=protocol,login='second-device'))
        api.action(dict(action='remove-user',protocol=protocol,login='second-device'))
        profile=api.action(dict(action='profile',protocol=protocol,login='this-phone'))
        file=private/'profile.json';runtime.atomic(file,json.dumps(profile))
        command=[sys.executable,str(ROOT/'tests/integration/routes_probe.py'),'--source',str(ROOT),'--worker',str(routes.worker()),'--xray',str(runtime.ROOT/'bin/xray'),'--profile',str(file)]
        probe=subprocess.run(command,capture_output=True,text=True,timeout=120)
        if probe.returncode:raise AssertionError(protocol+' encrypted HTTPS/DNS probe failed')
        health=api.action(dict(action='status',protocol=protocol))
        assert health['running'] and health['monitoring_available'] and health['filtering']['running']
        assert sum(x['upload'] for x in health['connections'])>0 and sum(x['download'] for x in health['connections'])>0
        assert all(x['generation'] for x in health['connections'])
        runtime.atomic(file,json.dumps(revoked))
        assert subprocess.run(command,capture_output=True,timeout=90).returncode!=0,'Revoked profile was accepted'
        if protocol in routes.PROTOCOLS:
            api.action(dict(action='remove-user',protocol=protocol,login='this-phone'))
            assert not api.action(dict(action='status',protocol=protocol))['running'],'No-user listener must stop'
            api.action(dict(action='add-user',protocol=protocol,login='this-phone'))
            runtime.atomic(file,json.dumps(api.action(dict(action='profile',protocol=protocol,login='this-phone'))))
            assert subprocess.run(command,capture_output=True,timeout=120).returncode==0,'First user could not restore access'
        review=api.action(dict(action='reset-plan',protocol=protocol))
        api.action(dict(action='reset-apply',protocol=protocol,token=review['token'],confirmation='DELETE VPN'))
        assert not runtime.directory(protocol).exists() and sentinel.read_text()=='preserve unrelated application'
        if filtering.exists():
            review=api.action(dict(action='filter-reset-plan'))
            api.action(dict(action='filter-reset-apply',token=review['token'],confirmation='DELETE VPN'))
        assert not filtering.exists()
        results.append(dict(protocol=protocol,round=round,detached_install=True,encrypted_https=True,tcp_udp_ad_filter=True,statistics=True,revoked_user_denied=True,managed_reset=True))
print(json.dumps(dict(lifecycle_rounds=results),indent=2))
