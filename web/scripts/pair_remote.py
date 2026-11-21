#!/usr/bin/env python3
"""Bounded SSH adapter for reviewed native pairs."""
import base64
from contextlib import ExitStack, contextmanager
import fcntl
import gzip
import hashlib
import io
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import time

ENTRY = '/etc/rookstride-pair/manifest.json'
RELEASE = Path('/opt/rookstride-pair')
RESTORE_OPERATION = Path('/var/lib/rookstride-lifecycle/web-pair-restore.json')
FOLDERS = ('server', 'twohop', 'gateway', 'single')
STANDALONE_DNS_PATHS = (
    '/opt/rookstride-filter', '/var/lib/rookstride-filter',
    '/etc/systemd/system/rookstride-filter.service',
    '/etc/systemd/system/rookstride-filter-network.service',
)
HEX32 = re.compile(r'[a-f0-9]{32}')
HEX64 = re.compile(r'[a-f0-9]{64}')
MAX_REQUEST = 65536
MAX_RECOVERY_REQUEST = 2 * 1024 * 1024
MAX_RECOVERY_RESPONSE = 1572864 + 4096
MAX_ARCHIVE = 4 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
PAIR_LOGIN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}')
ENTRY_PORTS = {
    'awg': 51820, 'ikev2': 500, 'openvpn': 1194, 'xray': 443, 'xhttp': 443,
    'hysteria2': 443, 'outline': 443, 'shadowsocks': 443, 'trusttunnel': 443, 'naive': 443,
}
EXIT_PORTS = {**ENTRY_PORTS, 'awg': 443}
TOPOLOGY_FIELDS = ('pair', 'role', 'server', 'exit_host', 'engine', 'entry_protocol',
                   'exit_protocol', 'vpn_port', 'tunnel_port')
ROUTE_FIELDS = {
    'client_pool': '10.66.0.0/24', 'test_ip': '10.249.255.254',
    'entry_address': '10.253.0.2/30', 'exit_address': '10.253.0.1/30', 'route_table': 51831,
}
MANAGEMENT_LOCKS = (
    '/run/rookstride-management.lock', '/run/rookstride-lifecycle.lock',
    '/run/rookstride-pair.lock',
)


class PairRejected(ValueError):
    pass


def read(path, maximum):
    with Path(path).open('rb') as file:
        contents = file.read(maximum + 1)
    if len(contents) > maximum:
        raise ValueError('oversize')
    return contents


def protected(path):
    for part in (path, *path.parents):
        if part.is_symlink() or part.stat().st_uid != 0:
            raise ValueError('ownership')
    return path


def owned():
    manifest = Path(ENTRY)
    if not manifest.exists() and not manifest.is_symlink():
        return None
    return json.loads(read(protected(manifest), MAX_REQUEST))


def supported_plan(request):
    if not isinstance(request, dict):
        raise PairRejected('ownership-mismatch')
    entry_protocol, exit_protocol = request.get('entry_protocol'), request.get('exit_protocol')
    identity, entry, exit_address = request.get('pair'), request.get('server'), request.get('exit_host')
    if (not isinstance(entry_protocol, str) or entry_protocol not in ENTRY_PORTS
            or not isinstance(exit_protocol, str) or exit_protocol not in EXIT_PORTS
            or not isinstance(identity, str) or not HEX32.fullmatch(identity)
            or not isinstance(entry, str) or not isinstance(exit_address, str) or entry == exit_address
            or request.get('engine') != 'native-v2'
            or request.get('role') not in ('entry', 'exit')
            or type(request.get('vpn_port')) is not int or request['vpn_port'] != ENTRY_PORTS[entry_protocol]
            or type(request.get('tunnel_port')) is not int or request['tunnel_port'] != EXIT_PORTS[exit_protocol]
            or ('route_table' in request and type(request['route_table']) is not int)
            or 'access_mode' in request or any(key in request and request[key] != value
                                               for key, value in ROUTE_FIELDS.items())):
        raise PairRejected('ownership-mismatch')
    try:
        if str(IPv4Address(entry)) != entry or str(IPv4Address(exit_address)) != exit_address:
            raise ValueError('address')
    except ValueError:
        raise PairRejected('ownership-mismatch') from None
    return {**{key: request[key] for key in TOPOLOGY_FIELDS}, **ROUTE_FIELDS}


def node_protocol(plan):
    return plan['entry_protocol'] if plan['role'] == 'entry' else plan['exit_protocol']


def uses_pinned_identity(state, protocol):
    return (isinstance(state, dict) and state.get('protocol') == protocol
            and state.get('access_mode', None if protocol == 'ikev2' else 'profile') == 'profile')


def node_state(plan):
    import native_pair
    protocol = node_protocol(plan)
    if protocol == 'ikev2':
        import recovery_ike
        return recovery_ike.state(plan)
    return native_pair.runtime.load(protocol)


def normalize_ike_health(report):
    services = report.get('services')
    if not isinstance(services, dict):
        raise PairRejected('inactive-pair')
    return {**report, 'services': {
        **services, 'protocol': services.get('strongswan-starter') is True,
        'adguard': services.get('adguardhome') is True,
    }}


def node_health(plan, state):
    import native_pair
    if node_protocol(plan) == 'ikev2':
        from rookstride import admin
        return normalize_ike_health(admin.health())
    return native_pair.runtime.health(state)


def checked_snapshot(snapshot, plan):
    if not isinstance(snapshot, dict) or snapshot.get('plan') != plan or snapshot.get('role') != plan['role']:
        raise PairRejected('invalid-recovery')
    protocol = node_protocol(plan)
    state = snapshot.get('state')
    if not uses_pinned_identity(state, protocol):
        raise PairRejected('invalid-recovery')
    if protocol == 'ikev2':
        try:
            leaf = base64.b64decode(snapshot['identity_files']['tls/server.pem']['content'], validate=True)
        except (KeyError, TypeError, ValueError):
            raise PairRejected('invalid-recovery') from None
        # The IKE helper derives its generation from the exact PEM it restores.
        # For this protocol the old generation is retained with the certificate.
        if not leaf or state.get('instance') != hashlib.sha256(leaf).hexdigest()[:32]:
            raise PairRejected('invalid-recovery')
    return snapshot


def checked_archive(archive, plan):
    if not isinstance(archive, dict) or not isinstance(archive.get('nodes'), dict):
        raise PairRejected('invalid-recovery')
    for role in ('entry', 'exit'):
        checked_snapshot(archive['nodes'].get(role), dict(plan, role=role))
    return archive


def probe():
    machine = read('/etc/machine-id', 64).strip().decode('ascii')
    if not HEX32.fullmatch(machine) or not int(machine, 16):
        raise ValueError('identity')
    release = dict(line.split('=', 1) for line in
                   read('/etc/os-release', 8192).decode('utf-8').splitlines() if '=' in line)
    manifest = owned()
    owner = None if manifest is None else {
        'pairId': manifest['plan']['pair'], 'bundle': manifest['bundle'],
        'role': manifest['plan']['role'], 'resetting': manifest.get('resetting', False),
    }
    if manifest is not None:
        plan = manifest['plan']
        if manifest.get('version') != 2 or plan != supported_plan(plan):
            raise PairRejected('ownership-mismatch')
        if plan['entry_protocol'] != 'awg':
            owner['entryProtocol'] = plan['entry_protocol']
        if plan['exit_protocol'] != 'awg':
            owner['exitProtocol'] = plan['exit_protocol']
    architecture = platform.machine()
    return {
        'machine': hashlib.sha256(machine.encode()).hexdigest(),
        'os': release.get('ID', '').strip('"\''),
        'version': release.get('VERSION_ID', '').strip('"\''),
        'owner': owner,
        **({'runtimeArchitecture': architecture} if architecture in ('x86_64', 'aarch64') else {}),
        'standaloneDnsPresent': any(os.path.lexists(path) for path in STANDALONE_DNS_PATHS),
    }


def resolver(address):
    address = IPv4Address(address)
    if not address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
        raise ValueError('resolver')
    result = subprocess.run(
        ['/usr/sbin/ip', '-j', '-4', 'route', 'get', str(address)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8, check=True,
    )
    routes = json.loads(result.stdout)
    if not isinstance(routes, list) or len(routes) != 1:
        raise ValueError('resolver route')
    return {'local': routes[0].get('type') == 'local' or routes[0].get('dev') == 'lo'}


def digest(files):
    checksum = hashlib.sha256()
    for name, content in files:
        checksum.update(name.encode())
        checksum.update(content)
    return checksum.hexdigest()


def unpack(stream, target, expected):
    data = stream.read(MAX_ARCHIVE + 1)
    if not data or len(data) > MAX_ARCHIVE:
        raise ValueError('archive')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
        raw = archive.read(MAX_SOURCE + 1)
    if len(raw) > MAX_SOURCE:
        raise ValueError('archive')
    entries = json.loads(raw)
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ValueError('archive')
    files = []
    for name, encoded in entries:
        parts = name.split('/')
        if len(parts) < 2 or parts[0] not in FOLDERS or not all(
            part not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9._-]+', part) for part in parts
        ):
            raise ValueError('archive path')
        files.append((name, base64.b64decode(encoded, validate=True)))
    canonical = sorted({name for name, _ in files}, key=lambda name: (FOLDERS.index(name.split('/')[0]), name))
    if canonical != [name for name, _ in files] or digest(files) != expected:
        raise ValueError('recipe digest')
    for name, contents in files:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as file:
            file.write(contents)


def installed_digest(expected):
    files = []
    size = 0
    for folder in FOLDERS:
        for path in sorted(protected(RELEASE / folder).rglob('*'), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise ValueError('recipe link')
            if '__pycache__' in path.parts or path.suffix == '.pyc' or not path.is_file():
                continue
            content = read(protected(path), MAX_SOURCE - size)
            size += len(content)
            files.append((path.relative_to(RELEASE).as_posix(), content))
    if digest(files) != expected:
        raise ValueError('recipe digest')


def execute(root, script, request):
    result = subprocess.run([sys.executable, '-B', str(root / script)],
                            input=json.dumps(request).encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=36, check=False)
    if result.returncode or len(result.stdout) > 32768:
        raise ValueError('recipe')
    response = json.loads(result.stdout)
    if response.get('ok') is not True or not isinstance(response.get('result'), dict):
        raise ValueError('recipe')
    return response['result']


def exact_plan(request):
    import pair
    return pair.plan(supported_plan(request))


def managed_node(manifest, request, expected):
    import lifecycle
    import native_pair
    import pair
    plan = exact_plan(request)
    if manifest['plan'] != plan:
        raise PairRejected('ownership-mismatch')
    info = lifecycle.inspect()
    if (info.get('read_only') is not False or info['bundle'] != expected or info['plan'] != plan
            or lifecycle.route_override(manifest) is not None
            or any(op['state'] not in ('accepted', 'rolled-back', 'cancelled')
                   for op in lifecycle.records())):
        raise PairRejected('inactive-pair')
    for action in ('bootstrap', 'configure'):
        job = pair.ident(manifest['jobs'][action])
        if lifecycle.read(pair.STATE / job / 'status.json')['state'] != 'complete':
            raise PairRejected('inactive-pair')
    entry = plan['role'] == 'entry'
    if entry and (manifest.get('verified') is not True or not manifest.get('first_activated_at')):
        raise PairRejected('inactive-pair')

    protocol = node_protocol(plan)
    state = node_state(plan)
    if (not uses_pinned_identity(state, protocol)
            or state['server'] != (plan['server'] if entry else plan['exit_host'])
            or state['port'] != plan['vpn_port' if entry else 'tunnel_port']
            or state.get('pair') != (plan['pair'] if entry else None)):
        raise PairRejected('ownership-mismatch')
    if entry:
        transport = json.loads(read(protected(pair.OWN / 'transport.json'), MAX_REQUEST))
        native_pair.validate_material(plan, transport)
        if native_pair.filtering.exists() or state.get('pair_dns') != transport['dns']:
            raise PairRejected('ownership-mismatch')
    else:
        transport = native_pair.material(plan)
        if protocol != 'awg':
            native_pair.validate_material(dict(plan, role='entry'), transport)
    return info, plan, state, lifecycle.digest(transport)


def account_view(plan, state):
    import lifecycle
    import pair
    initial = json.loads(read(protected(pair.OWN / 'initial-user.json'), 4096))
    owner = state['initialLogin']
    if owner != initial.get('login') or not PAIR_LOGIN.fullmatch(owner):
        raise PairRejected('ownership-mismatch')
    if len(state['users']) > 252 or any(not PAIR_LOGIN.fullmatch(user['login']) for user in state['users']):
        raise PairRejected('inactive-pair')
    users = sorted(user['login'] for user in state['users'] if user.get('enabled', True))
    if owner not in users or len(set(users)) != len(users):
        raise PairRejected('inactive-pair')
    revision = lifecycle.digest({'pair': plan['pair'], 'instance': state['instance'], 'users': state['users']})
    return {'owner': owner, 'users': users, 'revision': revision}


def account_action(protocol, action, login, request, single_api):
    if (protocol == 'ikev2' and action == 'grant') != ('password' in request):
        raise ValueError('account password')
    if protocol != 'ikev2':
        return single_api.action({
            'action': {'profile': 'profile', 'grant': 'add-user', 'revoke': 'remove-user'}[action],
            'protocol': protocol, 'login': login,
        })

    from rookstride import admin
    if action == 'profile':
        profile = admin.profile({'login': login})
        return {'format': 'ikev2', 'name': 'rookstride-' + login + '.sswan',
                'content': json.dumps(profile, separators=(',', ':'))}
    args = {'action': 'add-user' if action == 'grant' else 'remove-user', 'login': login}
    if action == 'grant':
        args['password'] = request['password']
    return admin.dispatch(args)


@contextmanager
def management_lock():
    # Match lifecycle.management_lock's order. Obtain the locks before loading
    # installed Python, so a concurrent recipe update cannot replace it after verification.
    with ExitStack() as locks:
        for path in MANAGEMENT_LOCKS:
            handle = locks.enter_context(Path(path).open('a'))
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def manage(mode, request, expected):
    with management_lock():
        manifest = owned()
        if (manifest is None or manifest.get('resetting') or manifest.get('version') != 2
                or manifest['bundle'] != expected):
            raise PairRejected('ownership-mismatch')
        installed_digest(expected)
        sys.path[:0] = [str(RELEASE / 'server'), str(RELEASE / 'single')]
        import native_pair
        import pair_reset
        import recovery
        import run as single_api

        info, plan, state, bridge = managed_node(manifest, request, expected)
        entry = plan['role'] == 'entry'
        any_bridge = request.get('bridge')
        if any_bridge is not None and any_bridge != bridge:
            raise PairRejected('ownership-mismatch')
        action = request.get('action')
        if mode == 'management' and action == 'node':
            health = node_health(plan, state)
            healthy = health['services']['protocol'] is True
            result = {
                'pairId': plan['pair'], 'role': plan['role'], 'bridge': bridge,
                'topologyRevision': info['revision'], 'healthy': healthy,
            }
            if entry:
                bridge_up = subprocess.run(
                    ['/usr/bin/systemctl', 'is-active', '--quiet', 'rookstride-pair-bridge.service'],
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=8,
                ).returncode == 0
                result.update(account_view(plan, state))
                result['healthy'] = healthy and info['active'] and bridge_up
            else:
                result['dnsHealthy'] = health['services']['adguard'] is True
            return result

        if mode == 'management' and action in ('grant', 'revoke', 'profile') and entry:
            view = account_view(plan, state)
            login = request['login']
            if not isinstance(login, str) or not PAIR_LOGIN.fullmatch(login):
                raise ValueError('account login')
            protocol = node_protocol(plan)
            if action == 'profile':
                if login not in view['users']:
                    raise PairRejected('account-unavailable')
                return account_action(protocol, action, login, request, single_api)
            if request.get('revision') != view['revision']:
                raise PairRejected('roster-changed')
            if login == view['owner'] or (action == 'grant') == (login in view['users']):
                raise PairRejected('account-unavailable')
            if action == 'grant' and len(state['users']) >= 252:
                raise PairRejected('account-unavailable')
            result = account_action(protocol, action, login, request, single_api)
            if not (result.get('login') == login if action == 'grant' else result.get('removed') is True):
                raise ValueError('account change')
            return account_view(plan, node_state(plan))

        if mode == 'reset' and action in ('plan', 'check', 'apply'):
            import native_pair_reset
            import user_updates
            user_updates.ensure_no_runtime_update(destructive=True)
            if action == 'plan':
                return pair_reset.plan(plan)
            try:
                saved = json.loads(read(protected(native_pair_reset.path(plan)), MAX_REQUEST))
            except FileNotFoundError:
                raise PairRejected('removal-review-stale') from None
            token = request['token']
            if (not HEX64.fullmatch(token) or not secrets.compare_digest(saved['token'], token)
                    or saved['expires'] <= time.time()
                    or saved['review']['configuration'] != request['configuration']
                    or native_pair_reset.inspect(plan) != saved['review']):
                raise PairRejected('removal-review-stale')
            if action == 'check':
                return {'ready': True, 'role': plan['role']}
            return pair_reset.apply(dict(plan, token=token, confirmation='DELETE PAIR'))

        if mode == 'recovery' and action == 'export':
            return checked_snapshot(recovery.dispatch({'action': 'export'}), plan)
        if mode == 'recovery' and action == 'rehearse-pair' and entry:
            return recovery.dispatch({
                'action': 'rehearse-pair', 'archive': checked_archive(request['archive'], plan),
                'plans': dict(entry=plan, exit=dict(plan, role='exit')),
            })
        raise ValueError('request')


def restore_binding(request, expected):
    operation, fingerprint, revision = request['operation'], request['archiveDigest'], request['revision']
    if (not HEX32.fullmatch(operation) or not HEX64.fullmatch(fingerprint)
            or type(revision) is not int or not 2 <= revision <= 2**53-1):
        raise PairRejected('invalid-recovery')
    plan = supported_plan(request)
    return {
        'schema': 1, 'operation': operation, 'archiveDigest': fingerprint, 'revision': revision,
        'bundle': expected, 'topology': {key: plan[key] for key in TOPOLOGY_FIELDS},
    }


def store_restore_binding(binding):
    directory = RESTORE_OPERATION.parent
    protected(directory.parent)
    directory.mkdir(mode=0o700, exist_ok=True)
    protected(directory)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=directory, delete=False) as file:
            temporary = Path(file.name)
            json.dump(binding, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, RESTORE_OPERATION)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_restore_archive(stream, request, expected):
    # The fresh entry only unpacks and validates. This executes no installer.
    if request['role'] != 'entry':
        raise PairRejected('invalid-recovery')
    with tempfile.TemporaryDirectory(prefix='rookstride-restore-review-') as directory:
        source = Path(directory)
        unpack(stream, source, expected)
        sys.path[:0] = [str(source / 'server'), str(source / 'single')]
        import recovery
        plan = exact_plan(request)
        archive = checked_archive(request['archive'], plan)
        if archive.get('revision') != request['revision'] - 1:
            raise PairRejected('invalid-recovery')
        try:
            return recovery.validate_pair(archive, {'entry': plan, 'exit': dict(plan, role='exit')})
        except ValueError:
            raise PairRejected('invalid-recovery') from None


def restore_operation(stream, request, expected):
    action = request['action']
    binding = restore_binding(request, expected)
    if action == 'validate':
        return validate_restore_archive(stream, request, expected)
    with management_lock():
        manifest = owned()
        recorded = None
        if RESTORE_OPERATION.exists() or RESTORE_OPERATION.is_symlink():
            recorded = json.loads(read(protected(RESTORE_OPERATION), 4096))
            if recorded != binding:
                raise PairRejected('restore-ownership-mismatch')
        if manifest and (not recorded or manifest['bundle'] != expected or manifest['version'] != 2
                         or manifest.get('resetting') or any(manifest['plan'].get(k) != v
                             for k, v in binding['topology'].items())):
            raise PairRejected('restore-ownership-mismatch')
        if action == 'inspect':
            return {'recorded': recorded is not None, 'jobs': manifest['jobs'] if manifest else {}}
        if action == 'enroll':
            if recorded is None:
                store_restore_binding(binding)
            return {'recorded': True}
        if not manifest or not recorded or action not in ('identity', 'revision'):
            raise PairRejected('restore-ownership-mismatch')

        installed_digest(expected)
        sys.path[:0] = [str(RELEASE / 'server'), str(RELEASE / 'single')]
        import entry_migration
        import lifecycle
        import pair
        import recovery

        plan = exact_plan(request)
        if plan != manifest['plan']:
            raise PairRejected('restore-ownership-mismatch')
        protocol = node_protocol(plan)
        prior = lifecycle.read(lifecycle.ROOT / 'restores' / (plan['role'] + '.json'))
        if action == 'revision':
            if not prior or prior['state'] != 'complete' or not manifest['configured']:
                raise PairRejected('restore-incomplete')
            if plan['role'] == 'entry' and not manifest.get('activated'):
                raise PairRejected('restore-incomplete')
            state = node_state(plan)
            if (not uses_pinned_identity(state, protocol) or state['instance'] != prior['generation']
                    or recovery.restored_identity(state) != prior.get('restored_identity')):
                raise PairRejected('restore-ownership-mismatch')
            current = lifecycle.read(lifecycle.ROOT / 'inventory.json')
            if current:
                if (current['revision'] != request['revision'] or current['entry_operation'] != request['operation']
                        or current['anchor'] != lifecycle.anchor(manifest)):
                    raise PairRejected('restore-ownership-mismatch')
                return {'revision': current['revision']}
            return entry_migration.dispatch({
                'action': 'record-revision', 'deployment': plan['pair'],
                'operation': request['operation'], 'revision': request['revision'],
            })

        for stage in ('bootstrap',) if plan['role'] == 'exit' else ('bootstrap', 'configure'):
            job_id = manifest['jobs'].get(stage)
            state = lifecycle.read(pair.STATE / pair.ident(job_id) / 'status.json') if job_id else None
            if not state or state['state'] != 'complete':
                raise PairRejected('restore-incomplete')
        try:
            snapshot = recovery.validate(checked_snapshot(request['snapshot'], plan))
        except ValueError:
            raise PairRejected('invalid-recovery') from None
        if prior:
            identity = lifecycle.digest({'snapshot': snapshot, 'new_endpoint': None})
            if identity != prior['snapshot']:
                raise PairRejected('restore-ownership-mismatch')
            if prior['state'] == 'complete':
                state = node_state(plan)
                if (not uses_pinned_identity(state, protocol) or state['instance'] != prior['generation']
                        or recovery.restored_identity(state) != prior.get('restored_identity')):
                    raise PairRejected('restore-ownership-mismatch')
                recovery.check_restored_service(state)
                if plan['role'] == 'exit' and recovery.filter_policy() != snapshot['filter_policy']:
                    raise PairRejected('restore-ownership-mismatch')
                return {'restored': True, 'usage_generation': state['instance'], 'users': len(state['users'])}
            if prior['state'] != 'restoring' or request.get('resume') is not True:
                raise PairRejected('restore-resume-required')
        return recovery.dispatch({
            'action': 'restore', 'snapshot': snapshot, 'confirmation': 'RESTORE REVIEWED VPN IDENTITY',
        })


def run(stream):
    if os.geteuid() != 0:
        raise ValueError('administrator')
    raw = stream.readline(MAX_RECOVERY_REQUEST + 1)
    if not raw.endswith(b'\n') or len(raw) > MAX_RECOVERY_REQUEST:
        raise ValueError('request')
    data = json.loads(raw)
    mode = data['mode']
    large_actions = {'recovery': ('rehearse-pair',), 'restore': ('validate', 'identity')}
    if len(raw) > MAX_REQUEST and data['request']['action'] not in large_actions.get(mode, ()):
        raise ValueError('request')
    if mode == 'probe':
        return probe()
    if mode == 'resolver':
        return resolver(data['request']['address'])
    expected, request = data['bundle'], data['request']
    if not HEX64.fullmatch(expected) or not HEX32.fullmatch(request['pair']):
        raise ValueError('request')
    if mode == 'restore':
        return restore_operation(stream, request, expected)
    if mode in ('management', 'reset', 'recovery'):
        return manage(mode, request, expected)
    target_plan = supported_plan(request)
    manifest = owned()
    command = request.get('command')
    if manifest is None:
        if mode != 'recipe' or command != 'preflight' and not (
            command == 'start' and request.get('action') == 'bootstrap'
        ):
            raise ValueError('ownership')
        with tempfile.TemporaryDirectory(prefix='rookstride-pair-') as directory:
            root = Path(directory)
            unpack(stream, root, expected)
            return execute(root, 'server/pair.py', request)
    plan = manifest['plan']
    if manifest.get('resetting') or manifest['bundle'] != expected or manifest['version'] != 2 or plan != target_plan:
        raise ValueError('ownership')
    if mode == 'recipe' and command in ('preflight', 'start', 'status', 'health', 'material', 'overview'):
        if command == 'status' and request.get('job') not in manifest['jobs'].values():
            raise ValueError('ownership')
        script = 'server/pair.py'
    else:
        raise ValueError('request')
    installed_digest(expected)
    result = execute(RELEASE, script, request)
    if command == 'health' and node_protocol(plan) == 'ikev2':
        return normalize_ike_health(result)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    try:
        response = json.dumps({'ok': True, 'result': run(sys.stdin.buffer)})
        if len(response) > MAX_RECOVERY_RESPONSE:
            raise ValueError('response')
        print(response)
    except PairRejected as exc:
        print(json.dumps({'ok': False, 'code': str(exc)}))
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print('{"ok":false}')
