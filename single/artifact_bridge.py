"""Prepare fixed public archives only; never dispatch or modify an installer job."""
import ast
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
import platform
import pwd
import re
import signal
import socket
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
CACHE = Path('/var/cache/rookstride/artifacts')
LOCK = Path('/run/rookstride-artifacts.lock')
STAGING = Path('/tmp')
MACHINE = Path('/etc/machine-id')
ROOT_UID = 0
FILESYSTEM_ROOT = Path('/')
BUDGET = 60
HOSTS = ('github.com', 'api.github.com', 'release-assets.githubusercontent.com')


class Unavailable(Exception):
    """Only bounded transport failure permits an independently verified upload."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate artifact field')
        result[key] = value
    return result


def read_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def catalog():
    raw = (HERE / 'public-artifacts.json').read_bytes()
    value = read_json(raw)
    if set(value) != {'schema', 'redirect_hosts', 'artifacts'} or type(value['schema']) is not int or value['schema'] != 1 or value['redirect_hosts'] != list(HOSTS) or set(value['artifacts']) != {'adguard', 'xray', 'trusttunnel'}:
        raise ValueError('Public artifact catalog differs')
    # Compare data, without importing/executing an installer or reading a .pyc.
    tree = ast.parse((HERE / 'filtering.py').read_text())
    assignments = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ASSETS' for t in n.targets)]
    if len(assignments) != 1:
        raise ValueError('Public artifact pins differ')
    adguard = ast.literal_eval(assignments[0])
    xray = read_json((HERE / 'pins.json').read_bytes())['xray']
    trust = read_json((HERE / 'routes-pins.json').read_bytes())['trusttunnel']
    for name, entry in value['artifacts'].items():
        if set(entry) != {'version', 'assets'} or set(entry['assets']) != {'x86_64', 'aarch64'}:
            raise ValueError('Public artifact catalog differs')
        if entry['version'] != ('v0.107.80' if name == 'adguard' else (xray if name == 'xray' else trust)['version']):
            raise ValueError('Public artifact pins differ')
        for arch, asset in entry['assets'].items():
            if name == 'adguard':
                suffix, digest, size, api = adguard[arch]
                sources = [{'url': 'https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.80/AdGuardHome_linux_' + suffix + '.tar.gz', 'headers': {}}, {'url': 'https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/assets/' + str(api), 'headers': {'Accept': 'application/octet-stream'}}]
            else:
                original = (xray if name == 'xray' else trust)['assets'][arch]
                digest, size = original['sha256'], original['bytes']
                sources = [{'url': original['url'], 'headers': {}}]
            if asset != {'sha256': digest, 'bytes': size, 'sources': sources} or not re.fullmatch('[0-9a-f]{64}', digest) or type(size) is not int or not 0 < size <= 32 * 1024 * 1024:
                raise ValueError('Public artifact pins differ')
            for source in sources:
                check_url(source['url'])
    return value, hashlib.sha256(raw).hexdigest()


def check_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.fragment:
        raise ValueError('Public artifact HTTPS policy differs')


class FixedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_open(request, timeout):
    check_url(request.full_url)
    # Proxy environment is deliberately ignored: no alternate origin may supply bytes.
    response = urllib.request.build_opener(urllib.request.ProxyHandler({}), FixedRedirect()).open(request, timeout=timeout)
    try:
        check_url(response.geturl())
    except Exception:
        response.close()
        raise
    return response


def safe_directory(path, create=False):
    """Root-only namespace; unprivileged writers cannot race cache path components."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Public artifact path differs')
    current = FILESYSTEM_ROOT
    for part in path.relative_to(FILESYSTEM_ROOT).parts:
        parent = current
        current /= part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            if not create:
                return False
            current.mkdir(mode=0o700)
            sync_directory(parent)
            observed = current.lstat()
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != ROOT_UID or observed.st_mode & 0o022:
            raise ValueError('Public artifact directory needs review')
    return True


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def cache_lock():
    safe_directory(LOCK.parent)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_uid != ROOT_UID or observed.st_nlink != 1 or observed.st_mode & 0o077:
            raise ValueError('Public artifact lock needs review')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Public artifact preparation is busy; inspect before retrying') from None
        yield
    finally:
        os.close(fd)


def stamp(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def verify_fd(fd, asset, uid):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size != asset['bytes']:
        raise ValueError('Public artifact file needs review')
    digest = hashlib.sha256()
    count = 0
    while True:
        block = os.read(fd, min(65536, asset['bytes'] + 1 - count))
        if not block:
            break
        count += len(block)
        digest.update(block)
        if count > asset['bytes']:
            raise ValueError('Public artifact size differs')
    if count != asset['bytes'] or digest.hexdigest() != asset['sha256'] or stamp(before) != stamp(os.fstat(fd)):
        raise ValueError('Public artifact checksum or size differs')


def cached(asset):
    if not safe_directory(CACHE):
        return False
    try:
        fd = os.open(CACHE / asset['sha256'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        verify_fd(fd, asset, ROOT_UID)
    finally:
        os.close(fd)
    return True


def publish(name, asset):
    # A link is an atomic create-if-absent; unlike replace it cannot repair a cache.
    path = CACHE / asset['sha256']
    try:
        os.link(name, path, follow_symlinks=False)
    except FileExistsError:
        cached(asset)
    finally:
        os.unlink(name)
    sync_directory(CACHE)
    if not cached(asset):
        raise ValueError('Public artifact cache commit is uncertain')


@contextlib.contextmanager
def temporary_cache():
    safe_directory(CACHE, True)
    fd, name = tempfile.mkstemp(prefix='.public-', dir=CACHE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as out:
            yield out, Path(name)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def finish_cache(out, name, asset):
    out.flush()
    os.fsync(out.fileno())
    os.lseek(out.fileno(), 0, os.SEEK_SET)
    # Verify the actual written file, not just the downloaded/uploaded stream.
    # A short/changed write must never publish a corrupt content-addressed entry.
    verify_fd(out.fileno(), asset, ROOT_UID)
    publish(name, asset)


def transport(error):
    if isinstance(error, urllib.error.URLError):
        error = error.reason
    if isinstance(error, ssl.SSLEOFError):
        return True
    if isinstance(error, (ssl.SSLError, ssl.CertificateError)):
        return False
    return isinstance(error, (OSError, http.client.IncompleteRead))


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise Unavailable('Public artifact acquisition deadline reached')
    return min(12, seconds)


@contextlib.contextmanager
def acquisition_budget(deadline):
    # urllib's connect timeout does not bound DNS or a chain of redirects.
    # A real process timer bounds all blocking acquisition work together.
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError('Public artifact deadline is already in use')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise Unavailable('Public artifact acquisition deadline reached')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def read_deadline(response, deadline):
    # urllib's response has a real SSLSocket; update it before EVERY blocking read.
    # Test transports may expose the same bounded-read seam directly.
    seconds = remaining(deadline)
    if hasattr(response, 'settimeout'):
        response.settimeout(seconds)
    elif getattr(getattr(response, 'fp', None), 'raw', None) is not None:
        response.fp.raw._sock.settimeout(seconds)
    else:
        raise ValueError('Public artifact read deadline is unsupported')


def acquire(asset, deadline):
    for index, source in enumerate(asset['sources']):
        try:
            request = urllib.request.Request(source['url'], headers={'User-Agent': 'Rookstride-artifact-bridge', **source['headers']})
            with https_open(request, remaining(deadline)) as response:
                declared = response.headers.get('Content-Length')
                if declared is not None and (not re.fullmatch('[0-9]+', declared) or int(declared) != asset['bytes']):
                    raise ValueError('Public artifact declared size differs')
                with temporary_cache() as (out, name):
                    count, digest = 0, hashlib.sha256()
                    while True:
                        read_deadline(response, deadline)
                        # read1 returns after one socket read, unlike buffered read(n).
                        block = response.read1(min(65536, asset['bytes'] + 1 - count))
                        if not block:
                            break
                        count += len(block)
                        if count > asset['bytes']:
                            raise ValueError('Public artifact size differs')
                        digest.update(block)
                        out.write(block)
                        if declared is not None and count == asset['bytes']:
                            # HTTPResponse closes its fp at Content-Length zero.
                            # There is no further body read to time out or inspect.
                            break
                    if count != asset['bytes'] or digest.hexdigest() != asset['sha256']:
                        raise ValueError('Public artifact checksum or size differs')
                    finish_cache(out, name, asset)
                    return
        except urllib.error.HTTPError as error:
            if error.code not in (403, 408, 425, 429, 500, 502, 503, 504) and index + 1 == len(asset['sources']):
                raise ValueError('Public artifact upstream rejected the fixed release') from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError, socket.gaierror, http.client.IncompleteRead) as error:
            if not transport(error):
                raise ValueError('Public artifact TLS validation failed') from None
    raise Unavailable('Public artifact upstream transport is unavailable')


def upload_uid():
    if os.geteuid() != ROOT_UID:
        raise ValueError('Public artifact preparation requires root')
    value = os.environ.get('SUDO_UID')
    if value is None:
        return ROOT_UID
    if not re.fullmatch('0|[1-9][0-9]{0,9}', value):
        raise ValueError('Public artifact upload identity differs')
    return int(value)


def commit(asset, identifier, nonce):
    uid = upload_uid()
    parent = STAGING.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != ROOT_UID or parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX:
        raise ValueError('Public artifact staging root differs')
    directory = STAGING / ('rookstride-artifact-' + nonce)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(directory_fd)
        if observed.st_uid != uid or observed.st_mode & 0o077:
            raise ValueError('Public artifact upload directory needs review')
        fd = os.open(identifier, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            verify_fd(fd, asset, uid)
            os.lseek(fd, 0, os.SEEK_SET)
            before = os.fstat(fd)
            with temporary_cache() as (out, name):
                copied, digest = 0, hashlib.sha256()
                while True:
                    block = os.read(fd, min(65536, asset['bytes'] + 1 - copied))
                    if not block:
                        break
                    copied += len(block)
                    digest.update(block)
                    out.write(block)
                    if copied > asset['bytes']:
                        raise ValueError('Public artifact upload size differs')
                if copied != asset['bytes'] or digest.hexdigest() != asset['sha256'] or stamp(before) != stamp(os.fstat(fd)):
                    raise ValueError('Public artifact upload changed')
                finish_cache(out, name, asset)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def installed_filter():
    # Same source-validated existing-module predicate as a normal install. Never
    # call prepare_binary on a missing module, which would start another fetch.
    namespace = {'__file__': str(HERE / 'filtering.py'), '__name__': '_artifact_filter'}
    exec(compile((HERE / 'filtering.py').read_bytes(), str(HERE / 'filtering.py'), 'exec'), namespace)
    if namespace['exists']():
        namespace['prepare_binary']()
        return True
    return installed_classic_filter()


def owned_bytes(path, uid, limit, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or before.st_mode & (0o077 if private else 0o022) or not 0 < before.st_size <= limit:
            raise ValueError('Installed public component ownership differs')
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) != before.st_size or stamp(before) != stamp(os.fstat(fd)):
            raise ValueError('Installed public component changed')
        return bytes(raw)
    finally:
        os.close(fd)


def installed_classic_filter():
    """Completed owned pair only, including retained .79; never arbitrary presence."""
    manifest_path = FILESYSTEM_ROOT / 'etc/rookstride-pair/manifest.json'
    if not os.path.lexists(manifest_path):
        return False
    safe_directory(manifest_path.parent)
    manifest = read_json(owned_bytes(manifest_path, ROOT_UID, 1024 * 1024, True))
    plan = manifest.get('plan', {})
    if plan.get('role') != 'exit' or not re.fullmatch('[0-9a-f]{32}', str(plan.get('pair', ''))):
        return False
    if manifest.get('version') == 2 and plan.get('exit_protocol') == 'ikev2':
        action = 'bootstrap'
    elif manifest.get('version') == 1 and manifest.get('configured') is True:
        action = 'configure'
    else:
        return False
    job = manifest.get('jobs', {}).get(action)
    if not isinstance(job, str) or not re.fullmatch('[0-9a-f]{32}', job):
        return False
    receipt_path = FILESYSTEM_ROOT / 'var/lib/rookstride-pair' / job / 'status.json'
    if not safe_directory(receipt_path.parent):
        return False
    receipt = read_json(owned_bytes(receipt_path, ROOT_UID, 1024 * 1024, True))
    if receipt.get('job') != job or receipt.get('action') != action or receipt.get('state') != 'complete':
        return False
    unit = FILESYSTEM_ROOT / 'etc/systemd/system/adguardhome.service'
    binary = FILESYSTEM_ROOT / 'opt/AdGuardHome/AdGuardHome'
    for path in (unit, binary):
        safe_directory(path.parent)
    expected = (HERE.parent / 'gateway/systemd/adguardhome.service').read_bytes()
    if action == 'configure':
        expected = expected.replace(b'single-vps-vpn-dns-address.service', b'awg-quick@awg-exit.service')
    if owned_bytes(unit, ROOT_UID, 65536) != expected:
        raise ValueError('Installed classic DNS service differs')
    owned_bytes(binary, ROOT_UID, 100 * 1024 * 1024)
    data = FILESYSTEM_ROOT / 'var/lib/AdGuardHome'
    safe_directory(data.parent)
    account = pwd.getpwnam('adguard')
    if account.pw_dir != '/var/lib/AdGuardHome' or account.pw_shell != '/usr/sbin/nologin':
        raise ValueError('Installed classic DNS identity differs')
    for directory in (data, data / 'work'):
        observed = directory.lstat()
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != account.pw_uid or observed.st_mode & 0o077:
            raise ValueError('Installed classic DNS directory differs')
    owned_bytes(data / 'AdGuardHome.yaml', account.pw_uid, 1024 * 1024, True)
    return True


def dispatch(request):
    value, digest = catalog()
    action = request.get('action')
    fields = {'schema', 'action', 'catalog_sha256', 'architecture', 'machine'}
    extra = {'prepare': {'ids', 'reuse_installed'}, 'status': {'id'}, 'commit': {'id', 'nonce'}}
    if action not in extra or not fields <= set(request) or set(request) - fields - extra[action] or type(request['schema']) is not int or request['schema'] != 1:
        raise ValueError('Public artifact request differs')
    arch, machine = platform.machine(), hashlib.sha256(MACHINE.read_bytes()).hexdigest()
    if request['catalog_sha256'] != digest or request['architecture'] != arch or arch not in ('x86_64', 'aarch64') or request['machine'] != machine:
        raise ValueError('Public artifact source or machine differs')
    upload_uid()
    response = dict(schema=1, catalog_sha256=digest, architecture=arch, machine=machine)
    if action == 'prepare':
        ids = request.get('ids')
        reuse = request.get('reuse_installed', False)
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids) or len(ids) != len(set(ids)) or any(i not in value['artifacts'] for i in ids) or type(reuse) is not bool:
            raise ValueError('Public artifact selection differs')
    else:
        ids = [request.get('id')]
        if ids[0] not in value['artifacts'] or action == 'commit' and not re.fullmatch('[0-9a-f]{32}', str(request.get('nonce', ''))):
            raise ValueError('Public artifact selection differs')
    with cache_lock():
        if action == 'prepare':
            response.update(ready=[], phone_required=[], reused=[])
            deadline = time.monotonic() + BUDGET
            for identifier in ids:
                asset = value['artifacts'][identifier]['assets'][arch]
                if reuse and identifier == 'adguard' and installed_filter():
                    response['reused'].append(identifier)
                elif cached(asset):
                    response['ready'].append(identifier)
                else:
                    try:
                        remaining(deadline)
                        with acquisition_budget(deadline):
                            acquire(asset, deadline)
                        response['ready'].append(identifier)
                    except Unavailable:
                        response['phone_required'].append(identifier)
            return response
        asset = value['artifacts'][ids[0]]['assets'][arch]
        ready = cached(asset)
        if action == 'commit' and not ready:
            commit(asset, ids[0], request['nonce'])
            ready = True
        response.update(id=ids[0], ready=ready)
        return response


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError('Public artifact request exceeds its bound')
        request = read_json(raw)
        if not isinstance(request, dict):
            raise ValueError('Public artifact request differs')
        result = dispatch(request)
        print(json.dumps({'ok': True, 'result': result}, separators=(',', ':')))
    except Exception:
        # Public bytes need no diagnostics containing environment or caller data.
        print(json.dumps({'ok': False, 'error': 'Public artifact validation or preparation failed; inspect before installing.'}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
