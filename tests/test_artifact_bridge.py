"""Real temporary files; mocked public HTTP only, no installer or network calls."""
import contextlib
import copy
import errno
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import ssl
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'single'))
import artifact_bridge as bridge

loader = importlib.util.spec_from_file_location('classic_public_cache', PROJECT / 'gateway/scripts/public-artifact-cache.py')
classic = importlib.util.module_from_spec(loader)
loader.loader.exec_module(classic)


class Response(io.BytesIO):
    def __init__(self, raw, declared=None):
        super().__init__(raw)
        self.headers = {} if declared is None else {'Content-Length': declared}
        self.timeouts = []

    def settimeout(self, seconds):
        self.timeouts.append(seconds)


class ArtifactBridge(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.machine = self.base / 'machine-id'
        self.machine.write_bytes(b'exact machine bytes\n')
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for key, value in [('FILESYSTEM_ROOT', self.base), ('CACHE', self.base / 'cache/artifacts'), ('LOCK', self.base / 'artifact.lock'), ('STAGING', self.base), ('MACHINE', self.machine), ('ROOT_UID', os.getuid())]:
            self.stack.enter_context(patch.object(bridge, key, value))
        self.stack.enter_context(patch.object(bridge.platform, 'machine', return_value='x86_64'))
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.raw = {'adguard': b'fixed adguard archive', 'xray': b'fixed xray archive', 'trusttunnel': b'fixed trust archive'}
        self.registry = {'artifacts': {name: {'assets': {'x86_64': {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'sources': [{'url': 'https://github.com/fixed/' + name, 'headers': {}}]}}} for name, raw in self.raw.items()}}
        self.digest = '1' * 64
        self.stack.enter_context(patch.object(bridge, 'catalog', return_value=(self.registry, self.digest)))

    def request(self, action='prepare', **extra):
        return dict(schema=1, action=action, catalog_sha256=self.digest, architecture='x86_64', machine=hashlib.sha256(self.machine.read_bytes()).hexdigest(), **extra)

    def asset(self, name='adguard'):
        return self.registry['artifacts'][name]['assets']['x86_64']

    def seed(self, name='adguard', data=None):
        bridge.safe_directory(bridge.CACHE, True)
        path = bridge.CACHE / self.asset(name)['sha256']
        path.write_bytes(self.raw[name] if data is None else data)
        path.chmod(0o600)
        return path

    def stage(self, name='adguard'):
        nonce = 'a' * 32
        directory = bridge.STAGING / ('rookstride-artifact-' + nonce)
        directory.mkdir(mode=0o700)
        path = directory / name
        path.write_bytes(self.raw[name])
        path.chmod(0o600)
        return nonce, path

    def test_all_missing_archives_transport_failure_leaves_only_public_cache(self):
        with patch.object(bridge, 'https_open', side_effect=urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))):
            result = bridge.dispatch(self.request(ids=list(self.raw)))
        self.assertEqual(list(self.raw), result['phone_required'])
        self.assertEqual([], result['ready'])
        self.assertEqual([], result['reused'])
        self.assertEqual({'artifact.lock', 'machine-id'}, {p.name for p in self.base.iterdir()})
        # No child/filter/job/account/state directories or installer entrypoints exist.

    def test_upstream_success_then_all_cache_hits_make_no_second_download(self):
        calls = []
        def fetch(request, timeout):
            name = request.full_url.rsplit('/', 1)[1]
            calls.append(name)
            self.assertLessEqual(timeout, 12)
            return Response(self.raw[name], str(len(self.raw[name])))
        with patch.object(bridge, 'https_open', side_effect=fetch):
            result = bridge.dispatch(self.request(ids=list(self.raw)))
        self.assertEqual(list(self.raw), calls)
        self.assertEqual(list(self.raw), result['ready'])
        with patch.object(bridge, 'https_open') as fetch:
            self.assertEqual(list(self.raw), bridge.dispatch(self.request(ids=list(self.raw)))['ready'])
            fetch.assert_not_called()

    def test_real_httpresponse_content_length_closes_socket_without_false_refusal(self):
        raw = self.raw['adguard']
        class Socket:
            def makefile(inner, mode):
                stream = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(raw)).encode() + b'\r\n\r\n' + raw)
                stream._sock = inner
                return io.BufferedReader(stream)
            def settimeout(inner, seconds):
                self.assertGreater(seconds, 0)
        response = http.client.HTTPResponse(Socket());response.begin()
        with patch.object(bridge, 'https_open', return_value=response):
            self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['ready'])
        self.assertIsNone(response.fp)

    def test_typed_transport_includes_tls_eof_but_never_certificate_or_policy(self):
        for error in (ssl.SSLEOFError('closed'), urllib.error.URLError(ssl.SSLEOFError('closed')), TimeoutError(), urllib.error.URLError(ConnectionResetError())):
            with self.subTest(error=type(error).__name__), patch.object(bridge, 'https_open', side_effect=error):
                self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['phone_required'])
        for error in (ssl.SSLCertVerificationError('certificate'), urllib.error.URLError(ssl.SSLCertVerificationError('hostname')), ssl.SSLError('policy'), urllib.error.URLError('unknown TLS policy')):
            with self.subTest(error=type(error).__name__), patch.object(bridge, 'https_open', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'TLS validation'):
                    bridge.dispatch(self.request(ids=['adguard']))

    def test_corrupt_declared_truncated_and_oversize_downloads_are_not_phone_requests(self):
        raw = self.raw['adguard']
        for body, header in [(raw, '1'), (raw[:-1], None), (raw + b'x', None), (b'x' * len(raw), None), (raw, '-1')]:
            with self.subTest(body=body, header=header), patch.object(bridge, 'https_open', return_value=Response(body, header)):
                with self.assertRaises(ValueError):
                    bridge.dispatch(self.request(ids=['adguard']))
                if bridge.CACHE.exists():
                    self.assertEqual([], list(bridge.CACHE.iterdir()))

    def test_one_total_budget_interrupts_blocking_read_and_restores_signal_state(self):
        response = Response(self.raw['adguard'])
        original = signal.getsignal(signal.SIGALRM)
        def blocked(size):
            time.sleep(1)
        response.read1 = blocked
        start = time.monotonic()
        with patch.object(bridge, 'BUDGET', 0.04), patch.object(bridge, 'https_open', return_value=response) as fetch:
            result = bridge.dispatch(self.request(ids=list(self.raw)))
        self.assertLess(time.monotonic() - start, 0.5)
        self.assertEqual(list(self.raw), result['phone_required'])
        self.assertEqual(1, fetch.call_count)
        self.assertEqual(original, signal.getsignal(signal.SIGALRM))
        self.assertEqual((0.0, 0.0), signal.getitimer(signal.ITIMER_REAL))

    def test_earlier_origin_failure_uses_fixed_alternate_once(self):
        self.asset()['sources'].append({'url': 'https://api.github.com/fixed', 'headers': {'Accept': 'application/octet-stream'}})
        with patch.object(bridge, 'https_open', side_effect=[ConnectionResetError(), Response(self.raw['adguard'])]) as fetch:
            self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['ready'])
        self.assertEqual(2, fetch.call_count)
        self.assertEqual('https://api.github.com/fixed', fetch.call_args_list[1].args[0].full_url)
        self.assertEqual('application/octet-stream', fetch.call_args_list[1].args[0].get_header('Accept'))

    def test_public_403_rate_or_ip_refusal_uses_each_fixed_source_once_but_missing_release_is_fatal(self):
        headers = {'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '4102444800', 'Retry-After': '60'}
        for response_headers in ({}, headers):
            error = urllib.error.HTTPError('https://github.com/fixed/adguard', 403, 'rate or IP refusal', response_headers, None)
            with self.subTest(headers=response_headers), patch.object(bridge, 'https_open', side_effect=error) as fetch:
                self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['phone_required'])
                self.assertEqual(1, fetch.call_count)
        self.asset()['sources'].append({'url': 'https://api.github.com/fixed', 'headers': {'Accept': 'application/octet-stream'}})
        errors = [urllib.error.HTTPError(s['url'], 403, 'rate limited', headers, None) for s in self.asset()['sources']]
        with patch.object(bridge, 'https_open', side_effect=errors) as fetch:
            self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['phone_required'])
            self.assertEqual([s['url'] for s in self.asset()['sources']], [c.args[0].full_url for c in fetch.call_args_list])
        for code in (401, 404, 410):
            errors = [urllib.error.HTTPError(s['url'], code, 'fixed release refused', {}, None) for s in self.asset()['sources']]
            with self.subTest(code=code), patch.object(bridge, 'https_open', side_effect=errors) as fetch:
                with self.assertRaisesRegex(ValueError, 'upstream rejected'):
                    bridge.dispatch(self.request(ids=['adguard']))
                self.assertEqual(2, fetch.call_count)
        with patch.object(bridge, 'https_open', side_effect=[urllib.error.HTTPError('https://github.com/fixed/adguard', 403, 'IP refusal', {}, None), Response(self.raw['adguard'])]) as fetch:
            self.assertEqual(['adguard'], bridge.dispatch(self.request(ids=['adguard']))['ready'])
            self.assertEqual(2, fetch.call_count)

    def test_complete_filter_reuse_precedes_cache_and_peer_requires_actual_cache(self):
        path = self.seed(data=b'bad cache remains untouched')
        with patch.object(bridge, 'installed_filter', return_value=True), patch.object(bridge, 'https_open') as fetch:
            result = bridge.dispatch(self.request(ids=['adguard'], reuse_installed=True))
            self.assertEqual(['adguard'], result['reused'])
            self.assertEqual([], result['ready'])
            fetch.assert_not_called()
            with self.assertRaises(ValueError):
                bridge.dispatch(self.request(ids=['adguard'], reuse_installed=False))
        self.assertEqual(b'bad cache remains untouched', path.read_bytes())

    def classic_fixture(self, native=False):
        job, pair = 'c' * 32, 'd' * 32
        action = 'bootstrap' if native else 'configure'
        root_files = {
            'etc/rookstride-pair/manifest.json': json.dumps({'version': 2 if native else 1, 'configured': not native, 'plan': {'pair': pair, 'role': 'exit', 'exit_protocol': 'ikev2' if native else 'awg'}, 'jobs': {action: job}}).encode(),
            'var/lib/rookstride-pair/' + job + '/status.json': json.dumps({'job': job, 'action': action, 'state': 'complete'}).encode(),
            'opt/AdGuardHome/AdGuardHome': b'actual retained installed v0.107.79 bytes',
            'etc/systemd/system/adguardhome.service': (PROJECT / 'gateway/systemd/adguardhome.service').read_bytes(),
            'var/lib/AdGuardHome/AdGuardHome.yaml': b'actual original private filter preferences',
        }
        if not native:
            root_files['etc/systemd/system/adguardhome.service'] = root_files['etc/systemd/system/adguardhome.service'].replace(b'single-vps-vpn-dns-address.service', b'awg-quick@awg-exit.service')
        for name, raw in root_files.items():
            path = self.base / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw);path.chmod(0o600)
        (self.base / 'var/lib/AdGuardHome/work').mkdir(mode=0o700)
        self.stack.enter_context(patch.object(bridge.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid(), pw_dir='/var/lib/AdGuardHome', pw_shell='/usr/sbin/nologin')))
        return self.base / ('var/lib/rookstride-pair/' + job + '/status.json')

    def test_completed_owned_classic79_reuses_without_cache_network_or_writes(self):
        self.classic_fixture()
        before = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        with patch.object(bridge, 'installed_filter', side_effect=bridge.installed_classic_filter), patch.object(bridge, 'https_open') as fetch:
            result = bridge.dispatch(self.request(ids=['adguard'], reuse_installed=True))
            fetch.assert_not_called()
        self.assertEqual(['adguard'], result['reused']);self.assertEqual([], result['ready'])
        self.assertFalse(bridge.CACHE.exists())
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_native_ike_completed_bootstrap_classic_reuse_needs_exact_receipt(self):
        receipt = self.classic_fixture(native=True)
        self.assertTrue(bridge.installed_classic_filter())
        data = json.loads(receipt.read_text());data['job'] = 'f' * 32;receipt.write_text(json.dumps(data))
        self.assertFalse(bridge.installed_classic_filter())
        receipt.unlink()
        with self.assertRaises(FileNotFoundError):bridge.installed_classic_filter()

    def test_classic_foreign_unit_or_linked_config_refuses_without_changes(self):
        self.classic_fixture()
        unit = self.base / 'etc/systemd/system/adguardhome.service'
        expected = unit.read_bytes();unit.write_bytes(b'foreign unit')
        with self.assertRaisesRegex(ValueError, 'service differs'):bridge.installed_classic_filter()
        self.assertEqual(b'foreign unit', unit.read_bytes());unit.write_bytes(expected)
        config = self.base / 'var/lib/AdGuardHome/AdGuardHome.yaml'
        config.unlink();config.symlink_to(self.machine)
        with self.assertRaises(OSError):bridge.installed_classic_filter()
        self.assertTrue(config.is_symlink())

    def test_invalid_existing_cache_is_unchanged_and_never_downloaded(self):
        for variant in ('corrupt', 'symlink', 'hardlink', 'foreign', 'public'):
            with self.subTest(variant=variant):
                path = self.seed()
                if variant == 'corrupt':
                    path.write_bytes(b'wrong')
                elif variant == 'symlink':
                    path.unlink();path.symlink_to(self.machine)
                elif variant == 'hardlink':
                    os.link(path, self.base / 'alias')
                elif variant == 'public':
                    path.chmod(0o644)
                before = path.read_bytes()
                with contextlib.ExitStack() as stack:
                    if variant == 'foreign':
                        stack.enter_context(patch.object(bridge, 'ROOT_UID', os.getuid() + 1))
                    fetch = stack.enter_context(patch.object(bridge, 'https_open'))
                    with self.assertRaises((ValueError, OSError)):
                        bridge.dispatch(self.request(ids=['adguard']))
                    fetch.assert_not_called()
                self.assertEqual(before, path.read_bytes())
                path.unlink()
                if variant == 'hardlink':
                    (self.base / 'alias').unlink()

    def test_cache_directory_links_or_writable_ancestors_refuse(self):
        bridge.CACHE.parent.mkdir(mode=0o700)
        bridge.CACHE.symlink_to(self.base)
        with self.assertRaises(ValueError):
            bridge.dispatch(self.request('status', id='adguard'))
        bridge.CACHE.unlink()
        bridge.CACHE.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            bridge.dispatch(self.request('status', id='adguard'))

    def test_valid_commit_ack_is_durable_then_lost_reply_reconciles_read_only(self):
        nonce, path = self.stage()
        events = []
        real_fsync, real_link = os.fsync, os.link
        def fsync(fd):
            events.append('sync');return real_fsync(fd)
        def link(*args, **kwargs):
            events.append('publish');return real_link(*args, **kwargs)
        with patch.object(bridge.os, 'fsync', side_effect=fsync), patch.object(bridge.os, 'link', side_effect=link):
            result = bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
        self.assertTrue(result['ready'])
        self.assertIn('sync', events[:events.index('publish')])
        self.assertEqual('sync', events[-1])
        self.assertEqual(self.raw['adguard'], path.read_bytes())
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.base.rglob('*') if p.is_file()}
        with patch.object(bridge, 'commit') as commit:
            self.assertTrue(bridge.dispatch(self.request('status', id='adguard'))['ready'])
            self.assertTrue(bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))['ready'])
            commit.assert_not_called()
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.base.rglob('*') if p.is_file()})

    def test_upload_short_oversize_symlink_hardlink_or_public_bytes_refuse(self):
        for variant in ('short', 'oversize', 'symlink', 'hardlink', 'public', 'public-stage'):
            with self.subTest(variant=variant):
                nonce, path = self.stage()
                if variant == 'short':path.write_bytes(self.raw['adguard'][:-1])
                elif variant == 'oversize':path.write_bytes(self.raw['adguard'] + b'x')
                elif variant == 'symlink':path.unlink();path.symlink_to(self.machine)
                elif variant == 'hardlink':os.link(path, path.parent / 'alias')
                elif variant == 'public':path.chmod(0o644)
                elif variant == 'public-stage':path.parent.chmod(0o755)
                before = path.read_bytes()
                with self.assertRaises((ValueError, OSError)):
                    bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
                self.assertEqual(before, path.read_bytes())
                self.assertFalse(bridge.cached(self.asset()))
                import shutil
                shutil.rmtree(path.parent)

    def test_upload_uid_is_process_derived_and_request_cannot_override_it(self):
        nonce, path = self.stage()
        with patch.dict(os.environ, {'SUDO_UID': str(os.getuid() + 1)}):
            with self.assertRaisesRegex(ValueError, 'directory'):
                bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
        with self.assertRaisesRegex(ValueError, 'request differs'):
            bridge.dispatch(self.request('commit', id='adguard', nonce=nonce, uid=os.getuid()))
        self.assertEqual(self.raw['adguard'], path.read_bytes())
        self.assertFalse(bridge.cached(self.asset()))

    def test_upload_changed_between_validation_and_copy_is_not_committed(self):
        nonce, path = self.stage()
        original = bridge.verify_fd
        def change(fd, asset, uid):
            original(fd, asset, uid)
            path.write_bytes(b'x' * len(self.raw['adguard']))
        with patch.object(bridge, 'verify_fd', side_effect=change), self.assertRaisesRegex(ValueError, 'upload changed'):
            bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
        self.assertFalse(bridge.cached(self.asset()))
        self.assertEqual(b'x' * len(self.raw['adguard']), path.read_bytes())

    def test_short_written_cache_temporary_never_becomes_a_published_entry(self):
        nonce, path = self.stage()
        temporary = bridge.temporary_cache
        @contextlib.contextmanager
        def short_write():
            with temporary() as (out, name):
                yield SimpleNamespace(write=lambda block: out.write(block[:-1]), flush=out.flush, fileno=out.fileno), name
        with patch.object(bridge, 'temporary_cache', side_effect=short_write), patch.object(bridge, 'publish') as publish:
            with self.assertRaises(ValueError):
                bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
            publish.assert_not_called()
        self.assertFalse(bridge.cached(self.asset()))
        self.assertEqual(self.raw['adguard'], path.read_bytes())

    def test_private_upload_directory_link_and_unknown_claim_fields_are_refused(self):
        nonce, path = self.stage()
        real = path.parent
        renamed = self.base / 'retained'
        real.rename(renamed);real.symlink_to(renamed)
        with self.assertRaises(OSError):
            bridge.dispatch(self.request('commit', id='adguard', nonce=nonce))
        with self.assertRaises(ValueError):
            bridge.dispatch(self.request('commit', id='adguard', nonce=nonce, path=str(renamed)))
        self.assertFalse(bridge.cached(self.asset()))

    def test_existing_process_timer_is_preserved_and_cannot_be_repurposed(self):
        signal.setitimer(signal.ITIMER_REAL, 5)
        try:
            with patch.object(bridge, 'https_open') as fetch, self.assertRaisesRegex(ValueError, 'already in use'):
                bridge.dispatch(self.request(ids=['adguard']))
            fetch.assert_not_called()
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 4)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_changed_machine_catalog_architecture_or_unknown_id_never_acquires(self):
        for key, value in [('machine', '2'*64), ('catalog_sha256', '2'*64), ('architecture', 'aarch64'), ('ids', ['foreign'])]:
            request = self.request(ids=['adguard']);request[key] = value
            with self.subTest(key=key), patch.object(bridge, 'https_open') as fetch:
                with self.assertRaises(ValueError):bridge.dispatch(request)
                fetch.assert_not_called()

    def test_classic_consumer_reuses_verified_cache_and_refuses_corrupt_without_output(self):
        path = self.seed();target = self.base / 'copied'
        self.assertTrue(classic.copy_cached(self.asset()['sha256'], self.asset()['bytes'], target, bridge.CACHE, os.getuid(), self.base))
        self.assertEqual(self.raw['adguard'], target.read_bytes())
        target.unlink();path.write_bytes(b'bad')
        with self.assertRaises(ValueError):classic.copy_cached(self.asset()['sha256'], self.asset()['bytes'], target, bridge.CACHE, os.getuid(), self.base)
        self.assertFalse(target.exists());self.assertEqual(b'bad', path.read_bytes())


class FixedCatalog(unittest.TestCase):
    def test_actual_three_ids_both_architectures_match_actual_installer_pins(self):
        value, digest = bridge.catalog()
        self.assertEqual({'adguard', 'xray', 'trusttunnel'}, set(value['artifacts']))
        self.assertEqual(hashlib.sha256((bridge.HERE / 'public-artifacts.json').read_bytes()).hexdigest(), digest)
        with tempfile.TemporaryDirectory() as directory:
            here = Path(directory)
            for name in ('public-artifacts.json', 'filtering.py', 'pins.json', 'routes-pins.json'):
                (here / name).write_bytes((bridge.HERE / name).read_bytes())
            data = json.loads((here / 'public-artifacts.json').read_text())
            data['artifacts']['trusttunnel']['assets']['aarch64']['sha256'] = '0'*64
            (here / 'public-artifacts.json').write_text(json.dumps(data))
            with patch.object(bridge, 'HERE', here), self.assertRaisesRegex(ValueError, 'pins differ'):
                bridge.catalog()

    def test_redirect_policy_refuses_http_unknown_host_credentials_and_ports(self):
        handler = bridge.FixedRedirect()
        request = urllib.request.Request('https://github.com/fixed')
        for url in ('http://github.com/bytes', 'https://example.com/bytes', 'https://github.com:444/bytes', 'https://user@github.com/bytes'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'redirect', {}, url)

    def test_legacy_dns_and_classic_verify_cache_before_any_dns_publication(self):
        legacy = (PROJECT / 'server/install-pair-dns.sh').read_text()
        ordinary = (PROJECT / 'gateway/scripts/install.sh').read_text()
        self.assertNotIn('v0.107.79', legacy)
        self.assertLess(legacy.index('public-artifact-cache.py'), legacy.index('install -d -m 755 /opt/AdGuardHome'))
        self.assertLess(legacy.index('PYADGUARD\napt-get'), legacy.index('cat > /etc/unbound/'))
        self.assertLess(ordinary.index('public-artifact-cache.py'), ordinary.index('ike_packages.py'))
        self.assertIn('Existing pair DNS requires review', legacy)


if __name__ == '__main__':
    unittest.main()
