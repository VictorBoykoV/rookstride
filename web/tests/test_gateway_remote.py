"""Exercise guards locally using source files and fake target observations only."""
import base64
import contextlib
import gzip
from copy import deepcopy
import hashlib
import io
import re
import sys
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

WEB = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixed_gateway", WEB / "scripts/gateway_remote.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
pair_spec = importlib.util.spec_from_file_location("fixed_pair", WEB / "scripts/pair_remote.py")
pair_remote = importlib.util.module_from_spec(pair_spec)
pair_spec.loader.exec_module(pair_remote)


class PairWrapperGuards(unittest.TestCase):
    ports = {"awg": 51820, "ikev2": 500, "openvpn": 1194, "xray": 443, "xhttp": 443,
             "hysteria2": 443, "outline": 443, "shadowsocks": 443, "trusttunnel": 443, "naive": 443}

    def envelope(self, exit_protocol="openvpn", role="exit", entry_protocol="awg"):
        return {"pair": "a" * 32, "role": role, "server": "192.0.2.17", "exit_host": "198.51.100.18",
                "engine": "native-v2", "entry_protocol": entry_protocol, "exit_protocol": exit_protocol,
                "vpn_port": self.ports[entry_protocol],
                "tunnel_port": 443 if exit_protocol == "awg" else self.ports[exit_protocol]}

    def test_fresh_pair_envelopes_match_all_android_default_topologies(self):
        path = WEB.parent / "android/overlay/java/org/strongswan/android/rookstride/SingleProtocols.java"
        android_ports = {name: int(port) for name, port in re.findall(
            r'^\s*[A-Z][A-Z0-9_]*\("([a-z0-9]+)","[^"]+",(\d+),', path.read_text(), re.M
        )}
        self.assertEqual(android_ports, self.ports)
        self.assertEqual(gateway.PAIR_ENTRY_PORTS, android_ports)
        self.assertEqual(gateway.PAIR_EXIT_PORTS, {**android_ports, "awg": 443})

        def request(fields):
            payload = {"mode": "recipe", "bundle": "b" * 64,
                       "request": {"command": "preflight", **fields}}
            return pair_remote.run(io.BytesIO(json.dumps(payload).encode() + b"\n"))

        mixed = self.envelope()
        with patch.object(pair_remote.os, "geteuid", return_value=0), \
             patch.object(pair_remote, "owned", return_value=None), \
             patch.object(pair_remote, "unpack") as unpack, \
             patch.object(pair_remote, "execute", return_value={"ready": True}) as execute:
            for entry in android_ports:
                for exit_protocol in android_ports:
                    supported = self.envelope(exit_protocol, entry_protocol=entry)
                    self.assertEqual(request(supported), {"ready": True})
                    self.assertEqual(execute.call_args.args[1:], ("server/pair.py", {"command": "preflight", **supported}))
            for invalid in ({"tunnel_port": 443}, {"tunnel_port": 1194.0}, {"vpn_port": 1194},
                            {"entry_protocol": "openvpn"}, {"exit_protocol": "ikev2"},
                            {"exit_protocol": "unknown", "tunnel_port": 443}, {"entry_protocol": []},
                            {"access_mode": "password"}, {"route_table": 513},
                            {"exit_host": mixed["server"]}, {"server": ["invalid"]}):
                with self.subTest(invalid=invalid), self.assertRaises(pair_remote.PairRejected):
                    request({**mixed, **invalid})
            self.assertEqual(unpack.call_count, 100)
            self.assertEqual(execute.call_count, 100)

    def test_probe_adds_nondefault_methods_and_only_recognized_architectures(self):
        def contents(path, _maximum):
            if path == "/etc/machine-id":
                return b"a" * 32 + b"\n"
            return b'ID=ubuntu\nVERSION_ID="26.04"\n'

        awg = self.envelope("awg")
        manifest = {"version": 2, "bundle": "b" * 64, "plan": pair_remote.supported_plan(awg)}
        with (
            patch.object(pair_remote, "read", side_effect=contents),
            patch.object(pair_remote, "owned", return_value=manifest),
            patch.object(pair_remote.platform, "machine", return_value="aarch64") as machine,
        ):
            old = {"pairId": awg["pair"], "bundle": manifest["bundle"], "role": "exit", "resetting": False}
            self.assertEqual(pair_remote.probe()["owner"], old)
            for method in ("openvpn", "ikev2", "xray", "hysteria2"):
                manifest["plan"] = pair_remote.supported_plan(self.envelope(method, entry_protocol="naive"))
                proof = pair_remote.probe()
                self.assertEqual(proof["owner"], {**old, "entryProtocol": "naive", "exitProtocol": method})
                self.assertEqual(proof["runtimeArchitecture"], "aarch64")
            machine.return_value = "unexpected"
            self.assertNotIn("runtimeArchitecture", pair_remote.probe())
            manifest["plan"]["tunnel_port"] = 500
            with self.assertRaises(pair_remote.PairRejected):
                pair_remote.probe()

    def test_mixed_owned_exit_loads_openvpn_and_checks_certificate_bridge_shape(self):
        request = self.envelope()
        plan = pair_remote.supported_plan(request)
        expected = "b" * 64
        manifest = {"plan": plan, "jobs": {"bootstrap": "c" * 32, "configure": "d" * 32}}
        info = {"read_only": False, "bundle": expected, "plan": plan}
        lifecycle = SimpleNamespace(inspect=lambda: info, route_override=lambda _: None, records=lambda: [],
                                    read=lambda _: {"state": "complete"}, digest=Mock(return_value="bridge-digest"))
        state = {"protocol": "openvpn", "server": request["exit_host"], "port": 1194}
        transport = {"protocol": "openvpn", "profile": {"format": "openvpn", "content": "owned-fixture"}}
        native = SimpleNamespace(runtime=SimpleNamespace(load=Mock(return_value=state)),
                                 material=Mock(return_value=transport), validate_material=Mock())
        pair = SimpleNamespace(plan=lambda value: value, ident=lambda value: value, STATE=Path("/unused"))
        with patch.dict(sys.modules, {"native_pair": native, "lifecycle": lifecycle, "pair": pair}):
            self.assertEqual(pair_remote.managed_node(manifest, request, expected), (info, plan, state, "bridge-digest"))
            native.runtime.load.assert_called_once_with("openvpn")
            native.validate_material.assert_called_once_with({**plan, "role": "entry"}, transport)
            state["access_mode"] = "password"
            with self.assertRaises(pair_remote.PairRejected):
                pair_remote.managed_node(manifest, request, expected)

    def test_entry_accounts_use_the_selected_native_recipe_and_ike_requires_explicit_password(self):
        single = SimpleNamespace(action=Mock(return_value={"ok": True}))
        admin_profile = {"type": "ikev2-eap", "local": {"eap_id": "guest"}, "remote": {"cert": "fixture"}}
        admin = SimpleNamespace(profile=Mock(return_value=admin_profile), dispatch=Mock())
        with patch.dict(sys.modules, {"rookstride": SimpleNamespace(admin=admin)}):
            for method in self.ports.keys() - {"ikev2"}:
                for action, native_action in (("grant", "add-user"), ("revoke", "remove-user"), ("profile", "profile")):
                    result = pair_remote.account_action(method, action, "guest", {}, single)
                    self.assertEqual(result, {"ok": True})
                    single.action.assert_called_with({"protocol": method, "login": "guest", "action": native_action})
            single.action.reset_mock()
            password = "fixture-vpn-password"
            pair_remote.account_action("ikev2", "grant", "guest", {"password": password}, single)
            admin.dispatch.assert_called_with({"action": "add-user", "login": "guest", "password": password})
            pair_remote.account_action("ikev2", "revoke", "guest", {}, single)
            admin.dispatch.assert_called_with({"action": "remove-user", "login": "guest"})
            profile = pair_remote.account_action("ikev2", "profile", "guest", {}, single)
            self.assertEqual(profile["format"], "ikev2")
            self.assertEqual(profile["name"], "rookstride-guest.sswan")
            self.assertEqual(json.loads(profile["content"]), admin_profile)
            admin.profile.assert_called_once_with({"login": "guest"})
            admin.dispatch.reset_mock()
            for method, action, fields in (("ikev2", "grant", {}), ("ikev2", "revoke", {"password": password}),
                                           ("xhttp", "grant", {"password": password})):
                with self.assertRaisesRegex(ValueError, "account password"):
                    pair_remote.account_action(method, action, "guest", fields, single)
            single.action.assert_not_called()
            admin.dispatch.assert_not_called()

    def test_only_verified_runtime_assets_stage_for_the_correct_pair_member(self):
        source = (WEB.parent / "single/routes-pins.json").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), gateway.PAIR_ROUTE_PINS_SHA256)
        assets = json.loads(source)["assets"]
        topology = self.envelope("openvpn", role="entry", entry_protocol="hysteria2")
        request = {"action": "pairRuntime", "address": topology["server"], "topology": topology,
                   "runtimeArchitecture": "aarch64", "routesPins": base64.b64encode(source).decode()}
        stream = io.BytesIO(b"fixture verified by the actual runtime installer")
        with (
            patch.object(gateway, "eligible_version", return_value="24.04"),
            patch.object(gateway, "resume_reinstall", return_value=None),
            patch.object(gateway, "valid_address", return_value=True),
            patch.object(gateway.platform, "machine", return_value="aarch64"),
            patch.object(gateway.os.path, "lexists", return_value=False),
            patch.object(gateway, "exclusive_pair_reinstall", contextlib.nullcontext),
            patch.object(gateway, "runtime_ready", return_value=True),
            patch.object(gateway, "install_route_runtime") as install,
        ):
            self.assertEqual(gateway.dispatch(request, stream), {"ready": True})
            install.assert_called_once_with(gateway.PAIR_ROUTE_WORKER_ROOT, assets["aarch64"], stream)
            install.reset_mock()
            check = {**request, "action": "pairRuntimeCheck"}
            self.assertEqual(gateway.dispatch(check), {"ready": True})
            with patch.object(gateway, "runtime_ready", return_value=False):
                self.assertEqual(gateway.dispatch(check), {"ready": False})
            with self.assertRaises(gateway.GuardError):
                gateway.dispatch(check, stream)
            unused_exit = {**request, "address": topology["exit_host"], "topology": {**topology, "role": "exit"}}
            for change in ({"address": topology["exit_host"]}, {"runtimeArchitecture": "x86_64"},
                           {"routesPins": base64.b64encode(source + b" ").decode()},
                           {"topology": {**topology, "tunnel_port": 443}}):
                with self.subTest(change=change.keys()), self.assertRaises(gateway.GuardError):
                    gateway.dispatch({**request, **change}, stream)
            with self.assertRaisesRegex(gateway.GuardError, "does not require"):
                gateway.dispatch(unused_exit, stream)
            with self.assertRaises(gateway.GuardError):
                gateway.dispatch(request, None)
            install.assert_not_called()

            worker_exit = self.envelope("trusttunnel", role="exit", entry_protocol="xhttp")
            for role in ("entry", "exit"):
                candidate = {**worker_exit, "role": role}
                address = candidate["server" if role == "entry" else "exit_host"]
                self.assertEqual(gateway.dispatch({**request, "address": address, "topology": candidate}, stream),
                                 {"ready": True})
            self.assertEqual(install.call_count, 2)

    def test_staging_rejects_mismatched_owned_pairs_and_never_repairs_a_live_changed_runtime(self):
        install = Mock()
        topology = self.envelope("trusttunnel", role="exit", entry_protocol="xhttp")
        source = (WEB.parent / "single/routes-pins.json").read_bytes()
        request = {"action": "pairRuntime", "address": topology["exit_host"], "topology": topology,
                   "runtimeArchitecture": "x86_64", "routesPins": base64.b64encode(source).decode()}
        original = {**topology, **gateway.PAIR_ROUTE_FIELDS}
        manifest = {"configured": False, "plan": original}
        with (
            patch.object(gateway, "valid_address", return_value=True),
            patch.object(gateway.platform, "machine", return_value="x86_64"),
            patch.object(gateway.os.path, "lexists", return_value=True),
            patch.object(gateway, "exclusive_pair_reinstall", contextlib.nullcontext),
            patch.object(gateway, "read_pair_manifest", return_value=(b"manifest", manifest)),
            patch.object(gateway, "runtime_ready", return_value=False),
            patch.object(gateway, "install_route_runtime", install),
        ):
            for different in ({"pair": "c" * 32}, {"entry_protocol": "xray"}):
                manifest["plan"] = {**original, **different}
                with self.assertRaises(gateway.Conflict):
                    gateway.stage_pair_runtime(request, io.BytesIO())
            manifest.update(configured=True, plan=original)
            with self.assertRaisesRegex(gateway.Conflict, "configured Double VPN runtime"):
                gateway.stage_pair_runtime(request, io.BytesIO())
            install.assert_not_called()

    def test_ike_health_uses_the_native_services_and_rejects_a_public_exit_state(self):
        request = self.envelope("ikev2")
        plan = pair_remote.supported_plan(request)
        expected = "b" * 64
        manifest = {"plan": plan, "jobs": {"bootstrap": "c" * 32, "configure": "d" * 32},
                    "version": 2, "bundle": expected}
        state = {"protocol": "ikev2", "server": plan["exit_host"], "port": 500, "access_mode": "profile"}
        info = {"read_only": False, "bundle": expected, "plan": plan}
        lifecycle = SimpleNamespace(inspect=lambda: info, route_override=lambda _: None, records=lambda: [],
                                    read=lambda _: {"state": "complete"}, digest=Mock(return_value="bridge-digest"))
        transport = {"protocol": "ikev2", "profile": {"identity": plan["exit_host"], "certificate": "fixture"}}
        native = SimpleNamespace(runtime=SimpleNamespace(load=Mock(), health=Mock()),
                                 material=Mock(return_value=transport), validate_material=Mock())
        pair = SimpleNamespace(plan=lambda value: value, ident=lambda value: value, STATE=Path("/unused"))
        ike = SimpleNamespace(state=Mock(return_value=state))
        raw_health = {"services": {"strongswan-starter": True, "adguardhome": False, "unbound": True}}
        admin = SimpleNamespace(health=Mock(return_value=raw_health))
        modules = {"native_pair": native, "recovery_ike": ike, "pair": pair,
                   "lifecycle": lifecycle, "rookstride": SimpleNamespace(admin=admin)}
        with patch.dict(sys.modules, modules):
            self.assertEqual(pair_remote.managed_node(manifest, request, expected), (info, plan, state, "bridge-digest"))
            ike.state.assert_called_once_with(plan)
            native.runtime.load.assert_not_called()
            native.validate_material.assert_called_once_with({**plan, "role": "entry"}, transport)
            self.assertEqual(pair_remote.node_health(plan, state)["services"],
                             {**raw_health["services"], "protocol": True, "adguard": False})
            self.assertNotIn("protocol", raw_health["services"])
            state["access_mode"] = "password"
            with self.assertRaises(pair_remote.PairRejected):
                pair_remote.managed_node(manifest, request, expected)

        payload = {"mode": "recipe", "bundle": expected, "request": {"command": "health", **request}}
        with (
            patch.object(pair_remote.os, "geteuid", return_value=0),
            patch.object(pair_remote, "owned", return_value=manifest),
            patch.object(pair_remote, "installed_digest"),
            patch.object(pair_remote, "execute", return_value=raw_health),
        ):
            result = pair_remote.run(io.BytesIO(json.dumps(payload).encode() + b"\n"))
            self.assertTrue(result["services"]["protocol"])
            self.assertFalse(result["services"]["adguard"])

    def test_snapshot_contract_binds_ike_certificate_generation_and_xray_protocol(self):
        plan = pair_remote.supported_plan(self.envelope("ikev2"))
        leaf = b"fixture server PEM"
        details = {"content": base64.b64encode(leaf).decode()}
        snapshot = {"plan": plan, "role": "exit", "identity_files": {"tls/server.pem": details},
                    "state": {"protocol": "ikev2", "access_mode": "profile",
                              "instance": hashlib.sha256(leaf).hexdigest()[:32]}}
        self.assertEqual(pair_remote.checked_snapshot(snapshot, plan), snapshot)
        for patch_state in ({"instance": "f" * 32}, {"access_mode": "password"}, {"protocol": "awg"}):
            changed = {**snapshot, "state": {**snapshot["state"], **patch_state}}
            with self.subTest(patch_state=patch_state), self.assertRaises(pair_remote.PairRejected):
                pair_remote.checked_snapshot(changed, plan)
        xray = pair_remote.supported_plan(self.envelope("xray"))
        xray_snapshot = {"plan": xray, "role": "exit", "state": {"protocol": "xray"}, "identity_files": {}}
        self.assertEqual(pair_remote.checked_snapshot(xray_snapshot, xray), xray_snapshot)
        with self.assertRaises(pair_remote.PairRejected):
            pair_remote.checked_snapshot(xray_snapshot, plan)

    def test_mixed_restore_receipts_recheck_owned_identity_without_replaying_the_restore(self):
        for method in ("openvpn", "ikev2", "xray"):
            with self.subTest(method=method):
                self.check_mixed_restore_receipts(method)

    def check_mixed_restore_receipts(self, method):
        expected = "b" * 64
        request = {**self.envelope(method), "action": "revision", "operation": "c" * 32,
                   "archiveDigest": "d" * 64, "revision": 2}
        plan = pair_remote.supported_plan(request)
        manifest = {"plan": plan, "bundle": expected, "version": 2, "configured": True,
                    "jobs": {"bootstrap": "c" * 32, "configure": "d" * 32}}
        leaf = b"fixture server PEM"
        instance = hashlib.sha256(leaf).hexdigest()[:32] if method == "ikev2" else "e" * 32
        state = {"protocol": method, "instance": instance, "access_mode": "profile", "users": [{}]}
        identity_files = {"tls/server.pem": {"content": base64.b64encode(leaf).decode()}} if method == "ikev2" else {}
        policy = {"enabled": True, "level": "standard"}
        snapshot = {"plan": plan, "role": "exit", "state": state.copy(),
                    "identity_files": identity_files, "filter_policy": policy}
        prior = {"state": "complete", "generation": instance,
                 "restored_identity": "f" * 64, "snapshot": "0" * 64}
        inventory = {"revision": 2, "entry_operation": request["operation"], "anchor": "a" * 64}
        lifecycle = SimpleNamespace(ROOT=Path("/unused"), read=lambda path: inventory if path.name == "inventory.json" else prior,
                                    anchor=lambda _: inventory["anchor"], digest=lambda _: prior["snapshot"])
        native = SimpleNamespace(runtime=SimpleNamespace(load=Mock(return_value=state)))
        ike = SimpleNamespace(state=Mock(return_value=state))
        recovery = SimpleNamespace(restored_identity=Mock(return_value=prior["restored_identity"]),
                                   validate=Mock(side_effect=lambda value: value), check_restored_service=Mock(),
                                   filter_policy=Mock(return_value=policy), dispatch=Mock())
        migration = SimpleNamespace(dispatch=Mock())
        pair = SimpleNamespace(plan=lambda value: value, ident=lambda value: value, STATE=Path("/unused"))
        modules = {"entry_migration": migration, "lifecycle": lifecycle, "native_pair": native,
                   "pair": pair, "recovery": recovery, "recovery_ike": ike}
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "fixture.json"
            receipt.write_text(json.dumps(pair_remote.restore_binding(request, expected)))
            with patch.dict(sys.modules, modules), patch.object(sys, "path", sys.path.copy()), \
                 patch.object(pair_remote, "RESTORE_OPERATION", receipt), \
                 patch.object(pair_remote, "protected", side_effect=lambda path: path), \
                 patch.object(pair_remote, "owned", return_value=manifest), \
                 patch.object(pair_remote, "management_lock", contextlib.nullcontext), \
                 patch.object(pair_remote, "installed_digest") as installed:
                self.assertEqual(pair_remote.restore_operation(io.BytesIO(), request, expected), {"revision": 2})
                installed.assert_called_once_with(expected)
                if method == "ikev2":
                    ike.state.assert_called_once_with(plan)
                    native.runtime.load.assert_not_called()
                else:
                    native.runtime.load.assert_called_once_with(method)
                    ike.state.assert_not_called()
                migration.dispatch.assert_not_called()

                identity_request = {**request, "action": "identity", "snapshot": snapshot}
                self.assertEqual(pair_remote.restore_operation(io.BytesIO(), identity_request, expected),
                                 {"restored": True, "usage_generation": instance, "users": 1})
                recovery.check_restored_service.assert_called_once_with(state)
                recovery.dispatch.assert_not_called()
                recovery.filter_policy.return_value = {"enabled": False, "level": "standard"}
                with self.assertRaisesRegex(pair_remote.PairRejected, "restore-ownership-mismatch"):
                    pair_remote.restore_operation(io.BytesIO(), identity_request, expected)
                recovery.dispatch.assert_not_called()
                state["access_mode"] = "password"
                with self.assertRaisesRegex(pair_remote.PairRejected, "restore-ownership-mismatch"):
                    pair_remote.restore_operation(io.BytesIO(), request, expected)


class GatewayGuards(unittest.TestCase):
    def test_usage_excludes_identities_and_inactive_sessions(self):
        active = {"state": "ESTABLISHED", "children": [{}], "upload": 10, "download": 36,
                  "user": "private", "endpoint": "192.0.2.3"}
        inactive = {**active, "state": "CONNECTING"}
        admin = SimpleNamespace(sessions=Mock(return_value=[]),
                                connections=Mock(return_value=[active, inactive]))
        self.assertEqual(gateway.live_ike_usage(admin), {
            "available": True, "sessions": 1, "upload": 10, "download": 36})
        admin.sessions.side_effect = OSError("local monitoring unavailable")
        self.assertEqual(gateway.live_ike_usage(admin), {"available": False})

    def test_inspection_reports_supported_release_and_keeps_other_targets_ineligible(self):
        releases = (
            ("ubuntu", "22.04", "ready"),
            ("ubuntu", "24.04", "ready"),
            ("ubuntu", "26.04", "ready"),
            ("ubuntu", "26.10", "unsupported"),
            ("debian", "22.04", "unsupported"),
        )
        for identity, version, state in releases:
            with self.subTest(identity=identity, version=version), \
                 patch.object(gateway.os, "geteuid", return_value=0), \
                 patch.object(gateway.platform, "system", return_value="Linux"), \
                 patch.object(gateway.platform, "machine", return_value="x86_64"), \
                 patch.object(Path, "read_text", return_value=f'ID={identity}\nVERSION_ID="{version}"\n'), \
                 patch.object(Path, "is_dir", return_value=True), \
                 patch.object(Path, "is_file", return_value=True), \
                 patch.object(gateway, "inspect", return_value={"state": "ready"}) as inspect:
                result = gateway.dispatch({"action": "inspect"})
                self.assertEqual(result["state"], state)
                if state == "ready":
                    self.assertEqual(result["os"], f"Ubuntu {version}")
                    inspect.assert_called_once_with(None)
                else:
                    self.assertNotIn("os", result)
                    inspect.assert_not_called()

    def test_only_exact_bundled_sources(self):
        for pins in (gateway.PINNED, gateway.GUEST_PINNED, gateway.LIFECYCLE_PINNED):
            exact = {name: base64.b64encode((WEB.parent / name).read_bytes()).decode() for name in pins}
            self.assertEqual(set(gateway.bundle(exact, pins)), set(pins))
        files = {name: base64.b64encode((WEB.parent / name).read_bytes()).decode() for name in gateway.PINNED}
        self.assertEqual(set(gateway.bundle(files)), set(gateway.PINNED))
        for bad in ({}, {**files, "../extra": "eA=="}, {**files, "gateway/scripts/install.sh": "eA=="}):
            with self.assertRaises(gateway.GuardError):
                gateway.bundle(bad)

    def test_reinstall_bundle_validates_the_complete_native_source(self):
        paths = {"reinstall/run.py", "reinstall/boot-pins.json", "reinstall/upstream.json"}
        manifest = json.loads((WEB.parent / "reinstall/upstream.json").read_text())
        paths.update("reinstall/vendor/" + name for name in manifest["files"])
        files = {name: base64.b64encode((WEB.parent / name).read_bytes()).decode() for name in paths}

        def archive(values):
            return base64.b64encode(gzip.compress(json.dumps(values).encode())).decode()

        self.assertEqual(set(gateway.reinstall_bundle(archive(files))), paths)
        for invalid in ({"reinstall/vendor/../append": "eA=="}, {"reinstall/run.py": "eA=="}):
            with self.assertRaises(gateway.GuardError):
                gateway.reinstall_bundle(archive({**files, **invalid}))

    def test_reinstall_return_requires_the_job_receipt_and_an_actual_ubuntu_version(self):
        job = "a" * 32
        good = {"job": job, "version": "24.04", "state": "complete", "message": "fixture"}
        request = {"action": "ubuntuVerify", "job": job, "ubuntu": "24.04", "address": "203.0.113.10"}

        @contextlib.contextmanager
        def receipt(*_args, **_options):
            yield io.BytesIO(json.dumps(good).encode())

        with patch.object(gateway, "valid_address", return_value=True), \
             patch.object(gateway, "eligible_version", return_value="24.04") as os_version, \
             patch.object(gateway, "require_secure_directory"), \
             patch.object(gateway, "owned_file", receipt), \
             patch.object(Path, "read_bytes", return_value=b"b" * 32):
            self.assertEqual(gateway.dispatch(request), {"state": "returned", "ubuntu": "24.04"})
            self.assertEqual(gateway.dispatch({**request, "job": "c" * 32}), {"state": "waiting"})
            self.assertEqual(gateway.dispatch({**request, "ubuntu": "26.04"}), {"state": "waiting"})
            os_version.return_value = None
            self.assertEqual(gateway.dispatch(request), {"state": "waiting"})

    def test_paired_reinstall_requires_the_exact_owned_manifest_role_endpoint_and_recipe(self):
        entry, exit_address = "192.0.2.17", "198.51.100.18"
        request = {"pair": "a" * 32, "role": "exit", "operation": "b" * 32, "address": exit_address}
        digest = json.loads((WEB / "src/lib/pair-recipe.json").read_text())["digest"]
        self.assertEqual(gateway.PAIR_RECIPE_DIGEST, digest)
        manifest = {"version": 2, "bundle": digest, "configured": True, "plan": {
            "pair": request["pair"], "role": "exit", "server": entry, "exit_host": exit_address,
            "engine": "native-v2", "entry_protocol": "awg", "exit_protocol": "awg",
            "vpn_port": 51820, "tunnel_port": 443, "client_pool": "10.66.0.0/24",
            "test_ip": "10.249.255.254", "entry_address": "10.253.0.2/30",
            "exit_address": "10.253.0.1/30", "route_table": 51831,
        }}
        raw = json.dumps(manifest).encode()

        @contextlib.contextmanager
        def owned(path, limit, private=False):
            self.assertEqual(path, gateway.PAIR_MANIFEST)
            self.assertEqual(limit, 65536)
            self.assertTrue(private)
            yield io.BytesIO(raw)

        with patch.object(gateway, "owned_file", owned), patch.object(gateway, "valid_address", lambda value: value in (entry, exit_address)):
            self.assertEqual(gateway.require_pair_for_reinstall(request), (hashlib.sha256(raw).hexdigest(), manifest["plan"]))
            for wrong in ({"role": "entry"}, {"address": entry}, {"pair": "c" * 32}, {"operation": "invalid"}):
                with self.subTest(wrong=wrong), self.assertRaises(gateway.GuardError):
                    gateway.require_pair_for_reinstall({**request, **wrong})
            for drift in ({"bundle": "d" * 64}, {"resetting": True}, {"configured": False},
                          {"plan": {**manifest["plan"], "entry_protocol": "openvpn"}}):
                raw = json.dumps({**manifest, **drift}).encode()
                with self.subTest(drift=drift), self.assertRaises(gateway.Conflict):
                    gateway.require_pair_for_reinstall(request)
            mixed_plan = {**manifest["plan"], "exit_protocol": "openvpn", "tunnel_port": 1194}
            raw = json.dumps({**manifest, "plan": mixed_plan}).encode()
            self.assertEqual(gateway.require_pair_for_reinstall(request), (hashlib.sha256(raw).hexdigest(), mixed_plan))
            for protocol, port in (("ikev2", 500), ("xray", 443)):
                topology = {**manifest["plan"], "exit_protocol": protocol, "tunnel_port": port}
                raw = json.dumps({**manifest, "plan": topology}).encode()
                self.assertEqual(gateway.require_pair_for_reinstall(request), (hashlib.sha256(raw).hexdigest(), topology))
            topology = {**manifest["plan"], "entry_protocol": "ikev2", "vpn_port": 500,
                        "exit_protocol": "trusttunnel", "tunnel_port": 443}
            raw = json.dumps({**manifest, "plan": topology}).encode()
            self.assertEqual(gateway.require_pair_for_reinstall(request), (hashlib.sha256(raw).hexdigest(), topology))
            for drift in ({"tunnel_port": 443}, {"access_mode": "password"}, {"exit_protocol": "ikev2"}):
                raw = json.dumps({**manifest, "plan": {**mixed_plan, **drift}}).encode()
                with self.subTest(drift=drift), self.assertRaises(gateway.Conflict):
                    gateway.require_pair_for_reinstall(request)

        with patch.object(gateway.os.path, "lexists", return_value=True), self.assertRaises(gateway.Conflict):
            gateway.require_single_for_reinstall()

    def test_pair_review_seals_manifest_and_only_recovers_the_original_native_plan(self):
        original = {"pair": "a" * 32, "role": "entry", "operation": "b" * 32,
                    "address": "192.0.2.17", "ubuntu": "24.04", "files": {}}
        filesystem = "f" * 64
        snapshot = "1" * 64
        scope = {"machine": "e" * 64, "disk_bytes": 40 * 1024**3, "boot": "BIOS"}
        durable = {"job": "c" * 32, "version": "24.04", "fingerprint": "SHA256:" + "A" * 43,
                   "scope": scope, "paired_operation": original["operation"], "token": "d" * 64,
                   "expires": time.time() + 86400}
        native = SimpleNamespace(
            plan=Mock(return_value=durable.copy()), atomic=Mock(), inspect=Mock(return_value=scope.copy()),
            scope_digest=lambda value: json.dumps(value, sort_keys=True), start=Mock(),
        )
        with patch.object(gateway, "bundle", return_value={}), \
             patch.object(gateway, "require_pair_for_reinstall", return_value=(filesystem, original)), \
             patch.object(gateway, "exclusive_pair_reinstall", contextlib.nullcontext), \
             patch.object(gateway.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext("/unused")), \
             patch.object(gateway, "load_reinstall", return_value=native), \
             patch.object(gateway, "require_current_pair_snapshot"), \
             patch.object(gateway, "private_reinstall_plan", return_value=durable):
            result = gateway.manage_pair_reinstall_review({**original, "action": "pairUbuntuReview", "snapshot": snapshot})
            native.plan.assert_called_once_with({"version": "24.04", "paired_operation": "b" * 32})
            native.atomic.assert_called_once_with(gateway.REINSTALL_STATE / "plan.json", {
                **durable, "pair_manifest": filesystem, "recovery_snapshot": snapshot,
            })
            self.assertEqual(result["machine"], scope["machine"])
            self.assertEqual(result["fingerprint"], durable["fingerprint"])
            native.plan.reset_mock()
            native.atomic.reset_mock()
            plan = {**original, "action": "pairUbuntuPlan", "job": result["job"], "fingerprint": result["fingerprint"]}
            self.assertEqual(gateway.manage_pair_reinstall_review(plan), {"token": durable["token"]})
            for mismatch in ({"job": "e" * 32}, {"operation": "e" * 32}, {"fingerprint": "SHA256:" + "B" * 43},
                             {"ubuntu": "26.04"}):
                with self.subTest(mismatch=mismatch), self.assertRaises(gateway.Conflict):
                    gateway.manage_pair_reinstall_review({**plan, **mismatch})
            native.inspect.return_value = {**scope, "boot": "EFI"}
            with self.assertRaises(gateway.Conflict):
                gateway.manage_pair_reinstall_review(plan)
            native.inspect.return_value = scope
            durable["pair_manifest"] = "e" * 64
            with self.assertRaises(gateway.Conflict):
                gateway.manage_pair_reinstall_review(plan)
            native.plan.assert_not_called()
            native.atomic.assert_not_called()
            native.start.assert_not_called()

    def test_pair_recipe_is_rehashed_in_the_installed_bundle_order_before_recovery_export(self):
        def owned(path, limit):
            content = path.read_bytes()
            self.assertLessEqual(len(content), limit)
            return content + (b"\n" if changed and path.name == "recovery.py" else b"")

        changed = False
        with patch.object(gateway, "PAIR_RELEASE", WEB.parent), \
             patch.object(gateway, "require_secure_directory"), \
             patch.object(gateway, "read_owned", side_effect=owned):
            gateway.verified_pair_recovery_recipe()
            changed = True
            with self.assertRaises(gateway.GuardError):
                gateway.verified_pair_recovery_recipe()

    def test_pair_recovery_digest_matches_shared_javascript_canonical_encoding(self):
        snapshot = {"schema": 2, "role": "exit", "created": 1.25,
                    "state": {"users": [{"login": "fixture", "created": 123, "enabled": True, "person": "Amélie 🌐"}]},
                    "filter_policy": {"level": "standard", "enabled": True}}
        # pairArchiveDigest(snapshot without its top-level created timestamp).
        expected = "6195008ce2d51ea7f39dd60600ea7bdac2be3fef9f9bbd440641cca598231806"
        self.assertEqual(gateway.recovery_snapshot_digest(snapshot), expected)
        self.assertEqual(gateway.recovery_snapshot_digest({**snapshot, "created": 2.5}), expected)
        snapshot["state"]["users"][0]["created"] += 1
        self.assertNotEqual(gateway.recovery_snapshot_digest(snapshot), expected)
        with self.assertRaises(gateway.GuardError):
            gateway.recovery_snapshot_digest({**snapshot, "ambiguous": 1.25})

    def test_pair_recovery_export_rejects_changed_accounts_filter_and_wrong_role(self):
        reviewed = {"pair": "a" * 32, "role": "exit", "entry_protocol": "awg", "exit_protocol": "openvpn",
                    "exit_host": "198.51.100.18", "tunnel_port": 1194}
        original = {"schema": 2, "adapter": "openvpn-identity-v1", "purpose": "rookstride-owner-recovery-node",
                    "deployment": "a" * 32, "role": "exit", "created": 1.25,
                    "state": {"protocol": "openvpn", "server": reviewed["exit_host"], "port": 1194,
                              "users": [{"login": "fixture", "enabled": True}]},
                    "plan": reviewed,
                    "filter_policy": {"level": "standard", "enabled": True}}
        digest = gateway.recovery_snapshot_digest(original)

        def reply(snapshot):
            return SimpleNamespace(returncode=0, stdout=json.dumps(snapshot).encode())

        with patch.object(gateway, "verified_pair_recovery_recipe") as verify, \
             patch.object(gateway.subprocess, "run", return_value=reply({**original, "created": 2.5})) as command:
            gateway.require_current_pair_snapshot(reviewed, digest)
            verify.assert_called_once_with()
            self.assertEqual(command.call_args.args[0][-1], str(gateway.PAIR_RELEASE / "server"))
            for stale in ({"state": {**original["state"], "users": []}},
                          {"filter_policy": {"level": "standard", "enabled": False}}):
                command.return_value = reply({**original, **stale})
                with self.subTest(stale=stale), self.assertRaises(gateway.PairSnapshotChanged):
                    gateway.require_current_pair_snapshot(reviewed, digest)
            for invalid in ({"role": "entry"}, {"plan": {**reviewed, "tunnel_port": 443}},
                            {"state": {**original["state"], "server": "192.0.2.17"}},
                            {"state": {**original["state"], "port": 1194.0}},
                            {"state": {**original["state"], "access_mode": "password"}}):
                command.return_value = reply({**original, **invalid})
                with self.subTest(invalid=invalid), self.assertRaises(gateway.Conflict) as other:
                    gateway.require_current_pair_snapshot(reviewed, digest)
                self.assertIs(type(other.exception), gateway.Conflict)

            for protocol, port in (("ikev2", 500), ("xray", 443)):
                plan = {**reviewed, "exit_protocol": protocol, "tunnel_port": port}
                state = {**original["state"], "protocol": protocol, "port": port, "access_mode": "profile"}
                snapshot = {**original, "adapter": protocol + "-identity-v1", "state": state, "plan": plan}
                command.return_value = reply(snapshot)
                gateway.require_current_pair_snapshot(plan, gateway.recovery_snapshot_digest(snapshot))

    def test_native_result_distinguishes_a_snapshot_mismatch_from_other_conflicts(self):
        for conflict, reason in ((gateway.PairSnapshotChanged, "pair-snapshot-changed"), (gateway.Conflict, None)):
            output = io.StringIO()
            with self.subTest(conflict=conflict.__name__), \
                 patch.object(gateway.os, "umask"), patch.object(gateway.os, "environ", {}), \
                 patch.object(gateway.signal, "signal"), \
                 patch.object(gateway.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}\n"))), \
                 patch.object(gateway, "dispatch", side_effect=conflict("Fixture rejection.")), \
                 contextlib.redirect_stdout(output):
                gateway.main()
                expected = {"state": "conflict", "message": "Fixture rejection."}
                if reason:
                    expected["reason"] = reason
                self.assertEqual(json.loads(output.getvalue()), expected)

    def test_pair_snapshot_is_sealed_and_rechecked_under_the_same_locks_before_token_or_erase(self):
        scope = {"machine": "e" * 64, "disk_bytes": 40 * 1024**3, "boot": "BIOS"}
        manifest = "f" * 64
        snapshot = "1" * 64
        request = {"pair": "a" * 32, "role": "entry", "operation": "b" * 32,
                   "address": "192.0.2.17", "ubuntu": "24.04", "files": {}}
        plan = {"job": "c" * 32, "version": "24.04", "fingerprint": "SHA256:" + "A" * 43,
                "scope": scope, "paired_operation": request["operation"], "token": "d" * 64,
                "expires": time.time() + 86400}
        native = SimpleNamespace(plan=Mock(return_value=plan.copy()), atomic=Mock(), inspect=Mock(return_value=scope),
                                 CONFIRM="WIPE SERVER AND REINSTALL UBUNTU", scope_digest=lambda value: value, start=Mock())
        locked = False
        changed = False
        verified = []
        with self.assertRaisesRegex(gateway.GuardError, "Unknown action or fields"):
            gateway.dispatch({**request, "action": "pairUbuntuReview"})

        @contextlib.contextmanager
        def locked_pair():
            nonlocal locked
            self.assertFalse(locked)
            locked = True
            try:
                yield
            finally:
                locked = False

        def check_snapshot(call, sealed):
            self.assertTrue(locked)
            self.assertEqual(sealed, snapshot)
            self.assertEqual(call["role"], request["role"])
            verified.append(call["role"])
            if changed:
                raise gateway.Conflict("fixture snapshot changed")

        with patch.object(gateway, "bundle", return_value={}), patch.object(gateway, "reinstall_bundle", return_value={}), \
             patch.object(gateway, "require_pair_for_reinstall", return_value=(manifest, request)), \
             patch.object(gateway, "exclusive_pair_reinstall", locked_pair), patch.object(gateway, "require_secure_directory"), \
             patch.object(gateway.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext("/unused")), \
             patch.object(gateway, "load_reinstall", return_value=native), \
             patch.object(gateway, "private_reinstall_plan", return_value=plan), \
             patch.object(gateway, "require_current_pair_snapshot", side_effect=check_snapshot):
            gateway.manage_pair_reinstall_review({**request, "action": "pairUbuntuReview", "snapshot": snapshot})
            self.assertEqual(plan["recovery_snapshot"], snapshot)
            pending = {**request, "job": plan["job"], "fingerprint": plan["fingerprint"]}
            self.assertEqual(gateway.manage_pair_reinstall_review({**pending, "action": "pairUbuntuPlan"}), {"token": plan["token"]})
            apply = {**pending, "action": "pairUbuntuApply", "token": plan["token"],
                     "confirmation": native.CONFIRM, "password": "fixture only"}
            del plan["recovery_snapshot"]
            with self.assertRaises(gateway.Conflict):
                gateway.manage_pair_reinstall_review({**pending, "action": "pairUbuntuPlan"})
            with self.assertRaises(gateway.Conflict):
                gateway.apply_reinstall(apply)
            plan["recovery_snapshot"] = snapshot
            changed = True
            with self.assertRaises(gateway.Conflict):
                gateway.manage_pair_reinstall_review({**pending, "action": "pairUbuntuPlan"})
            with self.assertRaises(gateway.Conflict):
                gateway.apply_reinstall(apply)
            native.start.assert_not_called()
            self.assertEqual(verified, [request["role"]] * 4)

    def test_pair_apply_uses_reviewed_token_and_standalone_cannot_consume_paired_plan(self):
        req = {"action": "pairUbuntuApply", "files": "fixture", "job": "c" * 32,
               "fingerprint": "SHA256:" + "B" * 43, "token": "d" * 64,
               "confirmation": "WIPE SERVER AND REINSTALL UBUNTU", "password": "fixture only"}
        launched = {"job": req["job"], "version": "24.04", "fingerprint": req["fingerprint"], "state": "preparing"}
        plan = {"job": req["job"], "fingerprint": req["fingerprint"], "token": req["token"], "paired_operation": "b" * 32}
        native = SimpleNamespace(CONFIRM=req["confirmation"], start=Mock(return_value=launched))
        with patch.object(gateway, "reinstall_bundle", return_value={}), \
             patch.object(gateway, "require_pair_for_reinstall", return_value=("fixture", {})), \
             patch.object(gateway, "require_pair_reinstall_plan", return_value=plan), \
             patch.object(gateway, "exclusive_pair_reinstall", contextlib.nullcontext), \
             patch.object(gateway, "exclusive_install", contextlib.nullcontext), \
             patch.object(gateway, "require_secure_directory"), \
             patch.object(gateway, "require_single_for_reinstall"), \
             patch.object(gateway.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext("/unused")), \
             patch.object(gateway, "load_reinstall", return_value=native), \
             patch.object(gateway, "read_owned", return_value=json.dumps(plan).encode()):
            for wrong in ({"confirmation": "DELETE PAIR"}, {"token": "e" * 64}, {"action": "ubuntuApply"}):
                with self.subTest(wrong=wrong), self.assertRaises(gateway.GuardError):
                    gateway.apply_reinstall({**req, **wrong})
            native.start.assert_not_called()
            self.assertEqual(gateway.apply_reinstall(req), gateway.reinstall_status(launched))
            native.start.assert_called_once_with({
                "token": req["token"], "confirmation": req["confirmation"], "password": req["password"],
            })

    def test_only_ssh_and_known_os_sockets(self):
        ssh = 'tcp LISTEN 0 4 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=1),("systemd",pid=2,fd=1))'
        dns = 'udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=3,fd=2))'
        dhcp4 = 'udp UNCONN 0 0 0.0.0.0%eth0:68 0.0.0.0:* users:(("dhcpcd",pid=4,fd=3))'
        dhcp6 = 'udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:* users:(("dhcpcd",pid=4,fd=4))'
        mdns = 'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("systemd-resolve",pid=3,fd=5))'
        self.assertFalse(gateway.reserved_socket_or_application(ssh + "\n" + dns, "2222"))
        self.assertFalse(gateway.reserved_socket_or_application("\n".join((ssh, dns, dhcp4, dhcp6, mdns)), "2222"))
        for rows in ("", ssh.replace("sshd", "httpd"), dns, ssh + "\n" + dns.replace("127.0.0.53", "0.0.0.0"),
                     ssh + "\n" + dns.replace(":53 ", ":500 "), ssh + "\n" + "invalid",
                     ssh + "\n" + dhcp4.replace("dhcpcd", "other"), ssh + "\n" + dhcp6.replace(":546 ", ":500 "),
                     ssh + "\n" + dhcp4.replace("udp", "tcp", 1),
                     ssh + "\n" + mdns.replace("systemd-resolve", "other"),
                     ssh + "\n" + mdns.replace("udp", "tcp", 1)):
            self.assertTrue(gateway.reserved_socket_or_application(rows, "2222"))

    def test_route_collisions(self):
        self.assertFalse(gateway.conflicting_route([{"dst":"default"}, {"dst":"172.31.0.0/20"}]))
        for dst in ("10.252.0.44", "10.254.0.1", "10.0.0.0/8", "fd42:252::1"):
            self.assertTrue(gateway.conflicting_route([{"dst": dst}]))

    def test_only_the_exact_ssh_only_fail2ban_table_may_be_preserved(self):
        table = {"family": "inet", "table": "f2b-table"}
        fixture = [
            {"table": {"family": "inet", "name": "f2b-table", "handle": 5}},
            {"set": {**table, "name": "addr-set-sshd", "type": "ipv4_addr", "elem": ["192.0.2.15"]}},
            {"chain": {**table, "name": "f2b-chain", "type": "filter", "hook": "input", "prio": -1, "policy": "accept"}},
            {"rule": {**table, "chain": "f2b-chain", "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@addr-set-sshd"}},
                {"reject": {"type": "icmp", "expr": "port-unreachable"}},
            ]}},
        ]
        self.assertTrue(gateway.only_ssh_ban(fixture, "22"))
        self.assertFalse(gateway.only_ssh_ban(fixture, "2222"))
        self.assertFalse(gateway.only_ssh_ban(fixture + [fixture[0]], "22"))
        self.assertFalse(gateway.only_ssh_ban(fixture[:-1], "22"))
        for index, kind, field, value in (
            (1, "set", "elem", ["192.0.2.0/24"]),
            (2, "chain", "hook", "forward"),
            (2, "chain", "policy", "drop"),
            (3, "rule", "expr", [{"accept": None}]),
        ):
            with self.subTest(field=field):
                changed = deepcopy(fixture)
                changed[index][kind][field] = value
                self.assertFalse(gateway.only_ssh_ban(changed, "22"))

    def test_pair_preflight_covers_planned_routes_and_abbreviates_identity(self):
        self.assertTrue(gateway.conflicting_route([{"dst":"10.66.0.17"}], gateway.PAIR_NETWORKS))
        self.assertTrue(gateway.conflicting_route([{"dst":"10.253.0.2"}], gateway.PAIR_NETWORKS))
        machine = b"a" * 32
        with patch.object(gateway, "read_owned", return_value=machine + b"\n"), \
             patch.object(gateway, "guarded_fresh", return_value=True) as fresh:
            self.assertEqual(gateway.inspect_pair_node(), {"state":"ready", "machine":gateway.hashlib.sha256(machine).hexdigest()})
            fresh.assert_called_once_with(gateway.POOL_NETWORKS + gateway.PAIR_NETWORKS)

    def test_existing_dangling_link_refuses_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "configuration"
            path.symlink_to(Path(tmp) / "absent")
            with patch.object(gateway, "CONFLICTS", (str(path),)):
                self.assertTrue(gateway.has_conflicting_files())

    def test_refuses_unknown_actions_private_targets_and_extra_inputs(self):
        for req in ({"action": "run"}, {"action": "inspect", "files": {}},
                    {"action": "profile", "address": "127.0.0.1"},
                    {"action": "profile", "address": "169.254.169.254"}, {"action": "profile", "address": "239.0.0.1"}):
            with self.assertRaises(gateway.GuardError):
                gateway.dispatch(req)

    def test_partial_or_changed_owner_never_triggers_fresh_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(gateway, "OWNER", Path(tmp)), patch.object(gateway, "guarded_fresh") as fresh:
                self.assertEqual(gateway.inspect(None)["state"], "occupied")
                fresh.assert_not_called()

    def test_profile_only_uses_public_certificate_and_recorded_identity(self):
        managed = {"uuid": "fixed", "login": "visitor"}
        profile = gateway.client_profile("203.0.113.1", "visitor", managed, b"test public CA")["profile"]
        self.assertEqual(profile["local"], {"eap_id":"visitor"})
        self.assertEqual(base64.b64decode(profile["remote"]["cert"]), b"test public CA")
        self.assertNotIn("password", json.dumps(profile).lower())

    def test_missing_cert_or_inactive_service_cannot_recover_a_profile(self):
        marker = {"format":1, "address":"203.0.113.1", "uuid":"20000000-0000-0000-0000-000000000001",
                  "login":"first", "caDigest":gateway.hashlib.sha256(b"ca").hexdigest(),
                  "configDigest":gateway.hashlib.sha256(b"conf").hexdigest()}
        with patch.object(gateway, "valid_address", return_value=True), \
             patch.object(gateway, "read_owned", side_effect=[json.dumps(marker).encode(), b"conf"]), \
             patch.object(gateway, "ca_der", return_value=b"ca"), patch.object(gateway, "healthy_units", return_value=False):
            with self.assertRaises(gateway.GuardError):
                gateway.verified_instance("203.0.113.1")
        with patch.object(gateway, "valid_address", return_value=True), \
             patch.object(gateway, "read_owned", return_value=json.dumps(marker).encode()), \
             patch.object(gateway, "ca_der", return_value=b"different CA"):
            with self.assertRaises(gateway.GuardError):
                gateway.verified_instance("203.0.113.1")

    def test_staged_install_success_and_partial_failure_without_process_execution(self):
        original_temp = tempfile.TemporaryDirectory
        files = {name:base64.b64encode((WEB.parent / name).read_bytes()).decode() for name in gateway.PINNED}
        req = {"address":"203.0.113.1", "login":"owner", "vpnPassword":"fixture value", "files":files}
        for installer_code, verifier_code, session_control in ((0, 0, True), (1, 0, True), (0, 1, True), (0, 0, False)):
            with self.subTest(install=installer_code, verify=verifier_code, session_control=session_control), original_temp() as scratch, contextlib.ExitStack() as stack:
                root = Path(scratch)
                temporary_paths = []
                def local_workspace(prefix, dir):
                    self.assertEqual(dir, "/run")
                    return original_temp(prefix=prefix, dir=root)
                def fake_process(args, **kwargs):
                    file = Path(args[1])
                    work = file.parents[2]
                    temporary_paths.append(work)
                    self.assertEqual(args[0], "/bin/bash")
                    self.assertEqual(kwargs["cwd"], "/")
                    self.assertEqual(kwargs["stdout"], gateway.subprocess.DEVNULL)
                    self.assertEqual(kwargs["stderr"], gateway.subprocess.DEVNULL)
                    env = kwargs["env"]
                    self.assertNotIn("fixture value", str(env))
                    if file.name == "install.sh":
                        self.assertEqual(env["ROOKSTRIDE_VERIFY_SEPARATELY"], "YES")
                        self.assertEqual(env["ROOKSTRIDE_REQUIRE_SESSION_CONTROL"], "YES")
                        secret = Path(env["VPN_PASSWORD_FILE"])
                        self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(secret.read_text(), "fixture value\n")
                        return Mock(wait=Mock(return_value=installer_code))
                    self.assertEqual(file, work / "gateway/scripts/verify.sh")
                    self.assertEqual(env, gateway.SAFE_ENV)
                    self.assertFalse((work / "initial.password").exists())
                    return Mock(wait=Mock(return_value=verifier_code))
                stack.enter_context(patch.object(gateway, "OWNER", root / "owner"))
                stack.enter_context(patch.object(gateway, "exclusive_install", contextlib.nullcontext))
                stack.enter_context(patch.object(gateway, "inspect", return_value={"state":"ready"}))
                stack.enter_context(patch.object(gateway.tempfile, "TemporaryDirectory", local_workspace))
                stack.enter_context(patch.object(gateway.subprocess, "Popen", fake_process))
                stack.enter_context(patch.object(gateway, "ca_der", return_value=b"test public certificate"))
                stack.enter_context(patch.object(gateway, "read_owned", return_value=b"test gateway configuration"))
                stack.enter_context(patch.object(gateway, "healthy_units", return_value=True))
                stack.enter_context(patch.object(gateway, "session_control_ready", return_value=session_control))
                if installer_code or verifier_code or not session_control:
                    with self.assertRaises(gateway.RecipeFailure) as failure:
                        gateway.install(req)
                    self.assertEqual(str(failure.exception), "installation" if installer_code else "verification")
                    self.assertTrue(gateway.OWNER.is_dir())
                    self.assertFalse((gateway.OWNER / "verified.json").exists())
                else:
                    self.assertEqual(gateway.install(req)["state"], "installed")
                    record = (gateway.OWNER / "verified.json").read_text()
                    self.assertEqual(json.loads(record)["login"], "owner")
                    self.assertNotIn("fixture value", record)
                self.assertEqual(len(temporary_paths), 1 if installer_code else 2)
                self.assertFalse(temporary_paths[0].exists())


class RouteRuntime(unittest.TestCase):
    def fixture(self):
        files = {"rook-routes": b"worker stub", "libcronet.so": b"library stub"}
        asset = {}
        body = io.BytesIO()
        with gateway.tarfile.open(fileobj=body, mode="w:gz") as archive:
            for name, (size, digest) in gateway.RUNTIME_FILES.items():
                raw = files[name]
                member = gateway.tarfile.TarInfo(name)
                member.size = asset[size] = len(raw)
                asset[digest] = gateway.hashlib.sha256(raw).hexdigest()
                archive.addfile(member, io.BytesIO(raw))
        payload = body.getvalue()
        asset.update(archive_bytes=len(payload), archive_sha256=gateway.hashlib.sha256(payload).hexdigest())
        return payload, asset, files

    def test_archive_and_both_components_must_match_before_publish(self):
        payload, asset, files = self.fixture()
        with tempfile.TemporaryDirectory() as tmp, patch.object(gateway, "require_secure_directory"), \
             patch.object(gateway, "owned_file", side_effect=lambda path, _limit: path.open("rb")):
            root = Path(tmp) / "runtime"
            for body, pins in ((payload[:-1], asset), (payload + b"more", asset),
                               (b"!" + payload[1:], asset), (payload, {**asset, "library_sha256": "0" * 64})):
                with self.subTest(size=len(body), pins=pins["library_sha256"]), self.assertRaises(gateway.GuardError):
                    gateway.install_route_runtime(root, pins, io.BytesIO(body))
                self.assertFalse(root.exists())
                self.assertEqual(list(Path(tmp).iterdir()), [])

            gateway.install_route_runtime(root, asset, io.BytesIO(payload))
            target = root / asset["sha256"]
            self.assertEqual({path.name: path.read_bytes() for path in target.iterdir()}, files)
            self.assertEqual({path.stat().st_mode & 0o777 for path in target.iterdir()}, {0o700})
            self.assertTrue(gateway.runtime_ready(root, asset))
            gateway.install_route_runtime(root, asset, io.BytesIO(payload))
            self.assertEqual(list(Path(tmp).iterdir()), [root])

            (target / "rook-routes").write_bytes(b"changed")
            with self.assertRaises(gateway.GuardError):
                gateway.install_route_runtime(root, asset, io.BytesIO(payload))
            self.assertEqual((target / "rook-routes").read_bytes(), b"changed")

    def test_review_is_read_only_and_apply_keeps_the_existing_server_guard(self):
        _, asset, _ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            pins = folder / "pins.json"
            pins.write_text(json.dumps({"assets": {"x86_64": asset}}))
            routes = SimpleNamespace(PROTOCOLS=("hysteria2",), PINS=pins, WORKER=folder / "runtime")
            simple = SimpleNamespace(model=SimpleNamespace(PROTOCOLS=("hysteria2",)),
                                     action=Mock(return_value={"port": 4455}))
            request = {"method": "hysteria2", "port": 4455, "runtimeArchitecture": "x86_64"}
            stream = io.BytesIO(b"fixture")
            with patch.dict(sys.modules, routes=routes), \
                 patch.dict(gateway.os.environ, SSH_CONNECTION="203.0.113.1 1 203.0.113.2 22"), \
                 patch.object(gateway.platform, "machine", return_value="x86_64"), \
                 patch.object(gateway, "OWNER", folder / "owner"), patch.object(gateway, "SINGLE_STATE", folder / "single"), \
                 patch.object(gateway, "install_route_runtime", side_effect=gateway.GuardError("fixture")) as upload, \
                 patch.object(gateway, "inspect", return_value={"state": "ready"}) as inspect:
                review = gateway.single_action(simple, {"method": "hysteria2"}, "protocolReview", "203.0.113.2", "owner")
                self.assertEqual(review, {"port": 4455, "runtimeArchitecture": "x86_64"})
                upload.assert_not_called()
                inspect.return_value = {"state": "occupied"}
                with self.assertRaises(gateway.Conflict):
                    gateway.single_action(simple, request, "protocolApply", "203.0.113.2", "owner", stream)
                upload.assert_not_called()
                inspect.return_value = {"state": "ready"}
                result = gateway.single_action(simple, request, "protocolApply", "203.0.113.2", "owner", stream)
                self.assertEqual(result, {"state": "runtimeUnavailable"})
                upload.assert_called_once_with(routes.WORKER, asset, stream)
                self.assertFalse(gateway.OWNER.exists())
                self.assertEqual([call.args[0]["action"] for call in simple.action.call_args_list], ["plan", "plan"])

    def test_secure_empty_single_state_after_pair_removal_allows_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            state = folder / "single"
            state.mkdir(mode=0o700)
            simple = SimpleNamespace(model=SimpleNamespace(PROTOCOLS=("xray",)),
                                     action=Mock(return_value={"port": 443}))
            with patch.dict(sys.modules, routes=SimpleNamespace(PROTOCOLS=())), \
                 patch.dict(gateway.os.environ, SSH_CONNECTION="203.0.113.1 1 203.0.113.2 22"), \
                 patch.object(gateway, "OWNER", folder / "owner"), patch.object(gateway, "SINGLE_STATE", state), \
                 patch.object(gateway, "require_secure_directory") as check_directory, \
                 patch.object(gateway, "inspect", return_value={"state": "removed"}):
                request = {"method": "xray"}
                self.assertEqual(gateway.single_action(simple, request, "protocolReview", "203.0.113.2", "owner"),
                                 {"port": 443})
                check_directory.assert_called_once_with(state)
                (state / "unrecognised").touch()
                with self.assertRaises(gateway.Conflict):
                    gateway.single_action(simple, request, "protocolReview", "203.0.113.2", "owner")
                self.assertEqual(simple.action.call_count, 1)


class ProtocolMaintenance(unittest.TestCase):
    def setUp(self):
        self.filters = {
            "standard": ("Standard", "https://lists.example.test/standard"),
            "strong": ("Strong", "https://lists.example.test/strong"),
        }
        self.protection = True
        self.report = {"queries": 13, "blocked": 3, "privateValue": "fixture"}
        self.loaded = [
            {"name": "Standard", "url": self.filters["standard"][1], "enabled": True, "rules_count": 9},
            {"name": "Strong", "url": "https://custom.example.test/example", "enabled": True, "rules_count": 15},
            {"name": "Strong", "url": self.filters["strong"][1], "enabled": True, "rules_count": 0},
        ]
        self.filtering = SimpleNamespace(
            FILTERS=self.filters,
            load=Mock(return_value={"instance": "same-filter"}),
            api=Mock(side_effect=self.filter_status),
        )
        self.single = SimpleNamespace(
            runtime=SimpleNamespace(load=Mock(return_value={"filtering": "same-filter"})),
            filtering=self.filtering,
            action=Mock(return_value=self.report),
        )

    def filter_status(self, path):
        if path == "stats":
            return {"num_dns_queries": 13, "num_blocked_filtering": 3, "privateValue": "fixture"}
        if path == "filtering/status":
            return {"filters": self.loaded}
        if path == "dns_info":
            return {"protection_enabled": self.protection}
        self.fail("Unexpected private filter endpoint")

    def test_protocol_filter_uses_loaded_list_identity_and_verifies_each_change(self):
        first = gateway.protocol_filter(self.single, "awg", {})
        self.assertEqual(first, {"presets": ["standard"], "queries": 13,
                                 "blocked": 3, "protectionEnabled": True})
        self.single.action.assert_not_called()
        with self.assertRaises(gateway.Conflict):
            gateway.protocol_filter(self.single, "awg", {"level": "strong"})
        self.loaded[-1]["rules_count"] = 11
        second = gateway.protocol_filter(self.single, "awg", {"level": "strong"})
        self.assertIn("strong", second["presets"])
        self.single.action.assert_called_with({"action": "adguard", "protocol": "awg", "level": "strong"})
        with self.assertRaises(gateway.Conflict):
            gateway.protocol_filter(self.single, "awg", {"enabled": False})
        self.protection = False
        third = gateway.protocol_filter(self.single, "awg", {"enabled": False})
        self.assertIs(third["protectionEnabled"], False)
        self.single.action.assert_called_with({"action": "adguard", "protocol": "awg", "enabled": False})

    def test_protocol_filter_refuses_other_owners_and_unapproved_inputs(self):
        for fields in ({"level": "custom"}, {"enabled": 1}):
            with self.subTest(fields=fields), self.assertRaises(gateway.GuardError):
                gateway.protocol_filter(self.single, "xray", fields)
        self.filtering.load.return_value = {"instance": "changed-filter"}
        with self.assertRaises(gateway.Conflict):
            gateway.protocol_filter(self.single, "xray", {"enabled": True})
        self.single.action.assert_not_called()

    def test_protocol_usage_scopes_and_withholds_private_rows(self):
        for method, kind, scope, profiles in (
            ("awg", "handshake", "interface", 1),
            ("openvpn", "sessions", "active-sessions", 1),
            ("xray", "traffic", "daemon", None),
            ("hysteria2", "sessions", "daemon", 1),
        ):
            with self.subTest(method=method):
                self.single.action.return_value = {
                    "protocol": method, "statistics_kind": kind, "monitoring_available": True,
                    "running": True, "recent_peers": 1,
                    "connections": [
                        {"user": "fixture-one", "upload": 4, "download": 7, "generation": "internal"},
                        {"user": "fixture-two", "upload": 3, "download": 5, "vpn_addresses": ["192.0.2.1"]},
                    ],
                }
                self.assertEqual(gateway.protocol_usage(self.single, method),
                                 {"available": True, "kind": kind, "scope": scope,
                                  "profiles": profiles, "upload": 7, "download": 12})
                self.single.action.assert_called_with({"action": "status", "protocol": method})

    def test_protocol_usage_leaves_unavailable_or_malformed_monitoring_unavailable(self):
        report = {"protocol": "awg", "statistics_kind": "handshake", "running": True,
                  "monitoring_available": True, "recent_peers": 0}
        for fields in (
            {"monitoring_available": False, "connections": []},
            {"statistics_kind": "traffic", "connections": []},
            {"connections": [{"upload": False, "download": 10}]},
            {"connections": [{"upload": 1 << 53, "download": 10}]},
            {"connections": [{"upload": (1 << 53) - 1, "download": 10}, {"upload": 1, "download": 0}]},
            {"recent_peers": 1, "connections": []},
        ):
            with self.subTest(fields=fields):
                self.single.action.return_value = {**report, **fields}
                self.assertEqual(gateway.protocol_usage(self.single, "awg"), {"available": False})
        self.single.action.return_value = None
        self.assertEqual(gateway.protocol_usage(self.single, "awg"), {"available": False})

    def test_maintenance_refuses_unverified_gateway_before_native_helper(self):
        for action in ("protocolFilter", "protocolUsage"):
            with self.subTest(action=action), \
                 patch.object(gateway, "protocol_status", return_value={"state": "protocolFailed"}), \
                 self.assertRaises(gateway.Conflict):
                gateway.single_action(self.single, {}, action, "192.0.2.1", None)
        self.single.action.assert_not_called()


class GuestLifecycle(unittest.TestCase):
    def setUp(self):
        import_path = str(WEB.parent / "server")
        sys.path.insert(0, import_path)
        self.addCleanup(sys.path.remove, import_path)
        from rookstride import admin
        self.admin = admin
        self.guard = Mock()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name)
        self.marker = {"login": "owner", "uuid": "20000000-0000-0000-0000-000000000001"}
        secrets = folder / "test-users"
        secrets.write_text('owner : EAP "only-a-test"\n')
        def local_reader(path, limit, private=False):
            return path.open("rb")
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for target, name, value in ((admin, "STATE", folder), (admin, "SECRETS", secrets),
                                    (admin, "PAIR_ROOT", folder / "unused"),
                                    (admin, "run", Mock(return_value="")), (admin, "sessions", Mock(return_value=[])),
                                    (gateway, "owned_file", local_reader), (gateway, "require_secure_directory", Mock())):
            stack.enter_context(patch.object(target, name, value))

    def action(self, action, **fields):
        return gateway.guest_action(self.admin, self.guard, {"action":action, "address":"203.0.113.1", **fields},
                                    self.marker, b"fake public certificate")

    def test_download_grant_revoke_and_revision(self):
        first = self.action("guests")
        self.assertEqual(first["guests"], [])
        second = self.action("grant", login="family", vpnPassword="a test", revision=first["revision"])
        self.assertEqual(second["guests"], ["family"])
        self.assertNotEqual(first["revision"], second["revision"])
        self.assertNotIn("a test", json.dumps(second))
        owner = self.action("profile")["profile"]
        guest = self.action("profile", login="family")["profile"]
        self.assertNotEqual(owner["uuid"], guest["uuid"])
        self.assertEqual(guest, self.action("profile", login="family")["profile"])
        self.assertEqual(guest["local"], {"eap_id":"family"})
        with self.assertRaises(gateway.Conflict):
            self.action("revoke", login="family", revision=first["revision"])
        third = self.action("revoke", login="family", revision=second["revision"])
        self.assertEqual(third["guests"], [])
        self.assertNotEqual(first["revision"], third["revision"])
        with self.assertRaises(gateway.Conflict):
            self.action("profile", login="family")

    def test_guest_password_rotation_preserves_profile_and_other_users(self):
        initial = self.action("guests")
        first = self.action("grant", login="one", vpnPassword="old secret", revision=initial["revision"])
        second = self.action("grant", login="two", vpnPassword="separate secret", revision=first["revision"])
        profile = self.action("profile", login="one")["profile"]
        with self.assertRaises(gateway.Conflict):
            self.action("rotate", login="one", vpnPassword="new secret", revision=first["revision"])
        with self.assertRaises(gateway.Conflict):
            self.action("rotate", login="owner", vpnPassword="new secret", revision=second["revision"])
        rotated = self.action("rotate", login="one", vpnPassword="new secret", revision=second["revision"])
        self.assertEqual(rotated["guests"], ["one", "two"])
        self.assertNotEqual(second["revision"], rotated["revision"])
        self.assertEqual(self.action("profile", login="one")["profile"], profile)
        secrets = self.admin.SECRETS.read_text()
        self.assertNotIn("old secret", secrets)
        self.assertIn("new secret", secrets)
        self.assertIn("separate secret", secrets)

    def test_owner_unknown_duplicate_and_wrong_revision_rejected(self):
        revision = self.action("guests")["revision"]
        for req in ({"action":"grant", "login":"owner", "vpnPassword":"test", "revision":revision},
                    {"action":"revoke", "login":"owner", "revision":revision},
                    {"action":"revoke", "login":"missing", "revision":revision},
                    {"action":"grant", "login":"guest", "vpnPassword":"test", "revision":"old"}):
            with self.assertRaises(gateway.Conflict):
                self.action(**req)
        rev = self.action("grant", login="guest", vpnPassword="test", revision=revision)["revision"]
        with self.assertRaises(gateway.Conflict):
            self.action("grant", login="guest", vpnPassword="replacement", revision=rev)
        self.assertEqual(self.action("guests")["revision"], rev)

    def test_active_revocation_warning_reaches_caller(self):
        rev = self.action("guests")["revision"]
        rev = self.action("grant", login="guest", vpnPassword="test", revision=rev)["revision"]
        with patch.object(self.admin, "sessions", side_effect=OSError("test")):
            response = self.action("revoke", login="guest", revision=rev)
            self.assertIs(response["activeSessionsUncertain"], True)
            self.assertEqual(response["guests"], [])


if __name__ == "__main__":
    unittest.main()
