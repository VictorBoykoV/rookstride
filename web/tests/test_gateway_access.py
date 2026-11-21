import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


WEB = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(WEB / "scripts"), str(WEB.parent / "server")]
from gateway_access import CONFIG_MARKER, HELPER, SSH_CONFIG, SUDO_CONFIG, inspect
from scoped_access import Access


class StandaloneAuthorityTests(unittest.TestCase):
    now = 1700000000
    address = "203.0.113.40"
    method = "openvpn"
    request = {"address": address, "method": method}
    instance = "1" * 32
    job = "2" * 32
    bundle = "3" * 64
    server = "server-fixture"
    deployment = "deployment-fixture"
    binding = "vpn-" + hashlib.sha256(f"{server}:{method}:{instance}".encode()).hexdigest()[:24]
    owner = "var/lib/rookstride-web-gateway/protocol.json"
    native = "var/lib/rookstride-single/openvpn/state.json"
    receipt = f"var/lib/rookstride-single/jobs/{job}/status.json"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.authority = self.root / "var/lib/rookstride-access"
        self.write(self.owner, {
            "instance": self.instance, "method": self.method, "job": self.job,
            "bundle": self.bundle, "address": self.address,
        })
        self.write(self.native, {
            "owner": "rookstride-single-v1", "server": self.address, "instance": self.instance,
            "protocol": self.method, "port": 1194, "users": ["private VPN login"],
        })
        self.write(self.receipt, {
            "state": "complete", "protocol": self.method,
            "bundle": self.bundle, "install_context": {"instance": self.instance},
        })

    def write(self, relative, value, mode=0o600):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(mode)

    def update(self, relative, **changes):
        self.write(relative, json.loads((self.root / relative).read_bytes()) | changes)

    def install(self, binding=True):
        self.write(SSH_CONFIG, CONFIG_MARKER + b"fixture\n", 0o644)
        self.write(SUDO_CONFIG, CONFIG_MARKER + b"fixture\n", 0o440)
        self.write(HELPER, b"fixture\n", 0o755)
        access = Access(path=self.authority)
        self.addCleanup(access.db.close)
        access.initialize(self.server, self.deployment, {"host": "private endpoint fixture"}, [{
            "kind": "protocol", "id": self.binding, "protocol": self.method,
            "instance": self.instance, "server_id": self.server, "deployment_id": self.deployment,
        }] if binding else [])
        for file in self.authority.iterdir():
            file.chmod(0o600)
        return access

    def device(self, access, name, role, scope, *, revoked_device=False, revoked_grant=False,
               revoked_credential=False, link=None):
        access.put("grant", f"grant-{name}", {
            "scope": scope, "role": role, "revoked": revoked_grant,
        })
        access.put("device", f"device-{name}", {
            "account": f"account-{name}", "grant_id": f"grant-{name}",
            "revoked": revoked_device, "public_key": "private-in-test-receipt",
        })
        access.put("credential", f"account-{name}", {
            "kind": "device", "revoked": revoked_credential,
            "device_id": f"device-{name}" if link is None else link,
        })

    def invitation(self, access, name, role, scope, *, expires=None, claimed=None,
                   revoked_invite=False, revoked_credential=False):
        access.put("invitation", f"invite-{name}", {
            "role": role, "scope": scope, "revoked": revoked_invite, "account": f"invite-account-{name}",
            "expires": self.now + 60 if expires is None else expires,
            "nonce": "private-enrollment-test-nonce", "claimed_device": claimed,
        })
        access.put("credential", f"invite-account-{name}", {
            "kind": "bootstrap", "invitation_id": f"invite-{name}", "revoked": revoked_credential,
        })

    def status(self, request=None):
        return inspect(self.request if request is None else request, self.root, os.getuid(), self.now)

    def test_counts_only_current_scope_credentials_and_does_not_write(self):
        access = self.install()
        protocol = {"kind": "protocol", "id": self.binding, "users": "own"}
        deployment = {"kind": "deployment", "id": self.deployment, "users": "all"}
        server = {"kind": "server", "id": self.server}
        other = {"kind": "server", "id": "other-server"}
        self.device(access, "manager", "user_manager", protocol)
        self.device(access, "viewer-deployment", "viewer", deployment)
        self.device(access, "viewer-server", "viewer", server)
        self.device(access, "other", "viewer", other)
        self.device(access, "foreign-protocol", "viewer", protocol | {"id": "another-instance"})
        self.device(access, "changed-link", "viewer", server, link="device-forged")
        self.device(access, "revoked-device", "viewer", server, revoked_device=True)
        self.device(access, "revoked-grant", "viewer", server, revoked_grant=True)
        self.device(access, "revoked-credential", "viewer", server, revoked_credential=True)
        self.invitation(access, "same-protocol", "infrastructure", protocol)
        self.invitation(access, "same-server", "viewer", server)
        self.invitation(access, "other-server", "viewer", other)
        self.invitation(access, "invalid-user-scope", "viewer", server | {"users": "owner"})
        self.invitation(access, "null-user-scope", "viewer", server | {"users": None})
        self.invitation(access, "bad-scope-kind", "viewer", server | {"kind": "global"})
        self.invitation(access, "claimed", "viewer", server, claimed="device-existing")
        self.invitation(access, "expired", "viewer", server, expires=self.now)
        self.invitation(access, "revoked-invitation", "viewer", server, revoked_invite=True)
        self.invitation(access, "revoked-bootstrap", "viewer", server, revoked_credential=True)

        records = list(access.db.iterdump())
        self.assertEqual(self.status(), {"state": "enabled", "roles": [
            {"role": "infrastructure", "devices": 0, "invitations": 1},
            {"role": "user_manager", "devices": 1, "invitations": 0},
            {"role": "viewer", "devices": 2, "invitations": 1},
        ]})
        self.assertEqual(list(access.db.iterdump()), records)
        self.assertEqual(access.revision(), 1)

    def test_distinguishes_absent_disabled_and_stale_registration(self):
        self.assertEqual(self.status(), {"state": "notEnabled"})
        access = self.install(binding=False)
        self.assertEqual(self.status(), {"state": "notRegistered"})
        access.put("meta", "config", access.get("meta", "config") | {"disabled": True})
        for relative in (SSH_CONFIG, SUDO_CONFIG, HELPER):
            (self.root / relative).unlink()
        self.assertEqual(self.status(), {"state": "disabled"})

    def test_refuses_wrong_address_ikev2_and_user_supplied_scope(self):
        for request in (self.request | {"address": "203.0.113.41"},
                        self.request | {"method": "ikev2"},
                        self.request | {"scope": "global"}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.status(request)

    def test_refuses_old_install_receipt_or_wrong_authority_binding(self):
        self.update(self.receipt, state="running")
        with self.assertRaises(ValueError):
            self.status()
        self.update(self.receipt, state="complete")
        access = self.install()
        access.put("object", self.binding, access.get("object", self.binding) | {"instance": "4" * 32})
        with self.assertRaises(ValueError):
            self.status()

    def test_refuses_pair_manifest_or_remnant_and_linked_authorities(self):
        access = self.install()
        manifest = "etc/rookstride-pair/manifest.json"
        self.write(manifest, {"version": 2})
        with self.assertRaises(ValueError):
            self.status()
        (self.root / manifest).unlink()
        self.update(self.native, pair_dns={"address": "192.0.2.10"})
        with self.assertRaises(ValueError):
            self.status()
        self.update(self.native, pair_dns=None)
        access.put("credential", "incoming", {"kind": "peer"})
        with self.assertRaises(ValueError):
            self.status()
        access.db.execute("DELETE FROM records WHERE kind='credential'")
        access.put("peer", "outgoing", {"private_key": "fixture never inspected"})
        with self.assertRaises(ValueError):
            self.status()

    def test_refuses_corrupt_or_untrusted_administration_files(self):
        access = self.install()
        database = self.authority / "authority.sqlite"
        database.chmod(0o644)
        with self.assertRaises(ValueError):
            self.status()
        database.chmod(0o600)
        ssh_config = self.root / SSH_CONFIG
        ssh_config.rename(ssh_config.with_suffix(".fixture"))
        ssh_config.symlink_to(ssh_config.with_suffix(".fixture"))
        with self.assertRaises(ValueError):
            self.status()
        ssh_config.unlink()
        ssh_config.with_suffix(".fixture").rename(ssh_config)
        access.db.execute("UPDATE records SET value='invalid' WHERE kind='meta'")
        with self.assertRaises(sqlite3.Error):
            self.status()


if __name__ == "__main__":
    unittest.main()
