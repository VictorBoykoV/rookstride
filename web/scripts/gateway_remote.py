"""Fixed remote actions for one Rookstride IKEv2 gateway. JSON on stdin/stdout."""
import base64
import contextlib
import fcntl
import gzip
import hashlib
import hmac
import importlib.util
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C"}
SUPPORTED_LTS = ("22.04", "24.04", "26.04")
OWNER = Path("/var/lib/rookstride-web-gateway")
LOCK = Path("/run/rookstride-management.lock")
PAIR_LOCKS = (Path("/run/rookstride-lifecycle.lock"), Path("/run/rookstride-pair.lock"))
PAIR_MANIFEST = Path("/etc/rookstride-pair/manifest.json")
PAIR_RELEASE = Path("/opt/rookstride-pair")
PAIR_RECIPE_FOLDERS = ("server", "twohop", "gateway", "single")
MAX_PAIR_RECIPE_BYTES = 8 * 1024 * 1024
MAX_PAIR_SNAPSHOT_BYTES = 1572864 + 4096
PAIR_RECIPE_DIGEST = "445261dd249dade8e65665df9fff4abf3facfa2a41f038ae427244a1b6c62691"
PAIR_UBUNTU_FIELDS = {"pair", "role", "operation"}
PAIR_EXIT_PORTS = {"awg": 443, "openvpn": 1194, "ikev2": 500, "xray": 443}
CA = Path("/etc/ipsec.d/cacerts/single-vps-ca.pem")
EXPORTED_CA = Path("/root/single-vps-vpn/ca.pem")
CONFIG = Path("/etc/ipsec.conf")
UNITS = ("strongswan-starter", "unbound", "adguardhome", "single-vps-vpn-dns-address", "single-vps-vpn-firewall")
PINNED = {
    "gateway/scripts/install.sh": "944705d65be9808b403636ad7b9e10d79f82fbe0aba34e1c8d445db089a7c062",
    "gateway/scripts/prepare-adguard.py": "12b9338af018a3dcee66c1a664d4ce2b0c0b0c570ef9ab619fb7699df213987d",
    "gateway/scripts/public-artifact-cache.py": "3d83248a4f6ef3bedfaca63771950c7a96a9967cfcf88b142dd399570ab28226",
    "gateway/scripts/render-adguard-config.py": "d9e1e9dbd24e23f78de51228524eb0f647f2ab660315673230f9f7fcb6ec4742",
    "gateway/scripts/ubuntu_support.py": "eb5762e73f0b7b6c52c918bbd932a977b25b6c761f67eaffe2a408393dcf3a61",
    "gateway/scripts/validate-inputs.py": "0b180453f0afae20f42da1f83e84c1b713dbc8f8bdae8a78e7f2d1b75e14baeb",
    "gateway/scripts/verify.sh": "1e26c5a871d35ce1fe912d6f4c6d8c7707416b2f0dd1508e9192d86ce45e7f93",
    "gateway/scripts/vpn-firewall": "7b4a1e9808ecb96f4f3f8590112267b958e35036b4edefe596e1a4aa44c0ea26",
    "gateway/systemd/adguardhome.service": "58e72d92bc6a8c5ebf913e1aec28e8f1bb3e8eeb6f47a9f908b8f32338153eb5",
    "gateway/systemd/single-vps-vpn-firewall.service": "a312e0a4c8ea301074845110c57ed67d91513fa44542370c1299d6025ce41b0e",
    "gateway/templates/AdGuardHome.yaml": "37238a1d084a93e8cb85946845fd005f6db625ee3d83337ce0d3f6c1c2d4f68e",
    "server/ike_packages.py": "35b8b1553156c0c0ed07c6d21dafb4d5236709a2447daae05a6ec12ca92be11e",
    "server/rookstride/passwords.py": "40fb1a3aa397382f9bfe9f0594bbf278ba75628070c9b97233d44f9752e92236",
}
GUEST_PINNED = {
    "server/ike_public.py": "6fefb816f191dab1c23f17b5443b9a4ee8ace36b89de16697a8b6a5570020a6a",
    "server/rookstride/__init__.py": "a0b2ecc7bdf77a0c54aa31a67bed2176f5568e2170bcb6ff0bb897343ed55ac2",
    "server/rookstride/admin.py": "e27d826dcffb75fc16f12744afa82b48488337117f57cdfa25dfae038d3eabcb",
    "server/rookstride/engine_guard.py": "741b990fef0557ff93cc6ecc9039b2dc06abd8b6d8d405bec09a17ac9cadce98",
    "server/rookstride/passwords.py": "40fb1a3aa397382f9bfe9f0594bbf278ba75628070c9b97233d44f9752e92236",
    "server/rookstride/usage.py": "654b58bcf9fa62a114bb4724d3949a7effb9e0035866f296d8f68b4398e90222",
    "server/rookstride/vici.py": "66757e84369b33ef7240f3b1d471c01b1a39884ef9c1d8d6a0e4651a296f01e8",
}
LIFECYCLE_PINNED = {
    "reinstall/run.py": "7e79642236e788e7d795ab4b19163e7ba7e9e4f30aa2b2c2fd83348fc578862b",
    "server/ike_packages.py": PINNED["server/ike_packages.py"],
    "server/reset.py": "85cb0f5f5d27488d2d08ce6d7bf2b37cb240a584699dad5b0ad00755e91937ac",
    "single/access.py": "2759c77190470ec8a6167ae58934218a9bebf3db69ba65b098d78b9e8a14cef8",
    "single/model.py": "2af18d0133cc24a73d2f83dec1f1e4cea69d4f0050f182fcb0a16ddfedcfde44",
    "single/user_updates.py": "6c9df75636df77b2ae0a05d075df274bf9c18a306ea9b2e873a5b50c5e274000",
}
REINSTALL_BUNDLE_DIGEST = "3eef510612fc83574cb79ebd4fb76f1a383a4a66cd66f21cd5c1d9b68343489b"
REINSTALL_STATE = Path("/var/lib/rookstride-reinstall")
REINSTALL_RESULT = Path("/etc/rookstride-reinstall-result.json")
SINGLE_BUNDLE_DIGEST = "b2c65791f0c6173bb6c058a87ba85b94a71c220cff0e6dc58b348d4f8cd71e7e"
SINGLE_STATE = Path("/var/lib/rookstride-single")
SINGLE_METHODS = ("awg", "xray", "openvpn", "xhttp", "hysteria2", "outline", "shadowsocks", "trusttunnel", "naive")
# Limit the Android recipe to files and services created by this browser installer.
WEB_RESET_PATHS = frozenset((
    "/etc/ipsec.conf", "/etc/ipsec.secrets", "/etc/single-vps-vpn", "/root/single-vps-vpn",
    "/etc/ipsec.d/cacerts/single-vps-ca.pem", "/etc/ipsec.d/certs/single-vps-server-cert.pem",
    "/etc/ipsec.d/private/single-vps-server-key.pem", "/etc/unbound/unbound.conf.d/single-vps-vpn.conf",
    "/etc/sysctl.d/90-single-vps-vpn.conf", "/etc/systemd/system/single-vps-vpn-dns-address.service",
    "/etc/systemd/system/single-vps-vpn-firewall.service", "/etc/systemd/system/adguardhome.service",
    "/usr/local/sbin/single-vps-vpn-firewall", "/var/lib/AdGuardHome", "/opt/AdGuardHome", "/run/charon.vici",
))
# Includes inactive installs and all fixed paths the recipe will write or reuse.
CONFLICTS = (
    "/etc/ipsec.conf", "/etc/ipsec.secrets", "/etc/ipsec.d", "/etc/swanctl",
    "/etc/single-vps-vpn", "/root/single-vps-vpn", "/etc/strongswan.conf",
    "/etc/unbound", "/opt/AdGuardHome", "/var/lib/AdGuardHome",
    "/etc/openvpn", "/etc/wireguard", "/etc/amnezia", "/opt/amnezia",
    "/etc/xray", "/usr/local/etc/xray", "/etc/hysteria", "/etc/sing-box",
    "/etc/rookstride*", "/opt/rookstride*", "/var/lib/rookstride*",
    "/etc/twohop*", "/opt/twohop*", "/var/lib/twohop*", "/var/lib/docker",
    "/etc/sysctl.d/90-single-vps-vpn.conf", "/usr/local/sbin/single-vps-vpn-firewall",
    "/etc/systemd/system/single-vps-vpn*", "/etc/systemd/system/adguardhome.service",
    "/etc/systemd/system/rookstride*", "/usr/lib/systemd/system/adguardhome.service",
)
WRITABLE_PARENTS = (
    "/etc", "/root", "/var/lib", "/opt", "/run", "/usr/local/sbin",
    "/etc/sysctl.d", "/etc/systemd/system",
)
POOL_NETWORKS = tuple(map(ipaddress.ip_network, ("10.252.0.0/24", "10.254.0.1/32", "fd42:252::/64")))
# Match the client pool, bridge subnet and test source in server/pair.py's
# native-v2 plan. Applying the pair also requires its own recipe preflight.
PAIR_NETWORKS = tuple(map(ipaddress.ip_network, ("10.66.0.0/24", "10.253.0.0/30", "10.249.255.254/32")))
MAX_REQUEST = 256 * 1024
MAX_REINSTALL_REQUEST = 640 * 1024
MAX_RUNTIME_ARCHIVE = 16 * 1024 * 1024
MAX_RUNTIME_COMPONENT = 96 * 1024 * 1024
RUNTIME_FILES = {
    "rook-routes": ("bytes", "sha256"),
    "libcronet.so": ("library_bytes", "library_sha256"),
}


class GuardError(ValueError):
    """Only fixed, nonsecret messages may be returned to the caller."""


class Conflict(GuardError):
    """An account action no longer matches the reviewed state."""


class PairSnapshotChanged(Conflict):
    """The verified pair recovery identity differs from the review."""


class RecipeFailure(GuardError):
    """Identify the failed stage without returning commands or subprocess output."""


def result(state, message):
    return {"state": state, "message": message}


def run(args):
    return subprocess.run(args, env=SAFE_ENV, cwd="/", stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, timeout=12, check=True).stdout


def require_secure_directory(path):
    path = Path(path)
    for directory in reversed([path, *path.parents]):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise GuardError("A system directory has unexpected ownership or permissions.")


@contextlib.contextmanager
def owned_file(path, limit, private=False):
    require_secure_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022) or info.st_size > limit):
            raise GuardError("A managed file has changed. Review this server.")
        yield handle


def read_owned(path, limit):
    with owned_file(path, limit) as handle:
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise GuardError("A managed file exceeds its expected size.")
        return data


def eligible_version():
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() not in ("aarch64", "x86_64"):
        return None
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    version = release.get("VERSION_ID", "").strip('"')
    if (release.get("ID", "").strip('"') == "ubuntu" and version in SUPPORTED_LTS
            and Path("/run/systemd/system").is_dir()
            and all(Path(name).is_file() for name in ("/usr/bin/python3", "/usr/bin/apt-get", "/usr/bin/dpkg",
                                                      "/usr/bin/systemctl", "/usr/bin/ss", "/usr/sbin/ip"))):
        return version
    return None


def valid_address(value):
    if not isinstance(value, str):
        return False
    try:
        addr = ipaddress.IPv4Address(value)
        return addr.is_global and not addr.is_multicast and str(addr) == value
    except ValueError:
        return False


def bundle(files, pins=PINNED):
    if not isinstance(files, dict) or set(files) != pins.keys():
        raise GuardError("The installer bundle is incomplete or unexpected.")
    unpacked = {}
    for name, digest in pins.items():
        value = files[name]
        if not isinstance(value, str) or len(value) > MAX_REQUEST:
            raise GuardError("The installer bundle is invalid.")
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError:
            raise GuardError("The installer bundle is invalid.") from None
        if hashlib.sha256(raw).hexdigest() != digest:
            raise GuardError("The installer bundle does not match the reviewed recipe.")
        unpacked[name] = raw
    return unpacked


def stage_files(tree, files):
    for name, data in files.items():
        dest = tree / name
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o700 if name.endswith(".sh") else 0o600)


def reserved_socket_or_application(rows, ssh_port):
    # ss -H -lntup gives protocol, state, queues, local, peer, process names.
    found_ssh = False
    for row in rows.splitlines():
        columns = row.split(None, 6)
        if len(columns) < 7:
            return True
        proto, endpoint, owners = columns[0], columns[4], set(re.findall(r'\("([^"]+)",pid=', columns[6]))
        host, sep, port = endpoint.rpartition(":")
        host = host.strip("[]").split("%")[0]
        if not sep or not port.isdigit() or not owners:
            return True
        if proto == "tcp" and port == ssh_port and owners <= {"sshd", "systemd"}:
            found_ssh = True
            continue
        if port == "53" and host in {"127.0.0.53", "127.0.0.54"} and owners <= {"systemd-resolve", "systemd-resolved"}:
            continue
        if proto == "udp" and port == "5353" and host in {"0.0.0.0", "::", "*"} and owners <= {"systemd-resolve", "systemd-resolved"}:
            continue
        if proto == "udp" and port in {"68", "546"} and owners <= {"systemd-network", "systemd-networkd", "dhclient", "dhcpcd", "NetworkManager"}:
            continue
        if proto == "udp" and port == "323" and host in {"127.0.0.1", "::1"} and owners == {"chronyd"}:
            continue
        return True
    return not found_ssh


def conflicting_route(routes, pools=POOL_NETWORKS):
    for record in routes:
        destination = record.get("dst", "default")
        if destination == "default":
            continue
        network = ipaddress.ip_network(destination, strict=False)
        if network.prefixlen and any(network.overlaps(pool) for pool in pools if pool.version == network.version):
            return True
    return False


def has_conflicting_files():
    for pattern in CONFLICTS:
        if "*" in pattern:
            for path in Path("/").glob(pattern[1:]):
                if path == REINSTALL_RESULT and verified_reinstall_receipt(eligible_version()):
                    continue
                return True
        elif os.path.lexists(pattern):
            # exists() alone would allow the installer to follow a dangling link.
            return True
    return False


def only_ssh_ban(rows, ssh_port):
    # Match the complete stock Fail2ban nftables SSH jail. In particular, no
    # other table, forward hook, base policy, destination port or rule is allowed.
    if len(rows) != 4 or any(len(row) != 1 for row in rows):
        return False
    records = {kind: {k: v for k, v in item.items() if k != "handle"}
               for row in rows for kind, item in row.items()}
    family = {"family": "inet"}
    table = {**family, "table": "f2b-table"}
    ban_set = records.get("set", {})
    addresses = ban_set.pop("elem", [])
    if not isinstance(addresses, list) or any(not isinstance(addr, str) for addr in addresses):
        return False
    try:
        for address in addresses:
            ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return records == {
        "table": {**family, "name": "f2b-table"},
        "set": {**table, "name": "addr-set-sshd", "type": "ipv4_addr"},
        "chain": {**table, "name": "f2b-chain", "type": "filter", "hook": "input", "prio": -1, "policy": "accept"},
        "rule": {**table, "chain": "f2b-chain", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": int(ssh_port)}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@addr-set-sshd"}},
            {"reject": {"type": "icmp", "expr": "port-unreachable"}},
        ]},
    }


def guarded_fresh(pools=POOL_NETWORKS, *, allow_ssh_ban=False):
    for directory in WRITABLE_PARENTS:
        require_secure_directory(directory)
    if has_conflicting_files():
        return False
    units = run(["/usr/bin/systemctl", "list-unit-files", "--type=service", "--no-legend",
                 "--no-pager", "--plain"])
    if re.search(r"^(?:strongswan|ipsec|openvpn|wg-quick|adguardhome|unbound|xray|sing-box|tailscaled|zerotier|rookstride|docker)[@.\-]",
                 units, re.I | re.M):
        return False
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if len(ssh) != 4 or not ssh[3].isdigit():
        return False
    sockets = run(["/usr/bin/ss", "-H", "-lntup"])
    if reserved_socket_or_application(sockets, ssh[3]):
        return False
    for af in ("-4", "-6"):
        routes = json.loads(run(["/usr/sbin/ip", "-j", af, "route", "show", "table", "all"]))
        if conflicting_route(routes, pools):
            return False
    # The installer adds its own forwarding and NAT chains. Preserve existing policy.
    for name in ("iptables-save", "ip6tables-save"):
        executable = shutil.which(name, path=SAFE_ENV["PATH"])
        if executable and re.search(r"^(?:-A |:[\w-]+ (?:-|DROP|REJECT) )", run([executable]), re.M):
            return False
    nft = shutil.which("nft", path=SAFE_ENV["PATH"])
    if nft:
        rules = [row for row in json.loads(run([nft, "-j", "list", "ruleset"]))["nftables"]
                 if set(row) != {"metainfo"}]
        if rules and not (allow_ssh_ban and only_ssh_ban(rules, ssh[3])):
            return False
    # The recipe adopts an existing adguard account. A fresh target must have none.
    lookup = subprocess.run(["/usr/bin/getent", "passwd", "adguard"], env=SAFE_ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
    return lookup.returncode == 2


def ca_der():
    first = read_owned(CA, 32768)
    if read_owned(EXPORTED_CA, 32768) != first or first.count(b"BEGIN CERTIFICATE") != 1:
        raise GuardError("The original gateway certificate cannot be verified.")
    return ssl.PEM_cert_to_DER_cert(first.decode("ascii"))


def unit_states():
    return {unit: subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], env=SAFE_ENV,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=8).returncode == 0
            for unit in UNITS}


def verified_instance(address, require_active=True):
    marker = json.loads(read_owned(OWNER / "verified.json", 4096))
    if (not isinstance(marker, dict) or marker.get("format") != 1 or not valid_address(marker.get("address"))
            or (address is not None and marker["address"] != address) or not isinstance(marker.get("uuid"), str)
            or not isinstance(marker.get("login"), str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", marker["login"])):
        raise GuardError("The recorded VPN identity does not match this request.")
    uuid.UUID(marker["uuid"])
    ca = ca_der()
    if (hashlib.sha256(ca).hexdigest() != marker.get("caDigest")
            or hashlib.sha256(read_owned(CONFIG, 65536)).hexdigest() != marker.get("configDigest")
            or (require_active and not healthy_units())):
        raise GuardError("The recorded gateway or its services have changed.")
    return marker, ca


def healthy_units():
    return all(unit_states().values())


def session_control_ready():
    return Path("/run/charon.vici").is_socket()


def inspect(address):
    if os.path.lexists(OWNER):
        try:
            if os.path.lexists(OWNER / "protocol.json"):
                return protocol_status(address)
            if os.path.lexists(OWNER / "protocol.pending"):
                return result("occupied", "Check the interrupted VPN setup before continuing.")
            if os.path.lexists(OWNER / "protocol.removed.json"):
                marker = protocol_marker(address, "protocol.removed.json")
                if not os.path.lexists(SINGLE_STATE / marker["method"]) and not os.path.lexists(CONFIG):
                    return result("removed", "The browser-managed VPN was removed.")
            if os.path.lexists(OWNER / "removed.json") and not os.path.lexists(OWNER / "verified.json"):
                marker = json.loads(read_owned(OWNER / "removed.json", 4096))
                if (marker.get("format") == 1 and valid_address(marker.get("address"))
                        and address in (None, marker["address"])
                        and not any(os.path.lexists(path) for path in WEB_RESET_PATHS)
                        and not any(unit_states().values())):
                    return result("removed", "The browser-managed VPN was removed.")
            verified_instance(address)
            return result("installed", "The gateway created here is installed and its services are active.")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return result("occupied", "Setup is in progress, ended partway, or has changed. Inspect this server before any new installation.")
    try:
        if guarded_fresh(allow_ssh_ban=True):
            return result("ready", "Preflight found a supported server with no conflicting services or VPN configuration.")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    return result("occupied", "The server has existing services, conflicting settings, or a fresh configuration could not be verified.")


def protocol_marker(address, filename="protocol.json"):
    marker = json.loads(read_owned(OWNER / filename, 4096))
    marker.setdefault("method", "xray")
    if (not valid_address(marker.get("address")) or address not in (None, marker["address"])
            or marker["method"] not in SINGLE_METHODS
            or any(not re.fullmatch(r"[a-f0-9]{32}", marker[field]) for field in ("job", "instance"))
            or not re.fullmatch(r"[a-f0-9]{64}", marker["bundle"])):
        raise GuardError("The VPN installation identity could not be verified.")
    return marker


def protocol_status(address):
    marker = protocol_marker(address)
    method = marker["method"]
    job = json.loads(read_owned(SINGLE_STATE / "jobs" / marker["job"] / "status.json", 65536))
    if (job.get("protocol") != method or job.get("bundle") != marker["bundle"]
            or job.get("install_context", {}).get("instance") != marker["instance"]):
        raise GuardError("The VPN installation job changed.")
    if job["state"] in ("starting", "running"):
        if time.time() - job["updated"] <= 20 or subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "rookstride-single-install-" + marker["job"]],
            timeout=8, check=False,
        ).returncode == 0:
            return {"state": "protocolRunning", "method": method}
    if job["state"] == "complete":
        config = json.loads(read_owned(SINGLE_STATE / method / "state.json", 262144))
        if (config.get("owner") == "rookstride-single-v1" and config.get("protocol") == method
                and config.get("instance") == marker["instance"] and config.get("server") == marker["address"]):
            return {"state": "protocolInstalled", "method": method, "port": config["port"]}
    return {"state": "protocolFailed", "method": method}


def single_bundle(encoded):
    if not isinstance(encoded, str) or len(encoded) > MAX_REQUEST:
        raise GuardError("Unexpected single-server recipe archive.")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(encoded, validate=True))) as archive:
            content = archive.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise GuardError("The single-server recipe archive is too large.")
        files = json.loads(content)
        if not isinstance(files, dict) or len(files) > 32:
            raise GuardError("Unexpected single-server recipe archive.")
        result = {}
        digest = hashlib.sha256()
        for name in sorted(files):
            if not re.fullmatch(r"(?:server/(?:ike_packages|reset)\.py|single/(?:Dockerfile\.(?:awg|openvpn)|[a-z][a-z0-9_-]*\.(?:py|sh|json)))", name):
                raise GuardError("Unexpected single-server recipe file.")
            data = base64.b64decode(files[name], validate=True)
            result[name] = data
            digest.update(name.encode() + b"\0" + data + b"\0")
        if digest.hexdigest() == SINGLE_BUNDLE_DIGEST:
            return result
    except (OSError, EOFError, ValueError, TypeError):
        pass
    raise GuardError("The single-server bundle does not match the reviewed recipe.")


def runtime_members(asset):
    return ((name, asset[size], asset[digest]) for name, (size, digest) in RUNTIME_FILES.items())


def runtime_ready(root, asset):
    if not os.path.lexists(root):
        return False
    require_secure_directory(root)
    target = root / asset["sha256"]
    if not os.path.lexists(target):
        return False
    require_secure_directory(target)
    if {path.name for path in target.iterdir()} != RUNTIME_FILES.keys():
        raise GuardError("The installed VPN runtime contains unexpected files.")
    for name, size, digest in runtime_members(asset):
        actual = hashlib.sha256()
        with owned_file(target / name, size) as source:
            if name == "rook-routes" and not os.fstat(source.fileno()).st_mode & stat.S_IXUSR:
                raise GuardError("The installed VPN runtime permissions have changed.")
            count = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                actual.update(chunk)
                count += len(chunk)
        if count != size or actual.hexdigest() != digest:
            raise GuardError("The installed VPN runtime could not be verified.")
    return True


def copy_runtime_file(source, destination, size, digest, limit, mode):
    if type(size) is not int or not 0 < size <= limit:
        raise GuardError("The VPN runtime size is unexpected.")
    actual = hashlib.sha256()
    with destination.open("xb") as output:
        remaining = size
        while remaining:
            piece = source.read(min(remaining, 1024 * 1024))
            if not piece:
                raise GuardError("The VPN runtime transfer ended early.")
            output.write(piece)
            actual.update(piece)
            remaining -= len(piece)
        if source.read(1) or actual.hexdigest() != digest:
            raise GuardError("The VPN runtime does not match the reviewed archive.")
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(mode)


def install_route_runtime(root, asset, stream):
    require_secure_directory(root.parent)
    with tempfile.TemporaryDirectory(prefix=".rookstride-routes-", dir=root.parent) as tmp:
        stage = Path(tmp)
        archive_path = stage / "runtime.tar.gz"
        copy_runtime_file(stream, archive_path, asset["archive_bytes"],
                          asset["archive_sha256"], MAX_RUNTIME_ARCHIVE, 0o600)
        prepared = stage / "runtime"
        prepared.mkdir(mode=0o700)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) != len(RUNTIME_FILES) or {item.name for item in members} != RUNTIME_FILES.keys():
                raise GuardError("The VPN runtime archive has unexpected entries.")
            for name, size, digest in runtime_members(asset):
                member = archive.getmember(name)
                if not member.isfile() or member.size != size:
                    raise GuardError("The VPN runtime component has an unexpected format.")
                with archive.extractfile(member) as source:
                    copy_runtime_file(source, prepared / name, size, digest, MAX_RUNTIME_COMPONENT, 0o700)
        if runtime_ready(root, asset):
            return
        root.mkdir(mode=0o700, exist_ok=True)
        require_secure_directory(root)
        prepared.rename(root / asset["sha256"])


def manage_protocol(req, stream=None):
    action, address = req["action"], req["address"]
    files = single_bundle(req["files"])
    login = req.get("login")
    if login is not None and (not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", login)):
        raise GuardError("Invalid VPN login.")
    with exclusive_install(), tempfile.TemporaryDirectory(prefix="rookstride-web-protocol-", dir="/run") as tmp:
        tree = Path(tmp)
        stage_files(tree, files)
        path = str(tree / "single")
        sys.path.insert(0, path)
        try:
            import run as single
            if single.runtime.ROOT.is_symlink() or single.runtime.STATE.is_symlink():
                raise GuardError("Unexpected single-server data link.")
            fd = os.open(single.SINGLE_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            with os.fdopen(fd, "rb+") as lock:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022 or info.st_nlink != 1:
                    raise GuardError("The single-server lock has unexpected ownership.")
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return single_action(single, req, action, address, login, stream)
        finally:
            sys.path.remove(path)


def single_action(single, req, action, address, login, stream=None):
    if action in ("protocolReview", "protocolApply"):
        method = req.get("method", "xray")
        if method not in SINGLE_METHODS or method not in single.model.PROTOCOLS:
            raise GuardError("Unsupported VPN method.")
        ready = inspect(address)["state"]
        previous = os.path.lexists(OWNER / "protocol.removed.json")
        existing = any(os.path.lexists(SINGLE_STATE / protocol) for protocol in single.model.PROTOCOLS)
        if ready not in ("ready", "removed") or existing or os.path.lexists("/etc/rookstride-pair"):
            raise Conflict("The server changed. Inspect it before choosing another protocol.")
        if not previous:
            if os.path.lexists("/opt/rookstride-single"):
                raise Conflict("The server changed. Inspect it before choosing another protocol.")
            if os.path.lexists(SINGLE_STATE):
                # An owned pair reset can leave this directory empty.
                require_secure_directory(SINGLE_STATE)
                if next(SINGLE_STATE.iterdir(), None) is not None:
                    raise Conflict("The server changed. Inspect it before choosing another protocol.")
        import routes
        architecture = req.get("runtimeArchitecture")
        runtime = {}
        if method in routes.PROTOCOLS:
            try:
                machine = platform.machine()
                asset = json.loads(routes.PINS.read_text())["assets"][machine]
                ready_for_method = runtime_ready(routes.WORKER, asset)
                if not ready_for_method and action == "protocolReview":
                    runtime["runtimeArchitecture"] = machine
                elif not ready_for_method and not architecture:
                    return {"state": "runtimeUnavailable"}
            except (OSError, ValueError, KeyError):
                return {"state": "runtimeUnavailable"}
        elif architecture:
            raise GuardError("This method does not accept a VPN runtime.")
        ssh = os.environ.get("SSH_CONNECTION", "").split()
        if len(ssh) != 4 or not ssh[3].isdigit():
            raise GuardError("Could not verify the SSH port.")
        request = {"action": "plan", "protocol": method, "server": address, "login": login, "sshPort": int(ssh[3])}
        if action == "protocolReview":
            return {"port": single.action(request)["port"], **runtime}
        if type(req["port"]) is not int or not 1 <= req["port"] <= 65535:
            raise GuardError("Invalid reviewed VPN port.")
        if architecture:
            if architecture != machine or stream is None:
                raise GuardError("The VPN runtime does not match the target architecture.")
            # Recheck the selected listener before publishing the validated files.
            single.action({**request, "port": req["port"]})
            try:
                install_route_runtime(routes.WORKER, asset, stream)
            except (OSError, ValueError, tarfile.TarError):
                return {"state": "runtimeUnavailable"}
        OWNER.mkdir(mode=0o700, exist_ok=ready == "removed")
        pending = OWNER / "protocol.pending"
        with pending.open("x", encoding="utf-8") as handle:
            context = {"schema": 1, "owner": str(uuid.uuid4()), "task": uuid.uuid4().hex}
            json.dump(context, handle)
            handle.flush()
            os.fsync(handle.fileno())
        job = single.action({**request, "action": "start", "port": req["port"], "install_context": context})
        marker = {"address": address, "job": job["job"], "bundle": job["bundle"],
                  "instance": job["install_context"]["instance"], "method": method}
        with (OWNER / "protocol.tmp").open("x", encoding="utf-8") as handle:
            json.dump(marker, handle)
            handle.flush()
            os.fsync(handle.fileno())
        (OWNER / "protocol.tmp").replace(OWNER / "protocol.json")
        pending.unlink()
        return {"state": "protocolRunning", "method": method}
    status = protocol_status(address)
    if status["state"] != "protocolInstalled":
        raise Conflict("The VPN installation has not completed.")
    method = status["method"]
    request = {"protocol": method, "login": login}
    if action == "protocolRemoveReview":
        return {"token": single.action({**request, "action": "reset-plan"})["token"]}
    if action == "protocolRemoveApply":
        removed = single.action({**request, "action": "reset-apply", "token": req["token"], "confirmation": req["confirmation"]})
        still_active = single.model.proxy_protocol(method) and subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "rookstride-single-" + method],
            timeout=8, check=False,
        ).returncode == 0
        if removed.get("reset") is not True or os.path.lexists(SINGLE_STATE / method) or still_active:
            raise GuardError("VPN removal could not be verified.")
        (OWNER / "protocol.json").replace(OWNER / "protocol.removed.json")
        return {"state": "removed"}
    if action == "protocolProfile":
        profile = single.action({**request, "action": "profile"})
        return {"configuration": profile["content"], "method": profile["format"], "port": status["port"]}
    if action == "protocolFilter":
        return protocol_filter(single, method, req)
    if action == "protocolUsage":
        return protocol_usage(single, method)
    roster = protocol_roster(method)
    if action in ("protocolGrant", "protocolRevoke"):
        if req["revision"] != roster["revision"]:
            raise Conflict("The VPN accounts changed. Refresh the list.")
        if login == roster["owner"] and action == "protocolRevoke":
            raise Conflict("The VPN owner cannot be revoked.")
        if action == "protocolGrant" and len(roster["users"]) >= 256:
            raise GuardError("The VPN account list is full.")
        single.action({**request, "action": "add-user" if action == "protocolGrant" else "remove-user"})
        return protocol_roster(method)
    return roster


def protocol_roster(method):
    raw = read_owned(SINGLE_STATE / method / "state.json", 262144)
    config = json.loads(raw)
    users = sorted(user["login"] for user in config["users"] if user.get("enabled", True))
    return {"owner": config["initialLogin"], "users": users, "revision": hashlib.sha256(raw).hexdigest()}


def web_counter(value):
    return type(value) is int and 0 <= value <= (1 << 53) - 1


def protocol_filter(single, method, req):
    filtering = single.filtering
    state = single.runtime.load(method)
    if (state.get("pair_dns") or not state.get("filtering")
            or filtering.load()["instance"] != state["filtering"]):
        raise Conflict("The private DNS filter no longer matches this VPN.")
    update = {}
    if "level" in req:
        level = req["level"]
        if not isinstance(level, str) or level not in filtering.FILTERS:
            raise GuardError("Choose a supported DNS filtering preset.")
        update["level"] = level
    if "enabled" in req:
        if type(req["enabled"]) is not bool:
            raise GuardError("Choose whether DNS filtering is enabled.")
        update["enabled"] = req["enabled"]

    if update:
        report = single.action({"action": "adguard", "protocol": method, **update})
        queries, blocked = report.get("queries"), report.get("blocked")
    else:
        # Inspection is read-only. The native adguard action enrolls the
        # current installer helper before it delegates to the filter.
        stats = filtering.api("stats")
        queries, blocked = stats.get("num_dns_queries"), stats.get("num_blocked_filtering")
    # Verify by the reviewed list URL. Custom filters may share a display name.
    loaded = filtering.api("filtering/status")["filters"]
    enabled_urls = {row["url"] for row in loaded
                    if row.get("enabled") is True and web_counter(row.get("rules_count"))
                    and row["rules_count"] > 0}
    presets = [name for name, (_label, url) in filtering.FILTERS.items() if url in enabled_urls]
    protection = filtering.api("dns_info").get("protection_enabled")
    if (type(protection) is not bool or ("enabled" in update and protection is not update["enabled"])
            or ("level" in update and update["level"] not in presets)
            or not all(web_counter(value) for value in (queries, blocked))):
        raise Conflict("The DNS filter settings could not be verified.")
    return {"presets": presets, "queries": queries, "blocked": blocked,
            "protectionEnabled": protection}


def protocol_usage(single, method):
    kind, scope = {
        "awg": ("handshake", "interface"),
        "openvpn": ("sessions", "active-sessions"),
        "xray": ("traffic", "daemon"),
        "xhttp": ("traffic", "daemon"),
    }.get(method, ("sessions", "daemon"))
    unavailable = {"available": False}
    try:
        report = single.action({"action": "status", "protocol": method})
        if (not isinstance(report, dict) or report.get("protocol") != method
                or report.get("statistics_kind") != kind
                or report.get("running") is not True or report.get("monitoring_available") is not True):
            return unavailable
        rows = report.get("connections")
        if not isinstance(rows, list) or len(rows) > 256:
            return unavailable
        profiles = None if kind == "traffic" else report.get("recent_peers")
        if kind != "traffic" and (not web_counter(profiles) or profiles > len(rows)):
            return unavailable
        totals = {}
        for key in ("upload", "download"):
            counters = [row[key] for row in rows]
            if not all(web_counter(value) for value in counters):
                return unavailable
            totals[key] = sum(counters)
            if not web_counter(totals[key]):
                return unavailable
        return {"available": True, "kind": kind, "scope": scope, "profiles": profiles, **totals}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return unavailable


def inspect_pair_node():
    machine = read_owned(Path("/etc/machine-id"), 64).strip()
    if not re.fullmatch(rb"[a-f0-9]{32}", machine) or machine == b"0" * 32:
        raise GuardError("The server identity could not be confirmed.")
    try:
        ready = guarded_fresh(POOL_NETWORKS + PAIR_NETWORKS)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        ready = False
    return {"state": "ready" if ready else "occupied", "machine": hashlib.sha256(machine).hexdigest()}


@contextlib.contextmanager
def management_lock(path):
    require_secure_directory(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "rb+") as lock:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022 or info.st_nlink != 1:
            raise GuardError("The gateway management lock has unexpected ownership.")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise GuardError("Another gateway operation is running.") from None
        yield


@contextlib.contextmanager
def exclusive_install(check_reinstall=True):
    with management_lock(LOCK):
        if check_reinstall:
            reinstall = resume_reinstall()
            if reinstall and reinstall["state"] in ("preparing", "rebooting"):
                raise Conflict("An Ubuntu reinstall is already in progress.")
        yield


@contextlib.contextmanager
def exclusive_pair_reinstall():
    # Match the lock order used by the native pair lifecycle helper.
    with exclusive_install(), management_lock(PAIR_LOCKS[0]), management_lock(PAIR_LOCKS[1]):
        yield


def run_recipe(script, env, timeout):
    # Ubuntu mounts /run noexec. The system interpreter can read the reviewed
    # source in private temporary storage without changing mount protections.
    proc = subprocess.Popen(["/bin/bash", str(script)], cwd="/", env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        return proc.wait(timeout=timeout)
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        raise


def install(req):
    files = bundle(req["files"])
    login, password = req["login"], req["vpnPassword"]
    if (not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", login)
            or not isinstance(password, str) or not password or len(password.encode("utf-8")) > 127
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or ord(c) in (0x2028, 0x2029) for c in password)):
        raise GuardError("The VPN account details are invalid.")
    with exclusive_install():
        status = inspect(req["address"])
        if status["state"] == "installed":
            return result("occupied", "An existing verified gateway is already here. Reconnect to use its original profile.")
        if status["state"] != "ready":
            return status
        # The private directory is also a durable interruption marker. No automated retry or cleanup of gateway state.
        OWNER.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="rookstride-web-", dir="/run") as tmp:
            tree = Path(tmp)
            stage_files(tree, files)
            secret = tree / "initial.password"
            with secret.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(password.encode("utf-8") + b"\n")
            env = {**SAFE_ENV, "SERVER_ID": req["address"], "VPN_USER": login, "VPN_PASSWORD_FILE": str(secret),
                   "ROOKSTRIDE_VERIFY_SEPARATELY": "YES", "ROOKSTRIDE_REQUIRE_SESSION_CONTROL": "YES"}
            try:
                code = run_recipe(tree / "gateway/scripts/install.sh", env, 3000)
            finally:
                secret.unlink(missing_ok=True)
            if code:
                raise RecipeFailure("installation")
            if run_recipe(tree / "gateway/scripts/verify.sh", SAFE_ENV, 600) or not session_control_ready():
                raise RecipeFailure("verification")
        marker = {"format": 1, "address": req["address"], "login": login, "uuid": str(uuid.uuid4()),
                  "caDigest": hashlib.sha256(ca_der()).hexdigest(),
                  "configDigest": hashlib.sha256(read_owned(CONFIG, 65536)).hexdigest()}
        if not healthy_units():
            raise GuardError("Gateway services could not be confirmed. Existing changes were retained.")
        staging = OWNER / "verified.tmp"
        with staging.open("x", encoding="utf8") as handle:
            json.dump(marker, handle)
            handle.flush()
            os.fsync(handle.fileno())
        staging.replace(OWNER / "verified.json")
        return result("installed", "Server-side VPN, DNS and ad filtering checks passed.")


def client_profile(address, login, marker, ca):
    identity = marker["uuid"] if login == marker["login"] else str(uuid.uuid5(uuid.UUID(marker["uuid"]), login))
    return {"profile": {"uuid": identity, "name": "Rookstride VPN · " + login, "type": "ikev2-eap",
                        "remote": {"addr": address, "id": address, "cert": base64.b64encode(ca).decode("ascii")},
                        "local": {"eap_id": login},
                        "split-tunneling": {"block-ipv4": True, "block-ipv6": True}}}


def guest_inventory(admin, owner):
    with owned_file(admin.SECRETS, 256 * 1024, private=True) as secrets:
        info = os.fstat(secrets.fileno())
        # The revision exposes no password hash. The canonical writer atomically
        # replaces this file, so removing and recreating the same login needs a new review.
        metadata = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    if os.path.lexists(admin.STATE):
        require_secure_directory(admin.STATE)
    if os.path.lexists(admin.STATE / "users.json"):
        with owned_file(admin.STATE / "users.json", 512 * 1024, private=True):
            pass
    names = sorted(admin.username(user["login"]) for user in admin.user_inventory())
    if owner not in names or len(set(names)) != len(names):
        raise Conflict("The original account list has changed. Review this server.")
    if len(names) > 257:
        raise GuardError("This account list is too large for the browser workspace.")
    result = {"owner": owner, "guests": [name for name in names if name != owner]}
    result["revision"] = hashlib.sha256(json.dumps([metadata, names]).encode()).hexdigest()
    return result


def guest_action(admin, guard, req, marker, ca):
    owner = marker["login"]
    before = guest_inventory(admin, owner)
    action = req["action"]
    if action == "guests":
        return before
    try:
        login = admin.username(req.get("login", owner))
    except ValueError:
        raise GuardError("Use a VPN login of 1–64 letters, numbers, dots, hyphens, underscores or @.") from None
    if action == "profile":
        if login != owner and login not in before["guests"]:
            raise Conflict("That VPN account is no longer present.")
        return client_profile(req["address"], login, marker, ca)
    if before["revision"] != req["revision"]:
        raise Conflict("The guest list changed. Refresh it and review the change again.")
    if login == owner:
        raise Conflict("The server owner’s VPN account is protected.")
    if action in ("grant", "rotate"):
        if action == "grant" and login in before["guests"]:
            raise Conflict("That guest already has VPN access.")
        if action == "rotate" and login not in before["guests"]:
            raise Conflict("That guest has no access to change.")
        if action == "grant" and len(before["guests"]) >= 256:
            raise GuardError("The browser workspace supports up to 256 guests.")
        try:
            admin.vpn_password(req["vpnPassword"])
        except (TypeError, ValueError):
            raise GuardError("Use a printable VPN password of up to 127 UTF-8 bytes.") from None
        update = {"login": login, "password": req["vpnPassword"], "replace": action == "rotate"}
    else:
        if login not in before["guests"]:
            raise Conflict("That guest has no access to remove.")
        update = {"login": login}
    guard.require_idle()
    changed = admin.update_user(update, remove=action == "revoke")
    after = guest_inventory(admin, owner)
    if (login in after["guests"]) != (action != "revoke") or before["revision"] == after["revision"]:
        raise Conflict("The change could not be confirmed. Refresh the guest list.")
    if changed.get("warning"):
        after["activeSessionsUncertain"] = True
    return after


def manage_filter(admin, guard, req):
    with owned_file(Path("/root/single-vps-vpn/adguard-login.txt"), 4096, private=True) as handle:
        fields = dict(line.split(": ", 1) for line in handle.read().decode("utf-8").splitlines() if ": " in line)
    if fields.get("Dashboard") != "http://10.254.0.1:3000":
        raise GuardError("The managed DNS dashboard does not match this gateway.")
    level = req.get("level")
    if level is not None:
        if not isinstance(level, str) or level not in admin.FILTERS:
            raise GuardError("Choose a supported DNS filtering preset.")
        guard.require_idle()
    report = admin.adguard({"level": level} if level else {})
    enabled = {row.get("name") for row in report["filters"] if row.get("enabled") is True and row.get("rules", 0) > 0}
    presets = [preset for preset, (name, _url) in admin.FILTERS.items() if name in enabled]
    if level and level not in presets:
        raise Conflict("The selected filter could not be verified.")
    return {"presets": presets, "queries": report["queries"], "blocked": report["blocked"]}


def live_ike_usage(admin):
    try:
        active = [session for session in admin.connections(admin.sessions())
                  if session["state"] == "ESTABLISHED" and session["children"]]
        return {"available": True, "sessions": len(active),
                "upload": sum(session["upload"] for session in active),
                "download": sum(session["download"] for session in active)}
    except (OSError, ValueError, RuntimeError):
        return {"available": False}


def manage_guests(req):
    files = bundle(req["files"], GUEST_PINNED)
    with exclusive_install():
        marker, ca = verified_instance(req["address"])
        if os.path.lexists("/etc/rookstride-pair") or os.path.lexists("/etc/single-vps-vpn/public-certificate.json"):
            raise Conflict("The gateway has changed since initial setup. Review its configuration.")
        with tempfile.TemporaryDirectory(prefix="rookstride-web-admin-", dir="/run") as tmp:
            stage_files(Path(tmp), files)
            path = str(Path(tmp) / "server")
            sys.path.insert(0, path)
            try:
                from rookstride import admin, engine_guard
                if req["action"] == "filter":
                    return manage_filter(admin, engine_guard, req)
                if req["action"] == "usage":
                    return live_ike_usage(admin)
                return guest_action(admin, engine_guard, req, marker, ca)
            finally:
                sys.path.remove(path)


def manage_lifecycle(req):
    files = bundle(req["files"], LIFECYCLE_PINNED)
    with exclusive_install(), tempfile.TemporaryDirectory(prefix="rookstride-web-lifecycle-", dir="/run") as tmp:
        tree = Path(tmp)
        stage_files(tree, files)
        if req["action"] in ("ubuntuCheck", "ubuntuReview"):
            reinstall = load_reinstall(tree)
            if req["action"] == "ubuntuReview":
                require_single_for_reinstall()
                return reinstall_review(reinstall.plan({"version": req["ubuntu"]}))
            try:
                scope = reinstall.inspect()
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                return {"eligible": False}
            return {"eligible": True, "diskBytes": scope["disk_bytes"], "boot": scope["boot"]}
        verified_instance(req["address"], require_active=False)
        if any(os.path.lexists(path) for path in ("/etc/rookstride-pair", "/opt/rookstride-single",
                                                 "/var/lib/rookstride/jobs", "/etc/single-vps-vpn/public-certificate.json")):
            raise Conflict("This gateway needs a separate ownership review before removal.")
        resolver_config = Path("/etc/unbound/unbound.conf.d")
        require_secure_directory(resolver_config)
        if any(path.name not in {"remote-control.conf", "root-auto-trust-anchor-file.conf", "single-vps-vpn.conf"}
               for path in resolver_config.glob("*.conf")):
            raise Conflict("Additional DNS resolver configuration needs review before VPN removal.")
        server = str(tree / "server")
        single = str(tree / "single")
        sys.path[:0] = [server, single]
        try:
            import reset
            import user_updates
            user_updates.ensure_no_runtime_update(destructive=True)
            reset.STATE = OWNER
            reset.PATHS = tuple(path for path in reset.PATHS if str(path) in WEB_RESET_PATHS)
            reset.SERVICES = UNITS
            if req["action"] == "removeReview":
                plan = reset.plan()
                return {"token": plan["token"]}
            receipt = reset.apply({"token": req["token"], "confirmation": req["confirmation"]})
            if (not receipt.get("reset") or any(unit_states().values())
                    or any(os.path.lexists(path) for path in WEB_RESET_PATHS)):
                raise GuardError("Removal could not be verified.")
            (OWNER / "verified.json").replace(OWNER / "removed.json")
            return {"state": "removed"}
        finally:
            sys.path.remove(single)
            sys.path.remove(server)


def require_single_for_reinstall():
    if os.path.lexists("/etc/rookstride-pair"):
        raise Conflict("Use the original Double VPN tools for a paired gateway.")


def load_reinstall(tree):
    spec = importlib.util.spec_from_file_location("rookstride_ubuntu", tree / "reinstall/run.py")
    reinstall = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reinstall)
    return reinstall


def reinstall_review(plan):
    return {
        "token": plan["token"], "job": plan["job"], "ubuntu": plan["version"],
        "fingerprint": plan["fingerprint"], "diskBytes": plan["scope"]["disk_bytes"],
        "boot": plan["scope"]["boot"],
    }


def is_hex_id(value, length):
    return isinstance(value, str) and len(value) == length and re.fullmatch(r"[0-9a-f]+", value) is not None


def require_pair_for_reinstall(req):
    role = req["role"]
    if (role not in ("entry", "exit") or not is_hex_id(req["pair"], 32)
            or not is_hex_id(req["operation"], 32)):
        raise GuardError("Invalid Double VPN Ubuntu review.")
    with owned_file(PAIR_MANIFEST, 65536, private=True) as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise GuardError("The owned Double VPN manifest exceeds its size limit.")
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or manifest.get("version") != 2
            or manifest.get("bundle") != PAIR_RECIPE_DIGEST
            or manifest.get("resetting") or manifest.get("configured") is not True):
        raise Conflict("The owned Double VPN configuration could not be verified.")
    plan = manifest.get("plan")
    if not isinstance(plan, dict):
        raise Conflict("The owned Double VPN configuration could not be verified.")
    entry, exit_address = plan.get("server"), plan.get("exit_host")
    exit_protocol = plan.get("exit_protocol")
    if not isinstance(exit_protocol, str) or exit_protocol not in PAIR_EXIT_PORTS:
        raise Conflict("The owned Double VPN has an unsupported exit protocol.")
    expected = {
        "pair": req["pair"], "role": role, "server": entry, "exit_host": exit_address,
        "engine": "native-v2", "entry_protocol": "awg", "exit_protocol": exit_protocol,
        "vpn_port": 51820, "tunnel_port": PAIR_EXIT_PORTS[exit_protocol], "client_pool": "10.66.0.0/24",
        "test_ip": "10.249.255.254", "entry_address": "10.253.0.2/30",
        "exit_address": "10.253.0.1/30", "route_table": 51831,
    }
    node_address = entry if role == "entry" else exit_address
    if (not valid_address(entry) or not valid_address(exit_address) or entry == exit_address
            or any(type(plan.get(name)) is not int for name in ("vpn_port", "tunnel_port", "route_table"))
            or node_address != req["address"] or plan != expected):
        raise Conflict("The owned Double VPN does not match this reviewed server and role.")
    return hashlib.sha256(raw).hexdigest(), expected


def private_reinstall_plan():
    with owned_file(REINSTALL_STATE / "plan.json", 8192, private=True) as handle:
        raw = handle.read(8193)
    if len(raw) > 8192:
        raise GuardError("The Ubuntu review exceeds its size limit.")
    return json.loads(raw)


def verified_pair_recovery_recipe():
    """Verify the native installed recipe in pair_remote.py's bundle order."""
    digest = hashlib.sha256()
    remaining = MAX_PAIR_RECIPE_BYTES
    for folder in PAIR_RECIPE_FOLDERS:
        root = PAIR_RELEASE / folder
        require_secure_directory(root)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise GuardError("The owned Double VPN recipe has changed.")
            if "__pycache__" in path.parts or path.suffix == ".pyc" or path.is_dir():
                continue
            raw = read_owned(path, remaining)
            remaining -= len(raw)
            digest.update(path.relative_to(PAIR_RELEASE).as_posix().encode())
            digest.update(raw)
    if not hmac.compare_digest(digest.hexdigest(), PAIR_RECIPE_DIGEST):
        raise GuardError("The owned Double VPN recipe has changed.")


def recovery_snapshot_digest(snapshot):
    # The only per-export field is the outer timestamp. The native export
    # already strips transient metrics fields. Match pairArchiveDigest for
    # admitted native snapshots and reject ambiguous cross-language values.
    def valid(value):
        if type(value) is dict:
            return all(re.fullmatch(r"[ -~]+", key) and not key.isdigit() and valid(item)
                       for key, item in value.items())
        if type(value) is list:
            return all(valid(item) for item in value)
        if type(value) is int:
            return abs(value) <= (2**53 - 1)
        return value is None or type(value) in (str, bool)

    identity = {key: value for key, value in snapshot.items() if key != "created"}
    if not valid(identity):
        raise GuardError("The owned Double VPN recovery identity is invalid.")
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_pair_snapshot(plan, snapshot_digest):
    if not is_hex_id(snapshot_digest, 64):
        raise GuardError("Invalid Double VPN recovery identity.")
    verified_pair_recovery_recipe()
    # The caller already holds all three lifecycle locks. Invoke only export
    # through the verified helper without its CLI's second lock acquisition.
    source = "import sys,json;sys.path.insert(0,sys.argv[1]);import recovery;print(json.dumps(recovery.dispatch({'action':'export'})))"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-X", "pycache_prefix=/dev/null", "-c", source, str(PAIR_RELEASE / "server")],
        env=SAFE_ENV, cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=36, check=False,
    )
    if result.returncode or len(result.stdout) > MAX_PAIR_SNAPSHOT_BYTES:
        raise Conflict("The current Double VPN recovery identity could not be verified.")
    snapshot = json.loads(result.stdout)
    role = plan["role"]
    protocol = plan["entry_protocol" if role == "entry" else "exit_protocol"]
    endpoint = plan["server" if role == "entry" else "exit_host"]
    port = plan["vpn_port" if role == "entry" else "tunnel_port"]
    state = snapshot.get("state") if isinstance(snapshot, dict) else None
    if (not isinstance(snapshot, dict) or snapshot.get("schema") != 2
            or snapshot.get("adapter") != protocol + "-identity-v1"
            or snapshot.get("purpose") != "rookstride-owner-recovery-node"
            or snapshot.get("deployment") != plan["pair"] or snapshot.get("role") != role
            or snapshot.get("plan") != plan or not isinstance(state, dict) or state.get("protocol") != protocol
            or state.get("server") != endpoint or type(state.get("port")) is not int or state.get("port") != port
            or state.get("access_mode", None if protocol == "ikev2" else "profile") != "profile"):
        raise Conflict("The current Double VPN recovery identity does not match the reviewed role.")
    if not hmac.compare_digest(recovery_snapshot_digest(snapshot), snapshot_digest):
        raise PairSnapshotChanged("The Double VPN accounts, identity or filtering changed after the recovery archive was captured.")


def require_pair_reinstall_plan(reinstall, req, manifest, topology):
    plan = private_reinstall_plan()
    if (not isinstance(plan, dict) or not is_hex_id(req["job"], 32) or plan.get("job") != req["job"]
            or not isinstance(req["fingerprint"], str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", req["fingerprint"])
            or plan.get("fingerprint") != req["fingerprint"]
            or plan.get("paired_operation") != req["operation"]
            or plan.get("pair_manifest") != manifest or plan.get("version") not in SUPPORTED_LTS
            or ("ubuntu" in req and plan["version"] != req["ubuntu"])
            or not is_hex_id(plan.get("token"), 64)
            or not is_hex_id(plan.get("recovery_snapshot"), 64)
            or plan["expires"] <= time.time()
            or reinstall.scope_digest(plan["scope"]) != reinstall.scope_digest(reinstall.inspect())):
        raise Conflict("The paired Ubuntu review no longer matches this job or system disk.")
    require_current_pair_snapshot(topology, plan["recovery_snapshot"])
    return plan


def manage_pair_reinstall_review(req):
    files = bundle(req["files"], LIFECYCLE_PINNED)
    with exclusive_pair_reinstall(), tempfile.TemporaryDirectory(prefix="rookstride-pair-review-", dir="/run") as tmp:
        manifest, topology = require_pair_for_reinstall(req)
        tree = Path(tmp)
        stage_files(tree, files)
        reinstall = load_reinstall(tree)
        if req["action"] == "pairUbuntuPlan":
            return {"token": require_pair_reinstall_plan(reinstall, req, manifest, topology)["token"]}
        require_current_pair_snapshot(topology, req["snapshot"])
        reviewed = reinstall.plan({"version": req["ubuntu"], "paired_operation": req["operation"]})
        plan = private_reinstall_plan()
        if plan.get("job") != reviewed["job"] or plan.get("paired_operation") != req["operation"]:
            raise Conflict("The paired Ubuntu plan changed during review.")
        plan["pair_manifest"] = manifest
        plan["recovery_snapshot"] = req["snapshot"]
        reinstall.atomic(REINSTALL_STATE / "plan.json", plan)
        return {**reinstall_review(reviewed), "machine": reviewed["scope"]["machine"]}


def resume_reinstall(job=None):
    path = REINSTALL_STATE / "current.json"
    if not os.path.lexists(path):
        return None
    require_secure_directory(REINSTALL_STATE)
    current = json.loads(read_owned(path, 1024)).get("job")
    if not isinstance(current, str) or not re.fullmatch(r"[a-f0-9]{32}", current):
        raise GuardError("The recorded Ubuntu job cannot be verified.")
    if job is not None and current != job:
        return None
    folder = REINSTALL_STATE / current
    require_secure_directory(folder)
    result = json.loads(read_owned(folder / "status.json", 4096))
    if result.get("job") != current or result.get("state") not in ("preparing", "rebooting", "failed", "cancelled"):
        raise GuardError("The recorded Ubuntu job cannot be verified.")
    return result


def reinstall_status(result):
    return {
        "state": result["state"],
        "job": result["job"],
        "ubuntu": result["version"],
        "fingerprint": result["fingerprint"],
    }


def verified_reinstall_receipt(version, job=None):
    if not version:
        return False
    try:
        require_secure_directory(REINSTALL_RESULT.parent)
        with owned_file(REINSTALL_RESULT, 2048, private=True) as receipt:
            result = json.load(receipt)
        return (
            set(result) == {"job", "version", "state", "message"}
            and isinstance(result["job"], str)
            and re.fullmatch(r"[a-f0-9]{32}", result["job"])
            and (job is None or result["job"] == job)
            and result["version"] == version
            and result["state"] == "complete"
        )
    except (OSError, TypeError, ValueError):
        return False


def reinstall_bundle(encoded):
    if not isinstance(encoded, str) or len(encoded) > 620 * 1024:
        raise GuardError("The reinstall recipe archive is too large.")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(encoded, validate=True))) as archive:
            content = archive.read(2 * 1024**2 + 1)
        if len(content) > 2 * 1024**2:
            raise GuardError("The reinstall recipe archive is too large.")
        files = json.loads(content)
        if not isinstance(files, dict) or len(files) > 64:
            raise GuardError("Unexpected reinstall recipe archive.")
        data = {}
        digest = hashlib.sha256()
        for name in sorted(files):
            if (not name.startswith("reinstall/") or
                    any(part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._-]+", part) for part in name.split("/"))):
                raise GuardError("Unexpected reinstall recipe file.")
            value = base64.b64decode(files[name], validate=True)
            data[name] = value
            digest.update(name.encode() + b"\0" + value + b"\0")
        if digest.hexdigest() == REINSTALL_BUNDLE_DIGEST:
            return data
    except (OSError, EOFError, ValueError, TypeError):
        pass
    raise GuardError("The reinstall bundle does not match the reviewed recipe.")


def apply_reinstall(req):
    files = reinstall_bundle(req["files"])
    paired = req["action"] == "pairUbuntuApply"
    lock = exclusive_pair_reinstall if paired else exclusive_install
    with lock(), tempfile.TemporaryDirectory(prefix="rookstride-web-reinstall-", dir="/run") as tmp:
        if paired:
            manifest, topology = require_pair_for_reinstall(req)
        else:
            require_single_for_reinstall()
        require_secure_directory(REINSTALL_STATE)
        tree = Path(tmp)
        stage_files(tree, files)
        reinstall = load_reinstall(tree)
        if paired:
            plan = require_pair_reinstall_plan(reinstall, req, manifest, topology)
            if plan["token"] != req["token"] or req["confirmation"] != reinstall.CONFIRM:
                raise GuardError("The paired Ubuntu confirmation does not match the reviewed job.")
        else:
            plan = json.loads(read_owned(REINSTALL_STATE / "plan.json", 8192))
            if (plan.get("job") != req["job"] or plan.get("fingerprint") != req["fingerprint"]
                    or "paired_operation" in plan):
                raise GuardError("The reviewed Ubuntu plan changed.")
        result = reinstall.start({
            "token": req["token"], "confirmation": req["confirmation"],
            "password": req["password"],
        })
        return reinstall_status(result)


def dispatch(req, stream=None):
    if not isinstance(req, dict):
        raise GuardError("Invalid request.")
    action = req.get("action")
    base = {"action", "address"}
    accounts = base | {"files"}
    paired = accounts | PAIR_UBUNTU_FIELDS
    erase = {"job", "fingerprint", "token", "confirmation", "password"}
    expected = {"inspect": (base, {"action"}), "inspectPairNode": (base,), "install": (base | {"login", "vpnPassword", "files"},),
                "health": (base,), "filter": (accounts, accounts | {"level"}), "usage": (accounts,),
                "guests": (accounts,), "profile": (accounts, accounts | {"login"}),
                "grant": (accounts | {"login", "vpnPassword", "revision"},),
                "rotate": (accounts | {"login", "vpnPassword", "revision"},),
                "revoke": (accounts | {"login", "revision"},),
                "removeReview": (accounts,), "ubuntuCheck": (accounts,),
                "ubuntuReview": (accounts | {"ubuntu"},),
                "ubuntuApply": (accounts | erase,),
                "pairUbuntuReview": (paired | {"ubuntu", "snapshot"},),
                "pairUbuntuPlan": (paired | {"job", "fingerprint", "ubuntu"},),
                "pairUbuntuApply": (paired | erase,),
                "ubuntuStatus": (base | {"job"},),
                "ubuntuVerify": (base | {"job", "ubuntu"},),
                "removeApply": (accounts | {"token", "confirmation"},),
                "protocolStatus": (base,), "protocolUsers": (accounts,),
                "protocolFilter": (accounts, accounts | {"level"}, accounts | {"enabled"}),
                "protocolUsage": (accounts,),
                "protocolReview": (accounts | {"login"}, accounts | {"login", "method"}),
                "protocolApply": (accounts | {"login", "port"}, accounts | {"login", "method", "port"},
                                  accounts | {"login", "method", "port", "runtimeArchitecture"}),
                "protocolProfile": (accounts | {"login"},),
                "protocolGrant": (accounts | {"login", "revision"},),
                "protocolRevoke": (accounts | {"login", "revision"},),
                "protocolRemoveReview": (accounts,),
                "protocolRemoveApply": (accounts | {"token", "confirmation"},)}
    if not isinstance(action, str) or set(req) not in expected.get(action, ()):
        raise GuardError("Unknown action or fields.")
    if "runtimeArchitecture" in req and req["runtimeArchitecture"] not in ("x86_64", "aarch64"):
        raise GuardError("Unknown VPN runtime architecture.")
    if "address" in req and not valid_address(req["address"]):
        raise GuardError("A public IPv4 address is required.")
    version = eligible_version()
    if action == "ubuntuVerify":
        if not version or not verified_reinstall_receipt(req["ubuntu"], req["job"]):
            return {"state": "waiting"}
        machine_id = Path("/etc/machine-id").read_bytes().strip()
        if not re.fullmatch(rb"[a-f0-9]{32}", machine_id):
            return {"state": "waiting"}
        return {"state": "returned", "ubuntu": version}
    if not version:
        return {"state": "unsupported", "message": "Use a fresh Ubuntu 22.04, 24.04 or 26.04 LTS amd64 or arm64 VPS with root access and systemd."}
    if action == "ubuntuStatus":
        with exclusive_install(check_reinstall=False):
            job = resume_reinstall(req["job"])
            if job:
                return reinstall_status(job)
            plan_file = REINSTALL_STATE / "plan.json"
            if os.path.lexists(plan_file):
                require_secure_directory(REINSTALL_STATE)
                plan = json.loads(read_owned(plan_file, 8192))
                if plan.get("job") == req["job"] and plan["expires"] < time.time():
                    return reinstall_status({**plan, "state": "expired"})
            return {"state": "waiting"}
    job = resume_reinstall()
    if job and job["state"] in ("preparing", "rebooting"):
        if action == "inspect":
            return {"state": "occupied", "os": f"Ubuntu {version}"}
        raise Conflict("An Ubuntu reinstall is already in progress.")
    if action == "inspect":
        return {**inspect(req.get("address")), "os": f"Ubuntu {version}"}
    if action == "inspectPairNode":
        return {**inspect_pair_node(), "os": f"Ubuntu {version}"}
    if action == "install":
        return {**install(req), "os": f"Ubuntu {version}"}
    if action == "health":
        with exclusive_install():
            verified_instance(req["address"], require_active=False)
            services = unit_states()
            return {"vpn": services["strongswan-starter"], "filter": services["adguardhome"],
                    "resolver": services["unbound"], "firewall": services["single-vps-vpn-firewall"]}
    if action in ("removeReview", "removeApply", "ubuntuCheck", "ubuntuReview"):
        return manage_lifecycle(req)
    if action in ("pairUbuntuReview", "pairUbuntuPlan"):
        return manage_pair_reinstall_review(req)
    if action in ("ubuntuApply", "pairUbuntuApply"):
        return apply_reinstall(req)
    if action == "protocolStatus":
        return protocol_status(req["address"])
    if action.startswith("protocol"):
        return manage_protocol(req, stream)
    return manage_guests(req)


def main():
    os.umask(0o077)
    try:
        stream = sys.stdin.buffer
        raw = stream.readline(MAX_REINSTALL_REQUEST + 2)
        size = len(raw.removesuffix(b"\n"))
        if size > MAX_REINSTALL_REQUEST:
            raise GuardError("Request exceeds the size limit.")
        request = json.loads(raw)
        if size > MAX_REQUEST and (not isinstance(request, dict) or request.get("action") not in ("ubuntuApply", "pairUbuntuApply")):
            raise GuardError("Request exceeds the size limit.")
        has_archive = isinstance(request, dict) and "runtimeArchitecture" in request
        if not has_archive and stream.read(1):
            raise GuardError("The request contains unexpected additional data.")
        ssh_connection = os.environ.get("SSH_CONNECTION", "")
        os.environ.clear()
        os.environ.update(SAFE_ENV, SSH_CONNECTION=ssh_connection)
        # A browser disconnect must not signal an installer halfway through its plan.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        answer = dispatch(request, stream if has_archive else None)
    except RecipeFailure as exc:
        answer = {"state": "failed", "stage": str(exc)}
    except PairSnapshotChanged as exc:
        answer = {"state": "conflict", "reason": "pair-snapshot-changed", "message": str(exc)}
    except Conflict as exc:
        answer = {"state": "conflict", "message": str(exc)}
    except GuardError as exc:
        answer = {"state": "failed", "message": str(exc)}
    except Exception:
        answer = {"state": "failed", "message": "The gateway operation could not be verified. Inspect the server before retrying."}
    print(json.dumps(answer), flush=True)


if __name__ == "__main__":
    main()
