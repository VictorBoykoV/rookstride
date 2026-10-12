#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for script in scripts/*.sh scripts/vpn-firewall; do bash -n "$script"; done
python3 - <<'PY'
import ast
from pathlib import Path
for path in Path('scripts').glob('*.py'):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
PY
python3 scripts/validate-inputs.py vpn.example.net 10.252.0.0/24 fd42:252::/64 10.254.0.1
if python3 scripts/validate-inputs.py vpn.example.net 10.252.0.0/24 fd42:252::/64 10.252.0.1 >/dev/null 2>&1; then
  echo 'Overlapping DNS/client pool was accepted.' >&2; exit 1
fi

temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
python3 scripts/render-adguard-config.py templates/AdGuardHome.yaml 10.254.0.1 \
  10.252.0.0/24 '$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$temp/adguard.yaml"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=Example VPN Test CA' -keyout "$temp/ca.key" -out "$temp/ca.pem" >/dev/null 2>&1
SERVER_ID=vpn.example.net VPN_USER=example-user PROFILE_MTU=1280 \
  CA_CERT_FILE="$temp/ca.pem" OUTPUT_FILE="$temp/client.sswan" \
  bash scripts/generate-android-profile.sh >/dev/null
SERVER_ID=vpn.example.net VPN_USER=example-user CA_CERT_FILE="$temp/ca.pem" \
  OUTPUT_FILE="$temp/client.mobileconfig" bash scripts/generate-apple-profile.sh >/dev/null
python3 - "$temp" <<'PY'
from pathlib import Path
import ipaddress
import json
import plistlib
import re
import sys

temp = Path(sys.argv[1])
config = (temp / "adguard.yaml").read_text()
assert "10.254.0.1:3000" in config
assert "10.252.0.0/24" in config
assert "__" not in config
assert "querylog:\n  enabled: false" in config
assert "aaaa_disabled: true" in config
assert "schema_version: 34" in config
android = json.loads((temp / "client.sswan").read_text())
assert android["remote"]["addr"] == "vpn.example.net"
assert android["remote"]["id"] == "vpn.example.net"
assert android["remote"]["cert"]
assert android["local"]["eap_id"] == "example-user"
assert android["mtu"] == 1280
assert android["split-tunneling"] == {"block-ipv4": True, "block-ipv6": True}
assert "shared_secret" not in repr(android).lower()
with (temp / "client.mobileconfig").open("rb") as handle:
    apple = plistlib.load(handle)
vpn = next(p for p in apple["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed")
assert vpn["IKEv2"]["RemoteAddress"] == "vpn.example.net"
assert vpn["IKEv2"]["AuthName"] == "example-user"
assert vpn["IKEv2"]["IncludeAllNetworks"] == 1
assert "AuthPassword" not in vpn["IKEv2"]

for path in Path(".").rglob("*"):
    if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
        continue
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        continue
    for match in re.finditer(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", text):
        try:
            address = ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            continue
        if address.is_global:
            raise SystemExit(f"Unexpected public IPv4 in {path}")
print("repository checks passed")
PY
