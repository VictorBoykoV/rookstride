#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT"

python3 - <<'PY'
import ipaddress
import pathlib
import re
import sys

root = pathlib.Path(".")
text_files = []
for path in root.rglob("*"):
    if not path.is_file() or ".git" in path.parts:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    text_files.append((path, text))

banned = [
    "".join(("be", "get")),
    "".join(("b", "get")),
    "".join(("rus", "sia")),
    "".join(("ru", "ssian")),
    "".join(("RU", "_SSH_PASSWORD")),
    "".join(("US", "_SSH_PASSWORD")),
    ".".join(("109", "69", "19", "54")),
    ".".join(("80", "209", "241", "77")),
    "".join(map(chr, (116, 101, 97, 109, 118, 105, 99, 116, 111, 114))),
]

errors = []
for path, text in text_files:
    # The vendored metadata retains the original repository URL for license provenance.
    if path.as_posix() == "SOURCE.json":
        import json
        metadata = json.loads(text)
        origin = "https://github.com/VictorBoykoV/" + "".join(("be", "get")) + "-vpn-gateway"
        if metadata.get("origin") != origin:
            errors.append(f"{path}: unrecognized source origin")
        else:
            text = text.replace(origin, "https://github.com/example/upstream")
    folded = text.casefold()
    for value in banned:
        if value.casefold() in folded:
            errors.append(f"{path}: contains prohibited deployment-specific term")
    if re.search(r"[\u0400-\u04ff]", text):
        errors.append(f"{path}: contains Cyrillic text")

ipv4_re = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
for path, text in text_files:
    for match in ipv4_re.finditer(text):
        try:
            address = ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            continue
        if address.is_global:
            errors.append(f"{path}: contains non-example public IPv4 address")

link_re = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
for path, text in text_files:
    if path.suffix.lower() != ".md":
        continue
    for target in link_re.findall(text):
        target = target.strip().split("#", 1)[0]
        if not target or "://" in target or target.startswith(("mailto:", "data:")):
            continue
        candidate = (path.parent / target).resolve()
        if not candidate.exists():
            errors.append(f"{path}: missing local link target {target}")

if errors:
    print("\n".join(sorted(set(errors))), file=sys.stderr)
    raise SystemExit(1)
print(f"privacy_and_links=passed files={len(text_files)}")
PY

while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find . -type f -name '*.sh' -print0)
echo "shell_syntax=passed"

if python3 -c 'import yaml' >/dev/null 2>&1; then
  python3 - <<'PY'
import pathlib
import yaml
for path in pathlib.Path(".github/workflows").glob("*.y*ml"):
    yaml.safe_load(path.read_text(encoding="utf-8"))
PY
  echo "workflow_yaml=passed"
elif command -v ruby >/dev/null 2>&1; then
  ruby -e 'require "yaml"; Dir[".github/workflows/*.{yml,yaml}"].each { |f| YAML.parse_file(f) }'
  echo "workflow_yaml=passed"
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=Example VPN Test CA' \
  -keyout "$workdir/ca.key" -out "$workdir/ca.pem" >/dev/null 2>&1

SERVER_ID='vpn.example.net' \
VPN_USER='example-user' \
PROFILE_MTU='1280' \
VPN_PORT='443' \
CA_CERT_FILE="$workdir/ca.pem" \
OUTPUT_FILE="$workdir/test.sswan" \
bash scripts/generate-android-profile.sh >/dev/null

SERVER_ID='vpn.example.net' \
VPN_USER='example-user' \
CA_CERT_FILE="$workdir/ca.pem" \
OUTPUT_FILE="$workdir/test.mobileconfig" \
bash scripts/generate-apple-profile.sh >/dev/null

python3 - "$workdir/test.sswan" "$workdir/test.mobileconfig" <<'PY'
import json
import pathlib
import plistlib
import sys

android = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert android["remote"]["addr"] == "vpn.example.net"
assert android["local"]["eap_id"] == "example-user"
assert android["remote"]["port"] == 443
assert android["mtu"] == 1280
assert android["split-tunneling"] == {"block-ipv4": True, "block-ipv6": True}
assert "shared_secret" not in repr(android).lower()

with pathlib.Path(sys.argv[2]).open("rb") as handle:
    apple = plistlib.load(handle)
vpn = next(item for item in apple["PayloadContent"] if item["PayloadType"] == "com.apple.vpn.managed")
assert vpn["IKEv2"]["RemoteAddress"] == "vpn.example.net"
assert vpn["IKEv2"]["AuthName"] == "example-user"
assert vpn["IKEv2"]["IncludeAllNetworks"] == 1
assert vpn["IPv4"]["OverridePrimary"] == 1
assert vpn["IPv6"]["OverridePrimary"] == 1
assert "AuthPassword" not in vpn["IKEv2"]
print("generated_profiles=passed")
PY

echo "repository_validation=passed"
