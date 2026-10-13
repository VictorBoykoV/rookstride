#!/usr/bin/env bash
set -Eeuo pipefail

: "${ENTRY_HOST:?Set ENTRY_HOST}"
: "${EXIT_HOST:?Set EXIT_HOST}"

load_password() {
  local value_name="$1" file_name="$2" file value
  [[ -n "${!value_name:-}" ]] && return
  file="${!file_name:-}"
  [[ -n "$file" && -r "$file" ]] || {
    echo "Set $value_name or $file_name to a readable root-only file." >&2
    exit 1
  }
  if [[ -n "$(find "$file" -prune -perm /077 -print 2>/dev/null)" ]]; then
    echo "$file_name must not be accessible by group or other users." >&2
    exit 1
  fi
  IFS= read -r value < "$file"
  [[ -n "$value" ]] || { echo "$file_name is empty." >&2; exit 1; }
  printf -v "$value_name" '%s' "$value"
  export "$value_name"
}

load_password ENTRY_SSH_PASSWORD ENTRY_SSH_PASSWORD_FILE
load_password EXIT_SSH_PASSWORD EXIT_SSH_PASSWORD_FILE

SSH_USER="${SSH_USER:-root}"
CLIENT_POOL="${CLIENT_POOL:-10.250.0.0/16}"
TEST_SOURCE_IP="${TEST_SOURCE_IP:-10.249.255.254}"
ROUTE_TABLE="${ROUTE_TABLE:-51831}"

for command in ssh sshpass python3; do
  command -v "$command" >/dev/null || { echo "Missing local command: $command" >&2; exit 1; }
done

python3 - "$ENTRY_HOST" "$EXIT_HOST" "$SSH_USER" "$CLIENT_POOL" "$TEST_SOURCE_IP" "$ROUTE_TABLE" <<'PY'
import ipaddress
import re
import sys

entry_host, exit_host, ssh_user, client_pool, test_ip, table = sys.argv[1:]
host_re = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
user_re = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
for label, value in (("ENTRY_HOST", entry_host), ("EXIT_HOST", exit_host)):
    if not host_re.fullmatch(value):
        raise SystemExit(f"Invalid {label}")
if entry_host == exit_host:
    raise SystemExit("ENTRY_HOST and EXIT_HOST must be different")
if not user_re.fullmatch(ssh_user):
    raise SystemExit("Invalid SSH_USER")
pool = ipaddress.ip_network(client_pool, strict=True)
test = ipaddress.ip_address(test_ip)
if pool.version != 4 or test.version != 4 or test in pool:
    raise SystemExit("Invalid or overlapping CLIENT_POOL and TEST_SOURCE_IP")
if not table.isdigit() or not (1 <= int(table) <= 2**31 - 1):
    raise SystemExit("Invalid ROUTE_TABLE")
PY

if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$ENTRY_SSH_PASSWORD"
  echo "::add-mask::$EXIT_SSH_PASSWORD"
fi

remote() {
  local host="$1" password="$2"
  shift 2
  SSHPASS="$password" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
    "$SSH_USER@$host" "$@"
}

exit_public_ip="$(remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" \
  'curl -4 --connect-timeout 10 --max-time 20 -fsS https://api.ipify.org')"
python3 - "$exit_public_ip" <<'PY'
import ipaddress
import sys
ipaddress.IPv4Address(sys.argv[1])
PY

remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" \
  "set -Eeuo pipefail
   systemctl is-active --quiet awg-quick@awg-exit.service
   systemctl is-active --quiet twohop-vpn-exit-firewall.service
   systemctl is-active --quiet unbound.service
   iptables -t filter -S TWOHOP_EXIT_FWD >/dev/null
   iptables -t nat -S TWOHOP_DNS >/dev/null
   iptables -t nat -S TWOHOP_SNAT >/dev/null
   ip route show '$CLIENT_POOL' | grep -F 'dev awg-exit' >/dev/null
   WG_HIDE_KEYS=always awg show awg-exit >/dev/null"

remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
  "set -Eeuo pipefail
   systemctl is-active --quiet strongswan-starter.service
   systemctl is-active --quiet awg-quick@awg-exit.service
   systemctl is-active --quiet twohop-vpn-entry-routing.service
   ip rule show | grep -F 'from $CLIENT_POOL lookup $ROUTE_TABLE' >/dev/null
   ip route show table '$ROUTE_TABLE' | grep -F 'default dev awg-exit' >/dev/null
   ip route show table '$ROUTE_TABLE' | grep -F 'blackhole default' >/dev/null
   iptables -t filter -S TWOHOP_ENTRY >/dev/null
   cd /opt/twohop-vpn
   EXPECTED_EXIT_IP='$exit_public_ip' TEST_SOURCE_IP='$TEST_SOURCE_IP' bash scripts/verify-staged-egress.sh"

printf 'verification=passed\n'
printf 'exit_ipv4=%s\n' "$exit_public_ip"
