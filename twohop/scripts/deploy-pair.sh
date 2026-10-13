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
TUNNEL_ENTRY_ADDRESS="${TUNNEL_ENTRY_ADDRESS:-10.253.0.2/30}"
TUNNEL_EXIT_ADDRESS="${TUNNEL_EXIT_ADDRESS:-10.253.0.1/30}"
TUNNEL_PORT="${TUNNEL_PORT:-443}"
ROUTE_TABLE="${ROUTE_TABLE:-51831}"
ACTIVATE="${ACTIVATE:-false}"
ROTATE_TUNNEL_KEYS="${ROTATE_TUNNEL_KEYS:-false}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

for command in ssh sshpass scp wg python3; do
  command -v "$command" >/dev/null || { echo "Missing local command: $command" >&2; exit 1; }
done

python3 - "$ENTRY_HOST" "$EXIT_HOST" "$SSH_USER" "$CLIENT_POOL" "$TEST_SOURCE_IP" \
  "$TUNNEL_ENTRY_ADDRESS" "$TUNNEL_EXIT_ADDRESS" "$TUNNEL_PORT" "$ROUTE_TABLE" <<'PY'
import ipaddress
import re
import sys

entry_host, exit_host, ssh_user, client_pool, test_ip, entry_addr, exit_addr, port, table = sys.argv[1:]
host_re = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
for label, value in (("ENTRY_HOST", entry_host), ("EXIT_HOST", exit_host)):
    if not host_re.fullmatch(value):
        raise SystemExit(f"Invalid {label}")
if entry_host == exit_host:
    raise SystemExit("ENTRY_HOST and EXIT_HOST must be different")
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", ssh_user):
    raise SystemExit("Invalid SSH_USER")
pool = ipaddress.ip_network(client_pool, strict=True)
test = ipaddress.ip_address(test_ip)
entry = ipaddress.ip_interface(entry_addr)
exit = ipaddress.ip_interface(exit_addr)
if pool.version != 4 or test.version != 4 or entry.version != 4 or exit.version != 4:
    raise SystemExit("This release requires IPv4 tunnel and client addresses")
if entry.network != exit.network or entry.ip == exit.ip:
    raise SystemExit("Tunnel addresses must be different hosts in the same subnet")
if pool.overlaps(entry.network) or test in pool or test in entry.network:
    raise SystemExit("Client, test, and tunnel address ranges must not overlap")
if not (1 <= int(port) <= 65535) or not (1 <= int(table) <= 2**31 - 1):
    raise SystemExit("Invalid tunnel port or route table")
PY

[[ "$ACTIVATE" == true || "$ACTIVATE" == false ]] || { echo "ACTIVATE must be true or false" >&2; exit 1; }
[[ "$ROTATE_TUNNEL_KEYS" == true || "$ROTATE_TUNNEL_KEYS" == false ]] || { echo "ROTATE_TUNNEL_KEYS must be true or false" >&2; exit 1; }

if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$ENTRY_SSH_PASSWORD"
  echo "::add-mask::$EXIT_SSH_PASSWORD"
fi

TUNNEL_ENTRY_IP="${TUNNEL_ENTRY_ADDRESS%/*}"
TUNNEL_EXIT_IP="${TUNNEL_EXIT_ADDRESS%/*}"

remote() {
  local host="$1" password="$2"
  shift 2
  SSHPASS="$password" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
    "$SSH_USER@$host" "$@"
}

upload_bundle() {
  local host="$1" password="$2"
  tar -C "$REPO_ROOT" --exclude='.git' --exclude='audit-reports' --exclude='reports' -czf - . \
    | SSHPASS="$password" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
        "$SSH_USER@$host" 'install -d -m 700 /opt/twohop-vpn && tar -xzf - -C /opt/twohop-vpn'
}

rollback_on_error() {
  local status=$?
  trap - ERR
  remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
    'cd /opt/twohop-vpn && bash scripts/activate-ingress.sh quiesce' || true
  exit "$status"
}
trap rollback_on_error ERR

upload_bundle "$EXIT_HOST" "$EXIT_SSH_PASSWORD"
upload_bundle "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD"
remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
  'cd /opt/twohop-vpn && bash scripts/backup-existing-vpn.sh'

install_node() {
  local host="$1" password="$2" role="$3" rc=0 ready=false
  set +e
  remote "$host" "$password" "cd /opt/twohop-vpn && bash scripts/install-amneziawg.sh '$role'"
  rc=$?
  set -e
  if [[ "$rc" -eq 194 ]]; then
    echo "Rebooting the $role node to load its supported kernel..."
    remote "$host" "$password" 'nohup sh -c "sleep 2; systemctl reboot" >/dev/null 2>&1 &' || true
    sleep 10
    for _ in {1..90}; do
      if remote "$host" "$password" 'test -d /proc/1' >/dev/null 2>&1; then
        ready=true
        break
      fi
      sleep 5
    done
    [[ "$ready" == true ]] || { echo "$role node did not return after reboot" >&2; return 1; }
    remote "$host" "$password" "cd /opt/twohop-vpn && bash scripts/install-amneziawg.sh '$role'"
  elif [[ "$rc" -ne 0 ]]; then
    return "$rc"
  fi
}

install_node "$EXIT_HOST" "$EXIT_SSH_PASSWORD" egress
install_node "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" ingress

reuse=false
if [[ "$ROTATE_TUNNEL_KEYS" != true ]] \
  && remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" 'test -s /etc/amnezia/amneziawg/awg-exit.conf' \
  && remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" 'test -s /etc/amnezia/amneziawg/awg-exit.conf'; then
  reuse=true
fi

if [[ "$reuse" != true ]]; then
  workdir="$(mktemp -d)"
  trap 'rm -rf "$workdir"' EXIT
  umask 077
  exit_private="$(wg genkey)"
  exit_public="$(printf '%s' "$exit_private" | wg pubkey)"
  entry_private="$(wg genkey)"
  entry_public="$(printf '%s' "$entry_private" | wg pubkey)"
  psk="$(wg genpsk)"
  header_key="$(wg genkey)"
  mapfile -t headers < <(shuf -i 100000000-2000000000 -n 4)
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    for value in "$exit_private" "$entry_private" "$psk" "$header_key"; do echo "::add-mask::$value"; done
  fi

  cat > "$workdir/exit.conf" <<EOF
[Interface]
Address = $TUNNEL_EXIT_ADDRESS
MTU = 1280
Table = off
ListenPort = $TUNNEL_PORT
PrivateKey = $exit_private
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = ${headers[0]}
H2 = ${headers[1]}
H3 = ${headers[2]}
H4 = ${headers[3]}
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
HeaderProtectionKey = $header_key
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = $entry_public
PresharedKey = $psk
AllowedIPs = $TUNNEL_ENTRY_IP/32, $CLIENT_POOL, $TEST_SOURCE_IP/32
EOF

  cat > "$workdir/entry.conf" <<EOF
[Interface]
Address = $TUNNEL_ENTRY_ADDRESS
MTU = 1280
Table = off
PrivateKey = $entry_private
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = ${headers[0]}
H2 = ${headers[1]}
H3 = ${headers[2]}
H4 = ${headers[3]}
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
HeaderProtectionKey = $header_key
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = $exit_public
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0
Endpoint = $EXIT_HOST:$TUNNEL_PORT
PersistentKeepalive = 25
EOF

  SSHPASS="$EXIT_SSH_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=accept-new \
    "$workdir/exit.conf" "$SSH_USER@$EXIT_HOST:/tmp/awg-exit.conf"
  SSHPASS="$ENTRY_SSH_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=accept-new \
    "$workdir/entry.conf" "$SSH_USER@$ENTRY_HOST:/tmp/awg-exit.conf"
  exit_config=/tmp/awg-exit.conf
  entry_config=/tmp/awg-exit.conf
else
  echo "Reusing the existing tunnel key pair."
  exit_config=/etc/amnezia/amneziawg/awg-exit.conf
  entry_config=/etc/amnezia/amneziawg/awg-exit.conf
fi

remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" \
  "cd /opt/twohop-vpn && CLIENT_POOL='$CLIENT_POOL' TEST_SOURCE_IP='$TEST_SOURCE_IP' TUNNEL_EXIT_IP='$TUNNEL_EXIT_IP' TUNNEL_PORT='$TUNNEL_PORT' bash scripts/apply-egress.sh '$exit_config'"
remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
  "cd /opt/twohop-vpn && CLIENT_POOL='$CLIENT_POOL' TEST_SOURCE_IP='$TEST_SOURCE_IP' ROUTE_TABLE='$ROUTE_TABLE' bash scripts/stage-ingress.sh '$entry_config'"

exit_public_ip="$(remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" \
  "curl -4 --connect-timeout 10 --max-time 20 -fsS https://api.ipify.org")"
python3 - "$exit_public_ip" <<'PY'
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
  "cd /opt/twohop-vpn && EXPECTED_EXIT_IP='$exit_public_ip' TEST_SOURCE_IP='$TEST_SOURCE_IP' bash scripts/verify-staged-egress.sh"

if [[ "$ACTIVATE" == true ]]; then
  remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
    'cd /opt/twohop-vpn && bash scripts/activate-ingress.sh apply'
  remote "$ENTRY_HOST" "$ENTRY_SSH_PASSWORD" \
    "ip rule show | grep -F 'from $CLIENT_POOL lookup $ROUTE_TABLE'; ip route show table '$ROUTE_TABLE'; WG_HIDE_KEYS=always awg show awg-exit"
fi

remote "$EXIT_HOST" "$EXIT_SSH_PASSWORD" \
  "test \"\$(curl -4 --connect-timeout 10 --max-time 20 -fsS https://api.ipify.org)\" = '$exit_public_ip'; WG_HIDE_KEYS=always awg show awg-exit"
trap - ERR EXIT
if [[ -n "${workdir:-}" ]]; then
  rm -rf "$workdir"
fi
echo "Two-hop VPN deployment completed successfully. Exit IPv4: $exit_public_ip"
