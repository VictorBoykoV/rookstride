#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_EXIT_IP="${EXPECTED_EXIT_IP:?Set EXPECTED_EXIT_IP}"
TEST_SOURCE_IP="${TEST_SOURCE_IP:-10.249.255.254}"

cleanup() {
  /usr/local/sbin/twohop-vpn-entry-routing test-off >/dev/null 2>&1 || true
  ip address del "$TEST_SOURCE_IP/32" dev lo >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip address add "$TEST_SOURCE_IP/32" dev lo 2>/dev/null || true
/usr/local/sbin/twohop-vpn-entry-routing test-on

for attempt in $(seq 1 12); do
  handshake="$(awg show awg-exit latest-handshakes | awk 'NR==1 {print $2}')"
  now="$(date +%s)"
  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0 && now - handshake < 180)); then
    break
  fi
  sleep 5
done

handshake="$(awg show awg-exit latest-handshakes | awk 'NR==1 {print $2}')"
now="$(date +%s)"
[[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0 && now - handshake < 180)) || {
  echo "No recent AmneziaWG handshake." >&2
  exit 1
}

actual_ip="$(curl -4 --interface "$TEST_SOURCE_IP" --retry 2 --retry-delay 1 --retry-all-errors --connect-timeout 10 --max-time 20 -fsS https://api.ipify.org)" || { echo "Staged HTTPS exit check failed." >&2; exit 1; }
if [[ "$actual_ip" != "$EXPECTED_EXIT_IP" ]]; then
  echo "Unexpected staged egress IP: $actual_ip" >&2
  exit 1
fi

# TEST-NET-2 is deliberately unreachable. Success proves that the exit
# firewall redirected this conventional DNS request to its local resolver.
answers=''
for attempt in $(seq 1 6); do
  answers="$(dig +time=5 +tries=1 +short -b "$TEST_SOURCE_IP" @198.51.100.1 example.com A)" || true
  if printf '%s\n' "$answers" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    break
  fi
  sleep 2
done
printf '%s\n' "$answers" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'Exit DNS returned no IPv4 answer after startup retries.' >&2; exit 1; }

printf 'staged_exit_ipv4=%s\n' "$actual_ip"
printf 'amneziawg_handshake_age_seconds=%s\n' "$((now - handshake))"
printf 'dns_via_exit=ok\n'
