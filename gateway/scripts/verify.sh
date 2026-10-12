#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on the VPN server.' >&2; exit 1; }
source /etc/single-vps-vpn/network.env
for service in strongswan-starter unbound adguardhome single-vps-vpn-dns-address single-vps-vpn-firewall; do
  systemctl is-active --quiet "$service" || { echo "$service is not active" >&2; exit 1; }
done
# Services can be active before their sockets and connection definitions are ready.
# Consume full command output: grep -q plus pipefail can fail with SIGPIPE (141).
ready() {
  ip address show dev lo | grep -F "$DNS_IP/32" >/dev/null || return 1
  ss -tuln | grep -F "$DNS_IP:53" >/dev/null || return 1
  ss -tuln | grep -F "$DNS_IP:3000" >/dev/null || return 1
  ss -tuln | grep -F '127.0.0.1:5353' >/dev/null || return 1
  ipsec statusall | grep -F 'ikev2-vpn:' >/dev/null || return 1
  dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 example.com A | grep -E '^[0-9]+\.' >/dev/null || return 1
  dig +time=3 +tries=1 +short @"$DNS_IP" example.com A | grep -E '^[0-9]+\.' >/dev/null || return 1
}
healthy=false
for _ in {1..30}; do
  if ready; then healthy=true; break; fi
  sleep 1
done
[[ $healthy == true ]] || { echo 'VPN or DNS readiness check failed.' >&2; exit 1; }
blocked=false
for _ in {1..20}; do
  if [[ $(dig +time=3 +tries=1 +short @"$DNS_IP" doubleclick.net A) == 0.0.0.0 ]]; then
    blocked=true; break
  fi
  sleep 2
done
[[ $blocked == true ]] || { echo 'AdGuard filter is not blocking the test domain.' >&2; exit 1; }
echo 'Server-side VPN, DNS and ad-block checks passed.'
