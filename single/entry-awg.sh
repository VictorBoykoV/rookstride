#!/bin/bash
set -euo pipefail
amneziawg-go -f rsawg0 &
worker=$!
trap 'kill "$worker" 2>/dev/null || true; wait "$worker" || true' TERM INT EXIT
for attempt in {1..100}; do [[ -S /var/run/amneziawg/rsawg0.sock ]] && break; sleep .1; done
[[ -S /var/run/amneziawg/rsawg0.sock ]] || { echo "VPN control socket did not become ready" >&2; exit 1; }
awg setconf rsawg0 /vpn/server.conf
if [[ -n "${ROOK_PAIR_ROUTE:-}" ]]; then ip address add 10.66.0.1/24 dev rsawg0; else ip address add 10.67.0.1/24 dev rsawg0; fi
ip -6 address add fd42:670::1/64 dev rsawg0
ip link set rsawg0 mtu 1280 up
if [[ -n "${ROOK_DNS_ADDRESS:-}" ]]; then
  for transport in udp tcp; do
    iptables -t nat -A PREROUTING -i rsawg0 -p "$transport" --dport 53 -j DNAT --to-destination "$ROOK_DNS_ADDRESS:${ROOK_DNS_PORT:?}"
  done
  # Android's automatic Private DNS must fall back to the in-tunnel resolver.
  iptables -A FORWARD -i rsawg0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset
  iptables -A FORWARD -i rsawg0 -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable
fi
iptables -A FORWARD -i rsawg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o rsawg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if [[ -z "${ROOK_PAIR_ROUTE:-}" ]]; then
  iptables -t nat -A POSTROUTING -s 10.67.0.0/24 -o eth0 -j MASQUERADE
fi
ip6tables -P FORWARD DROP
wait "$worker"
