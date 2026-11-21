#!/bin/bash
set -euo pipefail
if [[ -n "${ROOK_DNS_ADDRESS:-}" ]]; then
  for transport in udp tcp; do
    iptables -t nat -A PREROUTING -i tun0 -p "$transport" --dport 53 -j DNAT --to-destination "$ROOK_DNS_ADDRESS:${ROOK_DNS_PORT:?}"
  done
  iptables -A FORWARD -i tun0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset
  iptables -A FORWARD -i tun0 -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable
fi
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if [[ -z "${ROOK_PAIR_ROUTE:-}" ]]; then
  iptables -t nat -A POSTROUTING -s 10.68.0.0/24 -o eth0 -j MASQUERADE
fi
ip6tables -P FORWARD DROP
exec openvpn --config /vpn/server.conf
