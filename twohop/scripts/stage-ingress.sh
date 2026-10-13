#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

CONFIG_SOURCE="${1:-/tmp/awg-exit.conf}"
[[ -s "$CONFIG_SOURCE" ]] || { echo "Missing tunnel configuration: $CONFIG_SOURCE" >&2; exit 1; }

AWG_INTERFACE=awg-exit
CLIENT_POOL="${CLIENT_POOL:-10.250.0.0/16}"
TEST_SOURCE_IP="${TEST_SOURCE_IP:-10.249.255.254}"
ROUTE_TABLE="${ROUTE_TABLE:-51831}"

[[ "$ROUTE_TABLE" =~ ^[0-9]+$ ]] || { echo "Invalid route table" >&2; exit 1; }

install -d -m 700 /etc/twohop-vpn /etc/amnezia/amneziawg
if [[ "$CONFIG_SOURCE" -ef /etc/amnezia/amneziawg/awg-exit.conf ]]; then
  chmod 600 /etc/amnezia/amneziawg/awg-exit.conf
else
  install -m 600 "$CONFIG_SOURCE" /etc/amnezia/amneziawg/awg-exit.conf
fi
install -m 700 scripts/remote/twohop-vpn-entry-routing /usr/local/sbin/twohop-vpn-entry-routing

cat > /etc/twohop-vpn/entry.env <<EOF
AWG_INTERFACE=$AWG_INTERFACE
CLIENT_POOL=$CLIENT_POOL
TEST_SOURCE_IP=$TEST_SOURCE_IP
ROUTE_TABLE=$ROUTE_TABLE
EOF
chmod 600 /etc/twohop-vpn/entry.env

cat > /etc/sysctl.d/90-twohop-vpn-entry.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sysctl --system >/dev/null

cat > /etc/systemd/system/twohop-vpn-entry-routing.service <<'EOF'
[Unit]
Description=Two-hop VPN fail-closed entry routing
After=network-online.target awg-quick@awg-exit.service
Wants=network-online.target awg-quick@awg-exit.service
Before=strongswan-starter.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/twohop-vpn-entry-routing boot

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now awg-quick@awg-exit.service
/usr/local/sbin/twohop-vpn-entry-routing stage

awg show awg-exit >/dev/null
