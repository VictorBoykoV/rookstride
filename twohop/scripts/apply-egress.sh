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
TUNNEL_EXIT_IP="${TUNNEL_EXIT_IP:-10.253.0.1}"
TUNNEL_PORT="${TUNNEL_PORT:-443}"
UPLINK_INTERFACE="${UPLINK_INTERFACE:-$(ip -4 route show default | awk 'NR==1 {print $5}')}"

[[ "$UPLINK_INTERFACE" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || { echo "Invalid uplink interface" >&2; exit 1; }
[[ "$TUNNEL_PORT" =~ ^[0-9]+$ ]] && ((TUNNEL_PORT >= 1 && TUNNEL_PORT <= 65535)) || { echo "Invalid tunnel port" >&2; exit 1; }

install -d -m 700 /etc/twohop-vpn /etc/amnezia/amneziawg
if [[ "$CONFIG_SOURCE" -ef /etc/amnezia/amneziawg/awg-exit.conf ]]; then
  chmod 600 /etc/amnezia/amneziawg/awg-exit.conf
else
  install -m 600 "$CONFIG_SOURCE" /etc/amnezia/amneziawg/awg-exit.conf
fi
install -m 700 scripts/remote/twohop-vpn-exit-firewall /usr/local/sbin/twohop-vpn-exit-firewall

cat > /etc/twohop-vpn/exit.env <<EOF
AWG_INTERFACE=$AWG_INTERFACE
UPLINK_INTERFACE=$UPLINK_INTERFACE
CLIENT_POOL=$CLIENT_POOL
TEST_SOURCE_IP=$TEST_SOURCE_IP
TUNNEL_EXIT_IP=$TUNNEL_EXIT_IP
TUNNEL_PORT=$TUNNEL_PORT
EOF
chmod 600 /etc/twohop-vpn/exit.env

cat > /etc/sysctl.d/90-twohop-vpn-exit.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.forwarding = 0
EOF
sysctl --system >/dev/null

if [[ "${MANAGE_UNBOUND:-YES}" == YES ]]; then
cat > /etc/unbound/unbound.conf.d/twohop-vpn.conf <<EOF
server:
    interface: $TUNNEL_EXIT_IP
    port: 53
    access-control: $CLIENT_POOL allow
    access-control: $TEST_SOURCE_IP/32 allow
    access-control: 0.0.0.0/0 refuse
    do-ip4: yes
    do-ip6: no
    prefer-ip6: no
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    qname-minimisation: yes
    prefetch: yes
EOF

mkdir -p /etc/systemd/system/unbound.service.d
cat > /etc/systemd/system/unbound.service.d/twohop-vpn.conf <<'EOF'
[Unit]
After=awg-quick@awg-exit.service
Requires=awg-quick@awg-exit.service
EOF

fi

cat > /etc/systemd/system/twohop-vpn-exit-firewall.service <<'EOF'
[Unit]
Description=Two-hop VPN exit routing and firewall
After=network-online.target docker.service awg-quick@awg-exit.service
Wants=network-online.target
Requires=awg-quick@awg-exit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/twohop-vpn-exit-firewall apply

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now awg-quick@awg-exit.service
systemctl enable --now twohop-vpn-exit-firewall.service
if [[ "${MANAGE_UNBOUND:-YES}" == YES ]]; then
  systemctl enable unbound.service
  systemctl restart unbound.service
fi

awg show awg-exit >/dev/null
ss -H -lun | grep -Eq "(^|:)${TUNNEL_PORT}[[:space:]]"
if [[ "${MANAGE_UNBOUND:-YES}" == YES ]]; then
  ss -H -lnut | grep -Eq "${TUNNEL_EXIT_IP}:53[[:space:]]"
fi
