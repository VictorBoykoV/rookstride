#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

if [[ "${EUID}" -ne 0 ]]; then
  echo "This installer must run as root." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot identify the operating system." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" ]]; then
  echo "Supported operating systems: Ubuntu and Debian." >&2
  exit 1
fi

if systemctl is-active --quiet strongswan-starter 2>/dev/null && [[ "${ALLOW_REPLACE:-}" != "YES" ]]; then
  echo "An active strongSwan installation was found." >&2
  echo "This clean installer will not replace it. Use an exact recovery backup instead." >&2
  echo "Set ALLOW_REPLACE=YES only when replacement is intentional." >&2
  exit 1
fi

SERVER_ID="${SERVER_ID:-}"
VPN_USER="${VPN_USER:-}"
CLIENT_POOL="${CLIENT_POOL:-10.250.0.0/16}"
IPV6_SINK_POOL="${IPV6_SINK_POOL:-fd42:250::/64}"
DNS_SERVERS="${DNS_SERVERS:-10.253.0.1}"
ALT_IKE_PORT="${ALT_IKE_PORT:-}"
VPN_PASSWORD_FILE="${VPN_PASSWORD_FILE:-}"

if [[ -z "$SERVER_ID" ]]; then
  [[ -t 0 ]] || { echo "Set SERVER_ID for non-interactive installation." >&2; exit 1; }
  read -r -p "VPN server hostname or IPv4 address: " SERVER_ID
fi
if [[ -z "$VPN_USER" ]]; then
  [[ -t 0 ]] || { echo "Set VPN_USER for non-interactive installation." >&2; exit 1; }
  read -r -p "Initial VPN username: " VPN_USER
fi

[[ "$SERVER_ID" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "Invalid SERVER_ID." >&2; exit 1; }
[[ "$VPN_USER" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo "Invalid VPN_USER." >&2; exit 1; }
[[ "$CLIENT_POOL" =~ ^[0-9./]+$ ]] || { echo "Invalid CLIENT_POOL." >&2; exit 1; }
[[ "$IPV6_SINK_POOL" =~ ^[0-9a-fA-F:/]+$ ]] || { echo "Invalid IPV6_SINK_POOL." >&2; exit 1; }
if [[ -n "$ALT_IKE_PORT" ]]; then
  [[ "$ALT_IKE_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
    && (( ALT_IKE_PORT <= 65535 )) \
    && [[ "$ALT_IKE_PORT" != 500 && "$ALT_IKE_PORT" != 4500 ]] \
    || { echo "Invalid ALT_IKE_PORT." >&2; exit 1; }
fi

if [[ -n "$VPN_PASSWORD_FILE" ]]; then
  [[ -r "$VPN_PASSWORD_FILE" ]] || { echo "Cannot read VPN_PASSWORD_FILE." >&2; exit 1; }
  IFS= read -r VPN_PASSWORD < "$VPN_PASSWORD_FILE"
else
  [[ -t 0 ]] || { echo "Set VPN_PASSWORD_FILE for non-interactive installation." >&2; exit 1; }
  read -r -s -p "Initial VPN password: " VPN_PASSWORD
  printf '\n'
fi
[[ ${#VPN_PASSWORD} -ge 12 ]] || { echo "Use a VPN password of at least 12 characters." >&2; exit 1; }
[[ "$VPN_PASSWORD" != *$'\n'* && "$VPN_PASSWORD" != *$'\r'* ]] || { echo "The password must be one line." >&2; exit 1; }

UPLINK_INTERFACE="${UPLINK_INTERFACE:-$(ip -4 route show default | awk 'NR==1 {print $5}')}"
[[ "$UPLINK_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { echo "Invalid uplink interface." >&2; exit 1; }

echo "Installing strongSwan IKEv2/EAP components..."
apt-get update -qq
apt-get install -y -qq \
  iproute2 \
  iptables \
  libcharon-extra-plugins \
  libstrongswan-extra-plugins \
  strongswan \
  strongswan-pki

if [[ -e /etc/ipsec.conf || -e /etc/ipsec.secrets ]]; then
  install -d -m 700 /root/twohop-vpn-backups
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  tar -C / -czpf "/root/twohop-vpn-backups/pre-clean-install-$stamp.tar.gz" \
    etc/ipsec.conf etc/ipsec.secrets 2>/dev/null || true
  chmod 600 "/root/twohop-vpn-backups/pre-clean-install-$stamp.tar.gz" 2>/dev/null || true
fi

install -d -m 700 \
  /etc/twohop-vpn \
  /etc/ipsec.d/private \
  /etc/ipsec.d/certs \
  /etc/ipsec.d/cacerts \
  /root/twohop-vpn-ca \
  /root/twohop-vpn-client

umask 077
pki --gen --type rsa --size 4096 --outform pem > /root/twohop-vpn-ca/twohop-ca-key.pem
pki --self --ca --lifetime 3650 \
  --in /root/twohop-vpn-ca/twohop-ca-key.pem --type rsa \
  --dn "CN=Two-Hop VPN Root CA" --outform pem \
  > /etc/ipsec.d/cacerts/twohop-ca-cert.pem
pki --gen --type rsa --size 3072 --outform pem \
  > /etc/ipsec.d/private/twohop-server-key.pem
pki --pub --in /etc/ipsec.d/private/twohop-server-key.pem --type rsa \
  | pki --issue --lifetime 1825 \
      --cacert /etc/ipsec.d/cacerts/twohop-ca-cert.pem \
      --cakey /root/twohop-vpn-ca/twohop-ca-key.pem \
      --dn "CN=$SERVER_ID" --san "$SERVER_ID" \
      --flag serverAuth --flag ikeIntermediate --outform pem \
  > /etc/ipsec.d/certs/twohop-server-cert.pem
cp /etc/ipsec.d/cacerts/twohop-ca-cert.pem /root/twohop-vpn-client/twohop-ca-cert.pem
chmod 600 /root/twohop-vpn-ca/twohop-ca-key.pem /etc/ipsec.d/private/twohop-server-key.pem
chmod 644 /etc/ipsec.d/cacerts/twohop-ca-cert.pem /etc/ipsec.d/certs/twohop-server-cert.pem /root/twohop-vpn-client/twohop-ca-cert.pem

if [[ "$SERVER_ID" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
  IPSEC_ID="$SERVER_ID"
else
  IPSEC_ID="@$SERVER_ID"
fi

cat > /etc/ipsec.conf <<EOF
config setup
  strictcrlpolicy=no
  uniqueids=never

conn ikev2-vpn
  auto=add
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  rekey=no
  mobike=yes
  dpdaction=clear
  dpddelay=30s
  left=%any
  leftid=$IPSEC_ID
  leftauth=pubkey
  leftcert=twohop-server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0,::/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightsourceip=$CLIENT_POOL,$IPV6_SINK_POOL
  rightdns=$DNS_SERVERS
  rightsendcert=never
EOF

escaped_password="${VPN_PASSWORD//\\/\\\\}"
escaped_password="${escaped_password//\"/\\\"}"
cat > /etc/ipsec.secrets <<EOF
$SERVER_ID : RSA "twohop-server-key.pem"
$VPN_USER : EAP "$escaped_password"
EOF
chmod 600 /etc/ipsec.secrets
unset VPN_PASSWORD escaped_password

# A controller may record its exact partial installation for safe resume.
if [[ -n "${IKE_OWNER_HASH_FILE:-}" ]]; then
  [[ "$IKE_OWNER_HASH_FILE" == /etc/rookstride-pair/ike-files.sha256 ]] || { echo 'Invalid ownership checkpoint.' >&2; exit 1; }
  sha256sum /etc/ipsec.conf /etc/ipsec.secrets > "$IKE_OWNER_HASH_FILE"
  chmod 600 "$IKE_OWNER_HASH_FILE"
fi

cat > /etc/twohop-vpn/ikev2.env <<EOF
UPLINK_INTERFACE=$UPLINK_INTERFACE
CLIENT_POOL=$CLIENT_POOL
IPV6_SINK_POOL=$IPV6_SINK_POOL
ALT_IKE_PORT=$ALT_IKE_PORT
EOF
chmod 600 /etc/twohop-vpn/ikev2.env

install -m 700 scripts/remote/twohop-vpn-ikev2-firewall /usr/local/sbin/twohop-vpn-ikev2-firewall
cat > /etc/systemd/system/twohop-vpn-ikev2-firewall.service <<'EOF'
[Unit]
Description=Two-hop VPN IKEv2 firewall and direct fallback egress
After=network-online.target strongswan-starter.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/twohop-vpn-ikev2-firewall apply

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/sysctl.d/90-twohop-vpn-ikev2.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv6.conf.all.forwarding = 1
EOF

sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now strongswan-starter.service
systemctl restart strongswan-starter.service
systemctl enable --now twohop-vpn-ikev2-firewall.service

ipsec status >/dev/null
printf 'IKEv2/EAP server installed.\n'
printf 'Server: %s\n' "$SERVER_ID"
printf 'Username: %s\n' "$VPN_USER"
printf 'Client CA certificate: /root/twohop-vpn-client/twohop-ca-cert.pem\n'
