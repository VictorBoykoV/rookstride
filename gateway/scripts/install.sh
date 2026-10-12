#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo 'Run this installer as root.' >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || {
  echo 'This release supports a fresh Ubuntu 24.04 VPS.' >&2; exit 1;
}
for path in /etc/ipsec.conf /etc/ipsec.secrets /etc/single-vps-vpn /var/lib/AdGuardHome /opt/AdGuardHome; do
  [[ ! -e $path ]] || { echo "Existing VPN/DNS configuration at $path; use a fresh VPS." >&2; exit 1; }
done
for service in strongswan-starter unbound adguardhome; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    echo "Existing $service service; use a fresh VPS." >&2; exit 1
  fi
done

SERVER_ID="${SERVER_ID:-}"
VPN_USER="${VPN_USER:-}"
CLIENT_POOL="${CLIENT_POOL:-10.252.0.0/24}"
IPV6_SINK_POOL="${IPV6_SINK_POOL:-fd42:252::/64}"
DNS_IP="${DNS_IP:-10.254.0.1}"
VPN_PASSWORD_FILE="${VPN_PASSWORD_FILE:-}"
[[ -n $SERVER_ID ]] || { [[ -t 0 ]] && read -r -p 'VPN hostname or public IPv4: ' SERVER_ID || exit 2; }
[[ -n $VPN_USER ]] || { [[ -t 0 ]] && read -r -p 'Initial VPN username: ' VPN_USER || exit 2; }
[[ $VPN_USER =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo 'Invalid VPN username.' >&2; exit 2; }
python3 "$ROOT_DIR/scripts/validate-inputs.py" "$SERVER_ID" "$CLIENT_POOL" "$IPV6_SINK_POOL" "$DNS_IP"

if [[ -n $VPN_PASSWORD_FILE ]]; then
  [[ -f $VPN_PASSWORD_FILE && -r $VPN_PASSWORD_FILE ]] || { echo 'VPN_PASSWORD_FILE is not readable.' >&2; exit 2; }
  [[ -z $(find "$VPN_PASSWORD_FILE" -prune -perm /077 -print) ]] || { echo 'VPN_PASSWORD_FILE must be mode 0600 or stricter.' >&2; exit 2; }
  IFS= read -r VPN_PASSWORD < "$VPN_PASSWORD_FILE" || [[ -n ${VPN_PASSWORD:-} ]]
else
  [[ -t 0 ]] || { echo 'Set VPN_PASSWORD_FILE for unattended installation.' >&2; exit 2; }
  read -r -s -p 'Initial VPN password (at least 16 characters): ' VPN_PASSWORD; printf '\n'
fi
[[ ${#VPN_PASSWORD} -ge 16 && $VPN_PASSWORD != *$'\r'* && $VPN_PASSWORD != *$'\n'* ]] || {
  echo 'Use a one-line VPN password of at least 16 characters.' >&2; exit 2;
}
UPLINK="$(ip -4 route show default | awk 'NR==1 {print $5}')"
[[ $UPLINK =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { echo 'Cannot identify the public network interface.' >&2; exit 2; }

apt-get update -qq
apt-get install -y -qq ca-certificates curl dnsutils iproute2 iptables \
  libcharon-extra-plugins libstrongswan-extra-plugins openssl python3-bcrypt \
  strongswan strongswan-pki unbound

install -d -m 700 /etc/single-vps-vpn /root/single-vps-vpn /etc/ipsec.d/private
install -d -m 755 /etc/ipsec.d/certs /etc/ipsec.d/cacerts /opt/AdGuardHome
umask 077
pki --gen --type rsa --size 4096 --outform pem > /root/single-vps-vpn/ca-key.pem
pki --self --ca --lifetime 3650 --in /root/single-vps-vpn/ca-key.pem --type rsa \
  --dn 'CN=Single VPS VPN Root CA' --outform pem > /etc/ipsec.d/cacerts/single-vps-ca.pem
pki --gen --type rsa --size 3072 --outform pem > /etc/ipsec.d/private/single-vps-server-key.pem
pki --pub --in /etc/ipsec.d/private/single-vps-server-key.pem --type rsa |
  pki --issue --lifetime 825 --cacert /etc/ipsec.d/cacerts/single-vps-ca.pem \
    --cakey /root/single-vps-vpn/ca-key.pem --dn "CN=$SERVER_ID" --san "$SERVER_ID" \
    --flag serverAuth --flag ikeIntermediate --outform pem \
    > /etc/ipsec.d/certs/single-vps-server-cert.pem
chmod 644 /etc/ipsec.d/cacerts/single-vps-ca.pem /etc/ipsec.d/certs/single-vps-server-cert.pem
cp /etc/ipsec.d/cacerts/single-vps-ca.pem /root/single-vps-vpn/ca.pem

IPSEC_ID="$SERVER_ID"
[[ $SERVER_ID =~ ^[0-9]+(\.[0-9]+){3}$ ]] || IPSEC_ID="@$SERVER_ID"
cat > /etc/ipsec.conf <<EOF
config setup
  uniqueids=never

conn ikev2-vpn
  auto=add
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  mobike=yes
  rekey=no
  dpdaction=clear
  dpddelay=30s
  left=%any
  leftid=$IPSEC_ID
  leftauth=pubkey
  leftcert=single-vps-server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0,::/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightsourceip=$CLIENT_POOL,$IPV6_SINK_POOL
  rightdns=$DNS_IP
  rightsendcert=never
EOF
escaped="${VPN_PASSWORD//\\/\\\\}"
escaped="${escaped//\"/\\\"}"
printf '%s : RSA "single-vps-server-key.pem"\n%s : EAP "%s"\n' \
  "$SERVER_ID" "$VPN_USER" "$escaped" > /etc/ipsec.secrets
chmod 600 /etc/ipsec.secrets
unset VPN_PASSWORD escaped

cat > /etc/single-vps-vpn/network.env <<EOF
UPLINK=$UPLINK
CLIENT_POOL=$CLIENT_POOL
IPV6_SINK_POOL=$IPV6_SINK_POOL
DNS_IP=$DNS_IP
EOF
chmod 600 /etc/single-vps-vpn/network.env
install -m 700 "$ROOT_DIR/scripts/vpn-firewall" /usr/local/sbin/single-vps-vpn-firewall
install -m 644 "$ROOT_DIR/systemd/single-vps-vpn-firewall.service" /etc/systemd/system/
cat > /etc/sysctl.d/90-single-vps-vpn.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
EOF

cat > /etc/systemd/system/single-vps-vpn-dns-address.service <<EOF
[Unit]
Description=Private DNS address for VPN clients
After=network.target
Before=adguardhome.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip address add $DNS_IP/32 dev lo
ExecStop=/usr/sbin/ip address del $DNS_IP/32 dev lo

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/unbound/unbound.conf.d/single-vps-vpn.conf <<'EOF'
server:
    interface: 127.0.0.1
    port: 5353
    access-control: 127.0.0.0/8 allow
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
unbound-checkconf

case "$(uname -m)" in
  x86_64) arch=amd64; checksum=c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f ;;
  aarch64) arch=arm64; checksum=3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae ;;
  *) echo 'AdGuard Home is packaged here for x86_64 and aarch64 only.' >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
archive="AdGuardHome_linux_${arch}.tar.gz"
curl -fL --retry 3 -o "$tmp/$archive" \
  "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.79/$archive"
printf '%s  %s\n' "$checksum" "$tmp/$archive" | sha256sum -c -
# Verified official archives may prefix member names with ./; extract in the private temp directory.
tar -xzf "$tmp/$archive" -C "$tmp"
install -m 755 "$tmp/AdGuardHome/AdGuardHome" /opt/AdGuardHome/AdGuardHome
id adguard >/dev/null 2>&1 || useradd --system --home /var/lib/AdGuardHome --shell /usr/sbin/nologin adguard
install -d -o adguard -g adguard -m 700 /var/lib/AdGuardHome /var/lib/AdGuardHome/work
admin_password="$(openssl rand -hex 24)"
admin_hash="$(printf %s "$admin_password" | python3 -c 'import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.buffer.read(),bcrypt.gensalt()).decode())')"
printf 'Dashboard: http://%s:3000\nUsername: admin\nPassword: %s\n' "$DNS_IP" "$admin_password" \
  > /root/single-vps-vpn/adguard-login.txt
chmod 600 /root/single-vps-vpn/adguard-login.txt
unset admin_password
python3 "$ROOT_DIR/scripts/render-adguard-config.py" \
  "$ROOT_DIR/templates/AdGuardHome.yaml" "$DNS_IP" "$CLIENT_POOL" "$admin_hash" \
  /var/lib/AdGuardHome/AdGuardHome.yaml
unset admin_hash
chown adguard:adguard /var/lib/AdGuardHome/AdGuardHome.yaml
chmod 600 /var/lib/AdGuardHome/AdGuardHome.yaml
install -m 644 "$ROOT_DIR/systemd/adguardhome.service" /etc/systemd/system/
/opt/AdGuardHome/AdGuardHome --check-config -c /var/lib/AdGuardHome/AdGuardHome.yaml \
  -w /var/lib/AdGuardHome/work

sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now single-vps-vpn-dns-address.service
systemctl enable --now unbound.service
systemctl restart unbound.service
systemctl enable --now adguardhome.service
systemctl enable --now strongswan-starter.service
systemctl restart strongswan-starter.service
systemctl enable --now single-vps-vpn-firewall.service
"$ROOT_DIR/scripts/verify.sh"
printf '\nInstalled. CA certificate: /root/single-vps-vpn/ca.pem\n'
printf 'AdGuard login: /root/single-vps-vpn/adguard-login.txt\n'
printf 'Run the client test in docs/CLIENTS.md before relying on the VPN.\n'
