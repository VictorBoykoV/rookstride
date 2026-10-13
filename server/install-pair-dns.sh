#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 && -f /etc/rookstride-pair/manifest.json ]] || { echo 'Owned pair required.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
ROOT_DIR="$(cd "$(dirname "$0")/../gateway" && pwd)"
DNS_IP="${TUNNEL_EXIT_IP:?}"
: "${CLIENT_POOL:?}" "${TEST_SOURCE_IP:?}"
apt-get -o DPkg::Lock::Timeout=1200 install -y -qq curl ca-certificates openssl python3-bcrypt
install -d -m 700 /root/rookstride-pair
install -d -m 755 /opt/AdGuardHome
cat > /etc/unbound/unbound.conf.d/twohop-vpn.conf <<'EOF'
server:
    interface: 127.0.0.1
    port: 5353
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    do-ip4: yes
    do-ip6: no
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    qname-minimisation: yes
    prefetch: yes
EOF
systemctl stop adguardhome 2>/dev/null || true
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
  > /root/rookstride-pair/adguard-login.txt
chmod 600 /root/rookstride-pair/adguard-login.txt
unset admin_password
python3 "$ROOT_DIR/scripts/render-adguard-config.py" \
  "$ROOT_DIR/templates/AdGuardHome.yaml" "$DNS_IP" "$CLIENT_POOL" "$admin_hash" \
  /var/lib/AdGuardHome/AdGuardHome.yaml
unset admin_hash
chown adguard:adguard /var/lib/AdGuardHome/AdGuardHome.yaml
chmod 600 /var/lib/AdGuardHome/AdGuardHome.yaml
sed 's/single-vps-vpn-dns-address.service/awg-quick@awg-exit.service/g' "$ROOT_DIR/systemd/adguardhome.service" > /etc/systemd/system/adguardhome.service
chmod 644 /etc/systemd/system/adguardhome.service
/opt/AdGuardHome/AdGuardHome --check-config -c /var/lib/AdGuardHome/AdGuardHome.yaml \
  -w /var/lib/AdGuardHome/work


# Allow the staged source as well as the client pool; nothing is exposed on public IPv4.
python3 - "$TEST_SOURCE_IP" <<'PYCODE'
from pathlib import Path
import sys
p=Path('/var/lib/AdGuardHome/AdGuardHome.yaml');s=p.read_text();s=s.replace('  use_private_ptr_resolvers:', '    - '+sys.argv[1]+'/32\n  use_private_ptr_resolvers:');p.write_text(s)
PYCODE
unbound-checkconf
systemctl daemon-reload
systemctl restart unbound
systemctl enable --now adguardhome
systemctl is-active --quiet unbound
systemctl is-active --quiet adguardhome
# A running process is not proof that the initial blocking list is loaded.
filter_ready=false
for attempt in {1..25}; do
  answer="$(dig +time=2 +tries=1 +short -b "$DNS_IP" @"$DNS_IP" doubleclick.net A 2>/dev/null || true)"
  if [[ "$answer" == 0.0.0.0 ]]; then filter_ready=true; break; fi
  sleep 2
done
[[ "$filter_ready" == true ]] || { echo 'Initial DNS blocking list is not ready; inspect its download and resume.' >&2; exit 1; }
