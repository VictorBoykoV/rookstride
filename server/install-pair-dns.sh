#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 && -f /etc/rookstride-pair/manifest.json ]] || { echo 'Owned pair required.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
ROOT_DIR="$(cd "$(dirname "$0")/../gateway" && pwd)"
DNS_IP="${TUNNEL_EXIT_IP:?}"
: "${CLIENT_POOL:?}" "${TEST_SOURCE_IP:?}"
# Fresh legacy DNS only; a completed older module is never an implicit upgrade.
for path in /opt/AdGuardHome /var/lib/AdGuardHome /etc/systemd/system/adguardhome.service /etc/unbound/unbound.conf.d/twohop-vpn.conf; do
  [[ ! -e $path && ! -L $path ]] || { echo 'Existing pair DNS requires review.' >&2; exit 1; }
done
if systemctl is-active --quiet adguardhome; then
  echo 'Existing pair DNS service requires review.' >&2; exit 1
fi
# Download tooling only; publish no DNS files until the archive is verified.
if ! command -v curl >/dev/null || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
  apt-get -o DPkg::Lock::Timeout=1200 install -y -qq curl ca-certificates
fi
case "$(uname -m)" in
  x86_64) arch=amd64; checksum=28593bc761d71469abdbc6f39ca42cbed763ec92b63082c729177b037ed51d18; size=12553060; asset=705629752 ;;
  aarch64) arch=arm64; checksum=d5e17d0d724418ddef8b7723ed8ade7eef4e621ec5b0e43a341859cca71a3d8f; size=11455816; asset=705629749 ;;
  *) echo 'AdGuard Home is packaged here for x86_64 and aarch64 only.' >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
archive="AdGuardHome_linux_${arch}.tar.gz"
if python3 "$ROOT_DIR/scripts/public-artifact-cache.py" "$checksum" "$size" "$tmp/$archive"; then
  :
else
  cache_status=$?
  [[ $cache_status == 10 ]] || exit "$cache_status"
  if ! curl -fL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 45 -o "$tmp/$archive" \
    "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.80/$archive"; then
    curl -fL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 45 --retry 1 -H 'Accept: application/octet-stream' \
      -o "$tmp/$archive" "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/assets/$asset"
  fi
fi
[[ $(stat -c %s "$tmp/$archive") == "$size" ]] || { echo 'Unexpected AdGuard Home archive size.' >&2; exit 1; }
printf '%s  %s\n' "$checksum" "$tmp/$archive" | sha256sum -c -
python3 - "$tmp/$archive" "$tmp/AdGuardHome" <<'PYADGUARD'
import pathlib,sys,tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    items=[p for p in archive.getmembers() if pathlib.PurePosixPath(p.name)==pathlib.PurePosixPath('AdGuardHome/AdGuardHome')]
    if len(items)!=1 or not items[0].isfile() or not 0<items[0].size<=100*1024*1024:
        raise ValueError('Unexpected AdGuard Home binary')
    binary=archive.extractfile(items[0]).read()
    if len(binary)!=items[0].size:raise ValueError('Incomplete AdGuard Home binary')
    pathlib.Path(sys.argv[2]).write_bytes(binary)
PYADGUARD
apt-get -o DPkg::Lock::Timeout=1200 install -y -qq openssl python3-bcrypt
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
install -m 755 "$tmp/AdGuardHome" /opt/AdGuardHome/AdGuardHome
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
