#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
package="$(cd "$(dirname "$0")/.." && pwd)"
[[ ( -f /etc/single-vps-vpn/network.env || ( -f /etc/twohop-vpn/entry.env && -f /etc/rookstride-pair/manifest.json ) ) && -f /etc/ipsec.secrets ]] || {
  echo 'This is not an installation of the supported single VPS gateway.' >&2; exit 2;
}
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq strongswan-swanctl
install -d -m 700 /opt/rookstride /var/lib/rookstride
cp -a "$package/server" /opt/rookstride/
cp -a "$package/gateway" /opt/rookstride/
chown -R root:root /opt/rookstride
chmod -R go-w /opt/rookstride
cat > /usr/local/sbin/rookstride-admin <<'EOF'
#!/bin/sh
cd /opt/rookstride/server
exec /usr/bin/python3 -m rookstride.admin
EOF
chmod 700 /usr/local/sbin/rookstride-admin
install -m 644 "$package/server/rookstride-stats.service" /etc/systemd/system/
systemctl daemon-reload
management_ready() {
  # A stale Unix socket file is not evidence of a running VICI listener.
  (cd /opt/rookstride/server && python3 -c 'from rookstride.vici import Vici; v=Vici(timeout=1); v.request("version"); v.sock.close()') >/dev/null 2>&1
}
if ! management_ready; then
  # A newly installed VICI plugin needs a daemon restart. Enrollment surfaces this.
  systemctl restart strongswan-starter
fi
ready=false
for _ in {1..30}; do
  if management_ready; then ready=true; break; fi
  sleep 1
done
[[ $ready == true ]] || { echo 'VPN management interface did not become ready.' >&2; exit 1; }
if [[ ${ROOKSTRIDE_STATS:-false} == true ]]; then
  systemctl enable --now rookstride-stats
fi
echo 'Management helper installed.'
