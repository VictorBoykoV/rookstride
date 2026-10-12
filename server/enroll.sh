#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
package="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f /etc/single-vps-vpn/network.env && -f /etc/ipsec.secrets ]] || {
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
if [[ ! -S /var/run/charon.vici ]]; then
  # Installing the VICI plugin requires one daemon restart. This is surfaced by the app.
  systemctl restart strongswan-starter
fi
if [[ ${ROOKSTRIDE_STATS:-false} == true ]]; then
  systemctl enable --now rookstride-stats
fi
echo 'Management helper installed.'
