#!/usr/bin/env bash
set -Eeuo pipefail

ROLE="${1:-}"
ARCHIVE="${2:-}"
[[ "$ROLE" == "ingress" || "$ROLE" == "egress" ]] || { echo "Usage: $0 ingress|egress BACKUP.tar.gz" >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -r "$ARCHIVE" ]] || { echo "Cannot read backup archive." >&2; exit 1; }

if tar -tzf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  echo "Unsafe path found in backup archive." >&2
  exit 1
fi

set +e
bash scripts/install-amneziawg.sh "$ROLE"
installer_rc=$?
set -e
if [[ "$installer_rc" -eq 194 ]]; then
  echo "A reboot is required. Reboot this VPS and run the restore command again." >&2
  exit 194
elif [[ "$installer_rc" -ne 0 ]]; then
  exit "$installer_rc"
fi

if [[ "$ROLE" == "ingress" ]]; then
  apt-get update -qq
  apt-get install -y -qq strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins
fi

tar -C / -xzpf "$ARCHIVE"
chmod 600 /etc/ipsec.secrets 2>/dev/null || true
chmod 600 /etc/amnezia/amneziawg/*.conf 2>/dev/null || true
systemctl daemon-reload
sysctl --system >/dev/null

if [[ -s /etc/amnezia/amneziawg/awg-exit.conf ]]; then
  systemctl enable --now awg-quick@awg-exit.service
fi

if [[ "$ROLE" == "ingress" ]]; then
  systemctl enable --now strongswan-starter.service
  systemctl restart strongswan-starter.service
  [[ -f /etc/systemd/system/twohop-vpn-ikev2-firewall.service ]] \
    && systemctl enable --now twohop-vpn-ikev2-firewall.service
  [[ -f /etc/systemd/system/twohop-vpn-entry-routing.service ]] \
    && systemctl enable --now twohop-vpn-entry-routing.service
  ipsec status >/dev/null
else
  [[ -f /etc/systemd/system/twohop-vpn-exit-firewall.service ]] \
    && systemctl enable --now twohop-vpn-exit-firewall.service
  systemctl enable --now unbound.service
fi

echo "$ROLE configuration restored. Run the deployment verification before allowing clients."
