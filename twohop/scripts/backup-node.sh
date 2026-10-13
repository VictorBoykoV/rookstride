#!/usr/bin/env bash
set -Eeuo pipefail

ROLE="${1:-}"
[[ "$ROLE" == "ingress" || "$ROLE" == "egress" ]] || { echo "Usage: $0 ingress|egress" >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

BACKUP_DIR=/root/twohop-vpn-backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="$BACKUP_DIR/twohop-vpn-$ROLE-$STAMP.tar.gz"
MANIFEST="$BACKUP_DIR/twohop-vpn-$ROLE-$STAMP.manifest.txt"
install -d -m 700 "$BACKUP_DIR"

paths=(
  /etc/amnezia/amneziawg
  /etc/twohop-vpn
  /etc/sysctl.d/90-twohop-vpn-exit.conf
  /etc/sysctl.d/90-twohop-vpn-entry.conf
)

if [[ "$ROLE" == "ingress" ]]; then
  paths+=(
    /etc/ipsec.conf
    /etc/ipsec.secrets
    /etc/strongswan.conf
    /etc/strongswan.d
    /etc/ipsec.d
    /etc/sysctl.d/90-twohop-vpn-ikev2.conf
    /etc/systemd/system/twohop-vpn-entry-routing.service
    /etc/systemd/system/twohop-vpn-ikev2-firewall.service
    /usr/local/sbin/twohop-vpn-entry-routing
    /usr/local/sbin/twohop-vpn-ikev2-firewall
    /root/twohop-vpn-ca
  )
else
  paths+=(
    /etc/unbound/unbound.conf.d/twohop-vpn.conf
    /etc/systemd/system/unbound.service.d/twohop-vpn.conf
    /etc/systemd/system/twohop-vpn-exit-firewall.service
    /usr/local/sbin/twohop-vpn-exit-firewall
  )
fi

existing=()
for path in "${paths[@]}"; do
  [[ -e "$path" || -L "$path" ]] && existing+=("${path#/}")
done
((${#existing[@]} > 0)) || { echo "No $ROLE configuration was found." >&2; exit 1; }

tar -C / -czpf "$ARCHIVE" "${existing[@]}"
chmod 600 "$ARCHIVE"
{
  printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'role=%s\n' "$ROLE"
  printf 'hostname=%s\n' "$(hostname)"
  sha256sum "$ARCHIVE"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null \
    | grep -Ei 'amneziawg|strongswan|charon|unbound' || true
} > "$MANIFEST"
chmod 600 "$MANIFEST"
printf '%s\n' "$ARCHIVE"
