#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This backup must run as root." >&2
  exit 1
fi

BACKUP_DIR=/root/twohop-vpn-backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="$BACKUP_DIR/strongswan-before-two-hop-$STAMP.tar.gz"
MANIFEST="$BACKUP_DIR/strongswan-before-two-hop-$STAMP.manifest.txt"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

paths=()
for path in \
  /etc/ipsec.conf \
  /etc/ipsec.secrets \
  /etc/strongswan.conf \
  /etc/strongswan.d \
  /etc/ipsec.d \
  /etc/xl2tpd \
  /etc/ppp \
  /etc/iptables/rules.v4 \
  /etc/iptables/rules.v6 \
  /etc/sysctl.d/90-twohop-vpn-ikev2.conf; do
  [[ -e "$path" || -L "$path" ]] && paths+=("${path#/}")
done

if ((${#paths[@]} == 0)); then
  echo "No existing VPN configuration was found." >&2
  exit 1
fi

tar -C / -czpf "$ARCHIVE" "${paths[@]}"
chmod 600 "$ARCHIVE"

{
  printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'hostname=%s\n' "$(hostname)"
  printf 'archive=%s\n' "$ARCHIVE"
  sha256sum "$ARCHIVE"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null \
    | grep -Ei 'strongswan|charon|libcharon|xl2tp|ppp' || true
} > "$MANIFEST"
chmod 600 "$MANIFEST"

printf '%s\n' "$ARCHIVE"
