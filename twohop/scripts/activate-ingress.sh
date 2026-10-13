#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

case "${1:-apply}" in
  apply)
    /usr/local/sbin/twohop-vpn-entry-routing activate
    systemctl enable twohop-vpn-entry-routing.service
    ;;
  quiesce)
    /usr/local/sbin/twohop-vpn-entry-routing quiesce
    systemctl enable twohop-vpn-entry-routing.service
    ;;
  rollback)
    systemctl disable twohop-vpn-entry-routing.service >/dev/null 2>&1 || true
    if [[ -x /usr/local/sbin/twohop-vpn-entry-routing ]]; then
      /usr/local/sbin/twohop-vpn-entry-routing rollback
    else
      echo "Routing helper is not installed; there is nothing to roll back."
    fi
    ;;
  *)
    echo "Usage: $0 apply|quiesce|rollback" >&2
    exit 2
    ;;
esac
