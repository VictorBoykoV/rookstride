#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
ACTION="${1:-}"
VPN_USER="${2:-}"
[[ "$ACTION" == "add" || "$ACTION" == "remove" ]] || { echo "Usage: $0 add|remove USERNAME" >&2; exit 2; }
[[ "$VPN_USER" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo "Invalid username." >&2; exit 1; }
[[ -r /etc/ipsec.secrets ]] || { echo "Missing /etc/ipsec.secrets." >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk -v user="$VPN_USER" '$1 != user || $2 != ":" || $3 != "EAP"' /etc/ipsec.secrets > "$tmp"

if [[ "$ACTION" == "add" ]]; then
  if [[ -n "${VPN_PASSWORD_FILE:-}" ]]; then
    [[ -r "$VPN_PASSWORD_FILE" ]] || { echo "Cannot read VPN_PASSWORD_FILE." >&2; exit 1; }
    [[ -z $(find "$VPN_PASSWORD_FILE" -prune -perm /077 -print) ]] || { echo "VPN_PASSWORD_FILE must be mode 0600 or stricter." >&2; exit 1; }
    IFS= read -r password < "$VPN_PASSWORD_FILE"
  else
    [[ -t 0 ]] || { echo "Set VPN_PASSWORD_FILE for non-interactive use." >&2; exit 1; }
    read -r -s -p "Password for $VPN_USER: " password
    printf '\n'
    read -r -s -p "Repeat password: " password_confirm
    printf '\n'
    [[ "$password" == "$password_confirm" ]] || { echo "Passwords do not match." >&2; exit 1; }
    unset password_confirm
  fi
  [[ ${#password} -ge 16 ]] || { echo "Use a password of at least 16 characters." >&2; exit 1; }
  escaped="${password//\\/\\\\}"
  escaped="${escaped//\"/\\\"}"
  printf '%s : EAP "%s"\n' "$VPN_USER" "$escaped" >> "$tmp"
  unset password escaped
fi

install -m 600 "$tmp" /etc/ipsec.secrets
ipsec rereadsecrets
echo "EAP user $VPN_USER updated ($ACTION)."
