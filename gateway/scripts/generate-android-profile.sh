#!/usr/bin/env bash
set -Eeuo pipefail

SERVER_ID="${SERVER_ID:-}"
VPN_USER="${VPN_USER:-}"
PROFILE_NAME="${PROFILE_NAME:-Single VPS VPN}"
CA_CERT_FILE="${CA_CERT_FILE:-}"
OUTPUT_FILE="${OUTPUT_FILE:-single-vps-vpn.sswan}"
PROFILE_URL="${PROFILE_URL:-}"
PROFILE_MTU="${PROFILE_MTU:-}"

[[ -n "$SERVER_ID" && -n "$VPN_USER" ]] || {
  echo "Set SERVER_ID and VPN_USER." >&2
  echo "Optional: PROFILE_NAME, CA_CERT_FILE, OUTPUT_FILE, PROFILE_URL, PROFILE_MTU." >&2
  exit 2
}
[[ "$SERVER_ID" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "Invalid SERVER_ID." >&2; exit 1; }
[[ "$VPN_USER" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo "Invalid VPN_USER." >&2; exit 1; }
if [[ -n "$PROFILE_MTU" ]]; then
  [[ "$PROFILE_MTU" =~ ^[0-9]+$ ]] && (( PROFILE_MTU >= 1280 && PROFILE_MTU <= 1500 )) \
    || { echo "PROFILE_MTU must be between 1280 and 1500." >&2; exit 1; }
fi

certificate=""
if [[ -n "$CA_CERT_FILE" ]]; then
  [[ -r "$CA_CERT_FILE" ]] || { echo "Cannot read CA_CERT_FILE." >&2; exit 1; }
  certificate="$(openssl x509 -in "$CA_CERT_FILE" -outform DER | base64 | tr -d '\n')"
fi

uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
python3 - "$OUTPUT_FILE" "$uuid" "$PROFILE_NAME" "$SERVER_ID" "$VPN_USER" "$certificate" "$PROFILE_MTU" <<'PY'
import json
import sys

output, uuid, name, server, username, certificate, mtu = sys.argv[1:]
profile = {
    "uuid": uuid,
    "name": name,
    "type": "ikev2-eap",
    "remote": {"addr": server, "id": server},
    "local": {"eap_id": username},
    "split-tunneling": {"block-ipv4": True, "block-ipv6": True},
}
if certificate:
    profile["remote"]["cert"] = certificate
if mtu:
    profile["mtu"] = int(mtu)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(profile, handle, indent=2)
    handle.write("\n")
PY
chmod 600 "$OUTPUT_FILE"
echo "Created $OUTPUT_FILE (the VPN password is intentionally omitted)."

if [[ -n "$PROFILE_URL" ]]; then
  [[ "$PROFILE_URL" == https://* ]] || { echo "PROFILE_URL must use HTTPS." >&2; exit 1; }
  if command -v qrencode >/dev/null 2>&1; then
    qr_file="${OUTPUT_FILE%.*}-qr.png"
    qrencode -o "$qr_file" "$PROFILE_URL"
    echo "Created $qr_file for $PROFILE_URL"
  else
    echo "Install qrencode, then run: qrencode -o profile-qr.png '$PROFILE_URL'"
  fi
fi
