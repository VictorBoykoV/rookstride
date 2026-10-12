#!/usr/bin/env bash
set -Eeuo pipefail

SERVER_ID="${SERVER_ID:-}"
VPN_USER="${VPN_USER:-}"
PROFILE_NAME="${PROFILE_NAME:-Single VPS VPN}"
CA_CERT_FILE="${CA_CERT_FILE:-}"
OUTPUT_FILE="${OUTPUT_FILE:-single-vps-vpn.mobileconfig}"
ON_DEMAND="${ON_DEMAND:-false}"
IDENTIFIER_PREFIX="${IDENTIFIER_PREFIX:-org.example.singlevpsvpn}"

[[ -n "$SERVER_ID" && -n "$VPN_USER" ]] || {
  echo "Set SERVER_ID and VPN_USER." >&2
  echo "Optional: PROFILE_NAME, CA_CERT_FILE, OUTPUT_FILE, ON_DEMAND, IDENTIFIER_PREFIX." >&2
  exit 2
}
[[ "$SERVER_ID" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "Invalid SERVER_ID." >&2; exit 1; }
[[ "$VPN_USER" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo "Invalid VPN_USER." >&2; exit 1; }
[[ "$IDENTIFIER_PREFIX" =~ ^[A-Za-z0-9.-]{3,200}$ ]] || { echo "Invalid IDENTIFIER_PREFIX." >&2; exit 1; }
[[ "$ON_DEMAND" == true || "$ON_DEMAND" == false ]] || { echo "ON_DEMAND must be true or false." >&2; exit 1; }
[[ "$OUTPUT_FILE" == *.mobileconfig ]] || { echo "OUTPUT_FILE must end in .mobileconfig." >&2; exit 1; }

if [[ -n "$CA_CERT_FILE" ]]; then
  [[ -r "$CA_CERT_FILE" ]] || { echo "Cannot read CA_CERT_FILE." >&2; exit 1; }
  openssl x509 -in "$CA_CERT_FILE" -noout >/dev/null
fi

python3 - "$OUTPUT_FILE" "$SERVER_ID" "$VPN_USER" "$PROFILE_NAME" \
  "$CA_CERT_FILE" "$ON_DEMAND" "$IDENTIFIER_PREFIX" <<'PY'
import pathlib
import plistlib
import re
import subprocess
import sys
import uuid

output, server, username, name, ca_path, on_demand, prefix = sys.argv[1:]

def new_uuid():
    return str(uuid.uuid4()).upper()

profile_uuid = new_uuid()
vpn_uuid = new_uuid()
ikev2 = {
    "AuthName": username,
    "AuthenticationMethod": "None",
    "DeadPeerDetectionRate": "Medium",
    "DisableMOBIKE": 0,
    "DisableRedirect": 0,
    "EnableCertificateRevocationCheck": 0,
    "EnablePFS": 0,
    "ExtendedAuthEnabled": 1,
    "IncludeAllNetworks": 1,
    "ExcludeLocalNetworks": 0,
    "ExcludeCellularServices": 1,
    "ExcludeAPNs": 1,
    "ExcludeDeviceCommunication": 1,
    "RemoteAddress": server,
    "RemoteIdentifier": server,
    "UseConfigurationAttributeInternalIPSubnet": 0,
}
if on_demand == "true":
    ikev2["OnDemandEnabled"] = 1
    ikev2["OnDemandRules"] = [{"Action": "Connect"}]

vpn_payload = {
    "IKEv2": ikev2,
    "IPv4": {"OverridePrimary": 1},
    "IPv6": {"OverridePrimary": 1},
    "PayloadDescription": "Configures a full-tunnel native IKEv2 VPN.",
    "PayloadDisplayName": name,
    "PayloadIdentifier": f"{prefix}.vpn.{vpn_uuid.lower()}",
    "PayloadType": "com.apple.vpn.managed",
    "PayloadUUID": vpn_uuid,
    "PayloadVersion": 1,
    "Proxies": {},
    "UserDefinedName": name,
    "VPNType": "IKEv2",
}

payloads = []
if ca_path:
    der = subprocess.run(
        ["openssl", "x509", "-in", ca_path, "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    cert_uuid = new_uuid()
    payloads.append({
        "PayloadCertificateFileName": "vpn-ca.cer",
        "PayloadContent": der,
        "PayloadDescription": "Installs the VPN server certificate authority.",
        "PayloadDisplayName": f"{name} CA",
        "PayloadIdentifier": f"{prefix}.ca.{cert_uuid.lower()}",
        "PayloadType": "com.apple.security.root",
        "PayloadUUID": cert_uuid,
        "PayloadVersion": 1,
    })

payloads.append(vpn_payload)
profile = {
    "PayloadContent": payloads,
    "PayloadDescription": "Installs a native full-tunnel IKEv2 VPN profile.",
    "PayloadDisplayName": name,
    "PayloadIdentifier": f"{prefix}.profile.{profile_uuid.lower()}",
    "PayloadOrganization": "Self-hosted VPN",
    "PayloadRemovalDisallowed": False,
    "PayloadType": "Configuration",
    "PayloadUUID": profile_uuid,
    "PayloadVersion": 1,
}

path = pathlib.Path(output)
with path.open("wb") as handle:
    plistlib.dump(profile, handle, fmt=plistlib.FMT_XML, sort_keys=True)
PY

chmod 600 "$OUTPUT_FILE"
echo "Created $OUTPUT_FILE (the VPN password is intentionally omitted)."
echo "Install it on an authorized Apple device, review the profile, and enter the EAP password when connecting."
