#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
LABEL="${1:-vps}"

section() {
  printf '\n## %s\n' "$1"
}

run_optional() {
  "$@" 2>&1 || true
}

redact_assignment_secrets() {
  sed -E \
    -e 's/^([[:space:]]*(secret|password|passwd|private[_-]?key|preshared[_-]?key|psk)[[:space:]]*=).*/\1 [REDACTED]/I' \
    -e 's/(PrivateKey|PresharedKey)[[:space:]]*=[[:space:]]*.*/\1 = [REDACTED]/I'
}

redact_ipsec_secrets() {
  sed -E \
    -e 's/^([^#][^:]*:[[:space:]]*(EAP|PSK|XAUTH|NTLM)[[:space:]]+).*/\1[REDACTED]/I' \
    -e 's/^([[:space:]]*:[[:space:]]*(RSA|ECDSA)[[:space:]]+).*/\1[KEY REFERENCE REDACTED]/I'
}

show_config_if_present() {
  local file="$1"
  if [[ -f "$file" ]]; then
    printf '\n### %s\n' "$file"
    if [[ "$file" == */ipsec.secrets ]]; then
      redact_ipsec_secrets < "$file"
    else
      redact_assignment_secrets < "$file"
    fi
  fi
}

section "Audit metadata"
printf 'label=%s\n' "$LABEL"
printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"

section "Operating system"
run_optional uname -a
if [[ -f /etc/os-release ]]; then
  sed -n -E '/^(PRETTY_NAME|ID|VERSION_ID|VERSION_CODENAME)=/p' /etc/os-release
fi
printf 'architecture=%s\n' "$(dpkg --print-architecture 2>/dev/null || uname -m)"

section "Interfaces and routes"
run_optional ip -brief link
run_optional ip -brief address
run_optional ip -4 route show table all
run_optional ip -6 route show table all
run_optional ip rule show
run_optional ip -6 rule show

section "Forwarding-related kernel settings"
for key in \
  net.ipv4.ip_forward \
  net.ipv6.conf.all.forwarding \
  net.ipv4.conf.all.src_valid_mark \
  net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.default.rp_filter \
  net.ipv4.conf.all.send_redirects \
  net.ipv4.conf.default.send_redirects; do
  run_optional sysctl "$key"
done

section "Listening sockets"
run_optional ss -H -lntup

section "VPN packages"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null \
    | grep -Ei 'strongswan|charon|libcharon|wireguard|amnezia|docker|containerd' || true
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa 2>/dev/null | grep -Ei 'strongswan|wireguard|amnezia|docker|containerd' || true
fi

section "VPN binaries"
run_optional ipsec --version
run_optional swanctl --version
run_optional awg --version
run_optional wg --version

section "Service state"
for unit in strongswan strongswan-starter strongswan-swanctl ipsec docker containerd awg-quick@awg-exit twohop-vpn-entry-routing twohop-vpn-exit-firewall; do
  if systemctl list-unit-files "$unit.service" --no-legend 2>/dev/null | grep -q .; then
    printf '%s: ' "$unit"
    systemctl is-active "$unit" 2>/dev/null || true
    systemctl is-enabled "$unit" 2>/dev/null || true
  fi
done

section "strongSwan configuration (secrets redacted)"
for file in \
  /etc/ipsec.conf \
  /etc/ipsec.secrets \
  /etc/strongswan.conf \
  /etc/strongswan.d/charon.conf \
  /etc/swanctl/swanctl.conf; do
  show_config_if_present "$file"
done

if [[ -d /etc/ipsec.d ]]; then
  printf '\n### Certificate and key inventory (names only)\n'
  find /etc/ipsec.d -maxdepth 2 -type f -printf '%p\n' 2>/dev/null | sort
fi

section "strongSwan runtime (no key material)"
run_optional ipsec statusall
run_optional swanctl --list-conns
run_optional swanctl --list-pools
run_optional ip -s xfrm policy

section "WireGuard and AmneziaWG runtime"
run_optional wg show
run_optional awg show

for root in /opt/amnezia /etc/amnezia /etc/wireguard /etc/amneziawg; do
  if [[ -d "$root" ]]; then
    printf '\n### %s inventory\n' "$root"
    find "$root" -maxdepth 4 -type f -printf '%p\n' 2>/dev/null | sort
    while IFS= read -r file; do
      printf '\n#### Safe tunnel fields from %s\n' "$file"
      grep -Ei '^[[:space:]]*(\[Interface\]|\[Peer\]|Address|ListenPort|MTU|Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=' "$file" 2>/dev/null \
        | redact_assignment_secrets || true
    done < <(find "$root" -maxdepth 4 -type f \( -name '*.conf' -o -name '*.ini' \) 2>/dev/null | sort)
  fi
done

section "Containers (environment and mounts intentionally omitted)"
if command -v docker >/dev/null 2>&1; then
  run_optional docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  run_optional docker network ls
fi

section "Firewall and NAT"
if command -v nft >/dev/null 2>&1; then
  run_optional nft list ruleset
fi
if command -v iptables-save >/dev/null 2>&1; then
  run_optional iptables-save
fi
if command -v ip6tables-save >/dev/null 2>&1; then
  run_optional ip6tables-save
fi

section "Persistent networking files"
for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/nftables.conf; do
  [[ -f "$file" ]] || continue
  printf '\n### %s\n' "$file"
  redact_assignment_secrets < "$file"
done

section "Audit complete"
printf 'This report excludes private-key contents, preshared keys, passwords, container environments, and XFRM state keys.\n'
