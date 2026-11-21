#!/bin/bash
set -euo pipefail
umask 077
# Start the pinned userspace engine explicitly. An unrelated older host kernel
# module must not change which implementation carries this route.
amneziawg-go -f awg-exit &
worker=$!
trap 'kill "$worker" 2>/dev/null || true; wait "$worker" || true' TERM INT EXIT
for attempt in {1..100}; do [[ -S /var/run/amneziawg/awg-exit.sock ]] && break; sleep .1; done
[[ -S /var/run/amneziawg/awg-exit.sock ]] || exit 1
awg-quick strip /vpn/awg-exit.conf > /tmp/bridge-wire.conf
awg setconf awg-exit /tmp/bridge-wire.conf
rm -f /tmp/bridge-wire.conf
addresses=$(sed -n 's/^Address = //p' /vpn/awg-exit.conf)
IFS=',' read -r -a assigned <<< "$addresses"
for address in "${assigned[@]}"; do ip address add "${address// /}" dev awg-exit; done
ip link set awg-exit mtu 1280 up
wait "$worker"
