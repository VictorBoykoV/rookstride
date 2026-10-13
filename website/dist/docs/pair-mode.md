# Two-server gateway · experimental

The `0.2.0-alpha1` source adds one complete recipe to the Android app:

```mermaid
flowchart LR
    Phone[Android / strongSwan] -->|IKEv2 + EAP| Entry[Entry VPS]
    Entry -->|AmneziaWG 3.1 · MTU 1280| Exit[Exit VPS]
    Exit --> Internet
    Exit --> AdGuard[Private AdGuard Home]
    AdGuard --> Unbound
    Admin[Rookstride administrator] -->|Independently pinned SSH| Entry
    Admin -->|Independently pinned SSH| Exit
```

The public alpha2 APK remains the single-server release. The new pair is an experimental build; its exact tests and remaining gates are in [PAIR-TESTING.md](pair-testing.md). WireGuard, OpenVPN and Xray client engines remain proposals.

## Requirements

- Two distinct, fresh Ubuntu 24.04 machines, x86_64 or arm64, with public IPv4 and Internet access.
- Independent SSH addresses, ports and root credentials or private keys. Passwordless sudo is also supported.
- Provider firewall access for entry UDP 500/4500 and exit UDP 443 by default. A custom client or bridge port can be selected before installation.
- A matching kernel and headers able to build/load the pinned AmneziaWG module. When a kernel change is required, the app offers an owned reboot and then resume.
- Reachable Ubuntu repositories, the signed AWG package repository and the checksum-pinned AdGuard Home release. The phone needs an Internet connection to both SSH endpoints.

One physical VPS cannot serve as both roles. The app checks machine IDs before changing either node, refusing aliases of the same machine. Two isolated local VMs can test the coordinator and real tunnel, but a production two-hop route needs two VPSs. Shared-host tests do not certify routing between independent providers.

## Install from Android

1. Add a **two-server gateway**. Enter separate entry and exit SSH details. Check each presented fingerprint against its provider console; a changed key stops the operation before authentication.
2. Set the public entry VPN address and exit tunnel endpoint. These may differ from their management SSH addresses. Create the initial VPN login with the generated strong password or another password of at least 16 characters.
3. Install. The app first prepares the exit, then the entry under a forwarding guard. Private tunnel keys are generated on each node and never leave it. Shared tunnel authentication material is transferred only through the two verified SSH sessions.
4. The coordinator configures exit DNS, configures IKEv2 and the bridge, checks a recent handshake, staged exit IPv4 and a real DNS answer, then activates client forwarding. It stops at a failed check.
5. Use **People → Use on this phone**, or export a password-free `.sswan` profile for the official strongSwan Android app. Share the VPN password separately.
6. Test the actual phone on Wi-Fi and mobile data: HTTPS, visible exit IPv4, DNS filtering and IPv6 behavior. A successful SSH install cannot establish that the phone’s network permits IKEv2.

AdGuard settings are sent to the exit; accounts, sessions and estimated user traffic are managed at the entry. The dashboard listens on the private exit tunnel address. The embedded client remains IKEv2; this mode does not add an AmneziaWG phone client.

## Interrupted installation and pause

Each node stores a root-owned pair manifest and detached systemd jobs. Closing the app or losing SSH does not kill the server job. Reopen the saved pair and choose **Install / resume / verify pair**. The saved plan, peer material and installer digest must match. The app does not silently switch an existing pair to new installer code.

Root-only job state/logs live under `/var/lib/rookstride-pair/JOB/`; ownership and material under `/etc/rookstride-pair/`. Never publish those files. A changed partial IKE configuration or changed owned tunnel configuration stops recovery.

**Pause client forwarding** raises a persistent guard. It does not restore a direct entry route. Resume repeats staged verification before activation. A bridge outage retains a blackhole route for VPN client addresses. Reboots restore the recorded active or paused state before IKE clients can use the gateway.

## Current boundaries

- Fresh pair installation and recovery of its owned jobs are supported. Pair upgrades, importing an arbitrary existing pair and an in-app pair data reset are not supported yet. Use provider rebuilds for disposable pair nodes. Single-server reset remains available for its recognized installations.
- Only one pair per dedicated node. No nested chains, selectable phone engines or mixed protocol recipes.
- IPv4 Internet routing; IPv6 client Internet traffic is rejected. Always-on Android lockdown is a separate phone setting. The admin app’s management traffic is exempt from its embedded VPN.
- DNS filtering cannot reliably remove YouTube in-video ads; apps with their own encrypted DNS may bypass domain filtering.
- Usage is an estimate at the entry, not provider billing. Both VPS providers and the exit’s address reputation still matter.

## Source and dependencies

The MIT backend is vendored under [twohop](https://github.com/VictorBoykoV/rookstride/blob/main/twohop/SOURCE.json) with the original repository/commit and exact file hashes. The new SSH coordinator and server job adapter are part of Rookstride’s GPL source. The original [Two-Hop VPN Gateway repository](https://github.com/VictorBoykoV/beget-vpn-gateway) retains its CLI workflow.

Ubuntu 24.04 pair builds pin `amneziawg-tools=1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1` and `amneziawg-dkms=1.0.0-0~202609061402+4569c4c~ubuntu24.04.1`. The loaded parser/module must retain 3.1 parameters and complete a real handshake. Availability of these package versions and support for a provider kernel remain deployment prerequisites. AdGuard Home 0.107.79 archives are SHA-256 verified before extraction.
