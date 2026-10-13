# Rookstride: one app, several routes

Research and source review: **13 October 2026**. This is an implementation proposal, not a claim that the published APK supports these routes.

> **Implementation update:** the `0.2.0-alpha1` source now includes the first IKEv2 → AmneziaWG pair. See [pair operations](pair-mode.md) and [pair test scope](pair-testing.md). This document retains the original design review; other engines remain proposals and the alpha2 binary is unchanged.

## Decision

**Yes. An Android phone can deploy and manage a two-server VPN by connecting to each VPS over SSH.** The phone coordinates the installation; the servers carry the traffic after installation. It must have network access, and both servers must reach their package sources. There is no need for a hosted Rookstride control plane.

Start with **IKEv2 on the entry + AmneziaWG 3.1 between entry and exit**. This reuses the existing embedded strongSwan client. Then add individual protocol adapters, with deployment, export, integrated connection and test status tracked separately. Offer tested recipes rather than every possible combination.

The current **0.1.0-alpha2 APK supports one VPS, IKEv2/strongSwan, AdGuard Home and Unbound**. Neither a two-host installer nor another client engine has been added to that binary. The original two-hop deployment did not receive a successful physical-phone end-to-end verification; the previous single-server tests do not certify a pair.

## What the names mean

- **strongSwan** is an implementation; the phone-facing protocol is IKEv2/IPsec.
- **AmneziaVPN** is an application and installer, not one protocol. AmneziaWG and Xray/VLESS/REALITY are different choices inside its ecosystem.
- **Two-hop** describes the route, not a specific protocol. The phone-to-entry connection and the entry-to-exit connection can differ.
- **Xray** is a proxy engine. A full-device VPN needs a TUN integration; a proxy listener alone does not capture every app's traffic.

Android permits one active VPN service per user/profile. A two-hop route should therefore be **phone → entry → exit**, with the second hop on the servers. It should not start two competing VPN services on the phone. Each engine must protect its transport socket from its own TUN to avoid a loop. [Android VPN documentation](https://developer.android.com/develop/connectivity/vpn).

## Proposed routes and capabilities

| Recipe | Phone → server/entry | Entry → exit | Deployment in alpha2 | Connect inside alpha2 | Next step |
|---|---|---|---|---|---|
| Single IKEv2 | IKEv2/IPsec | None | Yes | Yes | Keep as the small default |
| Two-hop IKEv2 | IKEv2/IPsec | AmneziaWG 3.1 | No; separate repository scripts exist | Existing engine could connect after pair provisioning | First pair adapter and pair tests |
| Single AmneziaWG | AmneziaWG 3.1 | None | No | No | Server adapter + compatible Android tunnel engine |
| Single WireGuard | WireGuard | None | No | No | Server adapter + official Android tunnel library |
| Single OpenVPN | OpenVPN, UDP first | None | No | No | Server adapter + client engine |
| Single Xray | VLESS + REALITY, one pinned transport recipe | None | No | No | Server adapter + TUN, UDP and DNS integration |
| Other two-hop recipes | One of the tested phone protocols | WireGuard/AWG/OpenVPN L3 tunnel | No | Depends on first-hop engine | Add one combination at a time |
| Xray as backhaul | Any supported first hop | Proxy transport + transparent routing adapter | No | No combined route tested | Later research; not a drop-in tunnel replacement |

**Inference from the existing code:** IKEv2 → AWG is the shortest path to two-hop support because the Android engine already exists and the backend already uses policy routing. That does not establish runtime compatibility or prove the fail-closed behavior of a future adapter.

### Why unrestricted dropdowns would be misleading

WireGuard, AWG and OpenVPN provide routable layer-3 interfaces. Their address pools, return paths, MTU, NAT and failure behavior still need explicit recipes. Xray has protocol/transport/security compatibility constraints; its documented matrix rules out some combinations. UDP/QUIC forwarding must be deliberately configured and tested. The documented Mux default rejects proxied UDP/443, which can cause browsers to fall back to TCP. [Xray transport matrix](https://xtls.github.io/en/config/transport.html), [Xray outbound/UDP configuration](https://xtls.github.io/en/config/outbound.html).

A different backhaul **does not change the phone-to-entry protocol**. If a network drops IKEv2 to the entry address, replacing AWG between the VPSs will not make that IKEv2 connection reachable. A different phone-facing engine, reachable endpoint and verified client route are needed. No protocol guarantees website access, a particular geolocation result or acceptance of a datacenter exit IP.

## Upstream reuse and Android support

| Component | Evidence | Integration decision |
|---|---|---|
| Amnezia installer | Its public client uses SSH server credentials and installs server containers; its codebase is Qt with several protocol engines | Reuse the orchestration ideas and inspect pinned adapters; avoid bringing the entire desktop/mobile application into this Java overlay |
| WireGuard Android | Official `com.wireguard.android:tunnel` embedding library | Suitable separate engine candidate; ordinary WireGuard does not parse AWG-specific parameters |
| AmneziaWG Android | Separate `tunnel` module; inspected interface parser contains 3.1 fields including header protection and randomized timers | Pin the Java parser **and native submodules** together, validate config round-trip, then connect against an actual 3.1 server. Parser support is not handshake proof |
| OpenVPN | OpenVPN 3 is a client library; OpenVPN for Android is an existing Android integration | Choose one engine after license/build/ABI review; do not embed two competing OpenVPN stacks |
| Xray | MPL-2.0 core with independent Android wrapper/TUN dependencies | Inventory every linked component's license, pin the core and wrapper, implement one VPN service owner |

Primary sources: [Amnezia client](https://github.com/amnezia-vpn/amnezia-client), [WireGuard embedding](https://www.wireguard.com/embedding/), [AmneziaWG Android](https://github.com/amnezia-vpn/amneziawg-android), [inspected AWG interface parser](https://github.com/amnezia-vpn/amneziawg-android/blob/master/tunnel/src/main/java/org/amnezia/awg/config/Interface.java), [OpenVPN 3](https://github.com/OpenVPN/openvpn3), [OpenVPN for Android](https://github.com/schwabe/ics-openvpn), [Xray core](https://github.com/XTLS/Xray-core).

Amnezia's current self-hosted documentation lists Android 9+ for its main app and AmneziaVPN 5.0.1.5+ for AWG 3.1. It also identifies a separate native AWG client. These are different products: neither establishes the minimum supported Android version of a future Rookstride engine. Keep Rookstride's existing Android 8 IKEv2 support; test each additional engine on API 26, 28 and 36 before advertising the same floor. AWG 3.1 configurations cannot be converted to AWG 2.0 and expected to work. [Amnezia FAQ](https://docs.amnezia.org/faq/).

The APK will grow when native engines are bundled; the current 26.1 MiB size cannot be promised for a multi-engine release. Prefer architecture-specific releases and measure installed size, startup, memory and battery. Optional engines should not silently raise the Android minimum for the existing IKEv2 route. Preserve exact corresponding source, notices and the signing identity; review licenses at each selected revision rather than treating a repository's headline license as the complete dependency inventory.

## Phone installation flow

1. Choose **one server / two servers**.
2. Choose a tested recipe. In advanced mode, choose only compatible phone and backhaul adapters; explain unavailable combinations.
3. Add each server independently: host, SSH port, administrator, password or key. Verify and pin **both** fingerprints before authentication. Do not silently trust a first key.
4. Inspect OS, CPU architecture, public connectivity, available disk/RAM, existing services, provider firewall requirements, kernel headers and module capabilities. Compare resolved addresses and server identity to reject two aliases for the same host.
5. Review the concrete plan and whether any reboot is required. Refuse an existing unrelated VPN. Back up owned state privately before an authorized migration.
6. Install the **exit first**. Install the entry with client forwarding blocked. Generate per-pair keys and private configuration without putting secrets in process arguments or logs.
7. Establish the backhaul. Verify a recent handshake, return route, exit IPv4 and DNS using a staged test source.
8. Activate the client pool only after verification. Export the pinned client profile and then verify from a separate device/app UID.
9. Display a clear outcome for each host: ready, awaiting reboot, paused, failed or needs inspection. A dropped phone connection is not success or failure by itself.

### Recovery is part of the installer

Two VPSs cannot be changed as one atomic transaction. Use a pair ID, per-host detached job, durable journal, bundle digest and idempotent steps. Persist progress on the servers and nonsecret plan references in the encrypted phone vault. Reattach after app process death or a network change; do not blindly repeat destructive steps. A rebooted server resumes only after the same pinned SSH identity and expected ownership manifest are confirmed.

On failure, **quiesce client forwarding** and retain the reject/blackhole protections. Keep SSH management on the ordinary server uplink. Do not automatically roll back into local Internet egress. Restoring a prior single-server route is a separate explicit migration operation.

## Audit of the existing Two-Hop VPN Gateway

Reviewed local revision **876039c60f92768c34516b89fa8a2420d88244ae** of [the existing repository](https://github.com/VictorBoykoV/beget-vpn-gateway). These are source findings; no new pair was deployed during this review.

| Finding | Exact source | Required before phone integration |
|---|---|---|
| Controller requires local `sshpass`, `scp`, `wg`, `shuf`, Python and a Bash environment | `scripts/deploy-pair.sh` | Native SSH/SFTP orchestration and structured server helpers; no assumption that Android can run the desktop script |
| One SSH user and implicit port 22; first keys accepted automatically | `scripts/deploy-pair.sh`, `StrictHostKeyChecking=accept-new` | Independent users/ports and explicit fingerprint pins; reuse Rookstride's stricter trust model |
| CLI activation defaults to true despite the staged-first development contract | `scripts/deploy-pair.sh`, `ACTIVATE` | Pair app must default to staged mode and require verified activation; align CLI defaults in a separately tested backend change |
| Error trap invokes rollback, which removes pool policy rules and the kill switch | `scripts/deploy-pair.sh`, `scripts/activate-ingress.sh`, `scripts/remote/twohop-vpn-entry-routing` | New fail-closed quiesce operation. Existing rollback is a restoration operation and may restore an entry's previous direct-egress behavior |
| Private configs go through predictable `/tmp/awg-exit.conf` paths and remain after copying | `scripts/deploy-pair.sh`, `scripts/apply-egress.sh`, `scripts/stage-ingress.sh` | Per-job directory mode 0700, config mode 0600, atomic install, cleanup on all outcomes; never delete unrelated files |
| Reuse selects the installed config as the source, then calls `install` onto that same destination | `scripts/apply-egress.sh`, `scripts/stage-ingress.sh` | Avoid same-file copy; verify existing manifest/parameters before reuse. GNU `install` rejects copying a file onto itself |
| Reuse is based on config-file presence rather than endpoint/pool/version agreement | `scripts/deploy-pair.sh` | Bind the plan digest, addresses, keys and adapter version to both hosts; reconfigure or reject mismatches |
| AWG packages come from a mutable PPA and module capabilities are not a complete 3.1 feature gate | `scripts/install-amneziawg.sh` | Record exact installed versions; pin tested inputs and prove the configuration is accepted by both loaded modules |
| Kernel fallback and reboot are controlled from a live controller connection; Debian fallback uses amd64 packages | `scripts/install-amneziawg.sh`, `scripts/deploy-pair.sh` | Durable reboot recovery, architecture-aware packages, matching running-kernel headers. A newer kernel is not inherently required if the existing one supports the module |
| Exit DNS is Unbound, not AdGuard Home | `scripts/apply-egress.sh` | Add a separate owned exit DNS adapter; do not claim AdGuard is already present in the two-hop repository |

These findings should be fixed and exercised on disposable hosts before vendoring a pair backend into a signed APK. Syntax/static checks alone cannot establish correct routing after boot or failure.

### Repository name and packaging

The README already calls it **Two-Hop VPN Gateway** and is provider/country neutral. Recommend the repository slug **`two-hop-vpn-gateway`** to match `single-vps-vpn-gateway`. Keep it usable as a standalone MIT backend and describe Rookstride as its phone controller. Preserve the old URL/redirect and update consumers deliberately; a rename is not required to begin integration.

Rookstride should bundle a reviewed clean snapshot at an exact commit/hash, retain MIT notices, and record the origin in a source manifest. Do not fetch and execute mutable `main` as root. Do not embed credentials, old operational history or deployment artifacts. No remote rename or new release was made for this local research revision.

## DNS, users, usage and reset

For two-hop, place **AdGuard Home and the recursive resolver on the exit**. Route client UDP/TCP DNS through the backhaul; bind it to private addresses, refuse public recursion, and expose the dashboard through the VPN or SSH forwarding. Test DNS when the backhaul fails. Encrypted DNS inside applications can still bypass DNS filtering. YouTube in-stream ads remain outside reliable DNS blocking.

Account models differ: IKEv2 EAP users, WireGuard/AWG public-key peers, OpenVPN client certificates and Xray UUIDs are not interchangeable. Give each adapter create/revoke/export/session/counter capabilities. For shared accounts, label endpoint observations without claiming a hardware identity. Do not present a backhaul's aggregate bytes as an individual user's usage. Counter resets, rekeys and gaps remain explicit; totals are not billing.

Reset should use an ownership manifest and a preview for **one node or the pair**. Close client forwarding before removing the exit. Refuse unknown/shared peers and extra services. Initially use a dedicated exit per pair; sharing one exit across pairs complicates reset ownership. Deleting the Ubuntu OS and unrelated files remains a provider rebuild, not an SSH “wipe everything” action.

## Implementation sequence and acceptance gates

| Stage | Deliverable | Gate |
|---|---|---|
| 1 | Pure plan model, adapter contract, per-node identity/ports, capability matrix | Validation, no secret persistence by default, unsupported combinations refused |
| 2 | Fix and pin IKEv2 → AWG backend; exit DNS adapter; durable jobs | Disposable Linux integration and forced-failure tests |
| 3 | Pair installation UI, resume/recovery, profile export and existing IKEv2 connection | Three complete wipe/install cycles on a disposable **pair**, plus physical-phone tests |
| 4 | First additional single-server protocol and compatible engine | Native/API/ABI/16-KiB, handoff, full traffic/DNS/IPv6 policy tests |
| 5 | Further recipes and per-engine monitoring | Each combination independently passes the same gates |

For a pair, test: install exit then entry; DNS and public IPv4 from staged source; real client TCP/UDP/QUIC; entry/exit reboot; backhaul stop/restart; failed package install; missing headers; changed host key; interrupted upload; phone disconnect/process death; stale jobs; repeated install; config reuse; address overlap/same-host aliases; revoke; reset with unknown files; and restore after an authorized reset. Stop the backhaul while sending client traffic and capture both ordinary uplinks to prove **no entry-side Internet fallback**. Verify IPv6 with an IPv6-capable mobile/Wi-Fi underlay. Repeat final clean cycles, not only cycles on intermediate builds.

Use Android 8/API26, 9/API28 and 16/API36 emulator coverage for any engine claiming the current minimum; add physical ARM/OEM phones, captive portals, Wi-Fi↔mobile handoff, battery restrictions and 16-KiB devices. Do not infer these passes from an APK build or emulator-only checks. Measure a small VPS under sustained load before making a capacity promise.

### Tests possible in this revision

Existing repository checks and Android JVM tests can be rerun locally. The reader, assets, links and documentation can be tested in the browser. A new two-hop runtime needs **two disposable reachable hosts**; the working single-server VPN is not a substitute. No new live pair reset/reinstall or additional protocol handshake is claimed. The test record accompanying this revision separates these checks from the earlier alpha2 live single-server evidence.

## Primary sources

- [Android VPN architecture and lifecycle](https://developer.android.com/develop/connectivity/vpn)
- [Amnezia self-hosted installation](https://docs.amnezia.org/documentation/instructions/install-vpn-on-server/)
- [Amnezia current compatibility FAQ](https://docs.amnezia.org/faq/)
- [Amnezia client source](https://github.com/amnezia-vpn/amnezia-client)
- [AmneziaWG Android source](https://github.com/amnezia-vpn/amneziawg-android)
- [WireGuard application embedding](https://www.wireguard.com/embedding/)
- [OpenVPN 3 client library](https://github.com/OpenVPN/openvpn3)
- [OpenVPN for Android](https://github.com/schwabe/ics-openvpn)
- [Xray core and license](https://github.com/XTLS/Xray-core)
- [Xray transport compatibility](https://xtls.github.io/en/config/transport.html)
- [Xray UDP/outbound behavior](https://xtls.github.io/en/config/outbound.html)
- [Existing Two-Hop VPN Gateway](https://github.com/VictorBoykoV/beget-vpn-gateway)

Upstream pages and mutable branches were checked on the research date. Before implementation, freeze exact revisions and rerun the compatibility review.
