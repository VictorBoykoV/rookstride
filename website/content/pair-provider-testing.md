# Two-provider pair tests · 0.2.0-alpha2

13–14 October 2026. Both nodes were distinct real-provider Ubuntu 24.04 VPSs with one vCPU and about one GiB RAM. The same signed, non-debuggable Android APK configured **both nodes** through its native SSH/SFTP coordinator. The desktop CLI installer was not used for these pair deployments. Nodes are anonymized as A and B; no deployment addresses, passwords, keys, hostnames or certificate identities are published.

APK SHA-256: `4ffd25954380da3a557c1eb36c377c628e9c4149a6b05872229c048d31b1f577`. Version code 4; same signing certificate as the earlier releases. 49 Python tests and 93 Android JVM tests passed. The APK's bundled server source matched the checkout; all 24 native libraries passed ZIP/LOAD/RELRO 16-KiB alignment checks.

## Fresh runs

| Run | Layout | Android installer API | Real data-plane client | Result |
|---|---|---|---|---|
| 1 | B entry / A exit | 26 | Embedded Android IKEv2 | Passed |
| 2 | A entry / B exit | 26 | Isolated Linux IKEv2 on the exit VPS | Passed |
| 3 | B entry / A exit | 36 | Embedded Android IKEv2 | Passed |
| 4 | A entry / B exit | 28 | Isolated Linux IKEv2 on the exit VPS | Passed |

Each run began after the previous pair was removed through the actual phone UI: review both nodes, type DELETE PAIR, stop/remove the entry, remove the exit, then swap roles. Independent SSH audits confirmed managed accounts/configuration/certificates/keys/history were removed, as were owned firewall chains, policy routes, the tunnel device and XFRM state. Ubuntu, package binaries, SSH identities and unrelated files remained. This is a gateway data reset, not an OS factory rebuild. Separately saved root-only recovery archives remain outside its scope.

The APK independently rejected unknown/changed SSH keys before authentication, refused two aliases of the same machine, and installed exit first under a guarded entry. An optional native SSH management relay was used because one management path was unavailable directly. Both physical-node keys stayed pinned; no desktop forwarding was used for the app's installation. An audit-only loopback SSH relay was used by the independent checker.

## What passed

- Pinned AmneziaWG 3.1 tools/module, a real cross-provider handshake and MTU 1280.
- Healthy IKE/statistics at the entry; AdGuard Home and Unbound at the exit; private DNS/dashboard sockets.
- Actual authoritative recursive DNS on the providers, with no lab TLS DNS forwarding.
- Standard blocking list loaded; Strong → Standard switches completed after loaded-rule checks. Failed-download unit tests preserved the existing filter.
- Real authenticated IKEv2/EAP, HTTPS exit IPv4, ad DNS and authenticated client-pool forwarding counters on both nodes.
- Bridge stop retained the entry blackhole and blocked a literal-IP TCP request while IKE remained established; restart restored HTTPS and DNS.
- Planned phone-process termination during exit bootstrap: the detached server job completed, and the same pair/APK resumed.
- Both-node reboot: saved certificate/tunnel material remained; services, routing and DNS recovered; the embedded client reconnected.
- Fresh entry certificates and tunnel material differed in every run; completed jobs removed secret requests and temporary configurations.

The isolated Linux client ran in network and mount namespaces on the exit VPS. Its veth firewall allowed only encrypted outer IKE to the entry and rejected plaintext VIP fallback. HTTPS was bound to the assigned VPN address, and both nodes' client-pool counters increased. This exercised the actual entry and backhaul across provider networks, including outage/recovery; it is not a physical-phone test. Its temporary namespace, chains and IKE files were removed, and host DNS remained unchanged. [QA client source](../tests/integration/ike_client_namespace.py), [strongSwan namespace documentation](https://docs.strongswan.org/docs/latest/howtos/nameSpaces.html).

## Failed attempts and network boundary

Development and unsuccessful attempts are excluded from the successful-run table. The original kernel on A lacked available matching headers; the app installed a current distribution kernel, offered its owned reboot and resumed. That kernel-replacement path was exercised on the development APK before the reset fix. A service-owned AdGuard directory initially exposed a reset review issue; the corrected release explicitly validates its service UID and root-owned ancestors, with a regression test and successful real resets.

Android-emulator IKE to A failed on UDP 500 and the supported custom UDP 443 port. A received requests and generated replies; the client saw no response. A separate short-lived UDP echo control received seven requests on A with no return reaching this computer, while the same control worked with B. IKE to A succeeded from the provider-side isolated client. This establishes a client-network return-path limitation, not a wrong-password diagnosis. Its precise network location remains unknown. A successful provider-side client does not certify a phone's Wi-Fi/mobile route to A.

Android 16's native coordinator and embedded IKEv2/separate-UID checks passed. Screen navigation remains incomplete: this emulator repeatedly showed system-wide startup ANRs in System UI/Google services. Unrelated Google apps were disabled on the empty test emulator to complete the independent native gates. Android 8/9 phone reset/navigation controls passed. Physical/OEM devices, ordinary permission prompts, real IPv6 underlays, network handoff/lockdown, sustained load, ARM64 servers and native 16-KiB runtime remain separate gates.

The failed literal IPv6 probe used an IPv4 emulator underlay; it does not establish real dual-stack mobile leakage behavior. DNS filtering cannot reliably remove YouTube in-video ads or force apps with private encrypted DNS to use the gateway resolver. Address reputation and each client's network still affect access.

[Machine-readable evidence](test-results/pair-provider-alpha2.json) · [Pair operations](PAIR-MODE.md) · [Historical local alpha1 tests](PAIR-TESTING.md)
