# Experimental pair testing

Build: **0.2.0-alpha1**, tested 13 October 2026. The same signed, non-debuggable APK passed three fresh two-node deployment cycles. Both disposable Ubuntu 24.04 machines were factory-reset between cycles; each had one vCPU, one GiB RAM and an eight-GiB disk.

| Cycle | Android emulator | Result | Extra check |
|---|---|---|---|
| 1 | Android 9 / API 28 | PASS | Fresh app-driven pair install and independent audits. |
| 2 | Android 8 / API 26 | PASS | Killed the phone app during bootstrap; the same owned job continued and resumed to completion. |
| 3 | Android 9 / API 28 | PASS after retries | Rebooted both configured nodes; services, guarded routing and the certificate persisted. Management needed one cold-list retry. |

## What each cycle checked

- Unknown and changed SSH keys rejected on both nodes before credentials; keys independently obtained from the test-machine consoles.
- Same-machine aliases refused before any mutation. Independent management ports and separate VPN/backhaul endpoints supported.
- App-driven exit-first bootstrap, entry guard, AWG 3.1 configuration, exit-side AdGuard Home/Unbound, staged handshake/IPv4/DNS verification and activation.
- User creation/revocation, password-free certificate-pinned profile export, MTU 1280, IPv6 blocking flags and exit-side filter preset changes.
- A real IKEv2/EAP tunnel in the embedded Android engine. A separate application UID verified HTTPS, exit IPv4, ad-domain DNS blocking and a failed literal IPv6 probe.
- Client-pool packet counters at entry and exit corroborated the backhaul path. A positive literal IPv4 TCP test became unreachable after stopping the entry bridge; a blackhole route remained. Restarting the bridge restored HTTPS and DNS filtering.
- Independent SSH audits: healthy services, module version, private DNS/dashboard listeners, immutable tunnel configuration, root-only keys, removed job requests/temporary password files, valid certificates and active guarded routes.

Cycle 3 completed installation and activation, then a management request timed out while AdGuard fetched the larger Strong list. The same signed APK resumed the owned pair and repeated the management checks after that download, including returning to Standard. This retry is recorded, not presented as an uninterrupted first-attempt pass. The first post-reboot DNS audit also ran before cold startup had settled; the repeated audit passed. The VM network discarded its test-only UDP forwarding exposure during the both-node reboot. It was restored before repeating the real-client test; no server installer or APK code changed.

Certificates differed across all three fresh installations. The cycle-3 certificate survived the both-node reboot. [Sanitized machine-readable evidence](test-results/pair-alpha1.json) records the checks without host addresses, credentials, keys or deployment certificate identities.

## Regression fixes and candidate runs

Development candidates are excluded from this pass series. Testing found and fixed a same-file installation error, matching-header detection that could select an unnecessary kernel upgrade, single-server DNS unit dependencies in the paired exit, transient systemd status-query failures, cold-resolver startup timing, and differing file-order rules between the phone and server’s installer-identity calculation. The complete real installer now has a cross-language identity regression check.

A cycle-3 fixture initially retained pre-restart SSH fingerprints. The app rejected the mismatch before authentication; identities were checked again through trusted VM access and the private fixture was refreshed before the successful fresh cycle. No host-key check was bypassed.

The lab’s initial loopback UDP relay established IKE but did not provide a representative IPsec return route. Final tests used the local VM network’s opaque UDP forwarder with a distinct peer address. The separate probe is cold-started for every measurement; the outage probe uses bounded literal-IP TCP to avoid counting a long DNS wait as a test result.

## Practical limits

The Android 16 / API 36 emulator repeatedly hit System UI ANRs and navigation focus failures before the pair installer ran. This is an incomplete compatibility gate, not a pass; the third fresh pair cycle used Android 9 / API 28. The earlier single-server alpha2 Android 16 result does not certify this new build.

Both machines share one physical host and public NAT address. Exit-IP agreement alone does not establish routing; authenticated-interface/client-pool counters were checked too. These tests do not certify a deployment between independent providers.

The local VM network intercepts ordinary authoritative DNS queries. A lab-only DNS-over-TLS forwarding file was used by Unbound; it is absent from the APK installer. Production installation defaults to recursive Unbound. Authoritative recursion must be checked from the chosen VPS network.

Emulators ran x86_64 with four-KiB pages. VPN consent and required permissions were pregranted only for automation. A failed literal IPv6 probe on this lab is not a test of an IPv6-capable mobile underlay.

Remaining gates: Android 16 pair UI and real-client rerun, physical Android devices/OEM behavior, independent-provider pairs, IPv6-capable handoff, sustained multi-user/one-GB capacity, native 16-KiB runtime, ARM64 server execution and the kernel-replacement/reboot branch. The APK includes arm64-v8a, armeabi-v7a and x86_64 and passes static 16-KiB ZIP/LOAD/RELRO checks. This is an experimental alpha; pair upgrades, arbitrary-pair import and pair data reset remain unsupported.

## Repeat the checks

Build and verify the signed APK using [BUILD.md](BUILD.md). The opt-in `PairIntegrationTest` reads `pair-integration.json` from the target app’s private files; its source defines the Gateway graph, separately verified host-key sets and fresh-install flag. A missing fixture skips the test and does not count as a pass. The test writes a private `vpn-test.json` for `VpnConnectionTest`.

Use two disposable fresh Ubuntu nodes. Keep fixtures/logs outside Git. Sign instrumentation with the same certificate as the non-debuggable release and check the installed APK checksum. Factory-rebuild both nodes between cycles. Independently check service health, source/config ownership, certificates, route guards and private DNS listeners. Run the separate [traffic probe](../tests/probe) under its own UID; establish positive connectivity before simulating a bridge outage. Close the app during one server job, resume it, and reboot both nodes in another cycle. Keep private keys on their nodes and export only sanitized boolean results.
