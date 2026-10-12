# Testing and release gates

Current release: **0.1.0-alpha2**, tested 13 October 2026. Earlier alpha1 checks are identified separately below.

## Three consecutive final-release cycles

All three runs used the **same signed, non-debuggable release APK**. Its installed checksum was matched against the build; testing did not substitute a debug app. The VPS was explicitly authorized for repeated gateway resets.

| Cycle | Android emulator | Result | Additional check |
|---|---|---|---|
| 1 | Android 16 / API 36 | PASS | Purged ten managed VPN/DNS packages; deliberately planted a stale VICI socket before installing. |
| 2 | Android 9 / API 28 | PASS | Fresh alpha1 installation upgraded to the final alpha2 signer/version. |
| 3 | Android 8 / API 26 | PASS | Signed alpha1 → alpha2 upgrade; rebooted the VPS and checked recovery before connecting. |

Each cycle independently checked:

1. App-driven reset, then an independent SSH audit: managed configuration/data and firewall chains removed, services stopped, private DNS address removed, SSH preserved.
2. App-driven installation, strict unknown/changed SSH-key rejection, user creation/removal, password-free pinned profile export and Strong → Standard filtering changes.
3. Independent server audit: six services healthy, loaded IKEv2 connection, working recursive DNS, blocked advertising test domain, suppressed AAAA answers, private DNS/dashboard listeners, exactly one jump per managed firewall chain, valid certificate chain, completed job and deleted temporary password/configuration files.
4. A real embedded IKEv2/EAP tunnel. A **separate application UID** checked HTTPS exit IPv4 against the selected VPS, blocked advertising DNS and a failed literal IPv6 connection. Rookstride's own administration traffic is exempt from its tunnel.

Certificates differed across all three installations. Cycle 3 retained its certificate and passed the same server audit after reboot. End-to-end cycle times were 225.0, 160.2 and 201.4 seconds, including reset, audits and a 45-second connected test; these are not installer-only speed benchmarks. Ubuntu and SSH were retained. Cycles 2 and 3 reused package binaries but removed gateway data and certificates; cycle 1 additionally purged the managed packages.

[Sanitized machine-readable results](test-results/alpha2.json) contain no deployment address, credentials or certificate fingerprints.

### Regression fixes verified

- **Cold installation and stale control socket:** a socket inode could survive a reset while the newly installed VICI plugin had not loaded. Checking only the socket file could incorrectly report readiness. Reset now removes the stopped daemon's socket, and enrollment requires an actual successful VICI `version` exchange, restarting and waiting when needed. The deliberately injected socket in cycle 1 verified this fix.
- **Modern Android native alignment:** NDK r27's flexible-page option supplied `max-page-size` but left RELRO aligned to 4 KiB. The build now also supplies `common-page-size=16384`. ZIP alignment and LOAD/RELRO alignment pass for all 24 native libraries across the three ABIs. This follows [official Android guidance](https://developer.android.com/guide/practices/page-sizes); a native 16-KiB runtime/device test remains a gate.

Early failed candidate runs are not counted as passes. Android 16's initial emulator boot hit System UI/Bluetooth failures and focus timeouts on the memory-limited host. After reducing background work and allowing startup to settle, the unchanged app passed the UI/Keystore tests and full cycle. Only one emulator ran at a time, and build tools were stopped before final tests.

VPN consent, battery exemption and notification permission were pregranted **only in disposable emulators** for automation. Physical phones still show normal Android permission dialogs; OEM behavior remains a separate test.

## Completed

- 25 Python tests pass: baseline/reset handling, shared accounts, reconnect/rekey generations, collector restart persistence, retention, malformed VICI messages, management input validation, credential quoting, reload rollback, reviewed gateway removal and removal of a real closed Unix socket.
- 86 Android JVM unit tests pass, including upstream parsing/range tests and administration input/secret persistence checks.
- Android 8/API 26, Android 9/API 28 and Android 16/API 36 emulators: navigation/demo/offline guide, Android Keystore encryption, strict SSH unknown/changed-key rejection, root authentication, deployment, user creation/removal, pinned profile export and AdGuard preset changes pass on the final signed APK.
- App-driven reset passes on both partial and running gateway services. Managed VPN/DNS files and firewall chains are removed; Ubuntu and SSH remain available. A clean app-driven reinstall completes.
- The embedded strongSwan engine establishes a real IKEv2/EAP-MSCHAPv2 tunnel. A separate test application confirms the selected VPS's IPv4 exit address, blocked test advertising DNS domain and failed literal IPv6 connection. The test application has a different Android UID because Rookstride's administration traffic is exempt from the tunnel.
- During alpha1 testing, the owner imported a profile into the official strongSwan app on a physical phone and confirmed connection and website access. That does not replace physical testing of the Rookstride APK.
- Alpha1 live accounting test: distinct old/new CHILD_SA generations appeared after rekey, totals persisted across collector restart, and revocation removed the temporary login and its established CHILD_SAs. Disconnect alone allowed client auto-reconnection, as the UI explains. The accounting Java/Python implementation is unchanged in alpha2.
- Alpha1 resource sample: on a one-CPU Ubuntu VPS with about 1.92 GiB RAM, a 40-second sample measured 15,516 KiB collector RSS, 0.025% of one CPU core and 189,120 bytes of database/WAL files. This is a short single-client sample, not a sustained-load capacity benchmark.
- The final signed, non-debuggable release builds for arm64-v8a, armeabi-v7a and x86_64; APK v2 signatures and 16-KiB alignment verify. Development/debug builds and JVM tests also passed during alpha2 development.
- Pinned strongSwan/OpenSSL source archives are checksum verified. The Android-native crypto smoke test confirms MD4 and DES support required for EAP-MSCHAPv2.
- Gateway repository checks pass. The live deployment exposed and fixed AdGuard archive member prefixes, ZIP executable permissions and readiness-check SIGPIPE/connection inspection.

## Remaining compatibility and stable-release gates

- Rookstride APK on API 26 and API 36 physical devices, including private-key SSH, permission dialogs, rotation, process restart, battery restrictions and ARM/16-KiB runtime behavior.
- Sustained throughput, many simultaneous shared-login clients and resource measurements on a 1-GB VPS.
- Network handoff, IPv6-capable mobile/Wi-Fi networks and always-on lockdown behavior on physical devices.
- Certificate-bound device authentication. This alpha uses separate per-device EAP logins and administrator labels; copying credentials does not bind them to physical hardware.

The phone profile test does not replace testing this new APK on physical devices. This release remains an alpha. Usage counters are operational estimates, not billing records. No claim of leak prevention while the VPN is disconnected is made; Android lockdown is a separate phone setting.

## Local host and server

Build host: Intel macOS 15.7, Temurin JDK 17.0.20.1, Android Gradle Plugin 8.13.0, Gradle 8.13, Android SDK 36, NDK 27.3.13750724. Minimum app API is 26; target API is 36. Emulators: Google APIs x86_64 images for APIs 26, 28 and 36, with hardware acceleration and 4-KiB runtime pages.

Server: Ubuntu 24.04.4, Linux 6.8.0-142-generic, packaged strongSwan 5.9.13, AdGuard Home 0.107.79. Embedded Android engine: strongSwan 6.1.0 with OpenSSL 3.5.9.

## Repeat the checks

1. Obtain explicit authorization to reset a disposable Ubuntu 24.04 gateway. Keep fixtures/logs outside Git and independently verify its SSH fingerprint.
2. Build the signed release and verify the APK as described in [BUILD.md](BUILD.md). For connected tests against a non-debuggable release, sign the instrumentation APK with the same certificate and install it with the release; do not count `connectedDebugAndroidTest` as testing that release binary.
3. The opt-in `ResetIntegrationTest`, `GatewayIntegrationTest` and `VpnConnectionTest` read `reset-test.json`, `integration.json` and `vpn-test.json` from the target app's private files. Their source defines the fixture contracts. A missing fixture skips the test: **a skipped test is not a deployment pass**. Rooted disposable emulators can stage fixtures; do not root an everyday phone for this purpose.
4. Independently inspect services, listeners, DNS, certificate validation, firewall rules and removal of temporary job files over SSH after each installation. Use the separate [traffic probe](../tests/probe) to exercise another application UID.
5. Repeat reset/install for each Android version, including one package-clean bootstrap and one VPS reboot. Record the installed APK checksum, fresh certificate identities privately and every failure. Export only sanitized results. Remove private fixtures and test applications afterward.

Private integration fixtures and logs remain outside Git. Live deployment/reset tests are opt-in and require owner authorization on a disposable or explicitly repurposed VPS. Do not leave private test configuration on a device used for routine connected-test runs.
