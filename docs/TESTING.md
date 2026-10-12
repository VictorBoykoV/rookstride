# Testing and release gates

Current release: **0.1.0-alpha1**, tested 12 October 2026.

## Completed

- 24 Python tests pass: baseline/reset handling, shared accounts, reconnect/rekey generations, collector restart persistence, retention, malformed VICI messages, management input validation, credential quoting, reload rollback and reviewed gateway removal.
- 86 Android JVM unit tests pass, including upstream parsing/range tests and administration input/secret persistence checks.
- Android 9/API 28 emulator: navigation/demo/offline guide, Android Keystore encryption, strict SSH unknown/changed-key rejection, root authentication, fresh deployment, user creation/removal, pinned profile export and AdGuard preset changes pass.
- App-driven reset passes on both partial and running gateway services. Managed VPN/DNS files and firewall chains are removed; Ubuntu and SSH remain available. A clean app-driven reinstall completes.
- The embedded strongSwan engine establishes a real IKEv2/EAP-MSCHAPv2 tunnel. A separate test application confirms the selected VPS's IPv4 exit address, blocked test advertising DNS domain and failed literal IPv6 connection. The test application has a different Android UID because Rookstride's administration traffic is exempt from the tunnel.
- The owner imported the replacement profile into the official strongSwan app on a physical phone and confirmed connection and website access.
- A live test login successfully rekeys: distinct old/new CHILD_SA generations are present in the usage database. Traffic totals persist across a collector restart. Revoking the temporary login removes it and leaves no established CHILD_SA for it. Disconnect alone allows client auto-reconnection, as the UI explains.
- On a one-CPU Ubuntu VPS with about 1.92 GiB RAM, a 40-second sample measured 15,516 KiB collector RSS, 0.025% of one CPU core and 189,120 bytes of database/WAL files. This is a short single-client sample, not a sustained-load capacity benchmark.
- Debug and signed, non-debuggable release APKs build for arm64-v8a, armeabi-v7a and x86_64. APK v2 signatures verify.
- Pinned strongSwan/OpenSSL source archives are checksum verified. The Android-native crypto smoke test confirms MD4 and DES support required for EAP-MSCHAPv2.
- Gateway repository checks pass. The live deployment exposed and fixed AdGuard archive member prefixes, ZIP executable permissions and readiness-check SIGPIPE/connection inspection.

## Remaining compatibility and stable-release gates

- Rookstride APK on minimum API 26 and current API 36 physical devices, including install/upgrade, private-key SSH, VPN consent, rotation, process restart and battery restrictions.
- Sustained throughput, many simultaneous shared-login clients and resource measurements on a 1-GB VPS.
- Network handoff, IPv6-capable mobile/Wi-Fi networks and always-on lockdown behavior on physical devices.
- Certificate-bound device authentication. This alpha uses separate per-device EAP logins and administrator labels; copying credentials does not bind them to physical hardware.

The phone profile test does not replace testing this new APK on physical devices. This release remains an alpha. Usage counters are operational estimates, not billing records. No claim of leak prevention while the VPN is disconnected is made; Android lockdown is a separate phone setting.

## Local host and server

Build host: Intel macOS 15.7, Temurin JDK 17.0.20.1, Android Gradle Plugin 8.13.0, Gradle 8.13, Android SDK 36, NDK 27.3.13750724. Minimum app API is 26; target API is 36. Emulator: Android 9/API 28 x86_64 with hardware acceleration.

Server: Ubuntu 24.04.4, Linux 6.8.0-142-generic, packaged strongSwan 5.9.13, AdGuard Home 0.107.79. Embedded Android engine: strongSwan 6.1.0 with OpenSSL 3.5.9.

The first emulator setup hit System UI ANRs; a lighter configuration and hardware graphics passed subsequent checks. The first supplied test VPS was unreachable. Testing used the replacement VPS after its owner explicitly authorized deleting the prior gateway and reusing it.

Private integration fixtures and logs remain outside Git. Live deployment/reset tests are opt-in and require owner authorization on a disposable or explicitly repurposed VPS. Do not leave private test configuration on a device used for routine connected-test runs.
