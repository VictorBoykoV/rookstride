# Copyright and third-party notices

Rookstride's original Android administration UI and storage helpers, local server helper, collector, tests, documentation and mascot are Copyright 2026 Victor Boyko and contributors, licensed GPL-3.0-or-later. See LICENSE.

The combined Android application embeds strongSwan 6.1.0, Copyright the strongSwan authors, licensed GPL-2.0-or-later. Upstream file headers and notices are preserved when the overlay is applied. The distribution of the combined app elects GPL version 3 or later. The source package includes the matching upstream archives and build recipe. See `licenses/strongSwan-COPYING` and the upstream AUTHORS file.

OpenSSL 3.5.9 is Copyright The OpenSSL Project Authors, licensed Apache-2.0. See `licenses/OpenSSL-LICENSE.txt` and the upstream source archive's notices.

Additional Java dependencies:

- Maintained JSch fork (mwiede), based on JCraft JSch: BSD-style license, preserved in its source/JAR.
- Bouncy Castle bcprov-jdk18on: Bouncy Castle/MIT-style license, preserved in its source/JAR.
- AndroidX and Material Components: Apache-2.0, upstream notices retained.
- Test-only JUnit, Mockito, AssertJ, AndroidX Test, Espresso and org.json retain their respective upstream licenses; these test libraries are not part of the release APK.

The bundled gateway scripts derive from `VictorBoykoV/single-vps-vpn-gateway`, revision recorded in `gateway/UPSTREAM`, and retain the MIT license in `gateway/LICENSE`. AdGuard Home is installed separately on the VPS from its official release, licensed GPL-3.0; Unbound and Ubuntu packages retain their own licenses. The APK does not bundle those server binaries.

StrongSwan, AdGuard, Android, OnePlus and Amnezia are names belonging to their respective projects/owners. Rookstride is an independent project. No vendor logo, slogan or proprietary UI artwork is included.

The two-hop server adapter bundles MIT-licensed Two-Hop VPN Gateway scripts. Origin, reviewed base commit and file digests are in twohop/SOURCE.json; its license is retained in twohop/LICENSE. The original Rookstride coordinator/server job code remains GPL-3.0-or-later.

Shared interface catalogs and translated beginner guides are original Rookstride work under GPL-3.0-or-later. Initial translations were generated and reviewed with model assistance; native-speaking community review is a separate recorded gate. Existing upstream translations retain upstream notices.

## Embedded single-server connection engines (private alpha2 edition)

AmneziaWG Android tunnel/configuration sources retain their Apache-2.0 notices;
the pinned AmneziaWG Go v3 engine and its dependency notices are preserved in
the corresponding source. Only the selected configuration/crypto API and
userspace JNI backend are included, not the upstream application's branding.

Amnezia libXray is MIT-licensed. Its pinned Amnezia Xray-core dependency retains
MPL-2.0 and dependency notices; tun2socks and all resolved Go dependencies retain
their source licenses. The original in-memory/protection additions and Android
service integration are GPL-3.0-or-later Rookstride work.

OpenVPN 3 Core is included under its MPL-2.0 licensing option; its original
MPL/AGPL alternative headers and full upstream license are preserved. Asio uses
the Boost Software License. The original JNI bridge is GPL-3.0-or-later. The
core links a separately built static OpenSSL 3.5.9, covered above.

Exact source archives, revisions and hashes are in android/engines/pins.json.
The corresponding-source package includes those archives, the original build
recipe and patches, and the resolved Go module archives/checksums. No external
VPN application is needed for these embedded connection engines.

## Additional connection methods (private alpha18)

The original `android/engines/routes` worker integrates sing-box 1.14.3 under
GPL-3.0-or-later and Outline SDK/x under Apache-2.0. Its dependencies and notices
are preserved as exact Go module archives, sums and a manifest. Hysteria2 uses
the pinned sing-box QUIC/Salamander implementation. Outline and the Shadowsocks
WSS compatibility preset share the protected SDK adapter; no new cipher is
implemented by Rookstride. XHTTP uses the existing pinned Xray engine.

NaïveProxy uses upstream Chromium/Cronet 150.0.7871.63 libraries distributed by
SagerNet/cronet-go. These are upstream prebuilt libraries: Rookstride builds the
Go adapter, not Chromium. The package includes the exact binding/library modules,
pinned NaïveProxy source, upstream build scripts, source provenance and retained
Chromium/third-party notices. See `android/engines/routes/build-pins.json` and
`docs/EMBEDDED-ENGINES.md` for the reproducibility boundary.

TrustTunnel's official Apache-2.0 endpoint 1.1.0 is downloaded separately onto
the VPS, verified against `single/routes-pins.json`; it is not embedded in the
APK. Its source archive and license are retained. The original HTTP/2 client
adapter and private forwarding/statistics integration are GPL-3.0-or-later.

The optional OS reinstall adapter includes an unmodified source snapshot from
[bin456789/reinstall](https://github.com/bin456789/reinstall), revision recorded in
`reinstall/upstream.json`, under GPL-3.0. Rookstride applies its integration patches
at preparation time; the vendored originals, exact hashes and license are supplied
with corresponding source. This adapter is separate from VPN removal.
