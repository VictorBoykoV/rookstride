# Copyright and third-party notices

Rookstride's original Android administration UI, local server helper, collector, tests, documentation and mascot are Copyright 2026 Victor Boyko and contributors, licensed GPL-3.0-or-later. See LICENSE.

The combined Android application embeds strongSwan 6.1.0, Copyright the strongSwan authors, licensed GPL-2.0-or-later. Upstream file headers and notices are preserved when the overlay is applied. The distribution of the combined app elects GPL version 3 or later. The source package includes the matching upstream archives and build recipe. See `licenses/strongSwan-COPYING` and the upstream AUTHORS file.

OpenSSL 3.5.9 is Copyright The OpenSSL Project Authors, licensed Apache-2.0. See `licenses/OpenSSL-LICENSE.txt` and the upstream source archive's notices.

Additional Java dependencies:

- Maintained JSch fork (mwiede), based on JCraft JSch: BSD-style license, preserved in its source/JAR.
- Bouncy Castle bcprov-jdk18on: Bouncy Castle/MIT-style license, preserved in its source/JAR.
- AndroidX and Material Components: Apache-2.0, upstream notices retained.
- Test-only JUnit, Mockito, AssertJ, AndroidX Test, Espresso and org.json retain their respective upstream licenses; these test libraries are not part of the release APK.

The bundled gateway scripts derive from `VictorBoykoV/single-vps-vpn-gateway`, revision recorded in `gateway/UPSTREAM`, and retain the MIT license in `gateway/LICENSE`. AdGuard Home is installed separately on the VPS from its official release, licensed GPL-3.0; Unbound and Ubuntu packages retain their own licenses. The APK does not bundle those server binaries.

StrongSwan, AdGuard, Android, OnePlus and Amnezia are names belonging to their respective projects/owners. Rookstride is an independent project. No vendor logo, slogan or proprietary UI artwork is included.
