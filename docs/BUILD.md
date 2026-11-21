# Build Rookstride

Use the [v0.4.0-alpha6 tag and corresponding source](https://github.com/VictorBoykoV/rookstride/releases/tag/v0.4.0-alpha6)
to reproduce the published Android prerelease. The default branch also carries
web app and documentation updates. See [web app setup](../web/README.md) for
the separate Node.js build.

## Requirements

Use macOS or Linux with Python 3.9+, JDK 17, Perl, Make, Git, Android SDK command-line tools, and several GB of free storage. The tested host configuration is recorded in TESTING.md. The repository holds the administration overlay; the bootstrap downloads checksum-pinned upstream source archives.

Install the Android SDK at `.tools/sdk` (or set `ROOKSTRIDE_SDK` to an existing SDK). Accept the Android SDK licenses yourself with `sdkmanager --licenses`, then install:

```sh
sdkmanager 'platform-tools' 'platforms;android-36' 'build-tools;35.0.0' 'ndk;27.3.13750724' 'ndk;30.0.16248370'
```

Use JDK 17 via `JAVA_HOME`. Dependencies are downloaded from Google's repository and Maven Central. Source inputs are strongSwan 6.1.0 and OpenSSL 3.5.9; checksums are in `scripts/bootstrap.py`. The Gradle 8.13 distribution is checksum verified. Java dependencies have exact versions in `scripts/prepare-android.py` and upstream Gradle files.

```sh
python3 scripts/bootstrap.py
# If SDK is elsewhere, set ANDROID_NDK_HOME to its ndk/27.3.13750724 directory.
bash scripts/build-crypto.sh
# Install Go; GOTOOLCHAIN pins the engine build to go1.26.8.
python3 scripts/bootstrap-engines.py
python3 scripts/build-engines.py
python3 scripts/collect-go-sources.py
python3 scripts/bootstrap-routes.py
python3 scripts/build-routes.py android linux
python3 scripts/collect-route-sources.py
bash scripts/build-android.sh assembleDebug testDebugUnitTest
```

The first native build can take tens of minutes. Use an 8GB+ build host and allow roughly 10GB of temporary storage. The prepared Gradle build uses a 2GB heap and two workers for the larger native APK. Result:
`.tools/strongswan-source/src/frontends/android/app/build/outputs/apk/debug/app-debug.apk`.
This is a development APK, signed with a debug key. It coexists with the official strongSwan app because the application ID and provider authorities differ. Only one VPN can be active on Android at a time.

The build script copies original code and vector assets, embeds a password-free installer bundle, changes branding/application ID, and adds a session-only password handoff to upstream's VPN control activity. JNI's `org.strongswan.android` namespace stays intact. The original profile editor and VPN engine remain available.

## Signed release

Create and securely retain a keystore outside Git, alias `rookstride`. Supply these environment variables without placing their values in command history or build logs:

- `ROOKSTRIDE_KEYSTORE`: absolute keystore path
- `ROOKSTRIDE_SIGNING_PASSWORD`: key and store password

```sh
bash scripts/build-android.sh assembleRelease
```

Verify with Android SDK `apksigner verify --verbose --print-certs`. Publish the APK's SHA-256, signing certificate fingerprint and exact source revision. Updates must use the same signing key. Losing the key prevents seamless updates. The alpha build includes arm64-v8a, armeabi-v7a and x86_64; publishing architecture-specific APKs can reduce download size. Build the same
release with `-ProokstrideAbis=arm64-v8a` for a smaller ARM64 APK (or use
`armeabi-v7a` / `x86_64`). Rename that output explicitly by architecture and audit
it with `verify-apk.py --abi arm64-v8a`. The default includes all three ABIs.

`release.json` is the version-name/version-code source for both APK preparation and source packaging. Increment the code for updates.

With JDK 17 available, audit the actual release:

```sh
python3 scripts/verify-apk.py \
  .tools/strongswan-source/src/frontends/android/app/build/outputs/apk/release/app-release.apk
```

The checker verifies the signature, version, non-debuggable manifest, ZIP alignment, native LOAD/RELRO alignment across three ABIs, and exact embedded installer/guide contents. `--sdk`, `--ndk` and `--build-tools` accept alternate installed tool locations. Compare its signer fingerprint with your trusted release fingerprint; a valid signature alone does not establish the publisher's identity.

For NDK r27, preparation adds both `max-page-size=16384` and `common-page-size=16384` to the native linker flags, following [Android's 16-KiB guidance](https://developer.android.com/guide/practices/page-sizes). Static alignment checks do not replace testing on a 16-KiB runtime/device.

## Tests

```sh
python3 -m unittest discover -s tests -v
bash gateway/scripts/test-repository.sh
bash scripts/build-android.sh testDebugUnitTest connectedDebugAndroidTest
```

The connected test command needs an Android emulator or authorized test phone. Do not put real VPS credentials into tests or screenshots. Keep integration configuration in ignored private files.

The release-cycle procedure and independent server/client checks are described in [TESTING.md](TESTING.md). Connected debug tests exercise a debug app; testing a non-debuggable signed release requires an instrumentation APK signed with the same key. The recorded alpha2 cycles used that release configuration.

To select the release as the instrumentation target, supply the same signing
environment as above and run:

```sh
bash scripts/build-android.sh -ProokstrideTestBuildType=release \
  testReleaseUnitTest assembleRelease assembleReleaseAndroidTest
```

Install both generated APKs on an isolated emulator. Select individual connected
test classes deliberately; live deployment tests are opt-in and can change a
server. For unattended `VpnConnectionTest`, prepare VPN consent, battery exemption
and, on Android 13+, notification permission on the **test emulator** before
starting instrumentation. An unanswered Android permission dialog is not a VPN
handshake failure. Keep the separate traffic probe installed; a passing native
connection assertion alone does not assert HTTPS, DNS or IPv6 probe results.

## Corresponding source

A binary release includes the exact Rookstride source, the verified strongSwan/OpenSSL and embedded-engine archives, exact Go dependency sources/notices, and source JARs with published Maven metadata for the exact resolved release-runtime libraries. After building the engines, run `python3 scripts/collect-go-sources.py`. After the Android build, run `python3 scripts/collect-java-sources.py`, then `python3 scripts/source-bundle.py`. The collector uses the resolved release classpath, official Google Maven/Maven Central sources, and records per-file SHA-256 hashes. Packaging verifies those hashes and excludes local build outputs, credentials and signing material. Documented upstream Cronet module archives contain prebuilt libraries; Go runtime source and its build-tool pins are retained. This package is sufficient to reapply the overlay and rebuild with the documented toolchain. A reproducible recipe is provided; bit-identical output across hosts has not been established.

Use the same pinned sources when reproducing a release. Updating strongSwan or OpenSSL requires rebuilding all crypto ABIs, reviewing the overlay patch points, and rerunning server, emulator and VPN integration gates.

Alpha18 adds the protected worker, its 69 exact dependency modules, Go runtime
source, the pinned NaïveProxy source/notice archive and separately installed
TrustTunnel endpoint source. Run `collect-route-sources.py` before preparation
and `source-bundle.py`; missing or changed archives are refused. The Cronet
libraries are upstream prebuilts. Their binding/library module identities and
NaïveProxy submodule revision are recorded in `android/engines/routes/build-pins.json`.
The [engine contract](EMBEDDED-ENGINES.md) explains the unverified Chromium
build/reproduction boundary. Do not equate rebuilding the Go adapter with
reproducing those upstream libraries from Chromium source.

## Two-server experimental build

The `0.2.0-alpha1` bundle includes `server`, the MIT `twohop` snapshot and the single-server `gateway` snapshot. The APK contains a SHA-256 installer identity calculated in canonical POSIX lexical path order within those three folders. The Java coordinator and Python helper must agree before an owned pair can resume. `verify-apk.py` checks the embedded files and identity; JVM tests compare the actual generated bundle as well as fixtures.

The signed instrumentation APK must match the release signing certificate. `PairIntegrationTest` is opt-in and requires two disposable Ubuntu 24.04 nodes with independently verified host keys. See [PAIR-TESTING.md](PAIR-TESTING.md) for the complete test scope and incomplete compatibility gates. Never include deployment fixtures, private logs or signing keys in a source archive.

## Offline stories and helper poses

The Android reader has its own English Persia edition. Its canonical text and
scene catalog is `stories/persia/catalog.json`; `stories/reader` contains the
asset-only HTML/CSS/JavaScript reader. The current edition has two chapters, ten
pages per chapter and six row-major panels per page (two columns by three rows).
Text is laid out separately from paintings. The reader offers one-panel and
full-page views, saved position and manual chapter selection; it has no audio or
narration bridge.

Regenerate the checked-in Android assets after a story, artwork or reader edit:

```sh
python3 scripts/prepare-stories.py
python3 scripts/prepare-stories.py --check --check-packed
python3 -m unittest discover -s tests -p test_story_package.py -v
```

The standard-library packer replaces historical app worlds with exactly 24 files:
three reader files, one catalog and twenty optimized whole-page WebPs. Artwork
lives in `stories/persia/art/ch01-p01.webp` through `ch02-p10.webp`. Selected
unchanged masters and exact generation/reference/hash provenance remain under
`stories/persia/masters` and `provenance.json`; masters never enter the APK.
`prepare-android.py` runs the packer and removes stale prepared app assets/classes
before overlaying the current edition. No image-generation service is needed to
build supplied artwork.

The structural gate enforces 2×10×6, unique identities, caption/image association,
reviewed asset filenames and exact source/packed byte parity. `verify-apk.py`
requires the same 24 files in the APK and rejects missing, extra or duplicate
story entries. These checks do not establish cultural or visual acceptance.
Inspect all generated panels, then test the actual signed reader on normal and
compact screens with large text, reduced motion, Back/resume and offline
isolation. The internal studio records editorial and visual acceptance separately.

`prepare-android.py` also converts canonical SVG helper poses to Android vector
drawables with a strict supported-feature check. This helper conversion is
separate from story painting production.

### Historical website checks

The retained website has a separate five-world/fifty-chapter collection and its
original optional narration. It is not the current Android catalog. Read-only
checks preserve its existing text, art, links and reader contracts:

```sh
python3 website/scripts/check.py
python3 website/scripts/check-worlds.py --website-only
```

Run `website/scripts/build.py` only when website regeneration is intended. That
historical builder also writes its old Android bundle. Restore the current app
edition with `python3 scripts/prepare-stories.py`, followed by
`--check --check-packed`, before building an APK. Do not ship the retired website
bundle in place of the current Persia reader.

Corresponding-source archives include `stories` authoring text, owned masters,
optimized art, exact provenance and reader source as well as the historical
website and pinned dependencies. Private studio/editorial context stays out of
public source. Publishing metadata may be updated after an app snapshot is
accepted; it does not change the tested app or its embedded story assets.

## Mixed Ubuntu acceptance

`MixedUbuntuIntegrationTest` is an opt-in signed-app/service/SSH test. Its private
`files/mixed-ubuntu-integration.json` fixture must contain `disposable: true` and
a pinned `gateway`/`pairExit` with distinct machines, saved administrator access,
`pairEngine: native-v2`, selected methods and VPN identities. Keep this fixture
outside source/APK; independently verify both SSH keys before provisioning it.
It reviews owned cleanup, installs both nodes, survives Journal/recreation and
checks real user creation/loading/sharing. Separate Linux clients verify encrypted
egress, exit-only canaries, filtering, outage/recovery and counters. Neither is a
physical phone/carrier acceptance substitute. See [Ubuntu compatibility](UBUNTU-COMPATIBILITY.md).
