# Build Rookstride

## Requirements

Use macOS or Linux with Python 3.9+, JDK 17, Perl, Make, Git, Android SDK command-line tools, and several GB of free storage. The tested host configuration is recorded in TESTING.md. The repository holds the administration overlay; the bootstrap downloads checksum-pinned upstream source archives.

Install the Android SDK at `.tools/sdk` (or set `ROOKSTRIDE_SDK` to an existing SDK). Accept the Android SDK licenses yourself with `sdkmanager --licenses`, then install:

```sh
sdkmanager 'platform-tools' 'platforms;android-36' 'build-tools;35.0.0' 'ndk;27.3.13750724'
```

Use JDK 17 via `JAVA_HOME`. Dependencies are downloaded from Google's repository and Maven Central. Source inputs are strongSwan 6.1.0 and OpenSSL 3.5.9; checksums are in `scripts/bootstrap.py`. The Gradle 8.13 distribution is checksum verified. Java dependencies have exact versions in `scripts/prepare-android.py` and upstream Gradle files.

```sh
python3 scripts/bootstrap.py
# If SDK is elsewhere, set ANDROID_NDK_HOME to its ndk/27.3.13750724 directory.
bash scripts/build-crypto.sh
bash scripts/build-android.sh assembleDebug testDebugUnitTest
```

The first native build takes several minutes. Result:
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

Verify with Android SDK `apksigner verify --verbose --print-certs`. Publish the APK's SHA-256, signing certificate fingerprint and exact source revision. Updates must use the same signing key. Losing the key prevents seamless updates. The alpha build includes arm64-v8a, armeabi-v7a and x86_64; publishing architecture-specific APKs can reduce download size.

`release.json` is the version-name/version-code source for both APK preparation and source packaging. Increment the code for updates. Alpha2 retains alpha1's signing certificate.

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

## Corresponding source

A binary release includes the exact Rookstride source, three verified native upstream archives, and source JARs with published Maven metadata for the exact resolved release-runtime libraries. After building, run `python3 scripts/collect-java-sources.py`, then `python3 scripts/source-bundle.py`. The collector uses the resolved release classpath, official Google Maven/Maven Central sources, and records per-file SHA-256 hashes. Packaging verifies those hashes and excludes toolchains, credentials, compiled files and signing material. This package is sufficient to reapply the overlay and rebuild with the documented toolchain. A reproducible recipe is provided; bit-identical output across hosts has not been established.

Use the same pinned sources when reproducing a release. Updating strongSwan or OpenSSL requires rebuilding all crypto ABIs, reviewing the overlay patch points, and rerunning server, emulator and VPN integration gates.

## Two-server experimental build

The `0.2.0-alpha1` bundle includes `server`, the MIT `twohop` snapshot and the single-server `gateway` snapshot. The APK contains a SHA-256 installer identity calculated in canonical POSIX lexical path order within those three folders. The Java coordinator and Python helper must agree before an owned pair can resume. `verify-apk.py` checks the embedded files and identity; JVM tests compare the actual generated bundle as well as fixtures.

The signed instrumentation APK must match the release signing certificate. `PairIntegrationTest` is opt-in and requires two disposable Ubuntu 24.04 nodes with independently verified host keys. See [PAIR-TESTING.md](PAIR-TESTING.md) for the complete test scope and incomplete compatibility gates. Never include deployment fixtures, private logs or signing keys in a source archive.

## Offline stories and helper poses

The checked-in Android story assets are the exact static reader inputs for the
release. To regenerate them after a story, artwork or reader edit, run:

```sh
python3 website/scripts/build.py
python3 website/scripts/check-worlds.py
python3 website/scripts/check.py
```

The builder uses Python’s standard library. It builds the local static site and
the asset-only Android edition from the same complete story source. SVG viewports
frame original paintings; the original PNGs and exact prompts remain in the
website source. `prepare-android.py` converts the six canonical SVG helper poses
to Android vector drawables, with a strict supported-feature check. No image
generation service is needed to build the provided assets.

Corresponding-source archives include the website source, story text, artwork
masters, reader and converter in addition to the pinned upstream archives.
Publishing metadata can be added to the website after the app snapshot is tagged;
it does not change the tagged app or its embedded story assets.
