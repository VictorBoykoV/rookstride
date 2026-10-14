# Rookstride 0.2.0-alpha3: progress and story tests

Checked 14 October 2026. Signed version code **5**, minimum API **26**, target API **36**.
The final APK is non-debuggable and uses the existing release certificate.

APK SHA-256: `a266710d9a6d6f96fde24603d13d06ff27465a95392654af3a4ecf71f37b690a`

## Exact signed release

| Emulator | Instrumentation cases | Result |
| --- | ---: | --- |
| Android 8.0 / API 26 | 5 | Passed |
| Android 9 / API 28 | 5 | Passed |

The same final APK passed both rows. Tests ran against the release package using a
separately signed instrumentation package with the same certificate. No VPS was
reset, reinstalled or changed by these tests.

The five cases cover:

1. Labeled offline demo, People, Sessions and Guide navigation.
2. Encrypted administrator credentials on disk and successful Vault decryption.
3. Real single-server foreground service while browsing Stories/Guide, returning
   to progress, recreating the Activity and moving it into the background.
4. The eight-checkpoint pair recipe, both health snapshots and explicit completion
   while the real foreground service runs independently of Stories.
5. The real asset-only WebView, five worlds, four-page reading, word-range
   highlighting, narration page advance, end-of-chapter stop, manual transitions,
   whole-chapter mode and disabled file/content/network access.

Transport is a bounded test fixture in cases 3 and 4. Narration events are a
controlled offline voice fixture in case 5. These tests exercise actual Android
services and WebView behavior; they are not provider deployments or audible TTS
quality checks. Public screenshots retain the explicit progress-fixture label.

## Source and artwork checks

- 49 Python server regression tests and 97 Android JVM tests passed.
- 24 native libraries across arm64-v8a, armeabi-v7a and x86_64 passed ZIP, LOAD and
  RELRO 16-KiB alignment checks. This is a packaging audit, not a native 16-KiB
  runtime test.
- Exact embedded gateway/server/two-hop files and all **134 offline story files**
  match the release source.
- 67 static website pages pass link, metadata, structured-data and public-data
  checks. Every chapter contains its complete text without JavaScript.
- Five worlds, fifty chapters and two hundred unique narrated pages contain
  **12,879 words**. Forty-five new original comic spreads plus the five preserved
  strips have two hundred bounded, inspected narration highlights.
- The separate [artwork audit](../website/qa/artwork-alpha3-audit.json) verifies
  selected PNG/WebP hashes, dimensions, sizes, portable provenance, cross-world
  character continuity and the six canonical helper vectors.

Compatibility fixes found during these iterations include directory URL handling,
old-WebView JavaScript syntax, flex spacing, missing legacy-reader assets and
captions covering illustrated focus objects. The first five Harbor retellings now
match the original art. Android 8/9 screenshots confirm that the actual paintings
render and captions sit beneath them. Browser checks cover one-page/whole-chapter
navigation, narrow-screen layout, voice availability and chapter stopping; an
available browser voice is not an audible performance certification.

## Android 16 and remaining gates

The Android 16 development emulator repeatedly displayed a system-wide **System UI
isn't responding** dialog. Of four development instrumentation cases, encrypted
storage passed; three UI cases failed because the window could not receive focus.
Graphics/backend changes and a fresh boot did not establish a reliable UI gate.
The final signed alpha3 UI is therefore **not certified on Android 16**. That is
separate from the earlier alpha2 native coordinator/VPN evidence.

Physical/OEM devices, ordinary permission prompts, audible installed English offline
voices, real IPv6/mobile handoff/lockdown, sustained VPS load and native 16-KiB
runtime remain gates. Narration is optional and does not open another chapter.

## Historical server evidence

The installer identity remains
`996adf929ac1b0d244a530a7b0ae89817e68fbaf8018f0bffebb53e9d9947c7f`,
exactly matching 0.2.0-alpha2. Its [four fresh provider-pair runs](PAIR-PROVIDER-TESTING.md)
tested that exact earlier APK. They are retained as historical evidence, without
being relabeled as fresh alpha3 deployments.

[Machine-readable current results](test-results/ui-alpha3.json) ·
[Installation progress and recovery](INSTALLATION-PROGRESS.md) ·
[Build and corresponding source](BUILD.md)
