# Localization test scope — 0.2.0-alpha4

This release adds five shared interface catalogs, native language selection, right-to-left layouts and translated beginner pages. It changes presentation, not server recipes or protocol engines. Historical alpha2 provider-pair runs and alpha3 reader/service tests retain their original APK identities.

The [machine-readable report](test-results/localization-alpha4.json) identifies the exact signed, non-debuggable APK. It records 56 Python tests, 97 JVM tests, signed release emulator checks and browser validation. The installer source digest remains unchanged; this release does not claim another provider reset/install cycle.

## Language and maintenance checks

557 messages per language: English, Russian, Persian, Arabic and Simplified Chinese. Authors reread their work, then a separate model reviewer compared meaning and requested corrections. Catalog keys, named/printf placeholders, fragment whitespace, technical identifiers, deletion phrases and plural forms are checked. Source text, English plural, translated catalog and translated plural hashes invalidate stale review. Compiled English strings round-trip against the native source index, so resource parsing cannot silently remove spaces or change escapes.

These are **model reviews, not native-speaking human review**. The [review record](../i18n/TRANSLATION-REVIEW.md) keeps community review unclaimed. Stories, narration and detailed engineering documents remain English, with translated notices.

## Signed native gates

The functional suite covers demo/guide/user/session navigation, Keystore encryption, real foreground-service survival through tabs/recreation/backgrounding, eight-checkpoint pair completion with bounded transport, offline narration events with a deterministic voice fixture, five language layouts, technical inputs, user-provided names/logins, persisted locale recreation, language changes during installation and bundled guides/plurals. The same APK is identified in every completed emulator row of the JSON report.

Android 8 runs at **130% text size**, checking text height and ellipsis as well as RTL direction and original technical inputs. A login literally named `Phone` remains `Phone`, rather than being mistaken for a translatable UI label. Enlarged onboarding scrolls. Raw passwords and draft secrets are not copied into locale catalogs or activity state.

Android 16 passed both resource/framework-language and encrypted-storage cases on the same signed APK. The locale case held an Activity lifecycle, without screen-focus assertions, and used non-streaming installation after the package service broke a streaming connection. These checks are separate from full screen navigation. Full Android 16 UI and physical-device behavior are not inferred from Android 8/9 passes.

## Website gates

104 static pages: 68 English pages, plus nine beginner pages in each additional locale. All local links, assets, metadata and release evidence are checked. A separate publication-mode build checks reciprocal language alternatives and the sitemap against a test origin; the distributed local build does not invent a hosted domain. Browser checks cover all 36 translated pages at the actual 400-pixel narrow viewport and four desktop infrastructure pages. No horizontal overflow was observed. Requested viewport sizes can differ from the browser's actual size; the report records the actual dimensions.

Language menus preserve available beginner routes. English story/technical pages clearly disclose their language. Saved-language and browser-language hints offer a choice, without forced redirects. Technical route diagrams and hashes are isolated LTR; art is shared and unmirrored. The locked offline comic export removes website-only language controls.

## Corrections and testing limits

Early tests found a language-dialog message hiding its choices. Visual review found reversed RTL fractions and adjacent header labels. Resource review found the need to quote Android strings to retain fragment whitespace. These issues were fixed before the reported final gates.

Test tooling also needed explicit English setup for legacy fixtures and rendered-frame screenshot waits. Three concurrent emulators plus a build overloaded the test host, expiring bounded transport waits and WebView callbacks; final functional runs use one emulator at a time. Test fixture transport and speech events are not provider deployment or audible narration claims.

Remaining gates: native-speaking community review, physical/OEM devices and screen readers, actual audible offline voices, full Android 16 UI navigation, real IPv6/mobile handoff and lockdown, sustained small-VPS load, and actual native 16-KiB runtime behavior. A build, aligned libraries, emulator checks and real-device VPN tests are separate evidence.
