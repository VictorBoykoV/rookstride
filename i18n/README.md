# Shared languages

English is the source catalog. Android strings, plural resources and compact offline beginner guides are generated from these JSON catalogs; the static website uses the same reviewed text. No new runtime translation dependency or cloud translation call is required.

| Locale | Name | Direction |
|---|---|---|
| en | English | Left to right |
| ru | Русский | Left to right |
| fa | فارسی | Right to left |
| ar | العربية | Right to left |
| zh-Hans | 简体中文 | Left to right |

Locale selection reflects the intended audience, not a measured ranking of VPN use. Stories and detailed engineering documents remain English in this release. The first journey and ordinary controls are translated.

## Update workflow

1. Edit `en.json`, with context in `contexts.json`. Semantic keys are preferred for new text. Legacy `m_…` keys identify existing source literals.
2. Update the same keys in every locale. Preserve named placeholders, fragment whitespace and the exact English deletion confirmations. Never translate stored protocol names, API fields, passwords, addresses, keys or fingerprints.
3. Review meaning, negation, safety prompts, entry/exit roles, shared terminology and layout expansion. Record the reviewer and source hashes in `reviews.json`. A source-text change invalidates prior translation review. A translation edit invalidates its file hash.
4. Run `python3 scripts/compile-locales.py`. Commit generated Android resources/index/guides with catalogs. Run website and native locale checks. Test right-to-left layouts and technical inputs, rather than shortening translations until they fit.
5. Keep native-speaking community review separate from model review. Report missing linguistic or device gates honestly.

Flat JSON catalogs are suitable for future Weblate import. A translation service is optional; keys, placeholders, review hashes and automated checks remain the repository's contract. Do not silently substitute English for missing committed keys. Unsupported device languages fall back to English; explicit English technical details are labeled.

See [research and platform backlog](../docs/PLATFORMS-AND-LANGUAGES.md) and [test scope](../docs/LOCALIZATION-TESTING.md). The APK carries compiled text, not translation tooling or review records. Artwork is shared across languages, keeping the increase mostly text.
