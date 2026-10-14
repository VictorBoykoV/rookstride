# Languages and future clients

Research reviewed **14 October 2026**. This is a design and backlog record, not a
promise of release dates. The earlier published `0.2.0-alpha3` client is Android and English.
The `0.2.0-alpha4` language edition adds five interface catalogs and translated
beginner guides; detailed stories remain English. Browser administration, an iPhone app, and
messenger administration are **proposed**. The current website is a static local
edition; it does not accept server credentials.

## Decision

Start with **English, Russian, Persian, Arabic, and Simplified Chinese**:
`en`, `ru`, `fa`, `ar`, `zh-Hans`. These choices follow the requested audience;
they are not a ranking of VPN use or a claim that a language identifies a country.
Persian and Arabic need separate translations and right-to-left layouts.
Simplified Chinese does not cover every Chinese reader; Traditional Chinese is a
later, separate catalog.

Translate the journey that lets someone succeed: introduction, download, first
setup, server identity confirmation, progress, recovery, VPN users, and reset
confirmation. Keep protocol names, commands, technical references, and release
evidence authoritative in English initially. Clearly label an English-only link
before opening it. Rook's illustrations can remain shared across languages;
visible captions, alternative text, and navigation belong in text catalogs.

The first language edition should not claim to translate all fifty stories.
The initial story reader controls and narration remain English, with a
translated notice in the app and worlds overview. Reader control localization
is a later content task.
Translate complete chapters in a later content phase, with the same stable page
IDs and illustrations. Read a story using a voice matching the **story's language**,
not merely the language of the app. Missing voices need a readable fallback.

### Choosing a language

- **Website:** English at the existing root URLs, a visible language menu using
  native language names, and separate translated URLs. A browser-language hint
  may offer a suggestion; it must not override a selected URL or force a redirect.
- **Android:** Follow the first supported system language by default, otherwise
  English. Offer “System default” and explicit choices in onboarding and Settings.
  Keep the choice editable. Changing it must not disconnect the VPN or cancel
  the independent deployment service. The in-app picker is outside open forms
  and unavailable during short administration actions. External system language
  changes can recreate an unsaved form; do not persist draft secrets merely to
  preserve that form. Restoring private in-memory drafts is a later UI task.
- **Other clients:** Use the same supported language tags and fallback rules;
  messenger `language_code` is a hint, not consent to change a saved preference.

Text catalogs should add much less data than duplicated illustrations or recorded
audio. Measure the actual APK/site increase at release time; do not advertise an
unmeasured kilobyte figure. Do not duplicate media per locale or add network
translation calls while a user enters credentials.

## A maintainable translation system

Keep versioned, stable message IDs, English source text, descriptions, named or
numbered placeholders, and a shared glossary in Git. Export platform formats at
build time if one source catalog is used; do not maintain two independent English
copies. Source changes must invalidate review against the old text, even when the
message ID is unchanged. Do not use the entire English sentence as a permanent ID.

| Choice | Appropriate use | Rookstride decision |
| --- | --- | --- |
| Android resources and AppCompat locales | Native strings/plurals, system fallback, Android per-app preference | Preferred native integration; keep support for Android 8 |
| Static JSON catalogs | Existing Python site builder and bundled HTML guide | Small build-time layer; generate complete HTML without requiring JavaScript |
| Weblate | Git-connected collaboration, reviews, native Android and web formats | Preferred future translation workspace; not a runtime dependency |
| Crowdin | Hosted collaboration and multi-format import/export | Viable alternative if maintainers choose it; no account or service integration assumed |
| Fluent / FormatJS | Rich grammatical messages, plurals, a larger interactive frontend | Evaluate if complexity warrants it; do not rewrite the static site to add a framework |

Android documents native resource resolution and bidirectional handling. Its
per-app language guidance recommends AppCompat for Android 12 and earlier;
changing a locale can recreate the Activity. That makes preserving deployment
ownership and form state an explicit compatibility gate. [Android languages and
cultures](https://developer.android.com/training/basics/supporting-devices/languages),
[per-app language preferences](https://developer.android.com/guide/topics/resources/app-languages).

Weblate supports Android resources and a continuous Git workflow, with review and
placeholder checks. It can be hosted separately; it should never run on a user's
small VPN server. Translation tools help find structural errors but do not certify
meaning. [Weblate formats](https://docs.weblate.org/en/latest/formats.html),
[continuous localization](https://docs.weblate.org/en/latest/admin/continuous.html),
[review workflow](https://docs.weblate.org/en/latest/devel/review.html),
[quality checks](https://docs.weblate.org/en/latest/user/checks.html).
Crowdin also supports Android XML, JSON, and iOS files. [Supported formats](https://support.crowdin.com/supported-formats/).
Fluent permits locale-specific grammatical variants; ICU/FormatJS supports named
arguments and plural/select messages. [Fluent](https://projectfluent.org/),
[FormatJS syntax](https://formatjs.github.io/docs/core-concepts/icu-syntax/).

### Content and review rules

1. **Write for beginners first.** Say “Server address”, “Administrator name”,
   “Check server identity”, “One server”, and “Two servers”. Explain a rented server
   once. Distinguish the server administrator password from a VPN user's password.
   Advanced details can show “SSH”, “fingerprint”, “entry”, and “exit” alongside
   their explanation.
2. **Translate whole messages.** Do not join separately translated sentence parts.
   Preserve placeholders, protocol identifiers, addresses, key fingerprints,
   commands, file paths, and user-entered values. A translation must never become
   a shell command, an authorization decision, or a recipe identifier.
3. **Use plural rules.** Russian and Arabic are not English with another noun.
   Use native plurals or a vetted plural formatter for remaining steps/users.
   Include zero and representative plural values in checks. [Intl.PluralRules](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl/PluralRules).
4. **Review meaning twice, then inspect the screen.** Check the initial translation
   independently for meaning, glossary consistency, politeness, and ambiguity;
   then verify it in its actual UI. A repeated model pass is not a native-speaker
   review. Record machine-assisted drafts and native review separately. Seek native
   reviewers before describing a language as fully reviewed, especially identity,
   recovery, permissions, and deletion text.
5. **Track review freshness.** Store the source revision/hash, context, review
   status, and reviewer attribution when available. Changed source becomes stale;
   release checks list new, missing, and stale messages. Blocking action meanings
   require current review. An incomplete page should explicitly remain English
   rather than look fully translated with an unexplained mixture.
6. **Accept contributions through reviewed changes.** Translation-only pull
   requests include glossary/context and screenshot evidence. Do not auto-publish
   arbitrary community or machine translations into credential/reset screens.

### Layout, accessibility, and discovery gates

- Declare document `lang` and `dir`; Persian/Arabic pages use `dir="rtl"`.
  Use start/end and CSS logical properties. Isolate mixed-direction addresses and
  fingerprints with explicit left-to-right presentation and copy buttons. Keep
  typed passwords exact. Language and direction are different properties.
  [W3C language declarations](https://www.w3.org/International/questions/qa-html-language-declarations),
  [W3C bidirectional markup](https://www.w3.org/International/questions/qa-bidi-css-markup),
  [CSS logical properties](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_logical_properties_and_values).
- Let labels wrap and cards grow. Avoid fixed text heights, tiny replacement
  fonts, and ellipsized destructive warnings. Use flexible columns and stacked
  phone controls. Do not mirror the Rook logo, comic artwork, identifiers, or
  chronological panel content merely because navigation is right-to-left.
- Test every critical journey at narrow phone widths, enlarged fonts, mixed
  Arabic/Persian and Latin content, long host names, large counters, landscape,
  screen readers, and the existing minimum Android version. Add expanded-text and
  RTL pseudolocale checks; Android provides `en-XA` and `ar-XB` for this purpose.
  [Android pseudolocales](https://developer.android.com/guide/topics/resources/pseudolocales).
- Each translated practical page needs actual translated static text, matching
  title/description/alternative text, working language links, and its own canonical
  URL. Once a real public domain is chosen, add reciprocal `hreflang` entries and
  `x-default` only for available translations. Never generate a translated-looking
  URL for an English-only chapter. This helps discovery; it does not guarantee
  ranking. [Google localized-page guidance](https://developers.google.com/search/docs/specialty/international/localized-versions).

## Share contracts, preserve native clients

Keep the reviewed **server recipes** reusable. Each frontend can render the same
recipe IDs, capabilities, configuration schema, checkpoint IDs, result/error codes,
and compatible version/digest. Native SSH transport, secure storage, notifications,
VPN APIs, and background lifetime stay platform-specific. A shared contract does
not require replacing the existing Android app with a cross-platform runtime.

Future progress should carry a stable code plus parameters; localization occurs in
the client. Raw server logs remain diagnostic text and must not be translated into
successful checkpoints. Keep redacted diagnostics separate from user explanations.

The common operation contract should identify a deployment, physical node, role,
recipe version, completed checkpoint, server-owned job, recoverable state, and
allowed next action. Use opaque references to credentials, never passwords or
private keys in events, URLs, chat messages, or persisted progress. Resume must query
the existing owned job and reject incompatible installer identities; it must not
reinstall automatically after a UI reload or language change.

Every adapter preserves independently pinned SSH identities, changed-key rejection,
fixed commands plus structured input, the fresh-install guard, explicit reviewed
reset, staged pair activation, and blocking when the bridge fails. A later HTTP
adapter must add equivalent authentication, ownership, replay protection, and
identity verification; Telegram login alone is not administrator authorization.

## Platform backlog

| Phase | Proposed deliverable | Acceptance gate before calling it available |
| --- | --- | --- |
| L1 — first language edition | Five-language Android setup/admin journey and practical website pages; visible English-only story/reference boundary | Complete catalogs; no dropped placeholders; independent linguistic passes; RTL/narrow/large-font checks; language change preserves forms, service, pins, and active VPN; exact signed APK tests |
| L2 — contributions and story editions | Optional Weblate workflow; translated complete chapters and matching voice choices | Source-staleness checks; attribution/review policy; no partly translated chapter; narration stops at chapter end; absent-voice and offline fallback tests |
| W1 — browser planning and handoff | Localized browser setup planner, route selection, non-secret recipe export, native-app handoff | No root password collection; clear “continue in the app” boundary; validate imports and reject arbitrary commands; keyboard/mobile/accessibility checks |
| W2 — browser administration prototype | Owner-controlled connector or local native helper, initially read-only health/progress | Document credential/relay trust boundary; authenticated origin/pairing; independent node verification; resumable jobs; reject changed keys; security review and disposable pair tests |
| I1 — iPhone administration | Native SSH management, shared recipes, localized setup, detached-job recovery | Keychain storage, physical iPhone lifecycle tests, supported OS policy, fresh disposable one- and two-node runs |
| I2 — iPhone VPN connection | System IKEv2 profile through Apple's VPN APIs, then evaluate other engines separately | Required entitlements/signing; exact authentication and server-identity tests; DNS/IPv6/bridge-outage/handoff tests on physical devices; applicable App Store review gates |
| T1 — Telegram companion | Localized guide/download/recipe chooser, non-secret reminders, native handoff | Explicit notification consent; validated Mini App identity/freshness; webhook authentication; no chat credentials or sensitive profiles |
| T2 — Telegram management | Optional narrowly scoped action requests to an already paired owner-controlled connector | Per-operation authorization and confirmation; replay/rate limits; revocation; no root access in Bot API data; threat review and recovery tests |
| C1 — Weixin/WeChat feasibility | Chinese guide and external handoff prototype; investigate Mini Program eligibility | Verify current account/category/review/domain rules in an actual developer account; validate target-version APIs and lifecycle; no availability promise before approval |

### Browser: useful, with a different connection boundary

Ordinary websites and PWAs cannot open arbitrary raw TCP/UDP connections to an SSH
server. A WebSocket talks WebSocket protocol; changing `ssh://` to `wss://` does not
turn port 22 into a WebSocket endpoint. Chrome documents Direct Sockets as an
**Isolated Web App** capability, not a universal public website API. [Chrome Direct
Sockets](https://developer.chrome.com/docs/iwa/direct-sockets),
[WebSocket constructor](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket).

**Design inference:** the lowest-risk browser first step is a translated planner
and native handoff. Direct browser administration needs a native local helper,
an explicitly enrolled connector on the user's infrastructure, or a relay/backend.
Those have different trust and bootstrap requirements. A phone browser cannot
silently install a local helper or a device-wide VPN. A server connector may need
initial setup through Android or a trusted provider console.

Keep the public information site separate from any future management origin. Do
not add a public “enter root IP and password” form backed by Rookstride's server.
Such a service would receive administrator secrets and create a new custody and
attack surface. A WebSocket relay with SSH cryptography in the client could avoid
giving the relay plaintext credentials, but does not remove the risks of delivered
JavaScript, XSS, origin compromise, pairing, and host-key verification. Evaluate
that only in a dedicated, reviewed prototype. Current management remains SSH-only;
do not expose a VPS web administration port as a side effect of translating pages.

### iPhone: native administration and VPN are separate gates

Apple's Personal VPN entitlement enables `NEVPNManager`; Apple also exposes
`NEVPNProtocolIKEv2`. This makes the existing IKEv2 server recipe a sensible first
compatibility target, not an already tested iPhone connection. Android's APK and
embedded engine do not become an iOS app by sharing recipes. [Personal VPN
entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.vpn.api),
[IKEv2 API](https://developer.apple.com/documentation/networkextension/nevpnprotocolikev2).

Apple's current guideline 5.4 requires VPN apps to use `NEVPNManager`, be offered
by an organization-enrolled developer, disclose data handling before use, and meet
its privacy and applicable territory licensing requirements. Recheck these before
distribution; an administration-only design needs its own classification review.
This research does not establish App Store approval. [App Review Guidelines,
section 5.4](https://developer.apple.com/app-store/review/guidelines/#vpn-apps).
Keep detached server jobs and explicit recovery because the iPhone app's foreground
life is not a reliable installation timer. Export shared messages into iOS formats
with context; Apple's localization tools support catalogs and translation exports.
[Xcode localization exports](https://developer.apple.com/documentation/xcode/exporting-localizations).

### Telegram: companion before administrator

Telegram Mini Apps provide a web UI and an optional user language tag. Their server
must validate `initData`, reject stale `auth_date` values, and distrust
`initDataUnsafe`; Bot API webhooks support a secret header. These authenticate the
platform session, not ownership of a VPS. [Mini Apps](https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app),
[Bot API webhooks](https://core.telegram.org/bots/api#setwebhook).

Keep server passwords, SSH private keys, VPN credentials, and full connection
profiles out of bot chats. Telegram distinguishes cloud chats from end-to-end
encrypted Secret Chats; a bot workflow is not a substitute for a private local
credential vault. [Telegram FAQ](https://telegram.org/faq#q-how-are-secret-chats-different).
Start with education, APK/source links, and non-secret native handoff. Future
management uses short-lived, revocable capabilities to a connector the owner has
already paired; reset or user deletion requires an explicit action review. Message
history and notifications must not disclose host addresses or private diagnostics.

### Weixin/WeChat: verify the actual platform first

Direct Weixin developer network/TCP pages could not be read by the research browser
on this date. Tencent's accessible Mini Program platform documentation describes
configured server domains and HTTP/WebSocket/TCP/UDP interfaces, including
`wx.createTCPSocket`; it is therefore inaccurate to assume every Mini Program has
the same socket limits as an ordinary browser. It also documents domain restrictions
and disallows raw IP addresses as configured domains. [Tencent network reference](https://intl.cloud.tencent.com/zh/document/product/1219/61745).

That Tencent product documentation is not proof that an arbitrary-IP SSH installer
is eligible for public Weixin distribution. Verify the current **Weixin** APIs,
base-library versions, domain registration, account/category requirements, and
review policy in the intended developer account. Do not confuse Tencent's
embeddable Mini Program platform with automatic WeChat approval. Until that gate
passes, publish this route as research only. A localized guide and handoff is the
first candidate; the same no-chat-credentials rule applies. References to recheck:
[Weixin network capability](https://developers.weixin.qq.com/miniprogram/en/dev/framework/ability/network.html),
[Weixin TCP API](https://developers.weixin.qq.com/miniprogram/dev/api/network/tcp/wx.createTCPSocket.html).

## Release and maintenance checklist

Keep a coverage manifest with each locale's scope, source revision, review state,
and tested screens. Publishing a language edition should state whether it covers
the practical journey, full documentation, or stories. Maintain one release identity
and installer digest; language selection must never choose an unreviewed recipe.

Recheck primary platform documentation before adopting a new dependency, expanding
supported OS versions, opening a credential-bearing transport, or publishing a new
client. Record changed policy/API assumptions in this document. Automated link and
catalog checks can run on every pull request; human language and trust-boundary
review remain separate gates. Future plans should appear on the website with
“Proposed” labels and acceptance conditions, not enabled install buttons.
