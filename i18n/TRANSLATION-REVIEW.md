# First language edition: translation review

Reviewed **14 October 2026**. Scope: the 557 shared interface, practical website,
and beginner-guide messages in `en.json`, translated into Russian (`ru`), Persian
(`fa`), Arabic (`ar`), and Simplified Chinese (`zh-Hans`), plus remaining-checkpoint
plurals. English story bodies and detailed technical documents are outside this
translation edition.

## What “model-reviewed” means

Two review stages are recorded for each locale:

1. The translation author reread the draft for meaning, important negations,
   administrator/VPN credential distinctions, destructive actions, terminology,
   and available-versus-proposed features, then checked catalog structure.
2. A separate model reviewer compared every translated message against the English
   source, reviewed checkpoint plurals and sentence composition, requested concrete
   corrections, and reread the corrected entries.

These are **model reviews, not reviews by human native speakers**.
`human_native_review` is `false` for every locale. Native-speaking community review
remains welcome and should be recorded independently, especially for server trust,
recovery, permissions, and reset instructions. Multiple model passes do not certify
perfect naturalness, regional terminology, or every reading ability.

The review describes text. Signed APK behavior, RTL layout, enlarged fonts,
screen-reader behavior, and physical-device tests have their own evidence; they are
not certified by this catalog record.

## Corrections made during independent review

- Made existing-VPN installation refusal explicit in Russian and Persian, so it
  cannot read as permission to install around a working configuration.
- Restored the Ubuntu requirement in Persian/Arabic onboarding and clarified the
  fresh Ubuntu requirement for both Chinese two-server nodes.
- Preserved separate per-device accounts in Persian sharing instructions, which
  matter for individual usage and revocation.
- Clarified Persian/Arabic refusal to reset unrecognized installations. Reset
  permanently removes recognized gateway data; Ubuntu, SSH, installed packages,
  and unrelated files remain. Removing a saved gateway from the phone remains a
  different action.
- Replaced wording that suggested test voice recordings with **simulated speech
  events** in release-test descriptions. Emulator and provider checks remain
  distinct from physical-device and audible-voice verification.
- Clarified legal/copyright notices in Persian/Arabic source descriptions.
- Corrected Arabic two-server summary composition and natural zero/one/two
  checkpoint forms. Russian one/few/many/other, Persian one/other, and Chinese
  other forms were inspected.

## Structural checks

The final reviewed files are checked for:

- Exactly the same 557 keys as English, with nonempty text values.
- Matching named and printf placeholders, including `%1$d` in every plural form.
- Exact leading/trailing whitespace and the same newline structure as source.
- Unchanged `DELETE VPN` and `DELETE PAIR` confirmation tokens.
- Retained protocol and technical identifiers such as SSH, IKEv2, IPsec,
  AmneziaWG, IPv4/IPv6, strongSwan, AdGuard Home, Ubuntu, and license identifiers.
- No inserted directional control characters in catalog text. Persian
  zero-width non-joiners are legitimate orthography, not direction controls.
- Unchanged extraction artifacts that are program syntax, date-format syntax,
  or certificate-store identifiers rather than prose.

Native-language display names and established local spellings of Android or the
fictional Rook character can be localized. User-entered addresses, account names,
passwords, fingerprints, actual recipe identifiers, and protocol settings cannot.
Translations are display text and must never become remote commands or permission
decisions.

## Keeping review current

`reviews.json` records SHA-256 of each English value for every locale, exact
translation-file bytes, exact plural-file bytes, context/source file hashes, and
the two model review stages. A source-text or translation change invalidates the
corresponding recorded review. Hashes establish which text was reviewed; they do
not evaluate its meaning.

When changing a message, keep its context clear, update the relevant translations,
review the changed entries, rerun structural checks, and regenerate native/site
outputs. Refresh review hashes only after that review. For a human contribution,
record the contributor and scope with their consent; do not silently change
`human_native_review` to `true` for an entire locale after reviewing one sentence.

Full-sentence messages with named placeholders are preferable to inherited phrase
fragments. Continue replacing fragments when their rendering code is revised so
each language can choose a natural word order. Preserve the current explicit
English-only boundaries for story narration and detailed technical references.

The review record also includes the canonical English plural-file hash. Its initial forms are the same English meanings used during review; later English plural edits invalidate every locale review.
