# Rookstride website

A local, portable, static website for the Rookstride Android project. Includes
setup and architecture guides, verified release links, open-source information,
original mascot lore and an animated comic journal. No accounts, analytics,
third-party scripts, build dependencies or external font requests.

## Preview

From this directory:

```sh
python3 scripts/build.py
python3 scripts/serve.py --port 8765
```

Open `http://127.0.0.1:8765/`. The server exposes only `dist`, and binds only to
the local computer. Stop it with Ctrl+C. The built site also works on a static
host that serves directory index files.

## Verify

```sh
python3 scripts/check.py
```

The checker validates local pages/assets, generated metadata, release references
and the complete story. Browser checks are recorded in `QA.md`.

## Prepare a future publication

Choose the actual HTTPS domain before generating search metadata:

```sh
python3 scripts/build.py --base-url https://YOUR-ACTUAL-DOMAIN
```

This generates absolute canonical/social URLs, a sitemap and its robots entry.
The local build deliberately omits canonical URLs and a sitemap because it has
no public domain yet. `llms.txt` and `llms-full.txt` are discovery conveniences;
support varies across crawlers. They do not guarantee ranking or citations.

Website hosting, DNS and search-console submissions are
outside this local edition. Future hosting should serve HTTPS, enable compression
and use the security headers in `headers.example`. For a release update, change
the verified version, URLs, hashes and sizes in `scripts/build.py` together with
the sanitized evidence in `content/alpha2-tests.json` and its checks. Keep
checksums tied to the exact release binary, then rebuild. A rebuild does not
silently select an unverified newer APK.

The folder is self-contained: it can be unpacked and rebuilt without cloning
the Android repository. Only Python 3.9 or later is needed. Use `--output` to
generate a separate publication folder while preserving the local edition.

## Files

- `scripts/build.py`: dependency-free static-page generation.
- `scripts/serve.py`: loopback preview with sensible headers and a real 404.
- `dist`: complete portable site and locally hosted assets.
- `content`: sanitized release evidence snapshot; no live server configuration.
- `PLAN.md`: scope, visitor journey and discovery decisions.
- `STORY-BIBLE.md`: original character, world and five chapters.
- `ARTWORK.md`: full-resolution illustrations, optimized assets and provenance.
- `artwork/prompts.json`: illustration prompts and provenance.
- `QA.md`: completed browser/content checks and remaining publication work.

Original website code, copy and brand: GPL-3.0-or-later, following the parent
project. Gateway scripts remain MIT; embedded strongSwan retains upstream notices.
Linked upstream projects are independent and are not sponsors of Rookstride.

## October route and journal revision

The `/routes/` page and `data/routes.json` distinguish the current one- or two-server app from additional protocol proposals and historical release evidence and future multi-engine plans. Full research is mirrored in `content/universal-gateway-research.md` so this website package builds independently of the app repository. When inside the app repository, the builder uses the canonical report in `../docs/UNIVERSAL-GATEWAY-RESEARCH.md`.

Five chapters, ten static pages, thirty described panels. Default Page view shows one page; Panel enlarges a complete illustration and caption; Whole chapter shows the original six-panel spread. Both new bridge stories have static text editions. Brand revision notes and the original/revised marks are in `brand/`. The public `0.1.0-alpha2` APK and its hashes remain unchanged.

The experimental `0.2.0-alpha2` pair now has a separate provider report and machine-readable evidence: four fresh app-configured deployments on two real providers, reversed roles, reviewed phone resets, real Android/Linux clients, interrupted-job resume and reboot recovery. The evidence states the computer-to-node-A UDP return failure and Android 16 System UI test limitation. Keep every artifact link tied to its exact release; the earlier one-server binary is not a pair APK.

The [published 0.2.0-alpha2 prerelease](https://github.com/VictorBoykoV/rookstride/releases/tag/v0.2.0-alpha2) has verified APK, corresponding-source, checksum and release-info uploads. Its separate `content/pair-release.json` manifest drives the new download section. The older release manifest and genuine earlier screenshots remain intact.


## Rook’s connected worlds and narration

The portable site includes 67 static pages: the original practical pages and comics,
Rook’s lore, five world indexes, cultural notes, and fifty complete chapter URLs.
Each chapter has four accessible narration pages. Source content lives in
`content/worlds.json`; `WORLDS.md` holds the index and cross-world cast. Original
chapter paintings and exact prompts stay in `artwork/chapters`, optimized complete
spreads in `brand/chapters`. SVG viewports display a single panel without editing
its pixels. Inspected approximate focus boxes animate the current scene object.

The same reader builds into Android’s asset-only WebView. Installed offline English
voices provide native narration; the website offers browser voices and labels those
that may use the network. No voice is recorded, no audio starts automatically, and
no next chapter starts without a choice. Manual turns, hiding the document, or leaving
Stories stop narration. Word ranges depend on the voice. Reduced motion disables
animated page turns and scene pulses. Without JavaScript every chapter’s four text
pages remain visible and crawlable.

Run `python3 scripts/check-worlds.py` after generation to verify all stories, all 45
new comic spreads, original five references, static/offline pages and four inspected
hotspots per new chapter. `--allow-art-in-progress` reports unfinished artwork
honestly during development. The ordinary `scripts/check.py` still verifies links,
metadata, old release identities, evidence and the public-data boundary.

Rook’s helper roles appear across setup, architecture, downloads and open-source
pages; the home page introduces him and brings him back at the story invitation.
See `../brand/AMBASSADOR.md` for consistent face, roles, tone and research sources.
