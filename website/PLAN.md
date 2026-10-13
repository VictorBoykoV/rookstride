# Rookstride website — local edition

## The visitor journey

The home page introduces an independent Android app that deploys and manages a
single self-hosted IKEv2 VPN. A visitor can download a verifiable alpha, follow
the setup guide, understand its infrastructure, inspect its source and test
evidence, or explore the original mascot's illustrated world.

| Page | Purpose |
| --- | --- |
| Home | Explain the product, show the actual demo, connect the practical and creative sides. |
| Start | Guide administrators and invited users through installation, connection, filtering and checks. |
| Architecture | Explain the SSH management path, VPN traffic path, DNS, access and usage estimates. |
| Download | Link the exact signed APK, matching source, checksums, release notes and test scope. |
| Open source | Explain the repositories, licenses, contribution routes and original brand. |
| Field journal | Introduce Rook; five illustrated chapters with panel/page/whole-chapter views with visible page turns. |
| Text edition | Provide every comic panel's narration and dialogue without animation. |

## Design

- Keep the existing original red bird SVG and wordmark.
- Signal red, warm paper, charcoal ink; bold product typography and a literary journal.
- Original generated harbor/comic art; actual offline-demo screenshots clearly labeled.
- Substantive static pages, a small progressive-enhancement script, local assets and no tracking.
- One complete page by default on every screen; optional individual Panel and Whole chapter views. Buttons,
  arrow keys and horizontal swipe; honor reduced-motion preferences.
- A non-JavaScript reader and complete HTML text edition remain available.

## Accuracy

The content follows the Rookstride source and documentation as of 13 October
2026. The product is an early alpha, not a proven stable release. Three signed-APK
emulator/VPS reset-and-reinstall cycles are described with their actual scope.
Physical-device, network-handoff, real IPv6-underlay and sustained-load gates
remain visible. No fabricated users, testimonials, anonymity guarantees, install
counts, capacity guarantees or affiliation claims.

DNS filtering is presented with its limitations, including YouTube in-video ads
and applications using their own encrypted DNS. Per-device EAP logins are not
hardware-bound certificates. Reset removes recognized gateway data; a whole OS
rebuild is a provider operation.

## Search and agent discovery

The important content is readable in the initial HTML. Each page has a distinct
title, description, headings, source links and structured data reflecting visible
facts. There are no hidden keyword pages or invented ratings. `llms.txt`, an
expanded text reference, release JSON and sanitized test evidence help machine
readers find specific information. A real publication URL is supplied at build
time to produce canonical links, absolute social metadata and a sitemap; the
local edition does not invent a hosted domain.

These measures make the project understandable and crawlable. Search rankings,
agent citations and rich-result eligibility are not guaranteed. The approach
follows Google's [helpful-content guidance](https://developers.google.com/search/docs/fundamentals/creating-helpful-content)
and [software-app structured-data guidance](https://developers.google.com/search/docs/appearance/structured-data/software-app).

## Local scope

No hosting registration, deployment, DNS change, VPS change or Git push is part
of this edition. Serve only `dist`, bound to loopback. Never copy server exports,
credentials, root addresses, signing secrets or private test logs into the site.

## Verification

Check internal links and assets; parse all JSON-LD; compare release metadata with
the project's published checksums; scan public text for deployment secrets;
inspect desktop and mobile layouts; exercise navigation, page turns, chapter
jumps, keyboard use, reduced motion and the text fallback in a real browser.
Document results and remaining publication steps in `QA.md`.

## Universal route research

A ninth static page at `/routes/` explains the first proposed IKEv2 → AWG 3.1 pair, protocol-engine candidates, recovery, source findings and new test gates. It labels everything beyond the current single-VPS IKEv2 APK as planned. Research is bundled as Markdown and machine-readable route status; no nonfunctional deployment choices were added to the app.
