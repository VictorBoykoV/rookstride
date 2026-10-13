# Local website verification

## Implemented experimental pair update

13 October 2026. The local routes page now documents the implemented IKEv2 → AWG pair, its SSH/job recovery flow, guide and sanitized evidence. The same signed `0.2.0-alpha1` APK completed three fresh local Ubuntu pair cycles; cycle 3 required documented retries. Android 16 pair compatibility remains incomplete; independent-provider and physical-device pair tests remain gates. See [PAIR-TESTING.md](../docs/PAIR-TESTING.md). No live VPS was changed.

Static checks: 9 pages, 377 internal references, 5 JSON-LD documents, 23 scanned text files, 10 comic pages and 30 panels. APK/source links for alpha2 remain tied to their original artifacts. The website mirrors pair docs/results and can rebuild outside the app repository. Fresh connected-Chrome verification confirmed the updated implementation/evidence copy and release boundaries; [captured route preview](qa/pair-preview.jpg). Standalone extracted rebuild and checker passed. The earlier UI checks below describe the unchanged reader and layouts; this update adds implementation/evidence copy.

## Earlier route-research snapshot

Completed **13 October 2026**. This revision updates the logo, journal and local research documentation. The published alpha2 APK and its earlier live single-server evidence are unchanged.

## Completed checks

| Check | Result |
|---|---|
| Static site | 9 pages; 375 internal link/asset references; no missing target or fragment |
| Metadata | Distinct titles/descriptions, one primary heading, English language, image labels/dimensions |
| Structured data | 5 local JSON-LD documents; 12 in the separate publication fixture; no invented ratings |
| Current release artifacts | Local APK and corresponding source match the original SHA-256 and byte-size manifest |
| Public content | 20 text files checked; no deployment address, private key or token; one documented dotted app version is explicitly distinguished from an IP |
| Stories | 5 chapters, 10 source pages, 30 described scenes with matching narration/dialogue |
| Reader sequences | All 30 panels, all 10 pages and all 5 chapter overviews visited through actual UI controls |
| Reader boundaries | Previous disabled at beginning; Next disabled at end; Home/End and chapter selection work |
| Reading position | Panel bookmark restores after reload; switching to Page preserves the containing page |
| Layout | All 8 main pages checked at 320 CSS pixels; research overflow found and fixed; all 3 modes also checked at 390 CSS pixels; tablet research and desktop journal inspected |
| Whole-chapter layout | Grid minimum-height issue found and fixed; navigation follows the page instead of overlapping it |
| Artwork | Uncropped panel view; naturally sized full-width illustrations in Page mode; original spread in Whole chapter; nested SVG prevents adjacent panel bleed |
| Animation and drag | Mouse drag started a 3D turning leaf, completed at the next chapter and cleared busy/leaf state |
| No-script fallback | Separate loopback server with `script-src 'none'`; all 10 pages and 30 panels available; inactive controls hidden and explanation shown |
| Source checks | Browser script syntax, local/privacy/link checks and repository whitespace checks pass |
| Website package | Extracted rebuild and standalone checker pass; canonical research mirror included |

The publication fixture uses the reserved `.example` namespace solely for testing canonical/social URLs, robots, breadcrumbs and a sitemap. The local deliverable has no invented public domain or sitemap. Static content and `llms.txt`/`llms-full.txt` remain readable to crawlers; `data/routes.json` labels the broader routes as proposals and the current APK as single-server IKEv2. Crawlability does not guarantee ranking or agent citations.

## Local app and backend regression checks

- **25 Python tests:** fresh pass, including reset ownership/confirmation, stale socket cleanup, accounting gaps/rekeys/shared accounts and management input rejection.
- **86 Android JVM tests:** forced fresh execution, zero failures/errors/skips. The new Android vector resources compile. No new APK was released.
- Bundled single-VPS backend repository checks pass.
- Two-Hop VPN Gateway repository checks pass: privacy/local links, shell syntax, workflow YAML and generated client profiles. New source findings are in its mobile integration review; passing static checks does not eliminate those findings.
- The first Python and Gradle attempts were blocked by the sandbox's local socket restriction. Their reruns completed with the required local execution permission. These were environment failures, not hidden passing test results.

## New two-hop and protocol scope

This revision researched and audited future routes. It did **not** install a pair, embed another VPN engine, run a new protocol handshake or reset a live VPS. The pair needs two disposable reachable hosts and its own forced-failure, reboot, resume, DNS/IPv6 and physical-client gates. Earlier alpha2 live cycles tested one VPS and do not certify pair behavior. Physical Rookstride/OEM, network handoff, real IPv6-underlay, sustained-load/1-GB and 16-KiB runtime gates still apply to the existing release.

## Browser and asset scope

Real connected Chrome browser on this Mac; measured CSS widths account for existing zoom. Actual mouse drag and keyboard/control navigation were exercised. Physical touch, Safari/Firefox and system reduced-motion preference were not newly certified; explicit motion-off was tested. The revised social card was rendered from the native SVG, exported as a true 1200 × 630 PNG and inspected. Original AI-generated PNG comic masters, prompts and optimized WebP assets remain in the package.

## Local delivery

The preview binds to loopback and serves only `dist`. It sends CSP, nosniff, referrer and permission headers. Hosting, DNS, repository pushes, a remote rename and VPS changes were not performed. A real public origin, HTTPS static hosting and host-specific headers remain publication steps. The recommended future neutral backend slug is `two-hop-vpn-gateway`; its current URL stays usable during review.
