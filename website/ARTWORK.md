# Original Rook illustrations

Created using the **built-in image generation tool**, with the harbor key art as
the character/style reference for the five comic spreads. Prompt set:
[artwork/prompts.json](artwork/prompts.json).

| Illustration | Full-resolution master | Optimized website asset |
| --- | --- | --- |
| Rook over Lantern Harbor | [rook-harbor.png](artwork/rook-harbor.png) | [rook-harbor.webp](dist/assets/rook-harbor.webp) |
| The borrowed light | [chapter-1.png](artwork/chapter-1.png) | [chapter-1.webp](dist/assets/chapter-1.webp) |
| The noisy market | [chapter-2.png](artwork/chapter-2.png) | [chapter-2.webp](dist/assets/chapter-2.webp) |
| The bridge that waited | [chapter-3.png](artwork/chapter-3.png) | [chapter-3.webp](dist/assets/chapter-3.webp) |

The hero master is 1536 × 1024; each comic spread is 1448 × 1086. WebP versions
retain the complete artwork. The reader uses SVG viewports to present individual
panels; dialogue and narration stay in real HTML. No generated lettering is used.

The existing [original SVG mark](dist/assets/rook.svg) is preserved. The
[social graphic](dist/assets/social-card.svg) is native SVG, rendered locally to
a true 1200 × 630 [PNG](dist/assets/social-card.png). These graphics were created
in code, separate from the generated illustrations.

Original brand, artwork and website materials follow GPL-3.0-or-later. The
fictional harbor and characters have no national or upstream-company affiliation.

Chapters 4–5 were generated on 13 October 2026 using the same inspected harbor reference. Original prompts and tool provenance are retained in `artwork/bridge-prompts.json`; untouched PNG masters remain alongside chapters 1–3. Optimized WebP files are format exports of those masters. Measured SVG viewports select panels without modifying the original illustrations; Panel mode uses the full selected illustration without cropping to fill.

The SVG logo revision is code-native. One swept crest, a rounded chin and a clear forward beak replace the old three-point silhouette. `brand/rook-v1.svg` preserves the original; `brand/DESIGN.md` records the feedback and compatibility note. The released APK has not changed.
