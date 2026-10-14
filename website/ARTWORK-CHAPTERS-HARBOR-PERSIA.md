# Harbor and Garden: chapter artwork

Fifteen original four-panel comics illustrate the finished story text in
`content/worlds.json`: Lantern Harbor chapters 6–10 and all ten chapters in the
Garden of Many Doors. The first five Harbor chapters retain their original
six-panel artwork and reading order.

Each new chapter was created with one separate built-in image generation call
on 14 October 2026. Every prompt specifies four chronological actions from that
chapter's four page descriptions and full narrative context. The existing harbor
illustration and the new world plates supply character/style references;
completed chapter art supplies repeat-character continuity. The pictures are
original compositions rather than a world cover reused for every page.

## Files and sizes

Masters are `artwork/chapters/<world>/<chapter-id>.png`, all 1536 × 1024.
Optimized copies are `brand/chapters/<world>/<chapter-id>.webp`, all 1024 × 683.
Format optimization resizes and compresses the complete illustration; it does
not repaint, crop, compose or change the depicted actions. Original PNGs are
unchanged. The fifteen optimized files together are 2,622,950 bytes.

| World | Chapter ID | WebP bytes |
| --- | --- | ---: |
| Harbor | `book-that-opened` | 175,500 |
| Harbor | `keeper-of-names` | 176,372 |
| Harbor | `tower-with-wings` | 174,358 |
| Harbor | `blank-page-atlas` | 176,320 |
| Harbor | `road-out-of-harbor` | 175,760 |
| Garden | `courtyard-welcome` | 168,894 |
| Garden | `four-ribbons-water` | 176,924 |
| Garden | `letter-in-wind` | 176,416 |
| Garden | `carpet-of-routes` | 175,012 |
| Garden | `well-after-sunset` | 179,432 |
| Garden | `princess-of-dawn` | 178,532 |
| Garden | `poem-with-room` | 171,070 |
| Garden | `caravan-of-notes` | 169,780 |
| Garden | `window-of-stars` | 170,326 |
| Garden | `sea-between-pages` | 178,254 |

All files are below the stricter 180,000-byte limit. WebP quality is selected
per illustration to meet that size limit while keeping the character silhouettes
and scene actions readable. The dense garden-water chapter was compressed again
from its unchanged master after the first attempt exceeded the limit.

## Reading order and panel viewports

The new comics use a 2 × 2 grid, read **top-left, top-right, bottom-left,
bottom-right**. Each page corresponds to one panel in that order. No narration,
dialogue balloons, lettering or captions are baked into these illustrations;
the readable story remains separate page text.

Normalized panel bounds are `[x, y, width, height]`:

```json
[[0, 0, 0.5, 0.5], [0.5, 0, 0.5, 0.5],
 [0, 0.5, 0.5, 0.5], [0.5, 0.5, 0.5, 0.5]]
```

At master size, those are `[0,0,768,512]`, `[768,0,768,512]`,
`[0,512,768,512]` and `[768,512,768,512]`. The cream gutters remain inside the
quadrants. SVG viewports can select a panel without changing the raster image;
calculate bounds from the actual delivered dimensions instead of assuming a
square image or rounding 683 into two identical integer heights.

## Narration highlights

`brand/chapters/harbor/hotspots.json` and
`brand/chapters/persia/hotspots.json` contain four entries per chapter, in the
same reading order. Each `{x,y,w,h,label}` rectangle is a **percentage of its
individual panel**, not of the complete 2 × 2 spread. Rectangles were estimated
by inspecting the actual generated scenes; they are approximate visual targets,
not exact pixel segmentation.

The chosen target is a visible story element: the atlas, a private curtain,
the young dragon, a prepared telescope, a sealed envelope, a lantern, the water
channel or a participating character. Labels describe the object actually
depicted. They do not invent an invisible feature or cover the page with an
unrelated floating mascot badge. Playback should retain accessible text and
work without highlighting or motion.

## Character continuity

Rook remains the red bird with a swept crest, clear beak, white eye patch,
charcoal scarf, cream satchel and brass lantern. Pip is the rabbit courier; Moss
is the hedgehog mapmaker with spectacles. Lumen is an owl librarian; Nell is a
mouse writer; Mira is an otter inventor.

Sima is a cream owl in turquoise, Nima an otter garden keeper in a green apron,
Darya a hare courier in blue, and Leila a fox weaver in ochre. Aster is the
patient camel. Soraya is a capable fox astronomer with a modest circlet and
navy cloak; Zephyr is a gentle ochre dragon with blue-gray wings. The final
ship chapter uses the completed Chinese-world welcome illustration as a
reference for Mei, a brown otter printer in a blue apron. That keeps the
cross-world introduction recognizable.

The tower stories preserve the characters' agency. Mira and Soraya direct their
own plans; experienced caretakers do the repairs; Rook listens and carries
messages. Dragons are frightened neighbors who receive help rather than symbols
for real peoples. The Garden is an invented setting inspired by living Persian
cultural heritage, not a complete representation of Iran or every Iranian life.

## Provenance and validation

`artwork/chapters/harbor/prompts.json` and
`artwork/chapters/persia/prompts.json` record each exact final prompt, built-in
generation tool, returned output filename, relative project references,
reading order, sizes, compression setting and SHA-256 hashes for both original
PNG and optimized WebP. Public records contain no absolute personal filesystem
paths. No downloaded third-party character, national flag or company mascot
is included.

Validation decoded all fifteen PNGs and WebPs, checked dimensions and byte
limits, recomputed both hashes, matched fifteen complete chapter records to
fifteen four-entry hotspot records, and checked every rectangle stays within
its panel. All generated masters were visually inspected; the compressed
water chapter was also inspected after its tighter compression pass. There
are no pending conversion files.

The art and this original provenance document are GPL-3.0-or-later, consistent
with Rookstride's existing brand and story artwork. Text and illustrations are
fiction; technical claims and factual historical notes belong in the separately
sourced documentation.
