# China and Russia chapter artwork

Twenty original four-panel chapters illustrate **The River of Returning Lanterns** and **The Snowbound Library**: ten chapters per world, eighty chronological scenes. Every chapter has its own complete illustration rather than reusing a world cover.

## Source and runtime assets

- Full-resolution selected PNG masters: `artwork/chapters/china/` and `artwork/chapters/russia/`.
- Runtime WebP sheets: `brand/chapters/china/` and `brand/chapters/russia/`.
- Exact generation and repair prompts, portable reference filenames, selected generation filenames, dimensions, byte sizes, and both PNG/WebP SHA-256 hashes: each master directory’s `prompts.json`.
- Four visually checked narration hotspots for each chapter: each runtime directory’s `hotspots.json`.
- Artwork license: **GPL-3.0-or-later**, consistent with the Rookstride illustrated brand assets.

All illustrations were produced with the **built-in image_gen tool**, with one new generation for each chapter. Three additional focused edits corrected visible issues: unwanted lettering/a thought bubble in the river welcome; Bun mistakenly drawn as a rabbit in the stove chapter; and Jo’s species, costume, and arrival environment in the final sea-voyage panel. The exact repair prompts are retained. No CLI/API fallback was used.

Conversion only changes format, whole-sheet size, and compression. It does not composite images, add lettering, edit content, or crop the raster. Captions and narration remain separate, selectable text in `content/worlds.json`.

## Reader layout

Each runtime sheet is **1024 × 1024 pixels**, with four equal panel cells separated by narrow cream gutters. Read top-left, top-right, bottom-left, bottom-right. The uniform crops are expressed as percentages of the whole sheet:

| Page | x | y | width | height |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0 | 0 | 50 | 50 |
| 2 | 50 | 0 | 50 | 50 |
| 3 | 0 | 50 | 50 | 50 |
| 4 | 50 | 50 | 50 | 50 |

Hotspot coordinates are percentages **within the corresponding panel**, not within the whole sheet. They are approximate visual bounds of an actual object or action. Where a textual focus has no literal pictured object, the label names the visible primary prop honestly: a delivery parcel, rail notice, story drawing, or route board. Each chapter has four bounded hotspot entries.

## Character continuity

Rook keeps his bright red bird body, swept crest, large white eye, projecting beak, charcoal scarf, cream satchel, brass lantern, and atlas. His borrowed dark ushanka and felt boots belong to the winter stories; the loan basket receives them before the sea journey, whose Rook has an uncovered crest. Dasha is the silver-grey fox librarian in a cream coat and navy scarf, matching the northbound-train handoff. Jo is the grey raccoon archivist in a plum vest, matching the completed Wide-Sky Commons artwork. Bun is an original small talking golden loaf, separate from the other animal neighbors.

Mei is a brown otter printer in a blue smock; Lin is a grey heron in a work vest. Jun is a young fox, Shen an otter ferryman, Misha a bear baker, Anya a tawny squirrel caretaker, and Vera an older fox storyteller. The settings include local craft alongside ordinary contemporary features such as printing, tablets, elevators, solar lighting, and trains. They are fictional places inspired by varied traditions, not claims that a single scene represents a whole country.

## Verification

All twenty selected masters were visually inspected for four distinct chronological scenes, mascot continuity, chapter props, gutters, and unwanted bubbles/lettering. Every runtime image is below **180,000 bytes**, square, and decodable. PNG and WebP hashes were recomputed after the final repairs. The twenty chapter IDs exactly match the ten China and ten Russia chapters in `content/worlds.json`; every ID also has four narration hotspots with valid 0–100 bounds. Public provenance contains no personal filesystem prefixes.

Combined runtime sheets: **3,435,506 bytes**. Selected PNG masters: **70,067,241 bytes**.

| World | Chapter | WebP bytes | WebP quality |
| --- | --- | ---: | ---: |
| china | `river-welcome` | 169124 | 40 |
| china | `bridge-of-many-hands` | 164856 | 25 |
| china | `printer-missing-dot` | 168520 | 30 |
| china | `flute-and-flag` | 171406 | 35 |
| china | `dragon-at-rain-pavilion` | 179366 | 30 |
| china | `moon-gate` | 171126 | 30 |
| china | `kite-that-came-down` | 173702 | 35 |
| china | `two-ferries` | 175722 | 35 |
| china | `roof-garden` | 171962 | 35 |
| china | `northbound-window` | 170406 | 45 |
| russia | `warm-door` | 177572 | 45 |
| russia | `loaf-that-stopped` | 177938 | 40 |
| russia | `bell-beneath-ice` | 173292 | 30 |
| russia | `house-of-joints` | 174658 | 35 |
| russia | `message-in-whiteout` | 174210 | 40 |
| russia | `night-train-curtain` | 155934 | 50 |
| russia | `tower-after-thaw` | 174454 | 35 |
| russia | `forest-two-choices` | 171768 | 35 |
| russia | `ship-beyond-snow` | 166648 | 50 |
| russia | `stories-by-stove` | 172842 | 45 |
