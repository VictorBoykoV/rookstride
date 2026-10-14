# Wide-Sky Commons chapter artwork

**10 original chapter comics · 40 illustrated scenes · 40 narration hotspots**

Each of the ten completed American-world chapters has its own four-panel
artwork. The scenes follow its four written pages in chronological order:
top left, top right, bottom left, bottom right. Four equal panels occupy a
square canvas with narrow cream gutters. The generated gutters are approximate,
so reader framing should respect the visible borders rather than claim an exact
six-pixel result.

## Files

- PNG masters: `artwork/chapters/america/<chapter-id>.png`.
- Optimized whole-comic images: `brand/chapters/america/<chapter-id>.webp`.
- Exact generation and correction prompts, references, inspection notes, and
  selected-file hashes: `artwork/chapters/america/prompts.json`.
- Four actual-object regions per chapter, in page order:
  `brand/chapters/america/hotspots.json`.

The masters are **1254 × 1254 pixels**. Every optimized comic is **1024 × 1024**
and below **180,000 bytes**. The ten optimized files total **1,744,112 bytes**;
the largest is **178,934 bytes**. Conversion resizes the entire canvas uniformly
and encodes WebP. It performs no panel crop, added lettering, pixel compositing,
or semantic image edit. A reader can frame each original quadrant as a page.

## The ten adventures

| Chapter | Distinct illustrated action |
| --- | --- |
| The open bench | Harbor welcome, a usable bench beside a repair, an archive visit, evening company |
| The hall of voices | Different proposals, an accessible discussion, a trial lamp, several useful reading corners |
| The charter in the light | Rain-damaged teaching copies, a complete source set, a missing-page check, restored public access |
| The bridge for wheels | An unanswered access drawing, user consultation, a direction-marker review, a shared level crossing |
| The signal for supper | Private records kept closed, a community broadcast, a verified update, a welcoming meal |
| The dragon at the gate | An intrusive ledger, a public review, the ledger removed, an honest maintenance detour |
| The courier without labels | A paused arrival-list copy, voluntary drawings, a quiet revision, agreed shared pictures |
| The paper-plane promise | A real passenger plan, paper-plane play during a delay, responsible boarding, a quiet window journey |
| Postcards across the worlds | Distinct travel accounts, invitations from other worlds, a checked reply, two credited atlases |
| The book left open | Harbor friends welcome Rook, Lumen opens the original atlas, one chosen tale, a new traveler |

## Character continuity

Rook preserves the canonical red silhouette, swept crest, white eye patch,
projecting beak, charcoal scarf, cream satchel, and ordinary brass lantern.
Recurring local friends keep their chosen identity: Jo the raccoon in a plum
vest, Ada the hare in a blue work shirt, Eli the turtle using a wheelchair,
Bea the black raven with headphones and a rust cardigan, Rosa the fox in a
plain blue pilot jacket, Sam the squirrel in a teal cardigan, and Flint the
rounded umber dragon. The finale returns Pip, Moss, Fern, and Lumen to the
Harbor cast.

The visual style uses textured warm paper, bold ink contours, signal red,
muted blue-gray, and ochre. No dialogue, captions, readable document lettering,
real organization marks, national insignia, or weapons are embedded. The
constitutional-source chapter is a peaceful library story about checking a
complete teaching display; its actual historical text remains in the separate
story and source notes.

## Focused flight correction

One additional built-in image edit corrected the final aircraft panel of
`paper-plane-promise`: Rook wears a fastened lap belt, luggage sits under the
seat, and the brass lantern is visibly unlit and secured with that luggage.
The first three panels retain their scenes, characters, and composition by
visual inspection. Some raster texture changed, so they are not claimed to be
pixel-identical. Both the original and correction prompts and hashes are in
the provenance record. The selected master and WebP contain the correction.

## Narration highlights

Hotspot coordinates are percentages **within each individual panel**, not the
whole four-panel canvas. Each entry supplies `x`, `y`, `w`, `h`, and an accessible
label for an object visible in the final image. They were estimated from the
actual output and checked to fit within 0–100%. The regions follow page order.

The preferred focus is the story's designated object. When a scene resolves
through a visible notice or review sheet, the region names that actual object.
These are broad reader emphasis regions, not segmentation masks or a claim of
word-by-word animation alignment. Gentle emphasis should respect reduced
motion, and the page remains understandable without playback.

## Verification and license

All ten PNGs and all ten WebPs decode. The chapter IDs exactly match the written
world's ten chapters. Every master is square; every WebP is 1024 pixels square;
all files meet the size cap. Every chapter has four valid bounded hotspots.
All ten grids were visually inspected for four chronological panels and
consistent character presentation.

The images are original AI-assisted artwork made with the **built-in image_gen
tool**, with the project's own world image and Rook illustration as references.
No CLI/API fallback was used. Artwork and brand assets are licensed
**GPL-3.0-or-later** with the Rookstride brand. Reference citations in the story
notes do not imply institutional endorsement.
