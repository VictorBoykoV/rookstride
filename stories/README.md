# Rook's illustrated journeys

Current Android edition: **Persia · An adventure through Iran**, from the original
series *Rook and the Atlas of Open Invitations*. Two chapters, ten pages each,
six panels per page. English text is real catalog text, separate from the artwork.

- `persia/catalog.json`: characters, narrative, dialogue, alt text and page order.
- `persia/masters/`: unchanged original generated PNGs and character reference.
- `persia/provenance.json`: exact prompts, references, hashes and review record.
- `persia/art/`: optimized full-page WebPs, the only art packed into the app.
- `reader/`: offline HTML/CSS/JavaScript; focused-panel and full-page reading,
  explicit turns, resume and chapter-end stop. No audio or remote requests.

The six panels follow English row order: top-left, top-right, middle-left,
middle-right, bottom-left, bottom-right. Crop viewports never repaint the master.
Text can be translated later without regenerating the paintings; this edition
is English only. A chapter resolves one local adventure and ends on a new clue.

Iranian locations are researched context. Named workshops, community events,
characters and the mysterious atlas are original fiction, not travel guidance.
Rook learns with capable local friends. Technical comparisons teach small ideas
without promises of invisibility, security or country-wide access.

Prepare and audit with `python3 scripts/prepare-stories.py` and
`python3 scripts/prepare-stories.py --check --check-packed` from the app root.
Historical website stories remain a separate edition; its website generator
must not overwrite the current app package after preparation. Corresponding
source includes this complete authoring tree, while APKs contain only the
reader, catalog and twenty WebPs. Original artwork follows the project's
GPL-3.0-or-later brand terms; reference artwork is not redistributed.
