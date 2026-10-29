# README images

Audience: readers and contributors who reuse or change the README images.
Purpose: record each image's source and distinguish illustrations from test evidence.
Prerequisites: none.

The documentation license is [CC-BY-4.0](https://github.com/hadijannat/dpp-conformance-engine/blob/main/LICENSES/CC-BY-4.0.txt).
[REUSE.toml](https://github.com/hadijannat/dpp-conformance-engine/blob/main/REUSE.toml) assigns metadata to `docs/**`.

| Image | Source and meaning |
| --- | --- |
| `dppce-overview.webp` | Conceptual cover made with the built-in OpenAI image-generation tool on 2026-10-29. It depicts a battery passport, test instruments, and evidence documents. It is not a screenshot or test result. `dppce-overview.png` is the original output. |
| `dpp-explained.webp` | Illustration for newcomers. A label on a battery pack leads to one passport card. Three role views show none, part, and all of a restricted section. |
| `three-steps.webp` | Three-panel illustration: describe the system, test it, and verify the report. |
| `dpp-anatomy.webp` | Labeled illustration of a DPP system. It marks the seven test areas, 01 to 07, and a separate mock registry. |
| `evidence-chain.webp` | Illustration of the evidence model. Only the signed report goes from the tester to the recipient. The recipient uses its own keys and an offline verifier. |
| `report-summary.png` | Existing screenshot of the synthetic local demo's HTML report, dated 2026-10-29 in the README. It illustrates that run only. |
| [Test areas](test-areas.svg) | Seven independent areas of selected checks. [Mobile](test-areas-mobile.svg) · [Editable source](test-areas.drawio) |
| [Run lifecycle](run-lifecycle.svg) | Planning, controlled live contact, outputs, and independent offline operations. [Mobile](run-lifecycle-mobile.svg) · [Editable source](run-lifecycle.drawio) |
| [Verdicts](verdicts.svg) | Five verdicts and the distinction between requirement and overall outcomes. [Mobile](verdicts-mobile.svg) · [Editable source](verdicts.drawio) |
| [Traceability](traceability.svg) | Sources, checks, results, and separate results and record-commitment trees. [Mobile](traceability-mobile.svg) · [Editable source](traceability.drawio) |

The README supplies text alternatives. Select linked diagrams and the report image to inspect them at full size.
The report screenshot is separate from the generated illustrations.
No image establishes legal compliance, product safety, or certification.

## Diagram layouts

The four diagrams were redesigned on 2026-10-29 as native SVGs, with editable Draw.io companion layouts.
Each `.drawio` file has a desktop page and a mobile page.
The README selects the stacked mobile SVG when its viewport is at most 600 pixels wide.
Each SVG has a title and description. Labels use system fonts, with no external resources or scripts.
Verdicts use symbols and words as well as color. Adjacent README text explains each diagram.
The diagrams describe the engine; they are not test evidence.

## Cover generation prompt

The built-in tool used this prompt. The original output was copied into this directory without visual edits.

```text
Use case: stylized-concept
Asset type: wide conceptual cover illustration for the GitHub README of an open-source Digital Product Passport conformance test engine, around a 3:1 composition.
Primary request: an engaging, sophisticated editorial illustration showing a physical product's digital passport being examined by transparent test instruments and producing inspectable evidence. Make it clear through imagery that the subject is software testing of product data.
Scene: quiet deep navy canvas with restrained subtle blueprint grid and generous breathing room. On the left, a small stylized industrial battery module with a floating passport document. In the center, a precise magnifying lens and layered transparent test plates examining structured data, connected by clean dotted paths. On the right, a tidy stack of evidence documents with small green check, amber question, and red cross symbols, plus a simple key suggesting a signed report. All are conceptual objects, never an actual app screenshot.
Style: premium editorial 3D illustration, soft matte ceramic and translucent glass, precise geometry, crisp silhouettes, subtle cinematic lighting. Teal, pale blue, white, small amber and coral accents. Broad-audience legibility at small sizes. Visually grounded, clean, restrained.
Text: no words, no letters, no numbers. All functional explanations will be real selectable text in the README.
Constraints: no people, no brand logos, no EU flag, no certificates, no approval seal, no padlock badge asserting security, no blockchain chain, no AI brain, no fake dashboard, no scannable QR code, no watermark. This is an illustration of testing and evidence, not a certification or all-passing result. Keep the three object groups large and uncluttered. Full opaque background.
```

## Generated illustrations

The cover and the four illustrations come from the built-in OpenAI image-generation tool.
Codex called the tool for each image. The tool does not report the name of its model.

For the four illustrations, a development agent wrote each first prompt from a fact sheet of the repository.
Another agent then inspected each output against that fact sheet: labels, arrows, product shape, and forbidden motifs.
For each defect, it wrote a corrected prompt for a new round. The prompts below are the final ones.
The session log of the tool shows that it received each final prompt without changes.
No person has reviewed the illustrations.

Labels inside an image only repeat README terms. The README text and the alt text carry all the information.
The zxing-cpp decoder found no symbol in any of the five images.

`cwebp` 1.6.0 converted each PNG output to WebP with `-q 85 -m 6 -sharp_yuv -metadata none`.
It scaled outputs wider than 1760 pixels to that width. No other edit changed the pixels.
The repository keeps the original PNG output of the cover only.

### `dpp-explained.webp`

The tool used this prompt in the second round.

```text
Use case: technical explainer illustration for the GitHub README of an open-source Digital Product Passport (DPP) conformance test engine.
Asset type: wide illustration, 2:1 landscape composition.
Primary request: show a newcomer what a Digital Product Passport is: a physical product carries a code, the code leads to a digital passport record, and different readers see different parts of that record.
Scene, left: an electric-vehicle traction battery pack: a large, flat, rectangular multi-module pack with a brushed aluminium housing, bolted mounting flanges along the edges, a cooling-plate base, and an orange high-voltage connector at one end. It is NOT a 12-volt car starter battery: no top terminal posts, no handle. On its top face sits one small white label with a simplified QR-style symbol: three corner squares and a few blocks, clearly stylized, not a real scannable code.
Scene, center: a dotted teal path rises from that label to one floating translucent glass passport card. The card shows a tiny battery pictogram at its top and then exactly six rows of abstract light-blue lines instead of text. Each row starts with a small square marker. The upper three rows (the open part) have teal markers and are clearly visible. The lower three rows (the restricted part) have amber, coral, and pale grey markers and sit behind a frosted pane.
Scene, right: three smaller copies of the same passport card stand side by side, each a different reader's view of the same six-row record. Every view keeps the same layout and the same six rows; only the frosted pane changes:
- First view: all three upper teal-marker rows are clear (not two, all three). All three lower rows stay behind the frosted pane.
- Second view: all three upper rows are clear, AND the amber-marker row and the coral-marker row of the lower part are clear. Only the last lower row (pale grey marker) stays behind a short frosted pane.
- Third view: all six rows are clear. No frosted pane at all. Never more than six rows.
The amount of clear content must visibly grow from left to right: three rows, five rows, six rows.
Small teal key shapes float beside the three views, one key per view, to suggest three access roles. Each key is a single, flat, simple key with one round or square bow and one blade; the three keys differ only in their cut pattern. A key must not overlap or merge with any dotted line, and must not have two blades or two shafts.
Text: no words, no letters, no numbers anywhere.

Style: premium editorial technical illustration in clean isometric 3D, in the same visual family as a deep-navy README cover. Soft matte ceramic surfaces and translucent glass panels, precise geometry, crisp silhouettes, subtle soft lighting, generous breathing room, uncluttered. Background: solid deep navy (close to #0d1d32) with a very faint blueprint grid, fully opaque, even margins. Palette: teal and pale blue for structure and connecting lines, white for labels, small amber accents, small coral accents. Every element must stay readable when the whole image is shown 880 pixels wide.
Avoid: people, faces, or hands; brand or company logos; EU flag or any ring of stars; certificates, diplomas, ribbons, rosettes, wax seals, or approval stamps; padlock or shield badges; blockchain chain links or chains of cubes; AI brain, neural network, or robot; clouds, globes, or world maps; dashboards, charts, graphs, or gauges; flames, lightning bolts, or thermometers; scannable QR codes; watermark; signature or artist mark.
```

### `three-steps.webp`

The tool used this prompt in the second round.

```text
Use case: technical explainer strip for the GitHub README of an open-source Digital Product Passport (DPP) conformance test engine.
Asset type: very wide three-panel strip, 3:1 landscape composition, three equal panels left to right, separated by generous space and joined by a thin teal arrow from panel to panel.
Panel 1, "1 Describe": two translucent glass documents with rows of abstract light-blue lines lie on a small platform: one is the owner's declaration of the system, the other lists endpoints and sample inputs for the tester. A small pen rests beside them.
Panel 2, "2 Test": a compact precision test instrument with a lens on the left and one server block on the right, the system under test. Between them stands one small gate (a narrow upright portal frame). Two thin parallel teal lines run between instrument and server, and BOTH pass through the opening of that one gate: the upper line has an arrowhead pointing at the server (request), the lower line has an arrowhead pointing back at the instrument (response). No line goes around the gate. Only one system is contacted; no network mesh.
In front of the instrument, on the platform, sits the sealed recording: a small closed rectangular case with frosted glass walls and a matte grey lid, standing upright, containing a neat stack of thin flat white record cards with faint abstract lines. It must NOT contain coins, discs, tokens, or anything gold, and it must NOT be a cylinder, a tube, a battery cell, a bell jar, or a padlock. Beside it, clearly apart, a tiny amber key hangs on its own small separate hook stand (the key is not inside and not touching the case). A report document with abstract lines lies on the platform.
Panel 3, "3 Verify": a separate small desk with its own key ring of three teal keys and a small self-contained verifier device with no cables. A report document with a small pen-nib signature mark rests on the desk; a soft teal check glyph appears on the verifier screen, nothing else. No line or arrow leaves panel 3 toward the server.
Text: draw ONLY these three labels, each spelled exactly, in a clean white sans-serif typeface, large and legible, centered above each panel: "1 Describe", "2 Test", "3 Verify". No other letters, words, numbers, code, or fake small print anywhere.

Style: premium editorial technical illustration in clean isometric 3D, in the same visual family as a deep-navy README cover. Soft matte ceramic surfaces and translucent glass panels, precise geometry, crisp silhouettes, subtle soft lighting, generous breathing room, uncluttered. Background: solid deep navy (close to #0d1d32) with a very faint blueprint grid, fully opaque, even margins. Palette: teal and pale blue for structure and connecting lines, white for labels, small amber accents, small coral accents. Every element must stay readable when the whole image is shown 880 pixels wide.
Avoid: people, faces, or hands; brand or company logos; EU flag or any ring of stars; certificates, diplomas, ribbons, rosettes, wax seals, or approval stamps; padlock or shield badges; blockchain chain links or chains of cubes; AI brain, neural network, or robot; clouds, globes, or world maps; dashboards, charts, graphs, or gauges; flames, lightning bolts, or thermometers; scannable QR codes; watermark; signature or artist mark; coins, money, or crypto tokens; batteries or battery cells of any shape.
```

### `dpp-anatomy.webp`

The tool used this prompt in the first round.

```text
Use case: accurate technical illustration for the GitHub README of an open-source Digital Product Passport (DPP) conformance test engine.
Asset type: wide labeled anatomy diagram, 16:9 landscape composition.
Primary request: an isometric cutaway "anatomy of a Digital Product Passport system" that marks the seven parts a test engine checks, numbered 01 to 07, from the code on the product to the version history.
Layout, left to right:
- Far left: an electric-vehicle traction battery pack: a large, flat, rectangular multi-module pack with a brushed aluminium housing, bolted mounting flanges, and an orange high-voltage connector. NOT a 12-volt car starter battery: no terminal posts, no handle. One small white label on its top face carries a simplified QR-style symbol (three corner squares and a few blocks, clearly stylized, not scannable). Marker 01 points at this label.
- A dotted teal path runs from the label to a short glowing link token shaped like a rounded tag with a small arrow, standing for the product identifier. Marker 02 points at this token. A thin arrow continues from the token into the passport system.
- Center: one isometric glass platform with a subtle outline, the passport system that is under test. On it stand, connected by thin teal lines: an API gateway block with several small ports (marker 03); a passport data document card with rows of abstract light-blue lines (marker 04); an access gate in front of the document with three keys of different cut patterns and three small view panes that reveal none, some, and all of a lower restricted section (marker 05); a second document card with a pen-nib signature mark and a small key beside it (marker 06); and a neat stack of three document versions with a small curved version arrow (marker 07).
- Outside the platform, to the right: a small box drawn with a dashed outline and a ghosted, stand-in look, linked by a dashed line to the version stack. This is a mock registry, not an official building.
Each marker is a small teal ring with its label beside it in white.
Text: draw ONLY these labels, each spelled exactly, in a clean white sans-serif typeface, sentence case, large and legible: "01 Data carrier", "02 Identifier", "03 Interface", "04 Data", "05 Access", "06 Integrity", "07 Lifecycle", "Mock registry". No other letters, words, numbers, code, URLs, or fake small print anywhere; documents use abstract lines instead of text.

Style: premium editorial technical illustration in clean isometric 3D, in the same visual family as a deep-navy README cover. Soft matte ceramic surfaces and translucent glass panels, precise geometry, crisp silhouettes, subtle soft lighting, generous breathing room, uncluttered. Background: solid deep navy (close to #0d1d32) with a very faint blueprint grid, fully opaque, even margins. Palette: teal and pale blue for structure and connecting lines, white for labels, small amber accents, small coral accents. Every element must stay readable when the whole image is shown 880 pixels wide.
Avoid: people, faces, or hands; brand or company logos; EU flag or any ring of stars; certificates, diplomas, ribbons, rosettes, wax seals, or approval stamps; padlock or shield badges; blockchain chain links or chains of cubes; AI brain, neural network, or robot; clouds, globes, or world maps; dashboards, charts, graphs, or gauges; flames, lightning bolts, or thermometers; scannable QR codes; watermark; signature or artist mark.
```

### `evidence-chain.webp`

The tool used this prompt in the third round.

```text
Use case: accurate technical illustration for the GitHub README of an open-source Digital Product Passport (DPP) conformance test engine.
Asset type: wide illustration, 2:1 landscape composition, two zones separated by a clear vertical gap. A thin faint dashed vertical line runs down the middle of the gap.
Primary request: show that a recipient can check a signed test report with keys it already trusts, without trusting the tester.
Left zone, labeled "Tester": a compact precision test instrument connects through one small gate (a narrow portal frame) to one server block, the system under test. Draw this as one continuous dotted teal line that leaves the instrument, passes through the gate, and visibly ends touching the front of the server block. This gate line is the only live connection in the whole image. From the instrument, records flow down into a sealed translucent glass capsule (the encrypted recording): a smooth rounded glass vault with no metal end caps or terminal nubs (not a battery). The record sheets inside the capsule are blank, with no marks or squiggles. The capsule's small amber key hangs on a separate hook on its own small stand beside it, never inside it. Amber keys appear ONLY here, in the Tester zone. No line or arrow touches the key or its stand. A circular rewind arrow loops around the capsule and its arrowhead ends at a small fingerprint glyph; it never points at the server or back into the capsule. Below, two small branching binary trees of glowing round sphere nodes joined by thin lines (hash trees, not chains, not cubes) stand side by side.
Single report: there is exactly ONE report document in the whole image (besides the blank capsule sheets); no document under each tree. One thin dotted line leaves the root of each tree; the two lines merge into one dotted arrow that ends at that single JSON report document with abstract lines. A pen-nib signature mark sits on that report document; it is the only pen-nib mark in the image.
Gap: that single signed report document floats in the gap, straddling the dashed line. Nothing else crosses: no key, no cable, no capsule.
Right zone, labeled "Recipient": a separate desk with its own key ring of three keys, all teal, held on one round ring. The ring hangs from a short teal line that descends from the very top edge of the image, beside the "Recipient" label, not out of the label, never from the report. No stand, rack, or hook post in the Recipient zone. A small self-contained verifier device with no cables and no incoming lines or arrows faces the report. Its screen shows only a soft teal check glyph.
Text: draw ONLY these two labels, each spelled exactly, in a clean white sans-serif typeface, large and legible: "Tester" above the left zone and "Recipient" above the right zone. No other letters, words, numbers, code, file names, digests, or fake small print anywhere.

Style: premium editorial technical illustration in clean isometric 3D, in the same visual family as a deep-navy README cover. Soft matte ceramic surfaces and translucent glass panels, precise geometry, crisp silhouettes, subtle soft lighting, generous breathing room, uncluttered. Background: solid deep navy (close to #0d1d32) with a very faint blueprint grid, fully opaque, even margins. Palette: teal and pale blue for structure and connecting lines, white for labels, small amber accents, small coral accents. Every element must stay readable when the whole image is shown 880 pixels wide.
Avoid: people, faces, or hands; brand or company logos; EU flag or any ring of stars; certificates, diplomas, ribbons, rosettes, wax seals, or approval stamps; padlock or shield badges; blockchain chain links or chains of cubes; AI brain, neural network, or robot; clouds, globes, or world maps; dashboards, charts, graphs, or gauges; flames, lightning bolts, or thermometers; scannable QR codes; watermark; signature or artist mark.
```
