# README images

Audience: readers and contributors who reuse or change the README images.
Purpose: record each image's source and distinguish illustrations from test evidence.
Prerequisites: none.

The documentation license is [CC-BY-4.0](https://github.com/hadijannat/dpp-conformance-engine/blob/main/LICENSES/CC-BY-4.0.txt).
[REUSE.toml](https://github.com/hadijannat/dpp-conformance-engine/blob/main/REUSE.toml) assigns metadata to `docs/**`.

| Image | Source and meaning |
| --- | --- |
| `dppce-overview.png` | Conceptual cover made with the built-in OpenAI image-generation tool on 2026-10-29. It depicts a battery passport, test instruments, and evidence documents. It is not a screenshot or test result. |
| `report-summary.png` | Existing screenshot of the synthetic local demo's HTML report, dated 2026-10-29 in the README. It illustrates that run only. |
| [Test areas](test-areas.svg) | Seven independent areas of selected checks. [Mobile](test-areas-mobile.svg) · [Editable source](test-areas.drawio) |
| [Run lifecycle](run-lifecycle.svg) | Planning, controlled live contact, outputs, and independent offline operations. [Mobile](run-lifecycle-mobile.svg) · [Editable source](run-lifecycle.drawio) |
| [Verdicts](verdicts.svg) | Five verdicts and the distinction between requirement and overall outcomes. [Mobile](verdicts-mobile.svg) · [Editable source](verdicts.drawio) |
| [Traceability](traceability.svg) | Sources, checks, results, and separate results and record-commitment trees. [Mobile](traceability-mobile.svg) · [Editable source](traceability.drawio) |

The README supplies text alternatives. Select linked diagrams and the report image to inspect them at full size.
The report screenshot is separate from the conceptual cover.
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
