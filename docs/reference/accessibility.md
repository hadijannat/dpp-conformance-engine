# Accessibility of the HTML report

Audience: assessors, and contributors who change the report.
Purpose: state the accessibility target, what the design does for it, and what is not verified.
Prerequisites: none.

## Target

The target is WCAG 2.2, level AA, for the HTML report that `dppce report` writes.
This page does not claim conformity. Automated checks alone cannot establish conformity, and
no manual review by a person has been done.

## What the design does

| Topic | Measure in `dppce.report.html` |
| --- | --- |
| Language | The document sets `lang="en"`. |
| Structure | One `h1`, sections with `h2`, and `header`, `main`, and `footer` landmarks. |
| Bypass | A "Skip to the report" link is the first focusable element. |
| Tables | Each table has a caption and column headers with `scope="col"`. |
| Meaning without color | A verdict is always a word, with a text symbol. Color carries no meaning. |
| Contrast | Text and borders use high-contrast colors in the light and the dark scheme. |
| Reflow | Wide tables scroll inside a focusable region with a label. The page has no fixed width. |
| Focus | Links and scroll regions have a visible focus outline. |
| No script | The page has no script and loads nothing from the network. |
| Plain language | The report starts with a summary in plain language. |
| Untrusted text | Every value from the tested system is escaped. |

## Diagrams

Diagrams in the documentation are text blocks or Mermaid diagrams. Each one has a text
alternative directly below it.

## Verification status

A development agent ran the checks below on 2026-10-14 and 2026-10-15. It used two reports that
the reference system produced: a clean run and a run with three seeded faults. They are not a
manual review by a person, and no accessibility scanner such as axe was run.

| Check | Status | Evidence |
| --- | --- | --- |
| Automated accessibility scan of a generated report | not run | No scanner was available in the development session. |
| Structure: language, title, landmarks, heading order, table captions and header scope, skip link target, no script, no external resource | run by an agent | A script that parses the generated HTML. No problem found. |
| Contrast of the color tokens, light and dark scheme | measured by an agent | WCAG relative luminance from the tokens in `dppce.report.html`. Text at least 7.2:1; borders at least 4.1:1. |
| Keyboard: first focusable element and its focus indicator | run by an agent in a browser | The first Tab reaches "Skip to the report", with a 3 px outline. A full keyboard-only review is not done. |
| Reflow at 320 CSS pixels | run by an agent in a browser | First run: the page was 665 pixels wide, because hashes in the scope list did not wrap. Fixed with `overflow-wrap` on `dd`; after the fix the page is 320 pixels wide. Wide tables scroll inside their own labeled region. |
| Screen reader review | not performed | none |
| 400 percent zoom, text spacing, and a full keyboard-only review | not performed | none |

## Manual review record

A reviewer fills in one row for each review. No review has been done, so the table is empty.

| Date | Reviewer | Tool and version | Report reviewed (decision digest) | Findings | Result |
| --- | --- | --- | --- | --- | --- |
