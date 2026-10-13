# Accessibility of the HTML report

Audience: assessors, and contributors who change the report.
Purpose: state the accessibility target, what the design does for it, and what is not verified.
Prerequisites: none.

## Target

The target is WCAG 2.2, level AA, for the HTML report that `dppce report` writes.
This page does not claim conformity. Automated checks alone cannot establish conformity, and
no manual review has been done.

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

| Check | Status | Evidence |
| --- | --- | --- |
| Automated accessibility scan of a generated report | not run | No scanner was available in the development session. |
| Keyboard-only review | not performed | none |
| Screen reader review | not performed | none |
| Contrast measurement | not performed | The colors were chosen for contrast. Nobody measured them. |
| Reflow at 320 CSS pixels and 400 percent zoom | not performed | none |

## Manual review record

A reviewer fills in one row for each review. No review has been done, so the table is empty.

| Date | Reviewer | Tool and version | Report reviewed (decision digest) | Findings | Result |
| --- | --- | --- | --- | --- | --- |
