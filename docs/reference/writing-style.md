# Writing style

Audience: contributors who write documentation.
Purpose: state the writing target, the automated checks, and their limits.
Prerequisites: none.

## Target

The target is Simplified Technical English in the style of ASD-STE100, Issue 9.
The source audit found that Issue 9 is the current issue. The audit could not read the
publisher's own pages, so the license terms are known from search excerpts only.
On that evidence, redistribution is not permitted. This repository therefore contains no text,
no rule, and no dictionary entry of that specification. See `catalogue/sources.yaml`.

## Rules that this project applies

- Procedures: at most 20 words in a sentence. Descriptions: at most 25 words.
- Short paragraphs. One topic in a paragraph.
- Active voice, when the agent is known.
- One term for one concept. Use the [glossary](glossary.md).
- American English.
- Each page starts with audience, purpose, and prerequisites.

## Automated checks

The rules in `styles/STE` are project-authored Vale rules for sentence length, word
replacements, likely passive constructions, words that end in -ing, and likely noun clusters.

```bash
vale docs README.md
```

Status: on 2026-10-15, `uv run just style` ran Vale 3.22.0 with these rules. It found 0 errors
and 0 warnings. Suggestions remain. See the [readiness page](../readiness.md), section 2.

## Limits

- Each rule is a heuristic. A finding is a prompt for a human review, not a defect.
- The rules do not check the approved vocabulary of Simplified Technical English.
- Full conformity with ASD-STE100 needs a review by a trained human editor. No such review
  has been done. This project does not claim conformity.

## What the style rules never change

Do not change these to satisfy a style rule:

- a legal citation, or a quotation from a legal text;
- an approved requirement interpretation;
- a license text;
- code, a schema identifier, a reason code, or a command.

## Documented exceptions

| Text | Rule | Reason |
| --- | --- | --- |
| Tables that list reason codes | Sentence length | A table cell is not a sentence. |
| `recording`, `signing`, `testing`, and similar terms | -ing forms | They are nouns of the project glossary. |
| Titles of laws and standards | All | They are quoted as published. |
