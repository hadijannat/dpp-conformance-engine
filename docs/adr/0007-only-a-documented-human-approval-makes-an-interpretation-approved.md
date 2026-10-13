# 0007. Only a documented human approval makes an interpretation approved

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

A requirement interpretation is a normative statement. Agents wrote the draft interpretations in this repository. Agreement between agents is not a human approval, and human approval is not accreditation.

## Decision

A requirement has a lifecycle: `placeholder`, `draft-needs-review`, `approved`, `superseded`, `withdrawn`. The loader rejects `approved` without an approval record that names the reviewer, the date, the rationale, the source version, and the review artifact. The lint rejects an agent-authored interpretation that is marked approved. The engine has no command that writes an approval record. Entries for EN, ISO, IEC, and DIN documents ship as placeholders with an empty paraphrase. An approved pack is imported from outside and never changes the shipped catalogue.

## Consequences

- The shipped catalogue supports illustrative and exploratory runs only.
- A reviewed claim needs a pack that a human maintainer wrote and signed off.
- No tool in this repository can fabricate an approval.

## Alternatives considered

- Ship agent interpretations as approved after an agent review: this would misstate their authority.
