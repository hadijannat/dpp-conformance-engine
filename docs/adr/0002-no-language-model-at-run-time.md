# 0002. No language model at run time

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

Language models helped to develop this engine. A conformance verdict must be reproducible and explainable. A model that judges applicability or a verdict would make neither property possible.

## Decision

Applicability, test execution, and verdict aggregation use deterministic code and versioned data only. No run-time path calls a language model. A language model can propose an interpretation during development. A human must approve it before it can support a claim.

## Consequences

- The same recording and inputs always give the same decision digest.
- Each verdict traces to a published rule.
- The engine cannot interpret free text. A requirement that needs judgment gets a manual step.

## Alternatives considered

- Let a model classify ambiguous responses: not reproducible, and not auditable.
