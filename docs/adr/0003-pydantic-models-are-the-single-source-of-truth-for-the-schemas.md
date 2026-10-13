# 0003. Pydantic models are the single source of truth for the schemas

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

The task needs versioned JSON Schemas and matching models. Two hand-written definitions drift apart.

## Decision

The Pydantic v2 models in `dppce.models` are the source. `scripts/gen_schemas.py` generates the JSON Schemas into `src/dppce/schemas/v1/`. A test fails if a generated file differs from the models. Each contract carries a `schema_version`. `dppce.migrations` upgrades an older document, and rejects an unknown version.

## Consequences

- A model change without a schema update fails the test suite.
- Every model is closed: an unknown key is an error.
- The schema text follows the style of the generator, not a hand-tuned style.

## Alternatives considered

- Schemas as the source with generated models: weaker validators and weaker typing.
- Two hand-written definitions with a comparison test: twice the work for the same guarantee.
