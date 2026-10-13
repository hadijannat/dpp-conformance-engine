# 0004. Applicability is a data tree with three-valued logic

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

Applicability rules live in YAML files that a third party can supply. Executing an expression language or a template from such a file is a code-execution risk. Missing information must not silently become "does not apply".

## Decision

An expression is a tree of five node shapes: a constant, a comparison, `all`, `any`, and `not`. The evaluator is a pure function that returns `true`, `false`, or `unknown` with a reason. It uses Kleene logic. A missing fact, or the value `unknown`, gives `unknown`. A type mismatch is a catalogue defect and raises an error.

## Consequences

- A YAML file cannot run code.
- An unknown fact gives an inconclusive verdict, never a not-applicable one.
- The language is small. A rule that it cannot express needs a new node shape and a new record.

## Alternatives considered

- A Python expression string: arbitrary code execution.
- A template engine: the same risk, and no three-valued result.
- Two-valued logic with defaults: turns missing information into a verdict.
