# 0001. Record architecture decisions

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

The project makes decisions that later contributors and assessors must be able to trace.

## Decision

Record each significant decision as a short Markdown file in `docs/adr/`, in the MADR style. Give each file a number that is never reused.

## Consequences

- A reader can find why the code is as it is.
- A decision changes only through a new record that supersedes the old one.

## Alternatives considered

- Keep decisions in commit messages only: hard to find and impossible to supersede cleanly.
