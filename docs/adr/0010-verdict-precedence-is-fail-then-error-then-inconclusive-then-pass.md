# 0010. Verdict precedence is fail, then error, then inconclusive, then pass

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

A verdict must never look better than the evidence. An execution defect must not read as a failure of the tested system, and missing evidence must not read as a pass.

## Decision

The precedence tables in the architecture contract, section 7, are normative for the code. A valid failing observation gives `fail`. With no failure, an execution defect gives `error`. Otherwise unknown applicability or missing evidence gives `inconclusive`. `pass` needs resolved applicability and every required step passed. `not_applicable` needs positively established non-applicability. Assessment paths are alternative ways to assess: any failing path fails the requirement, and one complete passing path is enough when none fails. The overall outcome uses applicable mandatory requirements only, and an empty run cannot pass.

## Consequences

- A check that raises is an error, never a fail.
- An unreachable system is inconclusive unless an approved test method says otherwise. The engine reads `on_unreachable: fail` as `inconclusive` outside reviewed mode, and the lint refuses it for a requirement that is not approved.
- A run with a recommended requirement that fails can still have the overall outcome pass. The report shows both.

## Alternatives considered

- Fail only if every alternative path fails: an unavailable path could hide a real failure.
