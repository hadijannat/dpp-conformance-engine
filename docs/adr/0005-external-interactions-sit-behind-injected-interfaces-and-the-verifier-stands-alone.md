# 0005. External interactions sit behind injected interfaces, and the verifier stands alone

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

Catalogue interpretation, applicability, verdicts, and evidence construction must be testable offline and must be reproducible. A recipient of a report must be able to verify it without the orchestrator and without the system under test.

## Decision

HTTP, the clock, keys, and local input artifacts are reached only through the protocols in `dppce.infrastructure.interfaces`. A check reaches the outside world only through an `Acquirer`. The live `Acquirer` is the policy transport. The replay `Acquirer` serves a recording. `dppce.verifier` imports the models, the evidence primitives, and the pure verdict functions only. A lint rule and a test enforce that it never imports the orchestrator, the adapters, or the transport.

## Consequences

- One evaluation code path serves a live run and a replay.
- The test suite needs no network.
- A new external service needs a protocol first, then an implementation.

## Alternatives considered

- Let adapters call an HTTP library directly: no single place for policy, recording, or replay.
