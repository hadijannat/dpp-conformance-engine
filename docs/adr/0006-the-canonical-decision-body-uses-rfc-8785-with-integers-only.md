# 0006. The canonical decision body uses RFC 8785 with integers only

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

The decision digest must be the same on every platform. JSON numbers are a known source of differences between implementations.

## Decision

The engine serializes its own decision body with RFC 8785 (JCS). A number must be an integer between -(2^53 - 1) and 2^53 - 1. A float is rejected. A quantity uses an integer unit, for example watt-hours. A time is a UTC string. JCS is the canonical form of the engine's own bodies only. It does not replace the processing rules of a credential securing specification.

## Consequences

- The digest does not depend on float formatting.
- Contracts cannot hold a fractional number. They use a smaller unit or a string.
- The verifier also requires a document to equal the canonical form of the validated model, so a default or a coerced value cannot hide a difference.

## Alternatives considered

- Allow floats under JCS number rules: correct in theory, fragile across libraries.
- A custom canonical form: no independent implementations to compare with.
