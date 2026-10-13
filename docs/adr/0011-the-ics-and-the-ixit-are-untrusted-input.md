# 0011. The ICS and the IXIT are untrusted input

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

The supplier of the system under test usually writes the ICS and the IXIT. Those files must not decide what the test host trusts, reads, or discloses.

## Decision

The trust bundle comes only from the operator. The operator confirms each non-public host, and each secret reference that the IXIT declares, on the command line. A secret reference can name only an environment variable with the `DPPCE_SECRET_` prefix or a file inside an operator-supplied directory. A role credential goes only to an origin that a validated authorization names. A path in the IXIT must stay inside the directory of the IXIT file. An ICS declaration cannot waive a mandatory requirement: declared non-implementation is a static conformance failure.

## Consequences

- A supplier cannot self-authorize a test, read a secret of a different system, or make the engine read a local file.
- A run needs more command-line arguments. Each one is a deliberate confirmation.
- The IXIT field for a trust bundle is a label only.

## Alternatives considered

- Load everything that the IXIT names: convenient, and exploitable by the party under test.
