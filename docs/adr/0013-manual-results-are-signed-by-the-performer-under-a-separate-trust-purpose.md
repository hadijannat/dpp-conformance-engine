# 0013. Manual results are signed by the performer under a separate trust purpose

- Status: proposed (not ratified by a human maintainer)
- Date: 2026-10-18
- Deciders: the owner chose the options on 2026-10-18; a human maintainer must ratify

## Context and problem

Every path of the EU draft pack holds a manual step. The engine had no input for the result of a manual step, so no such path could pass. A result must be attributable and verifiable without the recording. The supplier of the system under test must not be able to supply it.

## Decision

A manual result is a JWS Compact Serialization with `ES256` and `typ: "dppce-manual-result+jws"`. The person who performed the step signs it. The trust bundle names that key with the new purpose `manual`. Only the operator supplies a result, with `--manual-result`. The IXIT cannot name one. The check `manual.review` reads the result through the `Acquirer` as an input artifact. The report holds the whole compact JWS of each accepted result. The verifier checks it under the dimension `manual_results`. The payload names a role and no person. The header holds no certificate chain, and the evidence list must equal the list of the test purpose.

## Consequences

- A manual step can reach `pass` or `fail`. A refused result keeps `manual_unavailable`.
- The verifier stays standalone. It needs no recording to check a manual result.
- The report holds a key identifier, a role, and a time for each manual step. The laboratory maps the key identifier to a person.
- A verifier before this version does not know the dimension `manual_results`.

## Alternatives considered

- A hash commitment only: it binds the file but does not show who signed it.
- A result from the IXIT: the party under test could supply its own result.
- The name of the performer in the report: not needed for verification, and the report goes to other organizations.
- An `x5c` certificate chain in the header: it usually names the person, and the key identifier is sufficient.
- Structured evidence identifiers: a change of every shipped test purpose, with no gain for the verdict.
