# Architecture decision records

Audience: contributors and assessors.
Purpose: list the decisions that shape the engine, with the reason for each.
Prerequisites: none.

The records use the MADR style. A number is never reused. A changed decision gets a new record.

Status of all records: **proposed**. Decisions 0001 to 0012 are implemented in version 0.1.0rc1.
Decision 0013 is implemented after that version.
No human maintainer has ratified them yet. See the open question OQ-002.

| Record | Decision |
| --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions |
| [0002](0002-no-language-model-at-run-time.md) | No language model at run time |
| [0003](0003-pydantic-models-are-the-single-source-of-truth-for-the-schemas.md) | Pydantic models are the single source of truth for the schemas |
| [0004](0004-applicability-is-a-data-tree-with-three-valued-logic.md) | Applicability is a data tree with three-valued logic |
| [0005](0005-external-interactions-sit-behind-injected-interfaces-and-the-verifier-stands-alone.md) | External interactions sit behind injected interfaces, and the verifier stands alone |
| [0006](0006-the-canonical-decision-body-uses-rfc-8785-with-integers-only.md) | The canonical decision body uses RFC 8785 with integers only |
| [0007](0007-only-a-documented-human-approval-makes-an-interpretation-approved.md) | Only a documented human approval makes an interpretation approved |
| [0008](0008-the-first-signing-profile-is-jws-compact-serialization-with-es256.md) | The first signing profile is JWS Compact Serialization with ES256 |
| [0009](0009-records-are-committed-with-salted-commitments-and-a-domain-separated-merkle-tree.md) | Records are committed with salted commitments and a domain-separated Merkle tree |
| [0010](0010-verdict-precedence-is-fail-then-error-then-inconclusive-then-pass.md) | Verdict precedence is fail, then error, then inconclusive, then pass |
| [0011](0011-the-ics-and-the-ixit-are-untrusted-input.md) | The ICS and the IXIT are untrusted input |
| [0012](0012-one-policy-enforcing-transport-on-the-standard-library.md) | One policy-enforcing transport on the standard library |
| [0013](0013-manual-results-are-signed-by-the-performer-under-a-separate-trust-purpose.md) | Manual results are signed by the performer under a separate trust purpose |
