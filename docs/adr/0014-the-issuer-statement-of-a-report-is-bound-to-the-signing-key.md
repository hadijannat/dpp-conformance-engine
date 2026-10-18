# 0014. The issuer statement of a report is bound to the signing key

- Status: proposed (not ratified by a human maintainer)
- Date: 2026-10-18
- Deciders: the owner closed OQ-003 on 2026-10-18; a human maintainer must ratify

## Context and problem

The issuer statement in the manifest is free text from the operator, and readers see it. The verifier checked only that the issuer of the key equals the issuer of the attestation (gaps D6-04 and D8-12). A report could therefore name one issuer and carry the signature of another trusted issuer.

## Decision

The dimension `issuer_trust` binds the issuer statement of the report to the signing key. The verifier takes the issuer of a key from its own trust bundle only.

- A stated issuer identifier that differs from the issuer of the key fails with `ISSUER.STATEMENT.MISMATCH`. The detail names both values.
- A signed report that states the issuer `unspecified` fails with `ISSUER.STATEMENT.UNSPECIFIED`. This applies also when a trust bundle names a key with that issuer.
- An accreditation status other than `not accredited` with an empty reference fails with `ISSUER.ACCREDITATION.NO_REFERENCE`.
- On a pass, the detail shows the accreditation status and the reference as the operator declared them.

The rule applies only in the verifier. The decision body and its digest do not change.

The identifier is bound. The name is not, because the trust bundle holds no name. The HTML report labels the name as declared by the operator.

An issuer that stays `unspecified` gives `fail`, not `not_checked`. Here `not_checked` means that nothing could be evaluated. In this case a trusted key signed a report that names no issuer, which is a defect of the report. Both values keep `complete` false and give exit code 4.

Accreditation is declared by the operator. The engine never validates it. No issuer is written in the code: the operator states it with `--issuer-name`, `--issuer-id`, `--accreditation-status`, and `--accreditation-reference`.

## Consequences

- A report signed while its issuer is `unspecified` no longer verifies as complete. This includes every report from 0.1.0rc1. Run again with `--issuer-id`, then sign again.
- The quickstart in the README and in the tutorial passes `--issuer-id`.
- Two verification tests of the rc1 fixture now expect `issuer_trust` to fail.
- `plan` and `run` refuse an accreditation status other than `not accredited` without a reference (exit code 2).
- The verification report schema does not change. Only the detail texts change.

## Alternatives considered

- `not_checked` for `unspecified`: rejected for the reason above.
- A model validator on the issuer statement: an old signed report would then fail as a `structure` error and could not be rendered.
- A new decision version that carries the issuer of the key: it duplicates the trust bundle.
- An issuer name in the trust bundle, compared with the stated name: a change of the trust bundle contract, out of scope.
- A refusal at `dppce sign`: possible later.
- An X.509 (`x5c`) report profile: out of scope.
