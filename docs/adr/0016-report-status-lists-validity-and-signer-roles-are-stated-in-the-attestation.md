# 0016. Report status lists, validity, and signer roles are stated in the attestation

- Status: proposed (not ratified by a human maintainer)
- Date: 2026-10-18
- Deciders: the owner authorized the T1 contract packages on 2026-10-18; a human maintainer must ratify

## Context and problem

An issuer could not withdraw a signed report. A `status_as_of` date in the trust bundle gave `status` a pass, but no evidence about the report itself existed (gap D6-03). A report also could not carry a second signature with a declared role, for example a reviewer (gap D8-14, report part).

## Decision

- The issuer states the new facts in the signed attestation. Version `dppce.attestation/2` adds `role`, `status`, `valid_until`, and `supersedes`. Each field is present, and `null` has no value.
- `dppce sign` still writes version 1 byte for byte when it uses none of these fields.
- The trust bundle gains two purposes. `review` signs reviewer attestations. `status` signs status lists.
- One public key cannot hold `review` and `report`. The rule compares the key material, not the key identifier: `TRUST.KEY.ROLE_CONFLICT`.
- A status list is a signed compact JWS that `dppce` defines: `dppce.statuslist/1` with `typ: "dppce-status-list+jws"`.
- Its bitstring uses the encoding of the W3C Bitstring Status List v1.0, built with `zlib` and `base64` from the standard library.
- The operator supplies the list as a file with `--status-list`. Nothing fetches it. `run`, `replay`, and the IXIT never read it.
- The verifier gains the dimension `signers`, which is always mandatory, and the dimension `validity`.
- `status` is mandatory when the trust policy sets `require_status`, when a list is supplied, or when a passing issuer signature names a status entry.
- `validity` is mandatory when a passing issuer signature states `valid_until`.
- The lifecycle comes from every passing issuer signature. A difference between them fails `signers` with `SIGNER.LIFECYCLE.CONFLICT`.
- `run` and `replay` never sign. A person signs as reviewer with `dppce sign --role reviewer` and a key that only that person holds.

## Consequences

- Decision bodies, the envelope, and replays do not change. Decision digests do not change.
- A verifier from before this decision refuses a version 2 attestation. That is safe.
- The review key and the report key are kept apart, also under two key identifiers.
- A `status_as_of` date alone no longer gives `status` a pass.
- An extra signature can now make verification incomplete. It names a trusted key and does not verify, or its key does not hold the purpose of its role.
- The list of signatures is not signed. A holder can remove signatures. The issuer therefore states the lifecycle in each of its signatures.

## Alternatives considered

- A decision body version 3: it changes the replay layouts.
- New envelope fields: they are not signed, or they duplicate the attestation.
- A W3C verifiable credential for the status list: it needs the credential data model and JSON-LD processing.
- A fetch through the policy transport: ADR 0005 and ADR 0011 keep the verifier offline and the IXIT untrusted.
- A vendored W3C test suite: no license was located.
- A reviewer name in the attestation: ADR 0013 names a key and a role, not a person.
- A status entry in the IXIT: ADR 0011 does not let the supplier choose what the test host trusts.
- The lifecycle from the first passing signature only: a holder can reorder signatures.
- `signers` that fails on every key problem of an extra issuer signature: it changes the meaning of `issuer_trust`.
