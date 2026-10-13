# 0008. The first signing profile is JWS Compact Serialization with ES256

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

A report needs one interoperable signature profile first. More profiles multiply the verification paths that must be correct.

## Decision

Reports and test authorizations are signed as JWS Compact Serialization (RFC 7515) with `ES256`. The algorithm allowlist is fixed in code, and the header never selects the algorithm. The `typ` header separates a report attestation from an authorization. Explicit size limits apply, and a token above a limit is "too large", never "invalid". Keys in the repository are test keys with `TEST-ONLY-` names. Production keys come from an implementation of the `Signer` protocol for a KMS or a PKCS#11 device. COSE, RFC 3161 timestamps, Bitstring Status List, UNTP DCC export, and qualified electronic seals are separate profiles with their own capability states.

## Consequences

- ES256 is available in common KMS and HSM products.
- An ES256 signature is not deterministic. Replays compare the decision digest, not the signature.
- A report from this version carries no trusted timestamp.

## Alternatives considered

- EdDSA: simpler, but less widely available in hardware modules.
- Several profiles at once: more code to get wrong before the first one is validated.
