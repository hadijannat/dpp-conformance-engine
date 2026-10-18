# 0015. Trusted timestamps are RFC 3161 tokens over the report signature value

- Status: proposed (not ratified by a human maintainer)
- Date: 2026-10-18
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

The `timestamp` dimension could never pass (BL-004, gap D6-01). Key validity was judged only at the evaluation time, and the signer states `signed_at` (gap D6-02). An old report therefore failed `issuer_trust` after its key expired. Revoked serial numbers were not scoped by issuer (gap D8-10).

## Decision

- A timestamp is an RFC 3161 token whose imprint is SHA-256 over the JWS signature value. It proves that this signature existed at `genTime`.
- The token binds the signature, so it binds the attestation and the decision digest. The imprint is not over the decision digest, as BL-004 first stated. A digest token would not show when the signature existed.
- The trust bundle lists timestamp anchors apart from passport anchors. One purpose never trusts a certificate for the other.
- The TSA certificate path is checked at `genTime`. `issuer_trust` checks the report key at the earliest good `genTime` over its signature, or else at the evaluation time.
- A revocation carries `revoked_at`. Null means revoked at every time.
- A revoked serial number is scoped by its issuer name or its issuer key identifier.
- The engine never contacts a timestamp authority. `dppce timestamp imprint` prints the imprint. The operator gets a response file and attaches it with `dppce timestamp attach`.
- The verifier does no network I/O.
- `asn1crypto` (MIT, pure Python) parses the DER. `cryptography` verifies the signature.

## Consequences

- Trust bundle version 2 and run inputs version 3. A version 1 bundle with revoked serial numbers is refused, not guessed.
- The envelope and the decision body do not change. Decision digests and replays do not change.
- A compromised TSA key can backdate a token. The operator must revoke its certificate with `revoked_at` null or with the time of the compromise.
- One more run-time dependency.

## Alternatives considered

- An imprint over the decision digest: it does not show when a signature existed.
- `purposes` on each anchor: one shared list can be misconfigured. Two lists cannot mix.
- The ASN.1 module of `cryptography` (`cryptography.hazmat.asn1`): it adds no dependency. A spike decoded the needed structures. Its documentation says to consider the API unstable. Its backwards compatibility policy does not cover it. It also needs `cryptography` 47 or later.
- A request builder in the engine: the operator can make a request from the printed imprint. It is deferred.
- A fetch command through the policy transport: deferred. No test may contact a TSA.
- Issuer-less entries for a version 1 serial: they keep the D8-10 defect open.
- Re-timestamp chains for archived reports: deferred.
