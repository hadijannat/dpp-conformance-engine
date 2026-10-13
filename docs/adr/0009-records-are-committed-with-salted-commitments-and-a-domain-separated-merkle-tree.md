# 0009. Records are committed with salted commitments and a domain-separated Merkle tree

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

A report must bind the observations without disclosing them. A bare hash of a predictable value lets anyone confirm a guess. A report must also show if a result was omitted, repeated, replaced, or moved.

## Decision

Each raw record gets `HMAC-SHA256(salt, tag || plaintext)` with 32 random bytes of salt. The salt is drawn at acquisition and is stored inside the encrypted record. Records are encrypted with AES-256-GCM, and the data key lives apart from the recording. Results and record commitments are the leaves of SHA-256 Merkle trees with domain-separated leaf, node, and empty-tree hashes and the RFC 6962 tree shape. Lists are sorted by identifier, and the verifier rejects keys that are not strictly ascending.

## Consequences

- A commitment hides a predictable value.
- A replay reads the stored salts, so the digest repeats. A fresh run has fresh salts.
- The file-backed log is a development component. It does not implement RFC 9162 and gives no protection against equivocation.

## Alternatives considered

- Bare hashes of observations: leak predictable values.
- Deterministic salts: would weaken the randomness to gain repeatable artifacts.
