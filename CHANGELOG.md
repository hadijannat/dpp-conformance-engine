# Changelog

All notable changes to this project are recorded in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0rc1] - not released

This is a release candidate. It has not been tagged or published.

### Added

- Data contracts as Pydantic models, with generated JSON Schemas and a migration mechanism.
- Three-valued applicability evaluation over a restricted expression tree.
- Verdict aggregation with a published precedence table, and coverage of the selected catalogue.
- Deterministic planning, one evaluation path for live runs and replays.
- A policy-enforcing transport with protection against request forgery and DNS rebinding.
- Encrypted recordings with salted commitments, and retention by `dppce purge`.
- Canonical decision body (RFC 8785, integers only), Merkle roots, and JWS ES256 signing.
- A standalone verifier that reports each verification dimension separately.
- Thirteen checks for carrier, identifier, API, data, access, integrity, persistence, registry,
  and Asset Administration Shell, with a capability manifest.
- Battery profiles for EV, LMT, and industrial batteries, and a synthetic reference system.
- An illustrative requirement pack, a draft pack for Regulation (EU) 2023/1542, and placeholders
  for eight EN standards.
- A fault catalogue and a method-validation runner.
- JSON and HTML reports.

### Security

- Fixed during development, before any release: a parser differential in the verifier;
  request forgery through IPv6 translation prefixes; secrets in recorded headers and URLs;
  trust, secrets, paths, and private hosts selected by an untrusted IXIT; a library size limit
  reported as an invalid signature; certificate paths accepted without certificate authority
  constraints; revocation compared as text; and two fail-open paths in the access check.

[Unreleased]: https://example.invalid/compare/v0.1.0rc1...HEAD
[0.1.0rc1]: https://example.invalid/releases/tag/v0.1.0rc1
