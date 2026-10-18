# Changelog

All notable changes to this project are recorded in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- A new run writes the decision body as `dppce.decision/2`. Version 2 adds the required field
  `manifest.bound_files`, the hash of each file that the profile binds. A verifier of 0.1.0rc1
  rejects a version 2 body.
- The verifier and `dppce replay` still read a `dppce.decision/1` body as written, with the same
  decision digest. A version 1 body with `bound_files`, or a version 2 body without it, is a
  structure error.

## [0.1.0rc1] - 2026-10-15

This is a release candidate. Tag `v0.1.0rc1` marks it. It is not published on PyPI.

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
- Fixed after the independent security review of 2026-10-13
  (`validation/records/review-evidence-security-2026-10-13.md`, findings F-01 to F-17):
  - A limit of the engine on a signed passport is `inconclusive`, never an invalid signature.
  - A signed payload is compared with the published passport as a JSON value.
  - A request for a role is sent only with the credential of that role. It stops at a
    cross-origin redirect.
  - The access check decodes a body before it looks for a canary. It does not assess an
    encoded or undecodable body.
  - One request has a total time limit. A redirect to a path outside ASCII raises nothing.
  - A sample file is read from the confirmed path without following a link.
  - `dppce purge` lists first, deletes only with `--yes`, and deletes only an authentic
    recording. The index of a recording is authenticated.
  - Response header values are recorded only for a fixed list of safe names.
  - The operator confirms each public host (`--allow-remote-host HOST`), sets the retention
    period (`--retention-days`), and gives the time for a verification section (`--at`).
  - The verifier also checks that the verdicts in a signed report follow from its test results.

- Fixed after the review of the fix itself: the signed payload and the published passport are
  compared with exact numbers and with booleans apart from numbers; a `Link` header with
  anything but targets and relation names is removed as a whole.

### Fixed

- After the independent review of verdicts and planning of 2026-10-14
  (`validation/records/review-verdicts-and-planning-2026-10-14.md`, findings V-01 to V-09):
  - A test purpose identifier in two selected test packs is a plan error and a lint error.
  - `on_unreachable: fail` counts only in reviewed mode. The lint refuses it for a requirement
    that is not approved.
  - A step that its applicability left out of a path is named in `retained`.
  - `replay --times` needs 1 or more.
  - A step result must obey the step verdict table. A result for a step that the plan does not
    run is not evidence.
  - The lint refuses a stale approved requirement next to its successor.
  - An applicability defect at run time is exit code 2.

- Found by mutation testing: a signed token with a part that is not base64url is `MALFORMED`,
  not `BAD_SIGNATURE`.

- After review round 2 of 2026-10-14 (`validation/records/review-round-2-2026-10-14.md`):
  - The transport never raises on a URL that cannot be parsed, sends no credential on an
    anonymous request, applies one deadline to a whole fetch, reads a sample file only if it
    is still the confirmed regular file, drops URL fragments from records, and removes its own
    credential from a recorded answer that echoes it.
  - Purge reads every record before it deletes, deletes named files only, and the retention
    period is 0 to 3650 days. Records come back in acquisition order past r9999.
  - The verifier also derives claim levels, reasons, and coverage figures again. A deeply
    nested signature header is malformed, not a crash.
  - The integrity check does not pass an unknown critical extension or a TLS-only key, never
    raises on a malformed certificate, follows cross-signed paths, and reports a chain cap
    and an invalid trust anchor as limits, not as failures of the tested system.
  - The access check reads wide encodings and JSON escapes, searches redirect and link URLs,
    treats a null field as withheld, and is not fully checkable when redaction removed part
    of a URL.
  - `on_unreachable: fail` counts only for a test purpose whose requirements are all approved.
  - The report reflows at 320 CSS pixels.
  - Found by the follow-up reviews of these fixes: the credential scrub also covers redirect
    targets, header names, percent-encoded forms, and a credential cut by the body limit, and a
    credential needs 12 characters or more; the verifier checks each coverage count, the
    implementation denominator, the ratio labels, and the placeholder count; purge works
    through open directories, so a directory swapped in after the check is not emptied; and a
    passport signed with the key of a self-signed anchor passes again.
  - Draft EU pack: the status entries keep `unknown` for an earlier placing; the date rule is
    stated as the one comparison that it evaluates; the labels entry covers Article 13(1) to (3).

### Changed

- `--allow-remote-read` is replaced by `--allow-remote-host ORIGIN`.
- `--allow-private-host` and `--allow-remote-host` take an origin, such as
  `http://127.0.0.1:8765`, not a bare host.
- A recording needs its sealed index (`recording.sealed`). A recording written before that file
  existed is not replayed and not purged by `dppce purge`. No such recording was published.
  Delete it by hand after its retention period.
- `purge_expired` needs the data keys and returns what it kept and why.
- A role request no longer follows a cross-origin redirect (architecture, section 9).

[Unreleased]: https://github.com/hadijannat/dpp-conformance-engine/compare/v0.1.0rc1...HEAD
[0.1.0rc1]: https://github.com/hadijannat/dpp-conformance-engine/releases/tag/v0.1.0rc1
