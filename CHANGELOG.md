# Changelog

All notable changes to this project are recorded in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Stakeholder research dated 2026-10-29, with primary sources, evidence classes, coverage gaps, and proposed priorities.
- A conceptual README cover, mobile diagram layouts, editable Draw.io sources, and image provenance.
- README for a broad audience. It explains why the engine exists and who it is for.
  It lists the profiles and their packs, the execution modes and claim levels, and the limitations.
  It adds a path to test your own battery passport system.
  A table compares what stakeholders expect of a DPP conformance engine with this version.
  A list names related tools.
- Four diagrams in `docs/images/`: tested areas, run, verdicts, and traceability. Development agents
  drew them from a specification that agents checked against the architecture contract. No person
  has reviewed them. A screenshot shows the top of the HTML report of the demo.
  Each image has a text alternative directly below it.
- Each registered check declares a closed parameter model. The capability reference lists the
  parameters of each check.
- Lint codes `CAT019` to `CAT022`. `CAT019`: the parameters of a test purpose do not fit its check.
  `CAT020`: the cited version has no version token of the source record. `CAT021`, a warning: the
  source record shows a later version or amendment. `CAT022`: a date in a legal obligation is not
  in `applicable_dates` of its source.
- Lint code `CAT023`: the check of a test purpose probes a role that the test purpose does not
  list in `roles`. An absent parameter `role` counts as the default role of the check.
- Reason code `STATUS.SUPERSEDED_BY_SELECTED`. The planner excludes a draft in each mode if an
  approved entry in a selected pack names it in `supersedes`. The mode must permit that entry.
  Both entries must be illustrative, or neither. The planner does not change a pack file.
- The HTML report shows the severity of each test step. A step whose test purpose is not
  available shows the stored value with the label "Default".
- Signed manual-step results (ADR 0013). The operator supplies one with `--manual-result PATH` on
  `dppce plan` and `dppce run`. The check `manual.review` verifies it with a key of the trust
  purpose `manual`. The payload schema is `manualresult`.
- A manual result names the digest of its test purpose and the SUT version that the ICS declares.
  The time of the review must be in the validity period of the key. Otherwise the result is
  refused with a `MANUAL.*` code. No maximum age applies.
- The verifier has the mandatory dimension `manual_results`. The fault catalogue version 0.2.0 adds
  the evidence fault `E-13`.
- `dppce manual digest --test-purpose ID` prints the digest that a manual result must name. The
  check `manual.review` computes it with the same function.
- The schema `runinputs` for `inputs.json`, version `dppce.runinputs/2`. It records the data root
  and the digest of each input of the run.
- `dppce replay` checks the inputs before it evaluates. A missing data root or a changed input
  gives exit code 2 with `REPLAY.DATA_ROOT.MISSING` or `REPLAY.INPUT.CHANGED`.
- RFC 3161 timestamps (ADR 0015). The verifier checks each token in `timestamp_evidence` against
  the `timestamp_anchors` of the trust bundle. The imprint is SHA-256 over a report signature
  value. The `timestamp` dimension can give `pass`. The capability `evidence.rfc3161` is
  `supported`. The verifier does no network I/O.
- `dppce timestamp imprint` prints the imprint of each signature. `dppce timestamp attach` adds
  the token of a `TimeStampResp` file that the operator obtained. No command contacts a timestamp
  authority.
- The run-time dependency `asn1crypto` (MIT) parses timestamp tokens.
- Report status lists (ADR 0016, D6-03). The issuer signs a `dppce.statuslist/1` list. Its
  bitstring uses the W3C Bitstring Status List encoding. The operator supplies the file with
  `--status-list` on `dppce verify`, `dppce report`, and `python -m dppce.verifier`. Nothing
  fetches it. The capability `evidence.status_list` is `supported`.
- Attestation version 2 states `role`, `status`, `valid_until`, and `supersedes`. `dppce sign`
  takes `--role`, `--valid-until`, `--supersedes`, `--status-list-id`, and `--status-index`. A
  plain issuer signature is still version 1.
- A second signature with a declared role, for example `reviewer` (D8-14, report part). The
  trust purposes `review` and `status`. One public key cannot hold `review` and `report`:
  `TRUST.KEY.ROLE_CONFLICT`.
- The verifier has the mandatory dimension `signers` and the dimension `validity`. The HTML report
  lists each signature as declared. The fault catalogue version 0.5.0 adds `E-14` and `E-15`.
- Operator key tooling (D6-08). `dppce keys generate` writes a P-256 key as encrypted PKCS#8 and
  prints its public JWK. `dppce authorize` signs a test authorization with the key of the system
  owner. `dppce trust-bundle add-key` writes a `dppce.trust/2` bundle with one more key.
- `dppce open` writes the salt and the plaintext of one record. `dppce prove` writes the inclusion
  proof of one result. The schemas `opening` (`dppce.opening/1`) and `proof` (`dppce.proof/1`).
- `--opening` and `--proof` on `dppce verify` and `python -m dppce.verifier`. A supplied file adds
  the mandatory dimension `opening` or `proof`.
- `--data-key-id` and `--create-data-key` on `dppce run`. `--passphrase-ref`, `--secrets`, and
  `--allow-unencrypted-key` on `dppce sign`.
- `keys generate`, `sign --out`, `authorize`, `trust-bundle add-key`, `open`, and `prove` remove
  their new output file when the write fails, for example on a full disk. A retry then works.
  `run --create-data-key` removes a partial data key in the same way.
  `dppce open` prints its warning before it writes the file.
- Run provenance in `dppce.decision/3`. The run manifest records the authorization id and digest,
  the remote read flag, the trust bundle digest, the passport trust anchor fingerprints, the CA
  file digest, and the test items. Each field is left out while it has its absent value.
- A replay computes the provenance fields again, except the CA file digest and the remote read
  flag. The HTML report shows them in the scope section. `dppce compare` reports them as plan
  inputs. The fault catalogue version 0.12.0 adds `E-16` and `F-76`.
- OPTIONS is a read, like GET and HEAD. It needs no active scope, but an authorization must name
  it in its methods. Records keep the six access-control response headers. The allowed origin is
  redacted like a URL.
- A recorded Link value keeps the relation `linkset`, the JSON-LD context relation, and the GS1
  link types in `gs1:` and IRI form. The list of GS1 link types comes from the pinned file in
  `tests/vectors/gs1-webvoc/`. A test compares the two.
- `resolver.linkset` judges a linkset that a Link header of the linkset answers advertises
  (RFC 9264, section 6). The extra request comes only after both answers pass.
- The IXIT resource names `description`, `shells`, `submodels`, `view`, and `credential`.
  `api.contract` can judge the AAS description and shell list operations. The IXIT version stays
  `dppce.ixit/1`.
- `data.jsonschema`, `data.context`, and `data.rules` take the optional parameter `source`. It is
  `item`, `model`, `credential_payload`, `embedded_jsonld`, or the name of an IXIT sample. A
  credential payload is judged only after the credential verifies. Each embedded JSON-LD script
  of an HTML page is judged.
- `data.jsonschema` takes the parameter `schema`, and `data.rules` takes `rule_pack`. Each names a
  file under the data root. Each file that a test purpose of a selected test pack names is a
  bound file of the run.
- Reason codes `DATA.PARAMS.INVALID`, `DATA.SAMPLE.MISSING`, `DATA.CREDENTIAL.UNVERIFIED`,
  `DATA.EMBEDDED.MISSING`, and `DATA.EMBEDDED.TOO_LARGE`.
- Records and record openings keep `redirect_statuses`, the status of each redirect hop. The
  field is left out when it is empty, so an old recording keeps its commitments.
- `Request.follow_redirects`. With `false`, the transport returns the first answer and follows no
  redirect.
- `resolver.conformance` takes the parameter `expected_redirect_statuses`. The first hop of the
  default request must have one of these statuses. The default accepts 301, 302, 303, 307, and 308.
- Reason codes `RESOLVER.CONFORMANCE.REDIRECT_STATUS` and
  `RESOLVER.CONFORMANCE.HOP_STATUS_NOT_RECORDED`.
- The fault catalogue version 0.13.0 adds `F-77`, `F-78`, `B-09`, and `E-17`.

### Changed

- The README starts with a local demo and clearer reader routes. Its expectation table now cites sources.
  The diagrams use larger labels and separate result and record-commitment trees. Failed-run guidance preserves the evidence.
- `dppce sign --out`, `authorize`, `trust-bundle add-key`, and `prove` create each new file with
  mode 0600. Change the mode to share a report, a proof, a token, or a bundle.
- `dppce sign` needs `--out NEW_FILE` or `--in-place`. It no longer writes over the input by
  default. `--out` refuses the input path and any existing file.
- `dppce sign --in-place` refuses an input that is a symbolic link (`SIGN.INPUT.LINK`). The
  replaced file keeps the mode of the input.
- `dppce sign` refuses an unencrypted key unless `--allow-unencrypted-key` is given. The shipped
  TEST-ONLY report key is not encrypted, so the tutorial, the README, and the validation rig give
  that option.
- `dppce sign` refuses an envelope that fails `structure`, `ordering`, `results_root`,
  `records_root`, or `counts` (`ENVELOPE.BODY.INVALID`, exit code 2).
- `dppce run` no longer creates a missing data key. Give `--create-data-key` the first time.
  `--data-key-id` selects the key; the default is `local-data-key-1`. `compose.yaml`, the README,
  the tutorial, and the validation rig give `--create-data-key`.
- `--allow-private-host` and `--allow-remote-host` on `dppce run` refuse a value with userinfo, a
  query, a fragment, a space, or a control character. This includes an empty query or fragment,
  such as `http://127.0.0.1:8765?`. `dppce authorize` refuses such an endpoint with
  `AUTHORIZE.ENDPOINT.INVALID`. The refusal does not show the value.

- `status` no longer passes on a fresh `status_as_of` date alone. It needs a supplied status list
  with a clear bit. A report with `require_status` and no list is not complete.
- `signature` and `issuer_trust` consider only signatures with the role `issuer`. An extra
  signature that names a trusted key and does not verify, or whose key lacks the purpose of its
  role, now makes verification incomplete.
- An invalid trust bundle shows its first problem on the command line, for example
  `TRUST.KEY.ROLE_CONFLICT`, in place of a count of validation errors.

- The trust bundle is version `dppce.trust/2`. `revoked_certificates` scopes each revoked serial
  number by its issuer name or issuer key identifier (D8-10). `revoked_keys` and
  `revoked_certificates` carry `revoked_at`. `dppce.migrations` upgrades a version 1 bundle. It
  refuses one with revoked serial numbers (`TRUST.MIGRATION.UNSCOPED_SERIAL`) or a field of the
  wrong shape (`TRUST.MIGRATION.MALFORMED`).
- `inputs.json` is version `dppce.runinputs/3`, with a version 2 trust bundle. A version 2 record
  is upgraded. Decision digests do not change.
- `issuer_trust` checks a report key at the earliest `genTime` of a good timestamp over its
  signature, or else at the evaluation time. Each detail names that time. The revoked text is now
  "is revoked at" a time. A later failure ends with "Key validity was checked at" a time.
- The `signature` dimension passes if any signature verifies and binds. Before, a failing
  signature after a good signature whose key was not valid gave `fail`.

- `issuer_trust` binds the issuer statement to the signing key (ADR 0014). A signed report whose
  issuer identifier differs from the issuer of the key, or is `unspecified`, does not verify as
  complete. This includes every signed report from 0.1.0rc1.
- An accreditation status other than `not accredited` needs a reference. `plan` and `run` refuse
  one without it (exit code 2). The engine does not validate an accreditation.
- `inputs.json` is version `dppce.runinputs/2`. `dppce.migrations` upgrades a version 1 record,
  which still replays with no input check.
- `dppce replay` uses the recorded data root when `--data-root` is not given. A changed bound
  file now stops a replay with exit code 2 before it evaluates. Before, it gave exit code 4.
- The HTML report marks the issuer name and the accreditation fields as declared by the operator.

- `dppce plan`, `dppce run`, and `dppce replay` refuse a selected test pack whose parameters do not
  fit the check. They also refuse an ICS date fact that is not a calendar date. Both give exit code 2.
- A recording with such inputs can no longer be replayed. Replay it with the engine version that
  made it.

- A new run writes the decision body as `dppce.decision/3`. Version 2 adds the required field
  `manifest.bound_files`, the hash of each file that the profile binds. Version 3 also requires
  it. Only version 3 holds the run provenance fields of the manifest. A verifier of 0.1.0rc1
  rejects a version 2 or version 3 body.
- The verifier and `dppce replay` still read a `dppce.decision/1`, `/2`, or `/3` body as written,
  with the same decision digest. A version 1 body with `bound_files`, a version 2 or 3 body
  without it, or a version 1 or 2 body with a provenance field, is a structure error.

### Fixed

- The engine joins URL parts and judges public addresses with its own rules, not with the stdlib of
  the running Python. So CPython 3.12.3 and later releases give the same records and verdicts.
  Before, a redirect to a `Location` such as `http:b` got a false unknown-base mark on 3.12.3, and a
  6to4 address counted as public there.
- A public address now excludes six special-purpose ranges in `2001::/23` that CPython 3.12.3
  refuses, the deprecated site-local network `fec0::/10`, and the deprecated 6to4 relay anycast
  network `192.88.99.0/24`. A system under test at such an address needs an entry in
  `allow_private_hosts`.
- The origin override of the test rig keeps a path that starts with `//`. Before, CPython 3.12.12
  and later requested `////` for it.
- A secret reference whose value is not valid UTF-8 gives exit code 2 with a fixed message.
  Before, `dppce run` gave exit code 3 with a message that named one byte of the secret and its
  position.
- After the agent review of the adapters of 2026-10-18
  (`validation/records/review-adapters-2026-10-18.md`):
  - `api.contract` judges only the answer of the marked operation. A redirect, a query, or a
    dot segment gives `blocked`. A contract outside the subset is `unsupported` before the fetch.
    The body may be any JSON value.
  - JSON Schema checks use exact decimals and assert `format: uri`. A format that the engine
    cannot assert is never passed. A body too deep to validate is `blocked`.
  - The data, persistence, and registry checks judge a document only with status 200. 401, 403,
    and 404 give `<AREA>.RESPONSE.NOT_CONCLUSIVE`; another status gives `<AREA>.RESPONSE.STATUS`.
  - Update times are instants. A future update time is not fresh. `parse_stamp` accepts only the
    canonical ASCII form. The trust, authorization, attestation, and status list models refuse
    other stamps too. They also refuse a stamp that names no real moment, such as
    `2026-02-30T00:00:00Z`. A signed authorization with such a stamp gives `AUTHZ.MALFORMED`.
  - `data.context` reads every `@context`, and `data.rules` with no applied rule is `blocked`.
  - The registry check compares JSON values and never passes on an absent field.
  - Carrier texts without a usable URL are unresolved, and hostile images are blocked. The
    transport refuses a URL with a control character or a space.
  - The credential scrub covers more echo forms and keeps the end of a complete body.
  - A validation control fails when a planned step stops completing.
- An explicit port 0 is no longer read as the default port. Before, `http://127.0.0.1:0` had the
  origin `http://127.0.0.1`, so a confirmation or a credential for port 80 also covered it, and
  the transport connected to port 80. `--allow-private-host`, `--allow-remote-host`, and the
  endpoints of `dppce authorize` refuse port 0.
- `Observation.acquired_at` uses the shared stamp type. It refuses non-ASCII digits and a moment
  that does not exist, such as `2026-02-30T00:00:00Z`. The schemas `decision`, `envelope`,
  `opening`, and `proof` now give the pattern with `[0-9]`.
- The verifier gives `not_checked` for a supplied proof or opening when the dimension `ordering`
  does not pass. Before, a proof against a body with two results in the wrong order gave `pass`
  if the stated root was computed over that order. The index of a leaf is its position in
  ascending key order, so such a proof places the leaf where the order does not.

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
