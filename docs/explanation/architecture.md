# Architecture and engineering contract

Audience: contributors, reviewers, and assessors who must know how the engine reaches a verdict.
Purpose: define the module boundaries, the semantics, and the formats that all code must obey.
Prerequisites: read the [glossary](../reference/glossary.md).

This page is normative for the code base. It is not a legal text.
If the code and this page disagree, that is a defect. Fix one of them in the same change.

## 1. Pipeline

```text
plan -> run (acquire + evaluate) -> recording -> replay -> report -> sign -> verify
```

Text alternative: `plan` selects the requirements and test steps. `run` executes the steps
through a policy-enforcing transport and writes an encrypted recording. `replay` evaluates the
same recording again. `report` renders JSON and HTML. `sign` adds a signature. `verify` checks
the signed report and needs neither the orchestrator nor the system under test.

No language model takes part at run time. Applicability, execution, and verdicts are
deterministic code and versioned data.

## 2. Modules and import rules

| Module | Responsibility | May import |
| --- | --- | --- |
| `dppce.models` | Pydantic contracts. Single source of truth for the JSON Schemas. | nothing in `dppce` |
| `dppce.applicability` | Three-valued evaluation of expression trees. | `models` |
| `dppce.catalogue` | Load sources and packs, lifecycle rules, lint, import of approved packs. | `models`, `applicability` |
| `dppce.profiles` | Load profiles and the resources that they name. | `models` |
| `dppce.testdefs` | Load YAML test packs. Hold the allowlisted check registry. | `models`, `infrastructure.interfaces` |
| `dppce.adapters` | Implement and register checks. Publish the capability manifest. | `models`, `testdefs`, `infrastructure.interfaces`, `evidence.jws` |
| `dppce.verdicts` | Aggregation truth table and coverage. Pure functions. | `models` |
| `dppce.evidence` | Canonical JSON, Merkle tree, commitments, encryption, signing. | `models`, `infrastructure.interfaces` |
| `dppce.verifier` | Standalone verification of an envelope. | `models`, `evidence`, `verdicts` |
| `dppce.infrastructure` | Transport, recorder, replay, clock, key providers, reference server. | `models`, `evidence` |
| `dppce.orchestrator` | Plan, run, replay. | all of the above except `verifier` |
| `dppce.report` | JSON and HTML rendering. | `models`, `evidence` |
| `dppce.cli` | Command-line entry point. | all |

Rules:

1. `catalogue`, `applicability`, `verdicts`, and `evidence` do no network I/O.
2. `verifier` never imports `orchestrator`, `adapters`, `testdefs`, or the transport.
3. A check reaches the outside world only through the `Acquirer` protocol.
4. YAML is parsed only by `dppce.catalogue.load_data`. It uses a subclass of PyYAML's
   `SafeLoader` that also rejects a repeated key. A test proves that a `!!python/object` tag is
   rejected. No YAML value is evaluated as code or as a template.
5. No module fetches a schema, a JSON-LD context, or a `$ref` from the network. Every such
   resource is a pinned local file.

## 3. Data layout

```text
catalogue/sources.yaml             source audit records
catalogue/packs/*.yaml             requirement packs
profiles/battery/{ev,lmt,industrial}.yaml
profiles/battery/schemas/          project-authored JSON Schemas (item-level and model-level)
profiles/battery/rules/            rule packs
profiles/battery/contracts/        pinned OpenAPI contract of the reference system
profiles/battery/access/           declared access policy of the reference system
testpacks/*.yaml                   declarative test purposes
fixtures/                          synthetic inputs for tests; not shipped in the wheel
validation/                        fault catalogue and method-validation records
```

`catalogue`, `profiles`, and `testpacks` ship in the wheel under `dppce/_bundled/`.
`dppce.infrastructure.resources.data_root()` returns the bundled directory, or the repository
root in a source checkout. The CLI option `--data-root` overrides it.

## 4. Execution modes and claim levels

| Mode | Requirements that may be assessed | Claim level of a result |
| --- | --- | --- |
| `illustrative` | `authority_class: illustrative` only | `illustrative` |
| `exploratory` | review status `draft-needs-review` or `approved`, and illustrative ones | `diagnostic`, or `illustrative` |
| `reviewed` | review status `approved` only | `reviewed` |

A requirement that the mode does not permit is listed as an exclusion with a reason code.
It is never silently dropped. A `placeholder` requirement has no paraphrase and no tests.
It stays in the coverage counts and its verdict is `inconclusive`.

A test purpose runs only in a mode that its `permitted_modes` lists.

Only a human can set `approved`. The loader rejects an `approved` requirement that has no
`approval` record with reviewer, date, rationale, source version, and artifact.
The engine has no command that writes an approval record.

## 5. Applicability

An expression is a data tree with five node shapes: `const`, a comparison, `all`, `any`, `not`.
Evaluation returns `true`, `false`, or `unknown`, and a human-readable reason.

- Facts are addressed by dotted paths under `ics.` and `profile.`.
- A fact that is missing, or whose value is the string `unknown`, gives `unknown`.
- `all` is Kleene conjunction: `false` wins, then `unknown`, then `true`.
- `any` is Kleene disjunction: `true` wins, then `unknown`, then `false`.
- `not unknown` is `unknown`.
- `gt`, `ge`, `lt`, `le` accept two integers or two ISO dates. Any other pair is a catalogue
  defect: evaluation raises `ApplicabilityError` and `catalogue lint` reports it.
- `in`, `not_in` need a list operand. `contains` tests membership in a list-valued fact.

Missing information never becomes `false` and never becomes `not_applicable`.

## 6. Planning

`plan` is a pure function of the mode, profile, packs, test packs, ICS, sanitized IXIT, the
capability manifest, and the validated authorization. Its output is sorted by identifier.

For each requirement in the selected packs:

1. If the mode does not permit it, record an exclusion. Reason codes: `MODE.NOT_ILLUSTRATIVE`,
   `MODE.NOT_APPROVED`, `STATUS.SUPERSEDED`, `STATUS.WITHDRAWN`.
2. Evaluate `applicability`.
3. Evaluate `declared_support` when present. If the requirement is applicable and mandatory and
   `declared_support` is `false`, record a conflict. The requirement stays applicable.
   This is a static conformance failure: the declaration is the failing observation.
4. For each assessment path, evaluate the path applicability (default `true`).

For each test purpose that a selected requirement names, in a permitted mode and profile:

| Condition, tested in this order | Planned status |
| --- | --- |
| Step applicability is `false` | none; the step is left out of its path with a reason |
| Parent requirement applicability is not `true` | `skipped` |
| Step applicability is `unknown` | `skipped` |
| `manual: true` | `manual_unavailable` |
| Check is not in the registry, or its capability is `interface_only` or `unsupported`, or its optional dependency is not installed | `unsupported` |
| `requires_scope` is above `read` and no valid authorization grants it | `blocked` |
| Otherwise | none; the step is executed |

An unavailable adapter never produces `pass`.

## 7. Verdicts

### 7.1 Step verdict

| Execution status | Check result | Step verdict |
| --- | --- | --- |
| `completed` | passed | `pass` |
| `completed` | not passed, `on_check_failed: fail` | `fail` |
| `completed` | not passed, `on_check_failed: inconclusive` | `inconclusive` |
| `completed` | `unreachable`, `on_unreachable: inconclusive` | `inconclusive` |
| `completed` | `unreachable`, `on_unreachable: fail` | `fail` |
| `error` | any | `error` |
| `not_run`, `skipped`, `blocked`, `unsupported`, `manual_unavailable` | any | `inconclusive` |

A check that raises an exception gives status `error`. It never gives `fail`.

### 7.2 Path verdict

Inputs: the step verdicts of the steps that remain in the path. Precedence, first match wins:

1. Path applicability `false`: `not_applicable`.
2. Path applicability `unknown`: `inconclusive`.
3. Any step `fail`: `fail`.
4. Any step `error`: `error`.
5. Zero steps: `inconclusive`. A path with no executable step cannot pass.
6. Any step `inconclusive`: `inconclusive`.
7. Every step `pass`: `pass`.

### 7.3 Requirement verdict

Precedence, first match wins:

1. Requirement applicability `false`: `not_applicable`, with the recorded reason.
2. Requirement applicability `unknown`: `inconclusive`.
3. A static conformance conflict exists (section 6, step 3): `fail`.
4. No assessment path is defined: `inconclusive`.
5. Paths are alternative ways to assess. Take the paths whose verdict is not `not_applicable`:
   - none remain: `inconclusive` (no permitted path is declared as implemented);
   - any `fail`: `fail`. A valid failing observation establishes the failure, even if a
     different path passes. The disagreement is kept in `retained`;
   - any `pass`: `pass`. One complete path is enough. An error or a gap in a different path
     is kept in `retained`;
   - any `error`: `error`;
   - otherwise: `inconclusive`.
6. In `reviewed` mode a `pass` needs review status `approved`. If not, the verdict is
   `inconclusive`. The planner already excludes such a requirement; this is a second barrier.

Each other problem that the precedence hides is kept in `retained`.
For example a requirement that fails can also retain an error and a skipped step.

A valid failing observation is one from a completed step, on an applicable step of an
applicable requirement. A failing value seen while applicability is `unknown` establishes nothing.

### 7.4 Overall outcome of a run

The overall outcome uses the mandatory requirements only. Precedence:

1. No requirement result exists, or none is mandatory with applicability `true`: `inconclusive`.
   An empty run cannot pass.
2. Any `fail`: `fail`. 3. Any `error`: `error`. 4. Any `inconclusive`: `inconclusive`. 5. `pass`.

The overall outcome is the outcome for the selected catalogue scope. It is not a statement of
legal compliance. Results for `recommended` and `optional` requirements are reported separately.

### 7.5 Coverage

All figures are counts of requirements in the selected catalogue. Each ratio carries its
numerator, its denominator, and the label `of`.

- Implementation coverage: requirements with at least one path whose steps are all executable
  by a `supported` or `experimental` capability, over all requirements.
- Execution coverage: applicable requirements with at least one path whose steps all completed,
  over applicable requirements.
- Passing: applicable mandatory requirements with verdict `pass`, over applicable mandatory ones.

Placeholders, unknown applicability, exclusions, and missing manual assessments are counted
and shown. No figure may be labeled as coverage of a law or of a standard.

## 8. Checks

A check is a Python function `(CheckContext) -> CheckOutcome` in `dppce.adapters`.
It is registered under a dotted name in `dppce.testdefs.registry`. A test purpose can name
only a registered check. Parameters are validated data.

`CheckContext` gives: the test purpose, its parameters, the ICS, the IXIT, the profile, the
`Acquirer`, the evaluation time, a loader for pinned local resources, the trust bundle, and the
validated authorization. A check reads the clock from the context only.

Reason codes are stable and machine-readable. Format: `AREA.TOPIC.DETAIL` in upper case.
`AREA.OK` style codes mark a pass, for example `DATA.SCHEMA.OK`.

Initial registry:

| Check | Capability | Purpose |
| --- | --- | --- |
| `carrier.qr_decode` | `carrier.qr` | Decode a QR image artifact with zxing-cpp. Needs the `qr` extra. |
| `identifier.parse` | `identifier.parse` | Scheme-aware parse of the carrier payload. |
| `identifier.resolve` | `identifier.resolve` | Bounded resolution of the identifier to a passport. |
| `identifier.consistency` | `identifier.consistency` | Same identifier in carrier, resolver, passport, and ICS. |
| `api.contract` | `api.contract` | Response matches the pinned OpenAPI contract. |
| `data.jsonschema` | `data.jsonschema` | Document matches the pinned JSON Schema. |
| `data.context` | `data.context` | Every `@context` entry is in the pinned allowlist. |
| `data.rules` | `data.rules` | Rule pack: completeness, units, ranges, relationships, freshness. |
| `access.restricted_fields` | `access.policy` | A role does not get fields that the declared policy withholds. |
| `integrity.jws` | `integrity.jws` | Signature validity, issuer trust, and certificate validity, as separate findings. |
| `persistence.versions` | `persistence.versions` | Version history obeys the declared update rule. |
| `registry.consistency` | `registry.mock` | Registry record agrees with the passport. Passive lookup only. |
| `aas.validate` | `aas.validate` | Wrap aas-test-engines. Needs the `aas` extra. |

Digital consistency does not prove physical authenticity. A signature that verifies does not
prove that the signed attributes are true. Each check states such a limit in its message.

## 9. Transport policy

Every adapter uses one transport. Defaults: read-only methods, bounded, rate-limited, with a
`User-Agent` of `dppce/<version> (+<contact>)`.

- Destinations: only hosts in `IXIT.network.allowed_hosts`. Loopback, private, link-local, and
  other non-public addresses also need an entry in `allow_private_hosts`.
- The transport resolves the host once, checks every resolved address against the policy, and
  connects to the checked address. This prevents DNS rebinding.
- Redirects are followed by the transport, never by the HTTP library. Each hop is checked.
  An out-of-scope hop ends the request with `redirect_out_of_scope`.
- Credentials are sent only to the origin they are configured for. They are dropped on a
  cross-origin redirect.
- Methods other than `GET` and `HEAD` need a valid authorization with the matching scope.
- Limits: timeout, maximum body size (the body is truncated and flagged), maximum redirects,
  maximum request count, and minimum interval. Each limit that triggers is recorded.
- Secrets are removed from request headers before a record is created.
- Response bodies are bytes. HTML is never rendered or executed. Archives are never unpacked.

A transport failure is data: `Record.error`. The check reports `unreachable`.
By default that is `inconclusive`, because a connectivity failure does not prove a breach.

### 9.1 The IXIT is untrusted input

The supplier of the system under test can write the ICS and the IXIT. The engine therefore
does not let those files decide what the test host trusts or discloses:

- The trust bundle comes only from the operator (`--trust`). A bundle that the IXIT names is
  never loaded. Otherwise a supplier could name its own key as a trusted authorization issuer.
- Each non-public host in `IXIT.network.allow_private_hosts` must be confirmed by the operator
  with `--allow-private-host`. A public host needs an authorization or `--allow-remote-read`.
- A secret reference is `env:DPPCE_SECRET_<NAME>` or `file:<name>` inside the directory that
  the operator gives with `--secrets`. No other environment variable or file can be named.
- A role credential is sent only to an origin that a validated authorization names.
- A path in the IXIT is resolved and must stay inside the directory of the IXIT file.

## 10. Recording

A recording is a directory.

```text
recording.json     index: schema version, key id, delete-after date, record ids, commitments
records/<id>.enc   one encrypted record each
```

- Each record (metadata, sanitized request, response, body, salt) is serialized and encrypted
  with AES-256-GCM. The nonce is 96 random bits. The associated data is the record id and the
  schema version.
- The data key comes from a `DataKeyProvider`. The key is never stored in the recording directory.
- The index holds no URL, no header, and no payload.
- Commitment: `HMAC-SHA256(key = salt, message = "dppce.record.v1" || 0x00 || plaintext)`.
  The salt is 32 random bytes drawn at acquisition and stored inside the encrypted record.
  A bare hash of a predictable value is never published.
- `delete_after` is the acquisition date plus `IXIT.observation.retention_days`.
  `dppce purge` deletes recordings past that date.

Replay serves records by sequence. A replayed request that differs from the recorded one in
method, URL, or role gives `recording_mismatch`, which is an execution error.

## 11. Evidence

### 11.1 Canonical decision body

The decision body is serialized with RFC 8785 (JCS). Numeric constraint: every number is an
integer in the range -(2^53 - 1) to 2^53 - 1. Floats are rejected. Quantities use integer units.
Times are UTC strings `YYYY-MM-DDTHH:MM:SSZ`.
`decision_digest = "sha256:" + hex(SHA-256(JCS(decision body)))`.

JCS is the canonical form of the engine's own decision body only. It does not replace the
processing rules of any credential securing specification.

### 11.2 Merkle tree

Hash: SHA-256. `P = "dppce.merkle.v1" || 0x00 || label || 0x00`, where `label` is `results` or
`records`.

- Leaf hash: `H(P || 0x00 || leaf)`.
- Node hash: `H(P || 0x01 || left || right)`.
- Empty tree: `H(P || 0x02)`.
- One leaf: the root is the leaf hash.
- More leaves: split at the largest power of two below `n`, as RFC 6962 does. A node is never
  duplicated to pad an odd level.

Leaves, in ascending order of key:

- `results`: `JCS(result)` for each requirement result (key `R:` + id) and test result (key `T:` + id).
- `records`: `JCS({"record_id", "commitment"})` (key: record id).

The verifier rejects keys that are not strictly ascending. That detects a duplicate and a reorder.
The file-backed log in `evidence.devlog` is a development component. It does not implement
RFC 9162 and gives no protection against equivocation.

### 11.3 Signing profile

One profile: JWS Compact Serialization (RFC 7515) with `ES256`. The allowlist is `["ES256"]`.
The payload is `JCS(attestation)`. The protected header holds `alg`, `kid`, and
`typ: "dppce-attestation+jws"`. Keys in the repository are test keys and say so in their names.
Production keys come from a `Signer` implementation for a KMS or PKCS#11 device.
Qualified electronic seals, COSE, RFC 3161, Bitstring Status List, and UNTP DCC export are
separate profiles with their own capability states.

### 11.4 Verification

`dppce verify` needs the envelope, an explicit trust bundle, and an explicit evaluation time.
It reports each dimension separately:

| Dimension | Mandatory | Passes when |
| --- | --- | --- |
| `structure` | yes | The envelope matches the schema. |
| `ordering` | yes | Result and record keys are strictly ascending. |
| `results_root` | yes | The recomputed root and count equal the stated ones. |
| `records_root` | yes | The recomputed root equals the stated one. |
| `counts` | yes | Verdict counts and coverage totals equal the recomputed ones. |
| `signature` | yes | At least one signature verifies with an allowlisted algorithm and binds the recomputed digest. |
| `issuer_trust` | yes | The signing key is in the trust bundle and is valid at the evaluation time. A key that only the report supplies is not trusted. |
| `status` | per trust policy | Fresh status or revocation evidence is present and good. |
| `timestamp` | per trust policy | Trusted timestamp evidence is present and good. |

`complete` is true only if every mandatory dimension passes. If the trust policy makes
`status` or `timestamp` mandatory and the evidence is missing or stale, `complete` is false.
Verification never changes or restates the verdict about the tested system.

## 12. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command completed. For `run` and `replay`: the overall outcome is `pass`. |
| 1 | The system under test failed: the overall outcome is `fail`. |
| 2 | Usage or input error: bad arguments, invalid file, lint findings. |
| 3 | Execution error: the overall outcome is `error`, or the engine failed. |
| 4 | Evidence verification failed or is incomplete. Replay digest mismatch. |
| 5 | The run completed and the overall outcome is `inconclusive`. |

Every command accepts `--json` and then writes one JSON document to standard output.
