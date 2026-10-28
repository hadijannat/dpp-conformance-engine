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
| `dppce.adapters` | Implement and register checks. Publish the capability manifest. | `models`, `testdefs`, `infrastructure.interfaces`, `evidence.jws`, `evidence.manual`, `evidence.x509path` |
| `dppce.verdicts` | Aggregation truth table and coverage. Pure functions. | `models` |
| `dppce.evidence` | Canonical JSON, Merkle tree and inclusion proofs, commitments and record openings, encryption, signing, X.509 paths, RFC 3161 timestamp tokens, and report status lists. | `models`, `infrastructure.interfaces` |
| `dppce.verifier` | Standalone verification of an envelope. | `models`, `evidence`, `verdicts`, `migrations` |
| `dppce.migrations` | Upgrade a stored document to the current schema version. | nothing in `dppce` |
| `dppce.infrastructure` | Transport, recorder, replay, clock, key providers, reference server. | `models`, `evidence` |
| `dppce.orchestrator` | Plan, run, replay. | all of the above except `verifier` |
| `dppce.report` | JSON, HTML, JUnit XML, and SARIF rendering (JUnit and SARIF: P2-authorized). | `models`, `evidence` |
| `dppce.compare` | Compare the decision bodies of two runs. | `models` |
| `dppce.scaffold` | Draft an ICS and an IXIT from a shipped family example (`dppce init`). | `models`, `catalogue`, `adapters`, `infrastructure` |
| `dppce.cli` | Command-line entry point. | all |

Rules:

1. `catalogue`, `applicability`, `verdicts`, and `evidence` do no network I/O.
2. `verifier` never imports `orchestrator`, `adapters`, `testdefs`, or the transport.
3. A check reaches the outside world only through the `Acquirer` protocol.
4. YAML is parsed only by `dppce.catalogue.load_data`. It uses a subclass of PyYAML's
   `SafeLoader` that also rejects a repeated key and a key that cannot be a mapping key.
   `load_data` parses a JSON file with `parse_strict` (section 11), so a repeated key, `NaN`,
   `Infinity`, and a number outside the float range are rejected. A nesting deeper than the
   parser handles is an input error, not a crash. The envelope, the trust bundle, the recording,
   the manual result, the authorization, the record opening, the inclusion proof, the public JWK
   file, and the JWS header and payload are also parsed with `parse_strict`. Every body that the system under test returns is parsed with `parse_strict`.
   So is a sample artifact from the IXIT, such as an AAS file. A test proves that a `!!python/object` tag is rejected. No YAML value is
   evaluated as code or as a template. A URL template (section 9.2) is not evaluated either. The
   engine only replaces named placeholders with percent-encoded values under a fixed grammar.
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
A replay uses the data root that the run recorded, unless the operator gives `--data-root` (section 10.1).

## 4. Execution modes and claim levels

| Mode | Requirements that may be assessed | Claim level of a result |
| --- | --- | --- |
| `illustrative` | `authority_class: illustrative` only | `illustrative` |
| `exploratory` | review status `draft-needs-review` or `approved`, illustrative ones, and placeholders | `diagnostic`, or `illustrative`; `none` for a placeholder |
| `reviewed` | review status `approved` only, and never `authority_class: illustrative` | `reviewed` |

An illustrative requirement is a synthetic rule. It never gives the claim level `reviewed` or
`diagnostic`, also if a person marked it approved. Reviewed mode excludes it: with the reason
code `MODE.NOT_APPROVED` as for each requirement that is not approved, and with
`MODE.ILLUSTRATIVE_NOT_REVIEWABLE` if it is marked approved. Its claim level in that mode is `none`.

A requirement that the mode does not permit is listed as an exclusion with a reason code.
It is never silently dropped. A `placeholder` requirement has no paraphrase and no tests.
The loader rejects a placeholder that names a test. It stays in the coverage counts and its
verdict is `inconclusive`.

A test purpose runs only in a mode that its `permitted_modes` lists.
A test purpose identifier is unique in the selected test packs. The planner refuses a second
definition, also if the mode or the profile excludes one of the two.

Only a human can set `approved`. The loader rejects an `approved` requirement that has no
`approval` record with reviewer, date, rationale, source version, and artifact.
The engine has no command that writes an approval record.

The lint compares the cited version of each requirement that is not illustrative with its source
record. A version token is an ISO date, a dotted number such as `1.2.0`, or a year from 1900 to
2099 that stands alone. An eight-digit calendar date counts in its ISO form and as its year.

- `CAT020`, error: `source.version` has no token that also occurs in `edition_or_version` of the
  source record. The rule applies only if `edition_or_version` has a token.
- `CAT021`, warning: the source record shows a later version. The lint takes the latest ISO date
  in `source.version`. It reports each later ISO date in `edition_or_version` and each later
  amendment date. If `source.version` has no ISO date, the lint does not compare.

These rules compare text only. They do not show that a cited version is the correct one.

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
- In a requirement with `authority_class: legal_obligation`, each date literal must be a date in
  `applicable_dates` of its source record. The lint reports any other date literal with
  `CAT022`. The rule reads the requirement applicability, `declared_support`, and each path
  applicability.

Missing information never becomes `false` and never becomes `not_applicable`.

## 6. Planning

`plan` is a pure function of its inputs. Its output is sorted by identifier.
The inputs are the mode, the profile, the packs, the test packs, the ICS, the sanitized IXIT, and the capability manifest.
The validated authorization and the set of test purposes with a supplied manual result are inputs too.

Before it plans, the engine refuses these inputs with exit code 2. `plan`, `run`, and `replay`
apply the same rules.

- An ICS that does not fit the profile. Each characteristic must be a fact of the profile and
  have its type. A `date` fact is a calendar date written `YYYY-MM-DD` with ASCII digits. One
  message lists every problem of the ICS. A problem with a characteristic names the fact.
- A selected test pack with a test purpose whose parameters do not fit its registered check
  (section 8). The message names each such test purpose.
- A role that the profile does not declare in `roles`. The rule reads the roles of each IXIT identity and of the validated authorization.
  It also reads the access policy that the profile binds and each test purpose in the selected test packs.
  For a test purpose, it reads `roles` and the parameter `role` of `access.restricted_fields`. One message lists each such role and its source.
  A profile without `roles` declares `anonymous` only. A bound policy that cannot be read is not an input error here: the access check reports it (section 8.2).

For each requirement in the selected packs:

1. If the mode does not permit it, record an exclusion. Reason codes: `MODE.NOT_ILLUSTRATIVE`,
   `MODE.ILLUSTRATIVE_NOT_REVIEWABLE`, `MODE.NOT_APPROVED`, `STATUS.SUPERSEDED`, `STATUS.WITHDRAWN`.
   Before these rules, record an exclusion with `STATUS.SUPERSEDED_BY_SELECTED` in each mode if all of these are true:

   - The status of the requirement is `draft-needs-review`.
   - An approved requirement in a selected pack names it in `supersedes`. The order of the packs has no effect.
   - The mode permits that approved requirement.
   - Both are illustrative, or neither is.

   The reason names each such approved requirement. In any other case, `supersedes` has no effect on the plan.
   The planner never changes a pack file.
2. Evaluate `applicability`.
3. Evaluate `declared_support` when present. If the requirement is applicable and mandatory and
   `declared_support` is `false`, record a conflict. The requirement stays applicable.
   This is a static conformance failure: the declaration is the failing observation.
4. For each assessment path, evaluate the path applicability (default `true`).

For each test purpose that a selected requirement names, in a permitted mode and profile:

| Condition, tested in this order | Planned status |
| --- | --- |
| Step applicability is `false` | none; the step is left out of its path with a reason, and the requirement result names it in `retained` with the reason code of its exclusion |
| Parent requirement applicability is not `true` | `skipped` |
| Step applicability is `unknown` | `skipped` |
| `manual: true`, and no manual result is supplied for the step or its check is not `manual.review` | `manual_unavailable` |
| Check is not in the registry, or its capability is `interface_only` or `unsupported`, or its optional dependency is not installed | `unsupported` |
| `requires_scope` is above `read` and no valid authorization grants it | `blocked` |
| Otherwise | none; the step is executed |

An unavailable adapter never produces `pass`.

The operator supplies a manual result with `--manual-result` (section 9.1). The planner reads only the test purpose that the file names.
A step with a supplied result goes on to the next rows of the table. The check `manual.review` verifies the result (section 8.1).
A supplied result must belong to a step that the plan executes. A result for an excluded or skipped step is an input error.

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
A check cannot report `passed` and `unreachable` together. The result models refuse a step
verdict that this table does not give for the execution status.

A server error is not a failing observation. An answer with a status from 500 to 599 counts as a
connectivity failure (section 9). The check reports `unreachable`, and the step verdict follows
`on_unreachable`. By default that is `inconclusive`. It is `fail` only under the approved rule
below. This rule is an owner decision of 2026-10-18.

A rate-limited answer (status 429) counts in the same way (P2-31). The check reports
`unreachable` with `TRANSPORT.RATE_LIMITED`. It never reports a pass.

`on_unreachable: fail` is for an approved test method only: a connectivity failure does not
prove a breach. The engine reads the rule as written only in `reviewed` mode, and only if every
requirement that the test purpose names is approved and not illustrative. Otherwise it reads
the rule as `inconclusive`. The lint refuses the rule on a test purpose that names a requirement
that is not approved (`CAT017`).

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
   The barrier reads the review status only. The planner applies the rule for illustrative
   requirements, and the claim level of such a result is `none` in any case (section 4).

Each other problem that the precedence hides is kept in `retained`. That includes a step that
the planner left out of a path (`STEP.NOT_APPLICABLE`), because the steps that stay can pass alone.
A result for a step that the plan does not run is not evidence: it counts as `inconclusive`
with `RESULT.NOT_PLANNED`.
For example a requirement that fails can also retain an error and a skipped step.

A valid failing observation is one from a completed step, on an applicable step of an
applicable requirement. A failing value seen while applicability is `unknown` establishes nothing.

### 7.4 Overall outcome of a run

The overall outcome uses the mandatory requirements only. Precedence:

1. No requirement result exists, or none is mandatory with applicability `true`: `inconclusive`.
   An empty run cannot pass.
2. Any `fail`: `fail`. 3. Any `error`: `error`. 4. Any `inconclusive`: `inconclusive`. 5. `pass`.

The overall outcome is the outcome for the selected catalogue scope. It is not a statement of
legal compliance. Results for `recommended` and `optional` requirements do not change the overall
outcome. Each result shows its modality. The counts in a report summary cover all modalities.

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
A step with the check `manual.review` is not executable by a capability. It does not count for implementation coverage, also when a manual result is supplied.

## 8. Checks

A check is a Python function `(CheckContext) -> CheckOutcome` in `dppce.adapters`.
It is registered under a dotted name in `dppce.testdefs.registry`. A test purpose can name
only a registered check.

Each check declares a closed parameter model when it is registered. A check with no parameters
declares the empty model.

- The model refuses an unknown key, a value outside a fixed set, and a value of the wrong type.
- The default of a model field is the value that the check uses when the parameter is absent.
- `catalogue lint` reports `CAT023`, an error, if a check with the parameter `role` probes a
  role that the test purpose does not list in `roles`.
  An absent `role` counts as the default role of the check.
- `catalogue lint` reports a test purpose whose parameters do not fit its check with `CAT019`.
  This applies to shipped and imported test packs.
- `plan`, `run`, and `replay` refuse such a test pack (section 6).
- The rule applies to each test purpose whose check is registered, also to a manual one.
- An automated test purpose that names a check that is not registered is not checked. The lint
  reports it with `CAT006`, and the planner gives the step `unsupported`. A manual one gets
  `manual_unavailable`.
- A check still reads its parameters as written and keeps its own guards, because a
  `CheckContext` can be built without the planner.
- The capability reference page lists the parameters of each check. The page is generated from
  the models.

`CheckContext` gives: the test purpose, its parameters, the ICS, the IXIT, the profile, the
`Acquirer`, the evaluation time, a loader for pinned local resources, the trust bundle, and the
validated authorization. A check reads the clock from the context only.

Reason codes are stable and machine-readable. A new code has the format `AREA.TOPIC.DETAIL`
in upper case. Existing codes with two segments, for example `AAS.INVALID`, stay unchanged,
because codes are stable.
Codes such as `DATA.SCHEMA.OK` mark a pass.
A code can take one segment from a closed set at run time, for example `ACCESS.LEAK.EXPORT`.
The [reason-code catalogue](../reference/reason-codes.md) lists each code and each value of such
a set. It names the module that produces a code and, where the registered check function writes
it, the check. It names the step verdict where that call fixes it.
`scripts/gen_reference_docs.py` generates the catalogue from the string literals in `src/dppce`.
`--check` and a test fail when the page and the source disagree.
A reason code is part of the decision body. A changed code changes the decision digest of a
replayed recording.

Initial registry:

| Check | Capability | Purpose |
| --- | --- | --- |
| `carrier.qr_decode` | `carrier.qr` | Decode a QR image artifact with zxing-cpp. Needs the `qr` extra. |
| `identifier.parse` | `identifier.parse` | Scheme-aware parse of the carrier payload. The parameter `form` selects the GS1 Digital Link grammar. The schemes `https-url`, `did-web`, and `urn-uuid` have a parser. |
| `identifier.granularity` | `identifier.granularity` | Classifies a GS1 Digital Link carrier with a GTIN as model, batch, or item level, and compares the level with the granularity of the ICS. Experimental. |
| `identifier.resolve` | `identifier.resolve` | Bounded resolution of the identifier to a passport. |
| `identifier.consistency` | `identifier.consistency` | Compares the carrier identifier with the `id` of the resolved passport. With a QR image sample, it also compares the carrier identifier with the declared sample identifier. With `compare_item`, it also compares the resolved passport with the document at the target of the `item` template. With `sources`, it compares further values at JSON Pointers in place of the `id`. It does not read the ICS. |
| `identifier.equivalence` | `identifier.equivalence` | Compares the carrier with a declared identifier in GS1 canonical form. It does not change the exact-text rule of `identifier.consistency`. Experimental. |
| `api.contract` | `api.contract` | Response matches the pinned OpenAPI contract. |
| `data.jsonschema` | `data.jsonschema` | Document matches the pinned JSON Schema. With `source`, the document can be an IXIT sample, a verified credential payload, or embedded JSON-LD. |
| `data.context` | `data.context` | Every `@context` entry is in the pinned allowlist. A context of a `Link` header and a reference of a pinned context count too. `source` applies as for `data.jsonschema`. |
| `data.rules` | `data.rules` | Rule pack: completeness, units, ranges, relationships, freshness. Version 2 adds pattern, forbidden, equals, and each. `source` applies as for `data.jsonschema`. |
| `access.restricted_fields` | `access.policy` | A role gets each field that the declared policy gives it, and no field that the policy withholds from it. |
| `integrity.jws` | `integrity.jws` | Signature validity, issuer trust, and certificate validity, as separate findings. |
| `integrity.jose` | `integrity.jose` | Verifies a JWS credential or token under a named profile with its own algorithm allowlist. Signature, issuer trust, and validity are separate findings. The report signing profile is unchanged. Experimental. |
| `persistence.versions` | `persistence.versions` | Version history obeys the declared update rule. |
| `registry.consistency` | `registry.mock` | Registry record agrees with the passport. Passive lookup only. |
| `aas.validate` | `aas.validate` | Wrap aas-test-engines for a JSON, XML, or AASX sample. A metamodel version that the pinned release does not verify is `unsupported`. Needs the `aas` extra. |
| `aas.dpp_compose` | `aas.dpp_compose` | Checks the DPP metadata submodel of an AAS environment sample and its relation to the shell, as the pinned IDTA 02099-1 release states. Experimental. |
| `aas.api_profile` | `aas.api_profile` | Sends positive GET probes to an AAS server through the engine transport under a read profile of the AAS API 3.0. It sends no write, negative, or fuzz request. Experimental. |
| `manual.review` | `manual.review` | Verify the signed result of a manual step. The engine does not perform the review. |
| `identifier.negotiation` | `identifier.negotiation` | Sends five fixed `GET` requests to the carrier URL that differ only in the `Accept` header. Checks status, media type, weights, `Vary`, and the body shape. Experimental. |
| `resolver.linkset` | `resolver.linkset` | Fetches the linkset of the carrier identifier, and a linkset that a `Link` header of its answers advertises. Checks its RFC 9264 structure, its anchor, and the declared relations. It does not fetch link targets. |
| `resolver.well_known` | `resolver.well_known` | Checks the GS1 resolver description file at the carrier origin. A redirected file that would pass gives `blocked`. |
| `resolver.conformance` | `resolver.conformance` | Probes the status behavior of a GS1 resolver: the first redirect status of a default request, and the final status of two other requests. |
| `identity.did` | `identity.did` | Resolves a did:web DID, or reads an offline copy of its DID document. Checks the `id`, the verification methods, and the assertion methods. Resolution is not trust. Experimental. |
| `integrity.status_list` | `integrity.status_list` | Verifies a VC-JOSE credential, reads its W3C Bitstring Status List entry, gets and verifies the status list credential, and checks the bit. An unsigned, untrusted, unreachable, or stale list never gives `pass`. Experimental. |

`identifier.resolve` takes three optional parameters. `require_https`, default false, fails a
carrier URL or a redirect target whose scheme is not https with `IDENTIFIER.SCHEME.NOT_HTTPS`.
A refused carrier URL is not fetched. `accept` sets the `Accept` request header.
`accepted_media_types` lists the final media types that count as resolved. Without
`accepted_media_types` the check needs a final JSON object, as before. `IDENTIFIER.RESOLVED`
always means a final JSON object. A pass on another listed media type gives
`IDENTIFIER.RESOLVED.MEDIA_TYPE`. The observation summary always records the final media type.

A linkset (RFC 9264) is not a passport. An answer is a linkset only if it is a JSON object with
`linkset` as its only member. The value of `linkset` is a non-empty list of objects. The media
type does not decide. If a linkset media type comes with a different body, each check judges that
body as any other answer. After the
`accepted_media_types` test, a linkset gives `blocked` with `IDENTIFIER.RESPONSE.LINKSET`. The
check does not follow the links. If `accepted_media_types` lists one of the two linkset media
types, a linkset gives
`IDENTIFIER.RESOLVED.MEDIA_TYPE`. A linkset never gives `IDENTIFIER.RESOLVED`.

`identifier.resolve` reports an answer with a status of 429, or from 500 to 599, as `unreachable`
(section 9).
Any other status except 200, 404, and 410 gives `IDENTIFIER.RESOLUTION.STATUS`.

`identifier.consistency` takes one optional parameter, `compare_item`. It is a boolean with the
default `false`. With `true`, the check also fetches the target of the `item` template. It
compares that document with the resolved passport as JSON values, as `integrity.jws` compares a
payload. The check takes the first row that applies:

1. The carrier identifier is not a URL: `blocked`, `IDENTIFIER.NOT_RESOLVABLE`. A URL here is
   an `http` or `https` URL with a host, a valid port, and no control character or space.
   `identifier.resolve` uses the same test and gives `IDENTIFIER.UNRESOLVED` for any other text.
2. The resolver answer is not a JSON object with status 200, or it is a linkset:
   `blocked`, `IDENTIFIER.NOT_RESOLVED`.
3. An identifier differs: `IDENTIFIER.MISMATCH`. The check does not fetch the item target.
4. With `compare_item`, the `item` template gives no URL: `blocked`, `IDENTIFIER.NO_TARGET`. The
   item target is not fetched.
5. The item target is not a JSON object with status 200: `blocked`,
   `IDENTIFIER.BINDING.NOT_COMPARABLE`.
6. The two documents are different JSON values: `IDENTIFIER.BINDING.MISMATCH`.

A transport error or a server error on either fetch gives `unreachable`. The check always uses
the `item` template, also with `item_target: resolved`, because it compares the two routes.

`identifier.consistency` takes a second optional parameter, `sources`. It is experimental. It
lists 1 to 8 sources. Each source has a `label`, a `kind`, and a `pointer`. The `pointer` is a
JSON Pointer (RFC 6901). The `kind` selects the document:

- `resolved`: the passport that the carrier identifier resolves to.
- `resource`: the document at the IXIT resource template that the `label` names.
- `sample`: the JSON file of the IXIT sample that the `label` names.

The labels are unique. `sources` and `compare_item: true` are not used together. With `sources`,
the check does not compare the `id` of the resolved passport, unless a source points to it. It
fetches only for a source of the kind `resolved` or `resource`. A source of the kind `sample`
sends no request. Each value is compared with the carrier identifier as exact text. A value that
is present and is not text differs. The check takes the first row that applies:

1. The parameters are not valid: `blocked`, `IDENTIFIER.PARAMS.INVALID`. Nothing is read.
2. No carrier identifier is available: as without `sources`.
3. A present value differs from the carrier identifier: fail. With a QR image sample, a declared
   sample identifier that differs gives `IDENTIFIER.MISMATCH`. Otherwise the code is
   `IDENTIFIER.CROSS.MISMATCH`.
4. A source gives no document. The first such source in the list decides:
   - the kind `resolved`: the outcome of rule 1 or 2 without `sources`.
   - the kind `resource` without an IXIT template: `blocked`, `IDENTIFIER.NO_TARGET`.
   - a transport error or a server error: `unreachable`.
   - otherwise: `blocked`, `IDENTIFIER.CROSS.SOURCE_MISSING`.
5. A pointer does not resolve: `blocked`, `IDENTIFIER.CROSS.SOURCE_MISSING`.
6. Otherwise: pass, `IDENTIFIER.CONSISTENT`.

Rule 3 comes before rules 4 and 5. A system under test thus cannot turn a difference into
`blocked` when it changes the shape of another source. The observation summary names the
compared, the different, and the missing labels. It holds no identifier value.

`integrity.jws` verifies the JWS Compact Serialization only. A JWS JSON Serialization (RFC 7515,
section 7.2) is a JSON object with a non-empty base64url `payload`. Here, base64url text holds only
`A-Z`, `a-z`, `0-9`, `-`, and `_`. A signature has a non-empty base64url `signature`, and a
`protected` member, a `header` member, or both. A `protected` value is the base64url form of a
JSON object. A `header` value is a JSON object. The flattened form has the members of one
signature at the top level and no `signatures`. The general form has a non-empty list
`signatures` of signatures and none of their members at the top level. Such a body gives
`blocked` with `INTEGRITY.FORMAT.UNSUPPORTED` and an observation of the signed resource. Any other
body that is not a compact JWS gives `INTEGRITY.TOKEN.MALFORMED`. A
published passport that is a linkset gives `blocked` with `INTEGRITY.PAYLOAD.NOT_COMPARABLE`.
With `item_target: resolved`, a resolver answer that is a linkset gives
`INTEGRITY.NO_TARGET` first (section 9.2).

`integrity.jose` verifies a JWS under a profile of `dppce.evidence.jose_profiles`. Its profiles
are separate from the report signing profile (section 11.3). That profile, the allowlist of
`dppce.evidence.jws`, and `integrity.jws` do not change. The sources are RFC 7515, RFC 7517,
RFC 7518, RFC 8037, RFC 8725, and the W3C Recommendation VC-JOSE-COSE of 13 October 2026.

The check takes seven optional parameters:

- `profile`, default `vc-jose`. The value `vc-jose` judges a credential. The value `jws` judges
  any JWS and reads no `typ` and no claim.
- `key_source`, default `trust_kid`. With `trust_kid`, the `kid` names a key of the trust bundle
  with the purpose `passport`. With `x5c`, the chain in `x5c` must reach a passport anchor, as in
  `integrity.jws`. The value `x5c` needs the profile `jws`, because no rule binds a credential
  issuer to a certificate. With `did`, the `kid` is a did:web DID URL, and the rules of the key
  source `did` below apply. The set is closed.
- `did_sample` names the IXIT sample that holds an offline copy of the DID document. It needs the
  key source `did`. Without it, the check fetches the DID document through the transport.
- `source`, default `signed`. The value `signed` fetches the resource `signed`. The value `sample`
  reads the IXIT sample that `sample` names, default `credential`, and sends no request.
- `accept` sets the `Accept` header of the fetch. The media type of the answer is not judged.
- `algorithms` narrows the allowlist `ES256`, `ES384`, and `EdDSA`.

The check reads a compact, a flattened JSON, or a general JSON serialization. The shape rules of
`integrity.jws` above decide the JSON forms. Every signature must verify. The protected and the
unprotected header of a signature must not share a member name. The check takes the first row
that applies:

1. Invalid parameters: `blocked`, `INTEGRITY.JOSE.PARAMS`. No trust bundle: `blocked`,
   `INTEGRITY.TRUST.MISSING`. Nothing is read.
2. A transport error, a 429, or a status from 500 to 599: `unreachable`. A missing sample: `blocked`,
   `INTEGRITY.JOSE.SAMPLE_MISSING`. A status other than 200: `INTEGRITY.JOSE.NOT_AVAILABLE`. Only
   then, a body coding or a truncated body gives `blocked`, as `unusable` gives.
3. A body above 2 MiB: `blocked`, `INTEGRITY.JOSE.TOO_LARGE`. With more than 8 signatures, the
   check judges the first 8. It gives `blocked`, `INTEGRITY.JOSE.TOO_LARGE`, only if no row fails.
4. A body of another shape, or a header that is not a JSON object: `INTEGRITY.JOSE.MALFORMED`.
5. Then each signature in turn. A header without a string `alg` is `INTEGRITY.JOSE.MALFORMED`.
   The `alg` value `none`, `HS256`, `HS384`, or `HS512` gives `INTEGRITY.JOSE.ALGORITHM`, before
   any key is looked up.
6. A `crit` that is not a list of protected member names is `INTEGRITY.JOSE.MALFORMED`. A `crit`
   that names a member other than `b64` gives `INTEGRITY.JOSE.HEADER`.
7. A `b64` that is unprotected, or that `crit` does not name, is `INTEGRITY.JOSE.MALFORMED`. A
   protected `b64: false` that `crit` names gives `INTEGRITY.JOSE.HEADER` under `vc-jose`. Under
   `jws` it gives `blocked`, `INTEGRITY.JOSE.UNSUPPORTED`, because RFC 7797 defines this form.
8. Under `vc-jose`, a present `typ` other than `vc+jwt` gives `INTEGRITY.JOSE.TYPE`. The check
   compares it without case and accepts the prefix `application/`. An absent `typ` is permitted.
9. With `trust_kid`, no passport key with the `kid` gives `INTEGRITY.JOSE.ISSUER_UNTRUSTED`. A key
   that is revoked, or outside its validity at the evaluation time, gives
   `INTEGRITY.JOSE.KEY_NOT_VALID`. With `x5c`, a missing chain or a chain without a path to an
   anchor gives `INTEGRITY.JOSE.ISSUER_UNTRUSTED`. An `x5c` entry that is not a certificate gives
   `INTEGRITY.JOSE.MALFORMED`. A chain of certificates longer than the limit gives `blocked`.
   With `did`, the rules of the key source `did` below apply.
10. The key type gives the algorithm: P-256 gives `ES256`, P-384 gives `ES384`, and Ed25519 gives
    `EdDSA`. Another key type gives `blocked`, `INTEGRITY.JOSE.UNSUPPORTED`. An algorithm outside
    `algorithms`, or a header `alg` that differs from it, gives `INTEGRITY.JOSE.ALGORITHM`.
11. A signature that does not verify gives `INTEGRITY.JOSE.SIGNATURE`. This includes a signature
    of the wrong length.
12. With `x5c`, the certificate findings of `integrity.jws` follow in its order, with its codes.
13. Under `vc-jose`, the payload must be one JSON object with an `issuer` string or an `issuer`
    object with a string `id`. A claim of the wrong form gives `INTEGRITY.JOSE.CLAIMS`. An `iss`
    that differs from the issuer gives `INTEGRITY.JOSE.ISSUER_MISMATCH`.
14. A `validFrom` or an `nbf` after the evaluation time gives `INTEGRITY.JOSE.NOT_YET_VALID`. A
    `validUntil` before it, or an `exp` at or before it, gives `INTEGRITY.JOSE.EXPIRED`.
15. With `trust_kid` or `did`, a trusted key of another issuer gives
    `INTEGRITY.JOSE.ISSUER_UNTRUSTED`.
16. Otherwise: pass, `INTEGRITY.JOSE.OK`.

Only rows 3, 7, 9, 10, and 12 can give `blocked` after the body is read. Each applies to a
well-formed token only. An engine limit of one signature does not end the check. The check judges
every other signature, every chain, and the claims under `vc-jose`. A fail of any row comes before
any `blocked`, in every order of the signatures. A system under test therefore cannot reshape a
judged defect into a step that is not judged. A signature after the eighth is not judged, and such
a token is never a pass.

The key source `did` applies these rules to each signature, in this order, in row 9:

1. The `kid` must be a DID URL with a non-empty fragment. Another `kid` gives
   `INTEGRITY.JOSE.ISSUER_UNTRUSTED`.
2. No passport key of the trust bundle has the DID as its `issuer`:
   `INTEGRITY.JOSE.ISSUER_UNTRUSTED`. The DID document is not fetched. This rule comes before the
   DID method, so the `kid` of an untrusted signer cannot turn this fail into a limit.
3. The DID must be a did:web DID that maps to a URL, as for `identity.did`. A pinned DID of another
   DID method gives `blocked`, `INTEGRITY.JOSE.UNSUPPORTED`. Another did:web DID gives
   `INTEGRITY.JOSE.ISSUER_UNTRUSTED`.
4. The check resolves the DID with `resolve_did_web`, once for each DID. With `did_sample`, it
   reads the sample and sends nothing. A host without an answer, a redirect out of the scope, or a
   host that the operator did not confirm gives no answer (`unreachable`). A `blocked` outcome of
   the resolver gives `blocked` with its code. Both are kept like an engine limit.
5. A DID document that breaks a rule of `identity.did` gives `INTEGRITY.JOSE.ISSUER_UNTRUSTED`.
6. The `kid` is not an `assertionMethod` entry of the document: `INTEGRITY.JOSE.ISSUER_UNTRUSTED`.
7. The assertion method has no `publicKeyJwk`: `blocked`, `INTEGRITY.JOSE.UNSUPPORTED`.
8. No passport key of the DID has the same `kty`, `crv`, `x`, `y`, `n`, and `e` as the method:
   `INTEGRITY.JOSE.ISSUER_UNTRUSTED`. A matching key that is revoked, or outside its validity, gives
   `INTEGRITY.JOSE.KEY_NOT_VALID`.

Resolution is not trust. The document only shows which key the DID host publishes. The pinned key
decides trust, and row 15 binds it to the credential issuer. The observation of each DID document
follows the observation of the token.

`identifier.parse` takes the optional parameter `form`. Its values are `dppce-item`, the default,
and `gs1-dl`. The default keeps the strict grammar below, so existing decision digests do not
change.

The schemes `https-url`, `did-web`, and `urn-uuid` have a parser. Each other declared scheme
stays `unsupported`, and `unknown` stays `blocked`. A payload that does not match the declared
scheme gives `IDENTIFIER.SYNTAX.INVALID`, never `blocked`, because the payload comes from the
system under test. The parameter `form` applies to `gs1-digital-link` only. With another scheme,
a value of `form` other than the default gives `blocked` with `IDENTIFIER.PARAMS.INVALID`.

- `https-url`: the payload matches the RFC 3986 URI grammar of the `uri` format checker. The scheme
  is `https`. There is no user information and no fragment. The port, if any, is a number from 0
  to 65535. The host is a domain name by the rule of the `did-web` mapping: no IP address and no
  numeric shorthand such as `127.1`. One trailing dot in the host is allowed. A percent-encoded
  host is not a domain name.
- `did-web`: the payload maps to an https URL by the did:web mapping of `identity.did`. That
  mapping refuses IP hosts and numeric shorthand.
- `urn-uuid`: the payload is `urn:uuid:` and then a UUID in the textual form of RFC 9562, which is
  8-4-4-4-12 ASCII hexadecimal digits. The check does not judge version or variant.

With `require_https`, a valid `did-web` or `urn-uuid` identifier gives `IDENTIFIER.SCHEME.NOT_HTTPS`.

With the form `dppce-item`, `identifier.parse` accepts one GS1 Digital Link form. The URL starts with
`http://`, `https://`, `HTTP://`, or `HTTPS://`. With `require_https`, a valid identifier whose
scheme is not https gives `IDENTIFIER.SCHEME.NOT_HTTPS`. The host part is not empty and holds only `A-Z`,
`a-z`, `0-9`, `.`, `-`, `:`, `[`, and `]`. So user information and an IPv6 zone identifier are
refused. A port after the host is ASCII digits only, from 0 to 65535. The path is `/01/<GTIN>/21/<serial>`. The GTIN is 14 ASCII digits with a correct check
digit. The serial is 1 to 20 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`. The whole
URL holds only the characters that RFC 3986 permits in a URI, including `%`. Every other text
gives `IDENTIFIER.SYNTAX.INVALID`. This includes forms that GS1 permits, such as a GTIN without
a serial, a key qualifier, or a path prefix. The check reads the query and the fragment only for
their characters.

The form `gs1-dl` is experimental. It accepts an uncompressed GS1 Digital Link URI, as GS1
Digital Link URI Syntax 1.7.0 defines it. The AI data comes from the vendored GS1 Barcode Syntax
Dictionary in `testpacks/data/gs1-syntax-engine`. The parse steps follow `gs1_parseDLuri` of
gs1-syntax-engine with its default options. The vendored `dl.c` cases are the oracle.

- The URI starts with the same four scheme prefixes as in the form `dppce-item`.
- The host is not empty and holds no character that GS1 Digital Link refuses. The fragment is
  ignored.
- The authority is valid as in the form `dppce-item`: a port is a number from 0 to 65535, and
  IPv6 brackets are balanced. This rule is stricter than `dl.c`, which checks only characters.
- `require_https` applies as in the form `dppce-item`.
- A path prefix before the primary key is permitted.
- The primary key is an AI that a `dlpkey` entry of the dictionary names.
- The key qualifiers are an ordered subset of one qualifier list of that entry.
- Each AI value is percent-decoded. Its length, its character set, and its linters come from the
  dictionary. The linters include the check digit.
- A query parameter with a numeric name is a data attribute. Its AI must exist and carry the data
  attribute flag. A key qualifier of the path is not a data attribute.
- The check ignores every other query parameter.
- The check does not apply the pairing rules of the dictionary (`req` and `ex`).
- A linter of a data attribute that this version does not implement is not applied. The
  observation summary names it in `unchecked_linters`.

A failure gives `IDENTIFIER.SYNTAX.INVALID`. The observation summary names the failed rule in
`rule`. The rule is one value of the closed set `URI`, `KEY`, `QUALIFIER_ORDER`, `AI_VALUE`,
`CHECK_DIGIT`, `PERCENT`, and `ATTRIBUTE`. A valid URI gives a summary with `key`, `qualifiers`,
and `attributes`. These name AIs only, never values.

A URI with no primary key in the path can look compressed. This is so if its last segment has
at least 10 base64url characters and is not all digits. It gives `unsupported` with `IDENTIFIER.SYNTAX.COMPRESSED`, because this
version does not decompress. Another URL without a primary key and with such a last segment
also gives this outcome. It is never a pass.

`identifier.granularity` has no parameters. It parses the carrier identifier with the form
`gs1-dl`. The check takes the first row that applies:

1. The scheme of the ICS is `unknown` or not `gs1-digital-link`: as `identifier.parse`.
2. The ICS declares the granularity `unknown`: `blocked`, `IDENTIFIER.GRANULARITY.NOT_DECLARED`.
3. The carrier identifier looks compressed: `unsupported`, `IDENTIFIER.SYNTAX.COMPRESSED`.
4. The carrier identifier is not a valid uncompressed URI: `blocked`,
   `IDENTIFIER.GRANULARITY.NOT_PARSED`. `identifier.parse` judges the syntax.
5. The primary key is not a GTIN (AI 01): `unsupported`, `IDENTIFIER.GRANULARITY.KEY_UNSUPPORTED`.
6. The level differs from the declared granularity: `IDENTIFIER.GRANULARITY.MISMATCH`.
7. Otherwise: pass, `IDENTIFIER.GRANULARITY.OK`.

A key qualifier 21 (serial) or 235 (third-party controlled serialized extension) gives item
level. Else a key qualifier 10 (lot) gives batch level. Else the level is model.

`identifier.equivalence` takes one required parameter, `source`. It is one source as in the
parameter `sources` of `identifier.consistency`. The check compares the carrier identifier with
the source value in GS1 canonical form. It parses both with the form `gs1-dl`. In AI (01), a
GTIN-8, GTIN-12, or GTIN-13 is padded with zeros to 14 digits. This is the dl.c option
`permitZeroSuppressedGTINinDLuris`. `identifier.parse` keeps the default of dl.c: no padding.
The comparison then ignores the case of the scheme and the host, the case of a percent-encoding,
and a path prefix. It compares the scheme, the authority, and the primary key with its key
qualifiers. Query data attributes are not compared. The check takes the first row that applies:

1. The parameters are not valid: `blocked`, `IDENTIFIER.PARAMS.INVALID`. Nothing is read.
2. No carrier identifier is available: as `identifier.parse`.
3. The source gives no document: as rule 4 of `identifier.consistency` with `sources`.
4. The pointer does not resolve: `blocked`, `IDENTIFIER.CROSS.SOURCE_MISSING`.
5. The value is not text: fail, `IDENTIFIER.EQUIVALENCE.DIFFERENT`. The summary names `type`.
6. The carrier identifier looks compressed: `unsupported`, `IDENTIFIER.SYNTAX.COMPRESSED`.
7. The carrier identifier is not a valid uncompressed URI: `blocked`,
   `IDENTIFIER.EQUIVALENCE.NOT_PARSED`. The value is not a valid uncompressed URI: fail,
   `IDENTIFIER.EQUIVALENCE.DIFFERENT`. The summary names `syntax`. An unparsable text is never the
   same GS1 key. A value that looks compressed also fails, because the detection is a heuristic.
8. The canonical forms differ: fail, `IDENTIFIER.EQUIVALENCE.DIFFERENT`. The summary names the
   parts that differ, from the set `scheme`, `authority`, and `key`.
9. Otherwise: pass, `IDENTIFIER.EQUIVALENCE.OK`.

`identifier.consistency` stays exact text. A test purpose that accepts a GTIN in another length
uses `identifier.equivalence`.

`persistence.versions` takes six optional parameters. Each default is the layout of the reference
system. `entries_pointer`, default `/versions`, is a JSON Pointer (RFC 6901) to the list of
history entries. `version_field`, `time_field`, and `digest_field` name the members of an entry.
The defaults are `version`, `updated_at`, and `content_digest`. `digest_of` is `jcs-sha256` by
default: the digest covers the canonical form of the item. With `raw-sha256`, the digest covers
the bytes of the item body as served, so a body without a canonical form is comparable. A digest
has the form `sha256:<hex>`. `version_kind` is `integer` by default: the numbers must strictly
ascend. With `string`, the labels must be distinct non-empty strings, and the update times give
the order. The lint and the run planner refuse a malformed pointer. A pointer that resolves to no
list gives `PERSISTENCE.RESPONSE.NOT_JSON`. An entry that is not an object, or that lacks the
version or the time member, is a finding of `PERSISTENCE.UNDECLARED_CHANGE`. The check compares
the digest member of the last entry only. A missing digest member is a finding. The system under test therefore
cannot turn a fail into `blocked` or `inconclusive` with the shape of its history. Invalid
parameters that reach the check give `blocked` with `PERSISTENCE.PARAMS.INVALID`.

`registry.consistency` takes one optional parameter, `fields`: 1 to 16 pairs with a unique
`name`, a `registry_pointer`, and a `passport_pointer`. Both pointers follow RFC 6901. The
default is the two pairs `identifier` and `operator_identifier`, which compare `/identifier`
with `/id` and `/operator_identifier` with `/operator/identifier`. A pointer that resolves to
no value, or to `null`, makes the pair missing. A missing pair is not compared. A difference in
a compared pair gives `REGISTRY.INCONSISTENT` before a missing pair gives
`REGISTRY.FIELD.MISSING`. Declared pairs other than the default are experimental. Invalid parameters that reach the check give `blocked` with
`REGISTRY.PARAMS.INVALID`.

`data.jsonschema`, `data.context`, and `data.rules` take the optional parameter `source` (OD-07).
It selects where the judged document comes from. It is experimental. The parameter `document`
still selects the profile schema and the rules of the document kind.

- No `source` reads the resource that `document` names, as before. The observation summary does
  not change, so a recorded run keeps its decision digest.
- `item` or `model` reads that resource. The summary adds `source`.
- `credential_payload` reads the payload of a JWS credential. The credential is at the resource
  `signed`, or in an IXIT sample. The parameter `credential` holds the parameters of
  `integrity.jose`, with the profile `vc-jose` and the key source `trust_kid` as defaults.
- `embedded_jsonld` reads each `<script type="application/ld+json">` element of an HTML page. The
  page is at the resource that `document` names, or in the IXIT sample that `sample` names. The
  check asks for the resource with `Accept: text/html`.
- Any other value names an IXIT sample. The check reads the sample and sends no request.

A sample name that starts with `manual/` is refused. This applies to `source`, `sample`, and the
sample names in `credential`.

`data.jsonschema` takes the optional parameter `schema`, and `data.rules` takes `rule_pack`. Each
names a file under the data root, in place of the profile schema or the profile rule packs. The
path is relative and has no `.` or `..` segment. A file that a link takes out of the data root
gives `blocked`, with `DATA.SCHEMA.MISSING` or `DATA.RULES.MISSING`. The run binds each such file
(section 9.2).

`data.rules` reads rule packs of version 1 and version 2 (OD-11). Version 2 is experimental. The
[reference system page](../reference/reference-system.md), section 5.1, gives the format.

- A pack of version 1 cannot use a kind of version 2. It also cannot give a key of version 2 a
  value other than its default. Such a pack gives `blocked` with `DATA.RULES.MISSING`. A pack of
  version 1 keeps its outcomes and its reason codes.
- `pattern` matches the string at a JSON Pointer as a whole. The pattern is in a closed subset of
  regular expressions without nested quantifiers and without backreferences. It has at most three
  variable choices: quantifiers other than `{m}`, and `|` outside a character class. A value
  longer than `max_length` characters breaks the rule.
  Each rule has a pattern work budget of 2^24 units on one answer, and each match costs the square
  of the value length. A rule that would exceed its budget is not judged and gives `blocked` with
  `DATA.RULES.WORK_LIMIT`, unless another rule fails. One rule cannot use the budget of another.
- `forbidden` breaks if the field at a pointer is present, also with the value `null`.
- `equals` compares the string at a pointer with a constant or with the string at a second pointer.
- `each` applies one rule of another kind to each element of the array at a pointer.
- An absent field breaks only `required_fields` and `forbidden`. A present value of the wrong type
  breaks the rule. A reshaped document therefore gives a fail, not `blocked`.
- A failed `each` rule gives the reason code of its rule. The codes of version 2 come after the
  codes of version 1: `DATA.FIELD.FORBIDDEN`, `DATA.PATTERN.MISMATCH`, `DATA.EQUALITY.VIOLATED`.

`data.context` reads two more context sources. Both are experimental. No context is fetched.

- The `Link` header of the fetched document, when `source` is absent, `item`, or `model`. A link
  with the JSON-LD context relation names its target as a context, whatever its other parameters
  are. The JSON-LD 1.1 API, section 9.4.1, reads only the relation and the target of such a link.
  The check ignores the header for `application/ld+json`, as JSON-LD 1.1, section 6.1, states.
  It compares the media type without parameters.
- pyld 3.0.0 ignores the header only if the whole `Content-Type` value is `application/ld+json`.
  requests joins two `Content-Type` lines with `, ` and keeps their case. So pyld reads the header
  for `application/ld+json; charset=utf-8`, for `Application/LD+JSON`, and for two lines.
- For such a value, the header names no context and no fail. If pyld can read a context outside
  the allowlist there, or if the value is malformed, the check gives `blocked` with
  `DATA.CONTEXT.LINK_UNREADABLE`. This is an engine limit. So does an allowed context there whose
  pinned copy imports a context outside the allowlist.
- pyld 3.0.0 also loads another document: the target of a link with the relation `alternate` and
  the type `application/ld+json`. It does so if the whole `Content-Type` value does not match
  `^application/(\w*\+)?json$`. It reads a missing value as `application/octet-stream`.
- The check does not judge that document, so such a link gives `blocked` with
  `DATA.CONTEXT.LINK_UNREADABLE`. pyld reads the last `rel`, and the record keeps only the
  first. So a link with that type and a removed parameter gives `blocked` too.
- pyld also reads the last `type`, and the record keeps the first kept `type`. So redaction stops
  reading a value where a later `type` reads as `application/ld+json` (section 10). Such a value
  gives `DATA.CONTEXT.LINK_MALFORMED`.
- The record keeps a `Link` value only in the form that redaction keeps (section 10). A link
  without the context relation is ignored. Redaction keeps each link that RFC 8288, appendix B,
  reads before a malformed part. A context link before such a part still names its target.
- A JSON-LD processor splits a `Link` value at each comma outside `<...>` and quotes. So it can
  read a context link after the malformed part. A recorded value that reading did not finish
  therefore gives a fail, `DATA.CONTEXT.LINK_MALFORMED`, as an unparsable document does. The
  message counts the values and does not echo one.
- Redaction also stops reading where a model of jsonld.js and pyld reads the value differently
  (section 10). Examples are a parameter named `target`, and two `Link` lines that read
  differently once joined. Such a value gives `DATA.CONTEXT.LINK_MALFORMED` too. The check reads
  each recorded line alone. This is an engine limit: another processor can read a value
  differently.
- A malformed value is not a context entry. `DATA.CONTEXT.MISSING` and `DATA.CONTEXT.NOT_ALLOWED`
  come first, so a malformed value never turns them into another outcome.
- A recorded value that is the bare marker `<removed>`, after spaces and tabs are stripped, names no
  context and is not malformed. A recording from before P2-26 holds that form for each `Link` value
  that redaction did not keep, and an empty value records so too. So an old recording replays to
  the same decision digest. Redaction records a new malformed value without a link in another form
  (section 10).
- A recording from before P2-26 also holds the target `<<removed>>` for a target that `urlsplit`
  refuses. Reading stops there, but a value with that target is not malformed. New redaction never
  writes `<` in a target, so only an old recording holds it.
- A context target that redaction changed is compared in its redacted form. That form is not on
  the allowlist, so it gives `DATA.CONTEXT.NOT_ALLOWED`. A target that is not a URI reference is
  recorded as a marker, so it gives `DATA.CONTEXT.NOT_ALLOWED` too. It gives `blocked` with
  `DATA.CONTEXT.LINK_UNREADABLE` only if it equals the redacted form of an allowed URL. Then the
  engine cannot compare the two exactly. `DATA.CONTEXT.MISSING`, `DATA.CONTEXT.NOT_ALLOWED`, and
  `DATA.CONTEXT.LINK_MALFORMED` come first.
- The check resolves a relative context target with Python `urljoin` if the base path is plain.
  For a target that redaction keeps, the WHATWG URL parser and pyld 3.0.0 then give the same URL.
- `urljoin` removes empty segments of the base path, and it does not read `%2e` as `.`. The WHATWG
  URL parser and pyld 3.0.0 keep empty segments. A redirect can give such a base.
- In the path of an `http` or `https` URL, the WHATWG URL parser reads `\` as `/`. `urljoin` and
  pyld 3.0.0 read it as a character of a segment. No reader decodes `%5c`.
- So if the base path has an empty or dot segment or a `\`, the check resolves a relative path as
  these two readers do. It merges the paths as RFC 3986, section 5.2, states, and keeps empty
  segments.
- pyld reads the base as it is. The WHATWG URL parser first reads each `\` of the base path as
  `/`. Then it removes the dot segments of the base, and it reads `%2e` as `.`. The target counts
  with each URL that the two readers give.
- A URL outside the allowlist gives `DATA.CONTEXT.NOT_ALLOWED`. If each URL is allowed, the link
  is allowed. A fuzzer compared this resolution with pyld 3.0.0 and the `URL` class of Node.js 22.
  Its base paths also held `\`, `%5c`, and characters that the WHATWG URL parser percent-encodes.
- A reading keeps such a character as `urljoin` does. The fuzzer compared the WHATWG reading after
  the `URL` class wrote it, so percent-encoding alone was not a difference.
- The transport replaces an echoed credential of the engine in a recorded redirect target with
  `<removed>` (section 9). A credential can hold `/`, so the record then does not hold the fetched
  base path.
- So on a base path that holds the marker, a relative path target counts unresolved: the base, a
  `/`, and the target. That URL is never on the allowlist, so it gives `DATA.CONTEXT.NOT_ALLOWED`.
- The check cannot tell if the credential held `/`. The system put the credential into its own
  redirect target, so the fail stands. A target with an absolute path or an authority keeps its
  result.
- The transport marks a redirect target with the suffix `#<removed>` after a `Location` that a
  consumer can read as another path (section 10). Such a record does not hold the base path that
  a consumer reads.
- So on a base with this suffix, a relative path, a query, or an empty target counts unresolved:
  the base, a `/`, and the target. It gives `DATA.CONTEXT.NOT_ALLOWED`. The `Location` is the
  value of the system, so the fail stands.
- After a `Location` with an empty `;` parameter, the suffix is `#?<removed>`. On such a base,
  only a query or an empty target counts unresolved.
- On a marked base, a target with an absolute path or an authority keeps its result. The
  transport does not follow a `Location` that the WHATWG URL parser reads with another host, such
  as `/\h.example/doc` (section 10). So a consumer reads the fetched origin.
- `resolver.linkset` resolves a relative target in the same way. It does not fetch a target that
  the two readers resolve to different URLs. It does not fetch a relative path target on a base
  path that holds the marker. On a marked base, it does not fetch a target that counts unresolved
  there.
- The JSON-LD 1.1 API, section 9.4.1, rejects a document with more than one context link. Its
  error code is `multiple context link headers`, section 9.6.2. The check judges the target of
  each context link.
- `context_files` maps an allowed context URL to a pinned copy under the data root. The check
  reads each `@context` reference and each `@import` value of a pinned context. It follows a
  reference only into another pinned context.
- A reference outside the allowlist gives `DATA.CONTEXT.NOT_ALLOWED`. A pinned copy that is not a
  valid context gives `blocked` with `DATA.CONTEXT.FILE_INVALID`. The run binds each pinned copy
  (section 9.2).

The check takes the first row that applies. The rows of the schema or the rule packs come after
row 1 and before row 2.

1. Invalid parameters: `blocked`, `DATA.PARAMS.INVALID`. Nothing is read.
2. `credential_payload` without a trust bundle: `blocked`, `DATA.CREDENTIAL.UNVERIFIED`.
3. A missing sample: `blocked`, `DATA.SAMPLE.MISSING`. A fetch follows the rules of the item
   document: a missing answer is `unreachable`, and a status other than 200 is not judged.
4. A credential that does not verify under `credential`: `blocked`,
   `DATA.CREDENTIAL.UNVERIFIED`. The message and the summary name the code of `integrity.jose`.
   An unverified payload is never judged. `integrity.jose` reports the signature itself.
5. A page above 2 MiB: `blocked`, `DATA.EMBEDDED.TOO_LARGE`. A fetched page above the body limit
   of the transport policy gives `blocked`, `TRANSPORT.BODY_TRUNCATED`, first. The default body
   limit is 1 MiB, so `DATA.EMBEDDED.TOO_LARGE` applies to a fetched page only under a higher limit.
6. A sample, a payload, or a script that is not one JSON object gives a fail,
   `DATA.RESPONSE.NOT_JSON`. So does a page that is not UTF-8 text.
7. A page without such a script: fail, `DATA.EMBEDDED.MISSING`.
8. The check judges each embedded document. Any document that breaks the rule gives a fail.

A system under test therefore cannot turn a fail into `blocked` with a second script or with a
document that does not parse. The engine reads the page with the `html.parser` module of the
standard library. It never renders the page or runs a script.

`data.jsonschema` selects the dialect from the top-level `$schema` of the pinned schema:

- No `$schema`, or `https://json-schema.org/draft/2020-12/schema`, selects JSON Schema 2020-12.
- `http://json-schema.org/draft-07/schema` selects draft-07. A URI with an empty fragment `#` is
  the same URI.
- Any other value gives `blocked` with `DATA.SCHEMA.DIALECT`. A subschema that names a different
  dialect also gives `DATA.SCHEMA.DIALECT`.
- A keyword that the selected dialect ignores gives `blocked` with `DATA.SCHEMA.MALFORMED`. The
  validator would skip the keyword, so a document that breaks it would pass.
- For 2020-12, these keywords are `dependencies`, `additionalItems`, `$recursiveRef`, and
  `$recursiveAnchor`.
- For draft-07, these keywords are `dependentRequired`, `dependentSchemas`, `prefixItems`,
  `unevaluatedProperties`, `unevaluatedItems`, `minContains`, `maxContains`, `$dynamicRef`, and
  `$recursiveRef`.
- The engine looks for such a keyword only where the dialect expects a subschema, in
  `definitions`, and in each target of a local `$ref`. A property name is not a keyword.
- A local `$ref` that does not resolve gives `blocked` with `DATA.SCHEMA.MALFORMED`.

Both dialects compare numbers exactly and assert `format`. The engine asserts `date`,
`date-time`, `time`, `duration`, `email`, `idn-email`, `ipv4`, `ipv6`, `uuid`, `uri`,
`uri-reference`, `iri`, and `iri-reference`:

- `date`, `time`, and `date-time` follow RFC 3339, section 5.6. The time offset is required.
- A leap second is valid only at 23:59 UTC. In a `date-time`, it is also valid only on the last
  day of a month in UTC.
- `duration` follows RFC 3339, Appendix A. Its letters are case-insensitive, as all ABNF literals
  are.
- `uri` and `uri-reference` follow RFC 3986. `iri` and `iri-reference` follow RFC 3987.
- `email` and `idn-email` use the checks of jsonschema. These checks look only for an `@`.
- Any other format gives `blocked` with `DATA.SCHEMA.UNSUPPORTED_FORMAT`, because the engine
  cannot assert it.

`api.contract` reads the top-level `openapi` field of the bound contract before it sends a
request:

- `3.1.x` uses JSON Schema 2020-12, as `data.jsonschema` does. A `jsonSchemaDialect` other than
  the OpenAPI 3.1 base dialect or 2020-12 gives `blocked` with `API.CONTRACT.UNSUPPORTED_VERSION`.
- `3.0.x` makes the engine translate each Schema Object to 2020-12 with the same meaning. This
  applies to `components.schemas` and to the response schemas of the marked operation.
- A missing value, a value that is not a string, or any other version gives `blocked` with
  `API.CONTRACT.UNSUPPORTED_VERSION`.
- A contract schema that names a dialect other than 2020-12, or that uses an ignored keyword,
  gives `unsupported` with `API.CONTRACT.UNSUPPORTED_FEATURE`. A response schema cannot select
  draft-07, because its `$schema` would also apply to `components.schemas`.

The 3.0 translation changes these fields and keeps all other fields unchanged:

- `nullable: true` adds `null` to an explicit `type`, as OpenAPI 3.0.3 states. Without a `type`,
  it has no effect. Other keywords, for example `enum`, can still refuse `null`.
- A boolean `exclusiveMinimum` or `exclusiveMaximum` becomes the numeric form with the value of
  its bound. The bound must be present.
- The translation removes `example`, because it is an annotation only.
- `integer` accepts only a number without a fraction and without an exponent, as in JSON Schema
  Wright draft 00.

A field that is not a field of the 3.0 Schema Object, for example `const`, gives `blocked` with
`API.CONTRACT.UNSUPPORTED_VERSION`. An extension field that starts with `x-` stays unchanged.
`discriminator`, `writeOnly`, a `$ref` with a sibling field, and a boolean schema also give
`API.CONTRACT.UNSUPPORTED_VERSION`. These change validation in 3.0, and the translation does not
cover them. A `$ref` must name a schema in `components.schemas` exactly. Its name holds only letters, digits,
`.`, `-`, and `_`, as OpenAPI 3.0.3 requires for component keys. So no encoded separator can point
below a component. Any other target is not
translated, so it also gives `API.CONTRACT.UNSUPPORTED_VERSION`.

The three `resolver.*` checks send `GET` requests only. Each needs a carrier identifier that is an
`http` or `https` URL. Any other text gives `blocked` with `RESOLVER.NO_TARGET`, and nothing is
sent. A transport error, a 429, or a status from 500 to 599 gives `unreachable`. A body of an unexpected
shape is a fail, never `blocked`. So a system under test cannot reshape a wrong answer into one
that is not judged. A body coding or a body over the limit gives `blocked` only when a rule must
read the body. `resolver.conformance` never reads a body.

`resolver.linkset` takes one required parameter, `relations`: 1 to 16 relation types. Each is a
lower-case registered relation name or an `http` or `https` IRI. The name `anchor` is not a
relation. Another value gives `blocked` with `RESOLVER.PARAMS.INVALID`, and nothing is sent. The check sends two requests: the carrier URL
with `Accept: application/linkset+json`, and the carrier URL with the query `linkType=linkset`.
It judges each answer by the first rule that applies:

1. A status other than 200: `RESOLVER.LINKSET.STATUS`.
2. A media type other than `application/linkset+json`: `RESOLVER.LINKSET.MEDIA_TYPE`.
3. `RESOLVER.LINKSET.STRUCTURE` for one of these: the body is not a linkset (see
   `identifier.resolve` above). A link context has an `anchor` that is not a string. A relation
   member is not a list of objects with a string `href`.
4. No link context has the carrier URL, as exact text, as its `anchor`: `RESOLVER.LINKSET.ANCHOR`.
5. No such link context has a non-empty list for one of the `relations`:
   `RESOLVER.LINKSET.RELATION_MISSING`.

Otherwise the check passes with `RESOLVER.LINKSET.OK`. It does not fetch a link target, and it does
not judge the other target attributes.

An answer can also advertise its linkset in a `Link` header with the relation `linkset` (RFC 9264,
section 6). After both answers pass, the check reads the recorded `Link` headers of the two
answers. It takes the first `http` or `https` target with that relation and resolves a relative
target against the final URL of its answer. It fetches that target once with
`Accept: application/linkset+json` and judges the answer by rules 1 to 5. The transport policy
applies to that request as to every other request. The check reads only the recorded form of the
header (section 10). It reads a link whose only other parameter is a kept `type`. It does not
read a link with the marker of another parameter, such as `anchor`.
A target that redaction changed is not fetched.
No usable `Link` value, no answer, or a body that cannot be read leaves the pass unchanged. The
check sends the extra request only after both answers pass. So a broken `Link` value cannot turn
a fail into a missing answer.

`resolver.well_known` fetches `/.well-known/gs1resolver` at the origin of the carrier URL. The
rules judge the final answer, also after a redirect. A status other than 200 gives
`RESOLVER.WELLKNOWN.STATUS`. A media type other than `application/json` or a `+json` type gives
`RESOLVER.WELLKNOWN.MEDIA_TYPE`. A body that is not a JSON object gives `RESOLVER.WELLKNOWN.NOT_JSON`.
`resolverRoot` must be an `http` or `https` URL with the origin of the carrier URL. The check
compares origins in lower case and without a default port. Otherwise the check gives `RESOLVER.WELLKNOWN.ROOT`. The
other members of the file are not judged. A redirected file that obeys all of these rules gives
`blocked` with `RESOLVER.WELLKNOWN.REDIRECTED`, not a pass. So a redirect cannot hide a fail.

`identifier.negotiation` needs a carrier identifier that is an `http` or `https` URL. Otherwise it
gives `blocked` with `NEGOTIATION.NO_TARGET`, and nothing is sent. It sends five `GET` requests in
this order, with these `Accept` values: `application/json`, `text/html`, `application/ld+json`,
`text/html;q=0.2, application/json;q=0.9`, and `application/x-dppce-unsupported`. It sends no
other negotiation header. In particular, it sends no `Accept-Language`: a later package adds that
header. A transport error, a 429, or a status from 500 to 599 is no answer. The check sends all five
requests and judges the answers that it got. Only when no rule proves a fail does a missing answer
give `unreachable`. So a system cannot hide a proven fail with an error on another request.
The optional parameter `unsupported_answer` is `406` or `default`, and `default` is the default.
The check judges the answers by the first rule that applies. Rules on headers come before
rules on bodies. An answer with a body coding or a long body is set aside, so it cannot turn a
fail on another answer into `blocked`.

1. The `unsupported` answer must have the declared status: 406, or 200 for `default`:
   `NEGOTIATION.UNSUPPORTED`. The `json` request must get 200. The `html`, `json_ld`, and `weighted`
   requests get 200 or 406. Another status gives `NEGOTIATION.STATUS`.
2. A 200 answer to `application/json` must have `application/json` or a `+json` media type:
   `NEGOTIATION.MEDIA_TYPE`. The check does not judge the media type of the other answers.
3. The weighted request must get a 200 answer with a JSON media type when the `json` request got
   200. A 406 or a non-JSON type gives `NEGOTIATION.QUALITY`.
4. `Vary` is judged per URL. If the answers at one URL differ in status or media type, each 200
   answer there must list `Accept` or `*` in `Vary`: `NEGOTIATION.VARY.MISSING`. A URL that
   redirects one request and answers another also differs. The engine does not observe the
   `Vary` of a redirect hop. The check does not compare bodies, because a body can differ for
   reasons other than `Accept`.
5. A JSON media type needs a body that is valid JSON. A `text/html` answer needs a body with
   markup that is not valid JSON: `NEGOTIATION.BODY`. Other media types are not judged here.

Otherwise the check passes with `NEGOTIATION.OK`. The pass message names only these rules. The check
does not judge caching, language, or a `Content-Location` header.

`resolver.conformance` needs a carrier URL whose path holds `/01/` and 14 digits with a correct
check digit. Otherwise it gives `blocked` with `RESOLVER.NO_TARGET`, and nothing is sent. It sends
three requests in this order and stops at the first failure:

1. The carrier URL. The answer must come through at least one redirect:
   `RESOLVER.CONFORMANCE.NO_REDIRECT`. The status of the first hop must be in the parameter
   `expected_redirect_statuses`: `RESOLVER.CONFORMANCE.REDIRECT_STATUS`. Later hops are not judged.
2. The carrier URL with the query `linkType=linkset`. A redirect gives
   `RESOLVER.CONFORMANCE.LINKSET_REDIRECTED`. A final status other than 200 gives
   `RESOLVER.CONFORMANCE.LINKSET_STATUS`.
3. The carrier URL with the last digit of the GTIN increased by one, modulo 10. A final status of
   200 gives `RESOLVER.CONFORMANCE.INVALID_ACCEPTED`. A final status other than 400 or 404 gives
   `RESOLVER.CONFORMANCE.INVALID_STATUS`.

A redirect that the transport does not follow, out of the scope or past the redirect limit, still
counts as a redirect. For the second request, it gives `RESOLVER.CONFORMANCE.LINKSET_REDIRECTED`.
For the third request, its 3xx status gives `RESOLVER.CONFORMANCE.INVALID_STATUS`. For the first
request, the record keeps the status of the refused hop (section 10), and rule 1 judges it. So
neither a redirect out of the scope nor a redirect loop turns a fail into `blocked`. A followed
hop to a target that gives no answer, such as a 5xx status or a failed connection, gives
`unreachable` for the first request.

`expected_redirect_statuses` is a list of distinct values from 301, 302, 303, 307, and 308. Its
default holds all five, because GS1-Conformant Resolver 1.2.1 fixes no code. A test purpose that
needs one code declares it. Any other value gives `blocked` with `RESOLVER.PARAMS.INVALID`, and
nothing is sent. A record from before hop statuses has redirects but no status. Under the default
set it meets rule 1, because the transport follows only these five statuses. Under a declared
subset it gives `blocked` with `RESOLVER.CONFORMANCE.HOP_STATUS_NOT_RECORDED`.

The three requests use the transport default, `follow_redirects` true. Another check can reuse a
record of the same request (`fetch_once`). A record that follows no hop would give that check a 3xx
answer in place of the final answer.

Otherwise the check passes with `RESOLVER.CONFORMANCE.OK`.

`aas.validate` has a limit of the wrapped release. The release accepts an empty environment `{}`
as valid. So `AAS.VALID` does not show that the file has a shell or a submodel.
`aas.dpp_compose` judges the content of a DPP environment.

`aas.dpp_compose` takes one optional parameter, `artifact`, the IXIT sample. Its default is
`aas_file`. The check reads the sample as JSON with the strict parser. It sends no request and
needs no extra. It compares the sample with IDTA 02099-1 version 1.0, template release 1.0.2. The
template holds definition text from a European standard, so the project does not vendor it.
`tests/vectors/idta-02099-1/README.md` names the pinned file. A table in `src/dppce/adapters/aas.py`
holds its identifiers. A test derives the same table from a local copy that an operator supplies.
These rules apply:

- A semanticId matches if it is an object with one key. The value of that key must be the
  semanticId of the template as exact text. The reference type and the key type do not matter.
- A DPP metadata submodel is an object of the list `submodels` with the matching semanticId
  `https://admin-shell.io/idta/cds/dppMetadata/1`.
- A required element is a top-level element with the cardinality `One` in the template. Each one
  is a Property. An object of `submodelElements` is that element if it is the only object with its
  idShort. It must also have the `modelType` `Property`, a matching semanticId, and a non-empty
  string as `value`.
- A shell references a submodel if the last key of a reference in its `submodels` has the `id`
  of the submodel as its value. A submodel without a string `id` has no referencing shell.
- The mapping table of the IDTA 02099-1 documentation binds `uniqueProductIdentifier` to
  `assetInformation.globalAssetId`. The template binds no element to `specificAssetIds`, so the
  check does not read them.

The check judges each DPP metadata submodel and takes the first row that applies:

1. The sample is not available: `blocked`, `AAS.SAMPLE.MISSING`.
2. The sample is not a JSON object, or no submodel matches: `AAS.DPP.SUBMODEL_MISSING`.
3. A required element is missing: `AAS.DPP.ELEMENT_MISSING`. The observation summary names the
   idShorts in `missing_elements`.
4. No shell references a DPP metadata submodel, or a referencing shell has a `globalAssetId` that
   is not its `uniqueProductIdentifier` as exact text: `AAS.DPP.ID_MISMATCH`.
5. Otherwise: pass, `AAS.DPP.OK`.

Each problem of the sample shape is a fail, never `blocked`. So a system under test cannot reshape
a fail into a step that is not judged. The check does not judge value formats, value types,
optional elements, or concept descriptions. An AAS environment is not by itself a DPP.

`aas.api_profile` probes an AAS server with `GET` requests through `ctx.acquirer`. So the transport
policy, the authorization, and the request budget apply (section 9). It does not use the HTTP
client of aas-test-engines, and it sends no write, negative, or fuzz request. The profiles follow
IDTA-01002, Specification of the Asset Administration Shell, Part 2, version 3.0.4. The open
OpenAPI files of `github.com/admin-shell-io/aas-specs-api` at commit `f7bb302f` were read on
2026-10-26. No file is vendored. `tests/vectors/idta-01002-api/README.md` names the files.

The parameters are:

- `endpoint`, default `aas`: a key of `IXIT.endpoints`. Its value is the base URL of the API, an
  http or https URL without a query or a fragment. Another value gives `blocked`,
  `AAS.API.NO_TARGET`. The origin override of the test rig applies.
- `profile`, default `aas-repository-read`: `aas-repository-read` (AAS Repository, SSP-002) or
  `submodel-repository-read` (Submodel Repository, SSP-002).
- `id_source`, default `aas_shell_id`, and `id_pointer`, default none: the IXIT sample that gives
  the id of a shell, or of a submodel for `submodel-repository-read`. Without `id_pointer` the
  sample value is the id. With it, the id is the string at that JSON Pointer of the sample file.
  No id of 1 to 2000 characters gives `blocked`, `AAS.API.ID_MISSING`.
- `max_requests`, default 6, from 1 to 16: the most probes that the check sends.

ADR 0011 applies to the endpoint. With a validated authorization, an origin that it does not name
gives `blocked`, `AAS.API.NOT_AUTHORIZED`, and nothing is sent. Without one, the transport sends
only to an origin that the operator confirmed. Another origin gives `TRANSPORT.DENIED`.

An id in a path is UTF-8, base64url-encoded, without padding. The probes are, in this order:

1. `GET /description`.
2. `GET /shells?limit=1`, or `/submodels?limit=1`. If the answer has a cursor, one more page:
   `limit=1` and the percent-encoded `cursor`.
3. `GET /shells/{id}` and `GET /shells/{id}/submodel-refs`, or `GET /submodels/{id}`.
4. `GET` of a fixed unknown id: `/shells/{id}` or `/submodels/{id}`.

A broken rule gives a fail, `AAS.API.PROFILE`. The observation summary names the rule in `rule`,
a value of a closed set:

- `description_status`, `description_shape`: the description does not answer 200, or is not an
  object with a non-empty list of profile strings.
- `profile_not_declared`: no profile is
  `https://admin-shell.io/aas/API/<major>/<minor>/<specification>/SSP-001` or `SSP-002` of the
  service specification of the profile. SSP-001 is the full profile, which holds the read profile.
- `list_status`, `list_shape`: a list page does not answer 200, or the answer is not a paged
  result. A paged result is an object with an object `paging_metadata`. Its `result`, if present,
  is a list of objects with a string `id`. No `result` is an empty page. A cursor is a string of 1
  to 2048 characters.
- `list_empty`: the first page is empty and has no cursor, but the declared id answers 200 with a
  valid shape. So the list does not hold every element.
- `list_incomplete`: the probes reach a page without a cursor, and the pages read do not list the
  declared id. The declared id answers 200 with a valid shape. A cursor on the second page proves
  nothing.
- `paging_limit`: a page with `limit=1` holds more than one element.
- `paging_cursor`: the page of the cursor repeats an id of the first page.
- `item_status`, `item_shape`: the declared id does not answer 200, or the answer does not have that
  `id` and the `modelType` of the profile. A shell also needs an object `assetInformation`.
- `refs_status`, `refs_shape`: the submodel references do not answer 200, or the answer is not a
  paged result of references. A reference has a string `type` and a non-empty list of `keys`, each
  with a string `type` and `value`.
- `unknown_id_status`: the unknown id does not answer 404. A 200 is never accepted.
- `body_json`: under a declared version other than 3.0, a 200 answer is not JSON that the strict
  parser of the engine reads.

Other outcomes:

- A profile that the description declares only in another version than 3.0: `unsupported`,
  `AAS.API.VERSION_UNSUPPORTED`, if no version-independent rule fails. Only these probes run, in
  this order: the unknown id, the first list page, the declared id, and its submodel references
  for a shell. A 200 answer to the unknown id fails with `unknown_id_status`. Another 200 answer
  that is not strict JSON fails with `body_json`. A truncated or coded body is not judged. The
  check judges no other status or shape. This limit also comes before a missing answer, a refusal,
  or an unusable body.
- A transport error, a 429, or a status from 500 to 599: `unreachable`, as `no_answer` gives. A 401 or 403
  to the anonymous role: `blocked`, `AAS.API.NOT_CONCLUSIVE`. A body coding or a truncated body:
  `blocked`, as `unusable` gives.
- The probes need more requests than `max_requests`: `unreachable`, `AAS.API.BUDGET_EXHAUSTED`.
  A transport budget that ends gives `TRANSPORT.DENIED`.
- Every probe passes: `pass`, `AAS.API.OK`. The message names the probes that ran.

A fail ends the probes at once. After a missing answer or a refusal, the other probes still run.
Only the cursor page needs the first list page. The first missing answer or refusal is the
outcome only if no probe fails. So a system under test cannot turn a fail into a
step that is not judged. The check does not judge the body of the 404 answer, the media type, or
any operation outside the probes above.

`identity.did` takes the required parameter `did` and the optional parameter `source`. The URL
mapping follows the did:web Method Specification, a W3C CCG report. The commit `ea423c1` of
`github.com/w3c-ccg/did-method-web` was read on 2026-10-25. The document rules follow W3C DID
Core 1.0. The mapping is:

- The DID is `did:web:` and a domain name, then optional path segments after `:`. The domain name
  is not an IP address. Its last label is not all digits and does not start with `0x`, because a
  URL parser reads such a host as an IPv4 address.
- A port follows the domain name as `%3A` and a number from 1 to 65535. `%3a` is the same.
- Without a path, the URL is `https://<domain>[:<port>]/.well-known/did.json`. With a path, it is
  `https://<domain>[:<port>]/<segment>/.../did.json`.
- The URL is always https. The origin override of the test rig applies as to any other URL.
- A path segment holds only `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`, and is not `.` or `..`. A
  percent-encoded path segment is an engine limit.

Another text gives `blocked` with `IDENTITY.DID.PARAMS_INVALID`, and nothing is sent. The lint and
the run planner refuse such a DID.

Without `source`, the check fetches the URL with `GET` through the transport (section 9). The
DID host is often a third party. The operator must confirm its origin, as for any other origin.
A host that the operator did not confirm gives `TRANSPORT.DENIED`, which is no answer and never a
pass. A redirect out of the scope gives `TRANSPORT.REDIRECT_OUT_OF_SCOPE`. With `source`, the
check reads the IXIT sample of that name as an offline copy of the DID document, and sends nothing.
The observation summary names the source in `source`: `live` or `sample`.

The check takes the first rule that applies:

1. A transport error, a 429, or a status from 500 to 599: `unreachable`. A missing sample: `blocked`,
   `IDENTITY.DID.SAMPLE_MISSING`.
2. A status other than 200: `IDENTITY.DID.STATUS`. The rule does not read the body.
3. A body coding or a truncated body: `blocked`, as `unusable` gives. A document above 1 MiB:
   `blocked`, `IDENTITY.DID.TOO_LARGE`.
4. The body is not one JSON object for the strict parser of the engine: `IDENTITY.DID.NOT_JSON`.
5. The `id` is not the DID as exact text: `IDENTITY.DID.ID_MISMATCH`.
6. A `publicKeyJwk` holds a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, or `k`), or
   a method has a member whose name starts with `privateKey`: `IDENTITY.DID.PRIVATE_KEY`. The
   rule reads each verification method and each embedded method of every verification
   relationship, also a malformed one. A relationship can be a list or one object.
7. `IDENTITY.DID.VERIFICATION_METHOD` for one of these: `verificationMethod` is not a list. A
   method has no non-empty string `id`, `type`, or `controller`. A `publicKeyJwk` is not an object
   with a string `kty`. Two methods have the same id. A relative id starts with `#` and resolves
   against the DID.
8. An `assertionMethod` entry is not an embedded method and not the id of a method of the
   document: `IDENTITY.DID.ASSERTION_UNRESOLVED`. A reference to another DID document fails too.
9. A redirect that the transport followed, with a document that passes rules 4 to 8: `blocked`,
   `IDENTITY.DID.REDIRECTED`. So a redirect cannot hide a fail, and a redirected document never
   passes.
10. A method without `publicKeyJwk`, for example with `publicKeyMultibase`: `unsupported`,
    `IDENTITY.DID.KEY_FORMAT`. The engine reads JWK keys only.

Otherwise the check passes with `IDENTITY.DID.OK`. A document of an unexpected shape is a fail,
never `blocked`. The check does no JSON-LD processing and does not judge the media type or the
other members of the document. The observation summary holds counts, the status, and the media
type. It never holds an id, a key, or a URL.

Resolution is not trust. DNS and TLS name the host, not the issuer. A key of the document is
trusted only through a pinned `TrustedKey` of the trust bundle whose `issuer` equals the DID.
`dppce.adapters.did.resolve_did_web` gives the resolved document and its public keys by absolute
method id to other checks.

`integrity.status_list` follows the W3C Recommendation Bitstring Status List v1.0 of 15 May 2025.
It verifies the credential as `integrity.jose` does under the profile `vc-jose`. Then it reads the
`BitstringStatusListEntry` of the credential and judges its status list credential. The bitstring
decoder of section 11.4 is reused. The report status lists of section 11.4 do not change. The
check takes eight optional parameters:

- `key_source` (`trust_kid` or `did`), `did_sample`, `source`, `sample`, and `accept` have the
  meaning of `integrity.jose`. They apply to the credential and to the status list credential.
  `accept` is the `Accept` header of both fetches.
- `list_source`, default `live`. With `live`, the check fetches the `statusListCredential` URL with
  `GET` through the transport. With `sample`, it reads the IXIT sample that `list_sample` names,
  default `status_list`, and sends no list request.
- `purpose`, default `revocation`. The other value is `suspension`. The check judges the entries of
  this purpose only.

The status list host is often a third party. The operator must confirm its origin, as for any
other origin. A host that the operator did not confirm gives `TRANSPORT.DENIED`, which is no answer
and never a pass. For a third-party host, an offline copy from an IXIT sample is the default
choice.

The check takes the first rule that applies:

1. Invalid parameters: `blocked`, `INTEGRITY.STATUS.PARAMS`. No trust bundle: `blocked`,
   `INTEGRITY.TRUST.MISSING`. Nothing is read.
2. The credential: rows 2 to 16 of `integrity.jose`, with their codes. The check then reads the
   payload of the verified credential only.
3. `credentialStatus` is one entry or a list of entries. An entry that is not a JSON object with a
   string `type` gives `INTEGRITY.STATUS.ENTRY_MALFORMED`. For a `BitstringStatusListEntry`, a
   `statusPurpose` that is not a string gives the same code. Of another entry, only the type is read.
4. An entry for `purpose` with one of these problems gives `INTEGRITY.STATUS.ENTRY_MALFORMED`. The
   `statusListIndex` is not a base-10 integer in a string. The `statusListCredential` is not an
   `http` or `https` URL. The `id` is the URL of the list. A `statusSize` is not an integer above 0.
5. No entry for `purpose`: `unsupported`, `INTEGRITY.STATUS.ENTRY_TYPE`, if the credential has
   entries of another type only. Otherwise `INTEGRITY.STATUS.ENTRY_MISSING`. No list is fetched.
6. Then each entry for `purpose` in turn, at most 4. With more entries, the check judges the first 4
   and gives `blocked`, `INTEGRITY.STATUS.TOO_LARGE`, only if no rule fails.
7. Live: a transport error, a 429, or a status from 500 to 599 gives `unreachable`. A status other than 200
   gives `INTEGRITY.STATUS.LIST_NOT_AVAILABLE`. A body coding or a truncated body gives `blocked`.
   One URL is fetched once for each step.
8. Sample: a missing sample gives `blocked`, `INTEGRITY.STATUS.SAMPLE_MISSING`. A sample whose `id`
   is not the `statusListCredential` URL as exact text gives `blocked`, `INTEGRITY.STATUS.LIST_UNBOUND`.
   The engine cannot show that such a sample is the list of the entry.
9. A JSON credential without a JWS form whose `proof` is one or more well-formed Data Integrity
   proofs gives `unsupported`, `INTEGRITY.STATUS.LIST_FORMAT`. This engine does not verify such
   proofs. A well-formed proof has the `type` `DataIntegrityProof` and the string members
   `cryptosuite`, `proofPurpose`, `verificationMethod`, and `proofValue`. The list must name the
   issuer of the credential. Its `id` must be the `statusListCredential` URL. Each
   `verificationMethod` must be a DID URL whose DID is the issuer of the credential. That DID must
   also be the issuer of a pinned `passport` key. Any other list goes to row 10.
10. The list credential: the rows of `integrity.jose` under `vc-jose` with the same key source. A
    refused signature, algorithm, header, or JWS shape, or a body that is not secured, gives
    `INTEGRITY.STATUS.LIST_SIGNATURE`. An untrusted key, a key that is not valid, a key of another
    issuer, or an `iss` that differs from the issuer gives `INTEGRITY.STATUS.LIST_UNTRUSTED`. A
    verified list whose issuer is not the issuer of the credential gives the same code.
11. Claims of the wrong form give `INTEGRITY.STATUS.LIST_MALFORMED`. A list credential outside its
    `validFrom` and `validUntil` gives `INTEGRITY.STATUS.LIST_VALIDITY`. A list engine limit gives
    `blocked` or `unsupported` (`INTEGRITY.STATUS.LIST_FORMAT` for a key type).
12. `INTEGRITY.STATUS.LIST_MALFORMED` for one of these: the `id` of the verified list credential
    is not the `statusListCredential` URL as exact text, also in live mode. The `type` lacks
    `BitstringStatusListCredential`. The `credentialSubject` is not an object with the type
    `BitstringStatusList` and a string `encodedList`. Its `statusPurpose` is not one or more
    strings. A `ttl` is not an integer of at least 0.
13. The list does not name `purpose` in its `statusPurpose`: `INTEGRITY.STATUS.PURPOSE`.
14. An `encodedList` that does not decode gives `INTEGRITY.STATUS.LIST_MALFORMED`. A bitstring above
    16 MiB gives `blocked`, `INTEGRITY.STATUS.TOO_LARGE`. The decoder stops at that size.
15. Fewer than 131,072 bits: `INTEGRITY.STATUS.LIST_LENGTH`. An entry that ends past the end of the
    list: `INTEGRITY.STATUS.INDEX_RANGE`. An entry holds `statusSize` bits from the index times the
    `statusSize`.
16. A `statusSize` other than 1: `unsupported`, `INTEGRITY.STATUS.SIZE_UNSUPPORTED`. Rows 12 to 15
    apply to every `statusSize` first.
17. A set bit under `revocation`: `INTEGRITY.STATUS.REVOKED`, also from a stale list, because
    revocation is not reversible. A set bit under `suspension` in a list that is not stale:
    `INTEGRITY.STATUS.SUSPENDED`.
18. A stale list: `blocked`, `INTEGRITY.STATUS.STALE`. A list is stale if its `validFrom` plus its
    `ttl`, in milliseconds, is before the evaluation time. Without `ttl` or `validFrom`, the check
    does not judge staleness. The pass message then says so.
19. Otherwise: pass, `INTEGRITY.STATUS.OK`.

The Recommendation permits a list issuer other than the issuer of the credential. This version
does not support such a delegated status issuer: a pinned key of another issuer could clear the
bit. Only rows 6 to 9, 11, 14, 16, and 18 can give `blocked` or `unsupported`, or no answer,
after the credential is read. Each limit applies to one entry. The check judges every other entry
first. A fail of any entry comes before any limit, in every order of the entries. A
limit of a list ends its entry, because the engine does not judge a list that it did not verify.
The observation summary holds counts, states, and the status, never an index, a URL, or a key.

Digital consistency does not prove physical authenticity. A signature that verifies does not
prove that the signed attributes are true. Each check states such a limit in its message.

### 8.1 Manual results

A manual result is the signed result of one manual step. The person who performed the step signs it with a key of their own. See ADR 0013.

- Format: JWS Compact Serialization with `ES256`, as in section 11.3.
- The protected header holds exactly `alg`, `kid`, and `typ: "dppce-manual-result+jws"`. Any other parameter, such as `x5c`, is refused.
- Payload: `JCS(ManualResult)` with the schema version `dppce.manualresult/1`.
- The payload holds the test purpose, its digest, the SUT identifier, the SUT version, a role, and the time of the review.
- It also holds the outcome and the evidence items.
- The digest is `sha256:` and the hex SHA-256 of the RFC 8785 form of the test purpose as loaded.
- `dppce manual digest --test-purpose ID` prints this digest. It reads the test packs with `--data-root` and `--import-testpack`, as a run does. The check and the command use one function.
- The SUT version is the version that the ICS declares. It is `null` when the ICS declares none. The engine never invents one.
- The outcome is `pass` or `fail`. The role is one lowercase word, such as `inspector`.
- The payload names no person. The key identifier links the result to the performer in the records of the laboratory.

`manual.review` reads the result as the input artifact `manual/<test purpose id>`. The recording holds, commits, and replays it like any other artifact.
The check tests the result in this order. The first test that fails gives `manual_unavailable` with its reason code.

1. The artifact is present: `MANUAL.RESULT.MISSING`. It is not above the size limit: `MANUAL.RESULT.TOO_LARGE`.
2. The text is a compact JWS with a JSON header: `MANUAL.RESULT.MALFORMED`.
3. The header holds only `alg`, `kid`, and `typ`, and `typ` is the manual result type: `MANUAL.RESULT.MALFORMED`.
4. The algorithm is on the allowlist: `MANUAL.SIGNATURE.INVALID`.
5. The trust bundle names the key for the purpose `manual`: `MANUAL.KEY.UNTRUSTED`.
6. The key is not revoked and is valid at the evaluation time: `MANUAL.KEY.NOT_VALID`.
7. The token is not above the token limit: `MANUAL.RESULT.TOO_LARGE`. The signature verifies: `MANUAL.SIGNATURE.INVALID`.
8. The payload is a canonical `ManualResult` with a valid time: `MANUAL.RESULT.MALFORMED`.
9. The payload names this test purpose: `MANUAL.PURPOSE.MISMATCH`.
10. The payload holds the digest of this test purpose: `MANUAL.PURPOSE.DIGEST_MISMATCH`.
11. The payload names the SUT identifier of the ICS: `MANUAL.SUT.MISMATCH`.
12. The payload names the SUT version of the ICS, or `null` if the ICS declares none: `MANUAL.SUT.VERSION_MISMATCH`.
13. The time of the review is not after the evaluation time: `MANUAL.TIME.AFTER_EVALUATION`.
14. The time of the review is in the validity period of the key, `not_before` to `not_after`: `MANUAL.TIME.OUTSIDE_KEY_VALIDITY`.
15. The evidence items equal the `expected_evidence` items of the test purpose. The text, the order, and the number must match: `MANUAL.EVIDENCE.MISMATCH`.

Tests 10 and 12 bind the result to the method and to the system version that it answers.
Test 14 refuses a result with a review time outside the validity period of its key.
No maximum age applies to a manual result. ADR 0013 records this as a policy decision for the owner.

With no trust bundle, the check gives `error` with `MANUAL.TRUST.MISSING`. The command line refuses that case before the run.
A result that passes every test gives `completed`. The outcome `pass` is a check that passed (`MANUAL.REVIEW.OK`).
The outcome `fail` is a check that did not pass (`MANUAL.REVIEW.FAILED`). Section 7.1 applies unchanged.
The step then holds one observation of kind `artifact`. It references the record. Its summary holds `jws`, `kid`, `role`, `performed_at`, `outcome`, and `test_purpose_digest`.
A refused result puts no content of the file in the report. Its observation holds the record identifier only.
The engine does not perform the review. A valid signature shows who signed the result. It does not show that the review was correct.

### 8.2 Access probes

`access.restricted_fields` probes the access policy that the profile binds. The parameter `role` names the probed role.

- Each entry in `restricted` names a field path and the roles that may receive it.
- The path is entitled for each of those roles. It is withheld from every other role.
- An entry that names every declared role is a public path. The policy schema stays `dppce.accesspolicy/1`.
- A policy that names one path in two entries of `restricted`, or of `canaries`, is not valid.
- If the role has a withheld path, the check reads every channel of the policy. Otherwise it reads only the `fetch` channel.
- The check reads the channels in the order fetch, export, search, error, html. It stops reading after a transport error.
- A withheld path or a canary value in a channel is a leak. Section 5.2 of the reference system page gives the search rules.
- Each entitled path must be at the root of the `fetch` body, with a value other than `null`.
- Only the `fetch` channel must give content. The check reads the other channels for leaks only.
- A `401` or `403` answer on `fetch` to a role with an entitled path is a failure. The body of that answer does not change this.
- For a role with no entitled path, a `401` or `403` answer is not a failure. The check still searches its body for leaks.
- A policy that gives a role no path cannot tell a refusal from correct enforcement for that role.

The check takes the first row that applies.

| Condition | Status | Reason code |
| --- | --- | --- |
| The profile binds no readable and valid policy, or the ICS names no policy or a different one | `blocked` | `ACCESS.POLICY.MISSING`, `ACCESS.POLICY.NOT_DECLARED`, `ACCESS.POLICY.ICS_MISMATCH` |
| The role has no entitled path and no withheld path, or the policy names no channel | `blocked` | `ACCESS.POLICY.NOTHING_TO_PROBE` |
| A channel to read has a placeholder with no value | `blocked` | `ACCESS.NO_TARGET` |
| A channel leaks | `completed`, not passed | `ACCESS.LEAK.<CHANNEL>`, for the first leaking channel in reading order |
| `fetch` answers `401` or `403` to a role with an entitled path | `completed`, not passed | `ACCESS.ENTITLEMENT.REFUSED` |
| An entitled path is absent or `null` in a `fetch` body that is JSON | `completed`, not passed | `ACCESS.ENTITLEMENT.MISSING` |
| A channel answer cannot be judged. The first such answer in reading order decides. | `blocked`, or as in section 9 for a transport error or a server error | `TRANSPORT.*`, `ACCESS.RESPONSE.NOT_JSON`, `ACCESS.RESPONSE.NOT_DECODABLE` |
| The role has an entitled path, and the policy names no `fetch` channel | `blocked` | `ACCESS.ENTITLEMENT.NO_FETCH_CHANNEL` |
| A withheld path has no canary on a channel that is not JSON, or redaction removed a part of a URL | `blocked` | `ACCESS.POLICY.NOT_FULLY_CHECKABLE` |
| Otherwise | `completed`, passed | `ACCESS.POLICY.ENFORCED` |

An answer cannot be judged in these cases:

- It has a transport error, a truncated body, or an encoded body.
- The role has a withheld path, and the body cannot be searched.
- The role has an entitled path, and the `fetch` body is not JSON.
- A channel answers with a status of 429, or from 500 to 599. This applies to every channel and
  every role.
  The check still searches that body for a leak. A leak in it is a failing observation.

Only a leak or an entitlement failure outranks such an answer.

The message of `ACCESS.ENTITLEMENT.MISSING` names the status of the `fetch` answer and the missing paths.

Every outcome names the probed role and the credential issuer in its message. Each observation summary holds them as `role` and `credential_issuer`.
The credential issuer is the issuer of the validated authorization that grants the role. It is `null` for the anonymous role, and when no validated authorization grants the role.
The engine does not read a credential to find its issuer. No outcome holds a secret or a secret reference.

The observation summary holds the entitled paths, the missing paths, the leaked paths, and the status of the `fetch` answer. It never holds a field value.
A field that is present can still hold a wrong value. The public paths of the reference policy are a synthetic list. They are not a reading of Annex XIII.

## 9. Transport policy

Every adapter uses one transport. Defaults: read-only methods, bounded, rate-limited, with a
`User-Agent` of `dppce/<version> (+<contact>)`.

- Destinations: only hosts in `IXIT.network.allowed_hosts`. Loopback, private, link-local, and
  other non-public addresses also need an entry in `allow_private_hosts`.
- The transport resolves the host once, checks every resolved address against the policy, and
  connects to the checked address. This prevents DNS rebinding.
- Redirects are followed by the transport, never by the HTTP library. Each hop is checked.
  An out-of-scope hop ends the request with `redirect_out_of_scope`. So does a `Location` that
  is not a URL. So does a `Location` that the WHATWG URL parser reads with another host than
  `urljoin` does (section 10). A URL that cannot be parsed is never raised: it is `policy_denied`.
- The transport follows only the statuses 301, 302, 303, 307, and 308, with a `Location`, for
  `GET`, `HEAD`, and `OPTIONS`. The record keeps each redirect target and, in parallel, the status
  of the answer that named it. A refused hop keeps its target and its status too.
- A request with `follow_redirects` false follows no hop. The record then holds the first answer,
  a redirect included, with no redirect target and no hop status.
- A URL with a control character or a space is `policy_denied`. The URL parser would drop or
  strip such a character, and the record would name a request that was never sent.
- A non-public origin is reached only if the operator confirmed that origin
  (`--allow-private-host ORIGIN`), not only its host. A public origin without an authorization
  needs `--allow-remote-host ORIGIN`. The IXIT therefore cannot choose a different port or
  service on a confirmed host.
- Credentials are sent only to the origin they are configured for. A request for the
  `anonymous` role never carries a credential, also if one is configured under that name.
- A request for a role other than `anonymous` always carries the credential of that role.
  If no credential fits the target origin, the request is not sent: `authorization_denied`.
  Such a request does not follow a redirect to a different origin: `redirect_out_of_scope`.
  Otherwise the record would show the anonymous view under the name of the role.
- A request for the `anonymous` role can follow a cross-origin redirect inside the policy.
  Headers that the caller added stay with the first origin.
- One fetch has a total time limit (`total_timeout_ms`), apart from the limit for one read.
  Every redirect hop and every retry of that fetch share it.
- The transport asks for an unencoded body. A check does not assess an encoded body.
- Methods other than `GET`, `HEAD`, and `OPTIONS` need a valid authorization with the matching scope.
  The token request of an OAuth 2.0 role is the one exception. It needs the scope `credential`
  (section 9.3). That scope permits no request of a check.
- Limits: timeout, maximum body size (the body is truncated and flagged), maximum redirects,
  maximum request count, and minimum interval. Each limit that triggers is recorded.
- Secrets are removed from request headers before a record is created. If the tested system
  echoes a credential of the engine, its common forms are replaced with `<removed>` in header
  names and values, redirect targets, and the body. A `Link` value that holds a form is replaced as
  a whole with `<%3Cremoved%3E>, <removed>` instead (section 10). The forms are: plain,
  percent-encoded with or without `/` kept, in upper-case or lower-case hex, and with `/` written
  as `\/`. Where the body
  limit cut the body, a cut head of a form at its end is removed too. A complete body keeps its
  end. Other encodings, such as base64 or a mix of forms, are not recognized. A credential needs
  12 characters or more, so that its removal cannot change unrelated text of the evidence.
- A sample file is read only if it is still the regular file that was confirmed (device and
  inode). It is opened without following a link and without blocking.
- Response bodies are bytes. HTML is never rendered or executed. Archives are never unpacked.

A transport failure is data: `Record.error`. The check reports `unreachable`.
By default that is `inconclusive`, because a connectivity failure does not prove a breach.

A server error counts the same way (owner decision of 2026-10-18). An answer with a status from
500 to 599 gives `unreachable` with `TRANSPORT.SERVER_ERROR`. The check does not judge the body of
such an answer, also if it is JSON. Two exceptions apply:

- `integrity.jws` keeps `INTEGRITY.TOKEN.NO_ANSWER` for the signed passport. As before, it reads
  every status of 500 or higher as no answer.
- `access.restricted_fields` still searches such a body for a leak, on every channel. A leak is a
  failing observation. Otherwise the check reports `unreachable` (section 8.2).

A rate-limited answer counts the same way (P2-31). An answer with the status 429 gives
`unreachable` with `TRANSPORT.RATE_LIMITED` in every check, `integrity.jws` included. The check
does not judge its body. `access.restricted_fields` still searches that body for a leak.

The shared helper `dppce.adapters.common.no_reply` decides what is no answer: a transport error,
a 429, or a status from 500 to 599. The helper `unusable` calls it. `integrity.jws` tells
`unusable` to leave a server error to its own rule. Under another declared version,
`aas.api_profile` judges only the answers with the status 200.

These checks set a missing answer aside and still judge the other answers: `identifier.negotiation`,
`aas.api_profile`, `integrity.status_list`, `persistence.versions`, and the channels of
`access.restricted_fields`. In them, a missing answer cannot hide a fail that another answer proves.
`resolver.conformance`, `registry.consistency`, and `identifier.consistency` stop at the first
missing answer, as they do for a server error.

The transport waits for `Retry-After` once per fetch, and only for these conditions:

- The answer is a 429 to a `GET`, `HEAD`, or `OPTIONS` request. The transport never sends a write again.
- `Retry-After` is a number of seconds. The transport does not read the date form, because it
  depends on the clock of the system under test.
- The delay is 5 seconds or less, and it ends before the total time limit of the fetch.
- The request budget allows one more request.

After the wait, the transport sends the request one more time. The record holds the last answer
and the number of attempts. A 503 is not sent again: it stays a server error.

Security note: a system under test can answer 429 to avoid a verdict, as it can with a 5xx
answer. The conformance test report shows each rate-limited answer, and the step is
`inconclusive`. It is never a pass.

### 9.1 The IXIT is untrusted input

The supplier of the system under test can write the ICS and the IXIT. The engine therefore
does not let those files decide what the test host trusts or discloses:

- The trust bundle comes only from the operator (`--trust`). A bundle that the IXIT names is
  never loaded. Otherwise a supplier could name its own key as a trusted authorization issuer.
- A manual result comes only from the operator, with `--manual-result PATH` on `plan` and `run`. The IXIT cannot supply or select one.
- An IXIT sample name that starts with `manual/` is an input error. The engine reserves that namespace for manual results.
- The trust bundle names each key of a performer with the purpose `manual`. A key with only a different purpose is not trusted for a manual result.
- The command line reads a manual result only to find the test purpose that it names. It trusts nothing in the file before the check verifies it.
- A file that names no test purpose is an input error. So is a test purpose that is not a manual step with the check `manual.review`.
- A result for a step that the plan excludes or skips is an input error. The message gives the reason.
- Two files for one test purpose are an input error. So is a manual result without `--trust`.
- Each non-public host in `IXIT.network.allow_private_hosts` must be confirmed by the operator
  with `--allow-private-host ORIGIN` for the origin to reach on it. A public origin needs an
  authorization, or `--allow-remote-host ORIGIN`. A bare host is refused: it would confirm
  every port of that host.
- An IXIT may not name a secret for the role `anonymous`.
- The profile declares the closed set of roles. The IXIT cannot add a role. A role outside the set is an input error (section 6).
- The credential issuer in a report comes from the validated authorization. The IXIT cannot name it.
- The IXIT cannot name a data key, a signing key, a passphrase, or a key of the trust bundle.
  `keys generate`, `sign`, `authorize`, `trust-bundle add-key`, `open`, and `prove` read no ICS
  and no IXIT.
- A secret reference is `env:DPPCE_SECRET_<NAME>` or `file:<name>` inside the directory that
  the operator gives with `--secrets`. No other environment variable or file can be named.
- The IXIT declares a secret reference for a role. The operator must repeat exactly that
  reference with `--role-secret ROLE=REFERENCE`. An IXIT alone can never select a secret, for
  example one that belongs to a different system that the same laboratory tests.
- The client id of an OAuth 2.0 role is a reference too. The operator repeats it with
  `--role-client-id ROLE=REFERENCE`, because the engine sends the client id to the token endpoint.
- A role credential is sent only to an origin that a validated authorization names. Origins
  are compared in one normal form. In that form an explicit default port, such as `:80` for
  `http`, equals no port. An explicit port 0 is never the default port. `--allow-private-host`,
  `--allow-remote-host`, and `dppce authorize` refuse port 0. Role secrets for an origin that no
  authorization names are an input error, not a run without credentials.
- TLS trust anchors and the TLS client certificate come only from the operator (`--ca-file`,
  `--client-cert`, `--client-key`). The CA file adds to the default trust store and never replaces
  it. The client certificate goes only to an origin that a validated authorization names. Every
  other origin gets a context without it. `--client-cert` without an authorization is an input
  error. No option turns off certificate or host-name checks, or lowers the TLS 1.2 minimum.
- A path in the IXIT is resolved and must stay inside the directory of the IXIT file.
- A URL template of the IXIT is a path under an endpoint that the IXIT names. It cannot select
  a scheme, a host, or a port (section 9.2).
- The identifier split uses a fixed separator, not a pattern. A supplied regular expression
  could make the engine use unbounded time.
- The ICS cannot select the API contract or the access policy. It names the identifier that it
  expects. A different bound file gives `blocked`.
- The IXIT cannot select the contract operation that `api.contract` judges. The bound contract
  marks it. The IXIT template must match that path.
- With `item_target: resolved`, the resolved URL must also match that path, under the endpoint of
  the `item` template, with no query and no fragment. Otherwise `api.contract` gives `blocked`
  with `API.CONTRACT.PATH_MISMATCH`. Nothing is fetched.
- The fetch that `api.contract` judges must not follow a redirect, in either mode. A redirect
  gives `blocked` with `API.CONTRACT.PATH_MISMATCH`, because the body belongs to another URL.
- The IXIT can ask for the resolved item target (section 9.2). The system under test then selects
  that URL with a redirect. The transport checks each redirect hop. It checks the URL again when a
  check fetches it. A redirect therefore cannot add an origin that the operator did not confirm.
  The checks fetch the URL as `anonymous`, so no credential goes with it.

### 9.2 Resource templates and bound files

The IXIT gives the URL of each fetched passport resource. No adapter holds a URL path for a
passport resource.

- `IXIT.resources` maps a resource name to an endpoint name and a URL template. The names are
  `item`, `model`, `signed`, `versions`, `registry_record`, `description`, `shells`, `submodels`,
  `view`, and `credential`. The last five are additive, and `dppce.ixit/1` stays.
- `api.contract` judges any of these resources. The contract marks the operation with
  `x-dppce-resource`. An AAS description or shell list is one such operation.
- An unknown resource name is refused when the IXIT loads.
- A URL template starts with one `/`. It holds URL path and query characters and named
  placeholders, for example `/passports/{gtin}/{serial}/data`. It has no fragment.
- A URL template is not evaluated. The engine only replaces each named placeholder with a
  percent-encoded value. The template grammar is fixed.
- `{id}` is `IXIT.samples.passport_id`. `IXIT.id_parts` splits that value at a fixed separator
  into named parts. The split is data, not code.
- The split uses the first n-1 separators for n names. The last part keeps any further
  separator. No part can be empty.
- If the split fails, a template that uses a part gives `blocked`.
- One helper, `dppce.adapters.common.template_url`, builds the URL of every passport resource and
  access channel. It percent-encodes each placeholder value and appends the path to the endpoint.
- The resolver checks fetch the carrier identifier itself. That URL does not come from a template.
- `IXIT.item_target` is `template`, the default, or `resolved`. With `resolved`, `api.contract`,
  `data.jsonschema`, `data.context`, `data.rules`, and `integrity.jws` do not use the `item`
  template. They use the URL that the carrier resolves to.
- That URL is the last redirect target of the resolver exchange. If the resolver answers 200 with
  no redirect, it is the carrier URL.
- The engine reuses a resolver exchange that it fetched with the same `Accept` value. Each check
  reads the carrier sample again.
- One helper, `dppce.adapters.common.item_url`, gives this URL. A transport error or a server
  error at the resolver gives `unreachable`.
- A missing or unreadable carrier sample keeps its own outcome. These cases give `blocked` with
  `<AREA>.NO_TARGET`. They are a failed carrier check, a carrier that is not an HTTP or HTTPS
  URL, a resolver status other than 200, and a resolver answer that is a linkset (section 8).
  The engine does not follow the links of a linkset.
- Redaction can change the URL. The engine does not fetch a URL that holds `<removed>`, also in
  percent-encoded form. The check gives `blocked` with `<AREA>.NO_TARGET`.
- `integrity.jws` resolves the URL after it judges the signed passport. A resolver failure
  therefore cannot hide a signature finding.
- `api.contract` still needs the `item` template, because the engine matches the contract
  operation with it (section 9.1).
- The `model`, `signed`, `versions`, and `registry_record` resources and the access channels
  always use their templates. So do `identifier.consistency`, `persistence.versions`, and
  `registry.consistency`.
- `ixit_sanitized_hash` leaves out `item_target` when it has the default value. An IXIT without
  the field therefore keeps its hash.
- The endpoint must be an `http` or `https` URL with a host and with no query or fragment. A
  template therefore cannot change the scheme, the host, or the port.
- The transport policy (section 9) applies as before. A template cannot add a host or an origin
  that the operator did not confirm.
- A resource with no template gives `blocked` with `<AREA>.NO_TARGET`. The engine has no default
  path.
- The access policy names its probe channels as URL templates under the `api` endpoint. The
  same helper builds them with the same placeholders.

The profile binds the API contract and the access policy. The ICS names the identifier of each
one in `api.contract` and `access.policy`.

- The contract states its identifier in the top-level key `x-dppce-contract-id`. The policy
  states it in `policy_id`.
- If the ICS value is `unknown`, the check gives `blocked` with `API.CONTRACT.NOT_DECLARED` or
  `ACCESS.POLICY.NOT_DECLARED`.
- If the identifiers differ, the check gives `blocked` with `API.CONTRACT.ICS_MISMATCH` or
  `ACCESS.POLICY.ICS_MISMATCH`.
- A contract path item marks its resource with `x-dppce-resource`. `api.contract` judges only the
  marked operation.
- If the IXIT template path differs from the marked path, `api.contract` gives `blocked` with
  `API.CONTRACT.PATH_MISMATCH`. Nothing is fetched.
- The run manifest records `sha256:<hex>` of the raw bytes of each bound file in `bound_files`.
  These files are the contract, the policy, the schemas and rule packs of the profile, and each
  file that a test purpose names in a parameter.
  An unreadable file is recorded as `unavailable`.
- A new run writes the decision body schema version `dppce.decision/3`. In versions 2 and 3,
  `bound_files` is required. A `dppce.decision/1` body has no `bound_files`. Only version 3
  can hold the provenance fields of section 11.1. The verifier reads the three versions as
  written and rejects any other pairing as a structure error. The JSON Schema lists the three
  versions. The model checks the pairing.
- A replay reads the bound files again. The input check of section 10.1 stops a replay with a
  changed bound file before it evaluates (exit code 2).
- A record of run inputs migrated from `dppce.runinputs/1` has no input hashes. For such a
  record, only the decision digest comparison applies.
- In version 2, a changed bound file gives a different decision digest. A version 1 body has no
  `bound_files`, so its digest comparison does not detect a changed bound file.

### 9.3 Credential schemes and token acquisition

An IXIT identity names how the engine presents a role (OD-13). `scheme` has three values:

| Scheme | Fields | What a request of the role carries |
| --- | --- | --- |
| `bearer`, the default | `secret_ref` | `Authorization: Bearer <secret>` |
| `header` | `secret_ref`, `header_name` | `<header_name>: <secret>` |
| `oauth2_client_credentials` | `secret_ref`, `token_endpoint`, `client_id_ref` | `Authorization: Bearer <issued access token>` |

- A scheme takes only its own fields. Any other field of the table is an input error.
- An identity of the `bearer` scheme keeps the form that it had before OD-13. The sanitized IXIT
  hash and the decision digest of an earlier recording therefore do not change.
- `header_name` is a field-name token of 64 characters or less. It must not be `Host`, `Cookie`,
  `Content-Length`, a hop-by-hop header, a name that starts with `Proxy-`, or a header that the
  transport sets. It must not be a header whose value a record keeps (section 10). The transport
  refuses such a name too.
- The rules of sections 9 and 9.1 apply to each scheme. A secret goes only to its origin, and
  the anonymous role carries none.

The scheme `oauth2_client_credentials` follows RFC 6749, section 4.4:

- `secret_ref` is the client secret. `client_id_ref` is the client id. The operator confirms
  both references (section 9.1). The IXIT never holds a secret.
- `token_endpoint` is a key of `IXIT.endpoints`. The origin override of the test rig applies to
  it as to the other endpoints.
- Before the first request of the role, the engine sends one `POST` to the token endpoint. The
  body is `grant_type=client_credentials`. The client authenticates with HTTP Basic.
- The request goes through the transport policy, with its own total time limit. It counts
  against the request budget.
- It needs a valid authorization that names the origin of the token endpoint and the role, and
  that grants the scope `credential`. The method list of the authorization does not apply to it.
- The client secret goes only to the origin of the token endpoint, only over `https` or to a
  loopback address. The engine follows no redirect of the token request.
- The answer must be a 200 answer within the body limit. The strict JSON parser reads it. It
  must hold a string `access_token` in the bearer token form of RFC 6750 and a `token_type` of
  `Bearer` in any case. The token needs 12 characters or more.
- The engine registers the issued token as a secret in its credential form, `Bearer <token>`.
  Each later record is scrubbed of that form, in each spelling of section 9.
- The token endpoint belongs to the system under test, so it chooses the token. A bare token is
  therefore not removed. Its removal could hide a withheld field or make a JSON body unreadable.
  Limit: an echo of the bare issued token stays in a record.
- The client secret is a secret from the start of the run. So is the HTTP Basic value that the
  engine builds from the client id and secret. The request headers of a record never hold them.
- The engine asks once per role and run. It does not read `expires_in` and does not renew a token.
- The token exchange is not a record. Its request holds the client secret, and its answer holds
  the token. No check judges it. A replay therefore needs no token endpoint and sends no secret.
- If no usable token is issued, the requests of the role are not sent. A refusal, an answer that
  is not a usable token, or a policy denial gives `authorization_denied`. A transport failure of
  the token request gives its own transport error. The checks report `unreachable`, which is
  `inconclusive` and never a pass.
- A token that the resource refuses is an answer of the resource. The check judges it as usual.
  The engine does not ask for a new token. So a token endpoint cannot turn the refusal of a role
  into no answer.

Security note: a system under test can refuse a token to avoid a verdict for the role, as it
can with a 5xx answer. The step is then `inconclusive`. It is never a pass.

## 10. Recording

A recording is a directory.

```text
recording.json     index: schema version, key id, delete-after date, record ids, commitments
recording.sealed   the same index, encrypted and authenticated with the data key
records/<id>.enc   one encrypted record each
```

- Each record (metadata, sanitized request, response, body, salt) is serialized and encrypted
  with AES-256-GCM. The nonce is 96 random bits. The associated data is the record id and the
  schema version.
- The data key comes from a `DataKeyProvider`. The key is never stored in the recording directory.
- `dppce run` uses the key `--data-key-id` in the directory `--keys`. The default identifier is
  `local-data-key-1`.
- `run` creates a missing key only with `--create-data-key`. It draws 32 bytes from the operating
  system and writes the file with mode 0600.
- Without that option, a missing or unusable key is an input error, `KEYS.DATA_KEY.UNAVAILABLE`,
  with exit code 2. This check runs before the first request.
- The index records the key identifier. `replay`, `purge`, and `open` therefore need no key
  identifier option.
- The index holds no URL, no header, and no payload. It is clear text, so that a tool can list
  a recording with no key. It is not trusted alone: a reader with the key compares it with
  `recording.sealed` and refuses a recording whose index was changed.
- Commitment: `HMAC-SHA256(key = salt, message = "dppce.record.v1" || 0x00 || plaintext)`.
  The salt is 32 random bytes drawn at acquisition and stored inside the encrypted record.
  A bare hash of a predictable value is never published.
- `delete_after` is the acquisition date plus the retention period, 0 to 3650 days. The IXIT
  asks for a period (`observation.retention_days`). The operator can set it with `--retention-days`.
- `dppce purge` lists the recordings past that date. It deletes them only with `--yes`.
  It deletes a directory only if the index authenticates with the data key of the operator,
  every record decrypts and matches its commitment in that index, and the directory holds the
  files of that recording and nothing else. It opens each directory once, without following a
  link, and reads, checks, and deletes through that open directory. It deletes the files by
  name and then the empty directories, never recursively: a file that appears later stays,
  with the directory. A directory that was renamed or replaced during the purge is not removed.
- `read_recording` returns the records in acquisition order (numeric order of the identifiers).
- The record form holds `redirects` and, from P2-25 on, `redirect_statuses`: one status for each
  redirect target, in the same order. Each status is 301, 302, 303, 307, or 308. The form leaves
  out `redirect_statuses` when the list is empty. So a record from before P2-25 keeps its plaintext,
  its commitment, and the records root. A reader gives such a record an empty list. A check gives
  such a record the outcome and the message that it gave before P2-25. So an old recording replays
  to the same decision digest, unless a test pack or the catalogue changed. An empty list in the
  form, or a list of a different length than `redirects`, is a malformed record.
- A response header is recorded only if its name is in a fixed list of safe names. Each other
  value is replaced with `<removed>`. The list includes six CORS names (OD-06):
  `access-control-allow-origin`, `-allow-methods`, `-allow-headers`, `-expose-headers`,
  `-max-age`, and `-allow-credentials`. A URL in a recorded header is redacted: userinfo, the
  fragment, and credential-like query values are removed. The value of
  `access-control-allow-origin` is redacted in the same way.
- A `Link` value is read as RFC 8288, appendix B, reads it. A quoted string can hold `,` and
  `;`, and these do not split the value. An unquoted parameter value runs up to the next `;` or
  `,`. Only the first `rel` of a link counts, as section 3.3 states. A later `rel` is another
  parameter. A value keeps only its targets, a closed list of relations, and a
  fixed `type`. The list holds the registered relation names, `linkset`, the JSON-LD context
  relation, and the GS1 link types. The GS1 link types are those of the pinned GS1 Web Vocabulary
  file, in the `gs1:` form and the `https://ref.gs1.org/voc/` form. The pinned file is
  `v1.16/gs1Voc.jsonld` of `github.com/gs1/WebVoc` at commit
  `f8f407bf717233c871dca2f62f4e45b0940e8cad`.
- Each relation, an extension relation too, is compared without case, as RFC 8288, section 2.1.2,
  states. A kept relation has the spelling of the list. A relation outside the list is dropped one
  word at a time. A `type` with the value
  `application/linkset+json`, `application/ld+json`, or `application/json` is kept in lower case.
  These fixed values cannot carry a secret. Each other parameter, and each dropped relation, gives
  the link one marker, `<removed>`, after its relations and its type.
- Reading stops where a link-value does not start with a target in `<` and `>`, or where a link
  is followed by text other than `,`. The links before that point are kept, and one marker
  replaces the rest of the value. A target that is not a URI reference becomes the marker
  `%3Cremoved%3E`, and the other links stay. The output of redaction parses to the same links,
  and redaction of the output gives the same text.
- A value is not complete either if a processor model reads other targets or other context links.
  The model is the `Link` parser of jsonld.js 8.3.3. It splits a value at each `,` outside
  `<...>` and outside a quoted string that ends at the next `"`. Of each part, it reads the first
  target and then each parameter. A parameter replaces an earlier one of the same name. So the
  last `rel` counts, and the last parameter named exactly `target` replaces the target. A name
  with another case or with a space before `=` does not match.
- The record keeps the first kept `type` of a link. If the model reads the last parameter named
  exactly `type` as `application/ld+json` and the record keeps another type, the value is not
  complete. pyld loads the target of an alternate link with that type (section 8). Only
  redaction reads this rule, at record time, also on joined `Link` lines.
- pyld 3.0.0 uses the same three regular expressions with `re.findall`, so it reads each unquoted
  parameter value as empty. With an empty target, pyld loads the URL of the answer as the context.
  So for pyld, the model reads an unquoted `target` as empty, and such a value is not complete.
- pyld also reads an unquoted `rel` as empty, so it finds no context link there. The model keeps
  the jsonld.js reading of `rel`, so it reads each context link that pyld reads, and more. pyld
  raises an error on a link without parameters.
- This is an engine limit. The agreement check models the `Link` parsers of jsonld.js 8.3.3 and
  pyld 3.0.0. Another processor, or a later version of these two, can read a value differently.
  The agreement check does not see such a difference.
- The two parsers use three regular expressions with `\s`. In Python, these expressions took more
  than ten seconds on one value of about 2 KiB. The model is a scanner in linear time instead. A
  test compares it with the three expressions on 20,000 random values in Python syntax. A second
  test does so in JavaScript syntax. A third test reads values of 64 KiB in many shapes within a
  bound of five seconds.
- JavaScript and Python read `\s` differently: Python also matches `\x85`. The model reads each
  value twice, once with each set of white space. Both readings must agree with the engine.
- Redaction reads the value as the system sent it. A value with a control character other than
  HTAB, or with a character above `\xff`, is not complete. Such characters are not valid in an
  HTTP field value. The Python header parser can leave the line break of an obs-fold in a value.
  The characters `\x80` to `\xff` are allowed, because a header value arrives as latin-1 text.
  UTF-8 text such as `Å` arrives as `\xc3\x85`. This gate reads only the live value, not a
  recorded value. Before P2-26, redaction kept a target with a character such as `\x01`, so an
  old recording keeps its reading.
- An HTTP client gives the application one `Link` value: all `Link` lines in wire order, joined
  with `, `. Two lines can read the same alone and differently once joined. At record time,
  redaction joins the raw `Link` lines, with the header name compared without case. The model
  reads the joined value, and the engine reads each line. If the targets in order or their
  context links differ, the record of the last `Link` line gets the stop marker. A last line
  without a link records as `<%3Cremoved%3E>, <removed>`. If the reading of a line already
  stopped, this check is not made, because the record already shows the stop.
- A check never joins recorded lines. A recorded value holds markers that the model reads as
  targets. Each recorded line is canonical, so a check reads it alone. So an old recording replays
  to the same decision digest.
- `resolver.linkset` reads each recorded line too. After a joined difference, it can take the
  linkset of another line than a reader of the joined value does.
- A well-formed value without a link, such as an empty value, becomes the bare marker `<removed>`.
  An old recording holds this form too (section 8). A malformed value without a link becomes
  `<%3Cremoved%3E>, <removed>`, so its record still shows that reading stopped. The bare marker
  itself reads as a malformed value, so only its redaction gives a different text.
- A URI reference here holds only the characters of RFC 3986, section 2, and a `%` only before two
  hex digits. So a backslash, a control character, a space, or a non-ASCII character removes the
  target. URL parsers disagree on the host of a target with a backslash before `@`.
- A target with userinfo or with a `#` also becomes `%3Cremoved%3E`. Redaction would remove these
  parts without a trace, so the record would show a different URL than the system sent.
- A target with an empty authority, such as `https:///ctx` or `///ctx`, also becomes
  `%3Cremoved%3E`. Python joins its path to the host of the base URL. The WHATWG URL parser reads
  its first path segment as the host. Only redaction reads this rule, so an old record replays
  unchanged.
- A target with the scheme `http`, `https`, `ws`, `wss`, `ftp`, or `file` also becomes
  `%3Cremoved%3E` if `//` does not follow the scheme. Examples are `https:/ctx` and `https:ctx`.
  Python `urljoin` resolves such a target against the host of the base URL. pyld 3.0.0 keeps it
  as it is. Before this rule, the record of `https:user:pw@example.test/ctx` held the credential
  text. Only redaction reads this rule, so an old record replays unchanged.
- A target that Python `urljoin` can resolve to another URL than the WHATWG URL parser or pyld
  also becomes `%3Cremoved%3E`. `urljoin` drops an empty `;` parameter and an empty `?` query.
  It removes empty segments of a relative path that does not start with `/`. pyld 3.0.0 drops the
  first `.` of a relative path such as `.well-known/ctx`.
- The readers also differ on some dot segments: `%2e`, a final `..;x`, a dot segment after another
  segment, a dot segment in a URL with a scheme, and a final dot segment before a query. So a
  relative target keeps only a leading run of `.` and `..` segments.
- A fuzzer found these forms. It compared `urljoin` with the `URL` class of Node.js 22 and with
  the resolver of pyld 3.0.0. Only redaction reads this rule, so an old record replays unchanged.
- For a relative target, `urljoin` also removes empty segments of the base path. A redirect can
  give such a base. It can also give a base path with `\`, which the WHATWG URL parser reads as
  `/`. Redaction does not see the base, so this rule cannot remove such a target.
  `data.context` and `resolver.linkset` resolve it as the WHATWG URL parser and pyld do instead
  (section 8).
- The transport also removes an echoed credential from a recorded redirect target. A credential
  with `/` changes the base path, so neither check resolves a relative path target on that base
  (section 8).
- The transport resolves each `Location` with `urljoin`, which can remove the form that makes a
  base odd. The WHATWG URL parser of Node.js 22 reads `\` as `/` and `%2e` as `.`. It keeps the
  empty segments of a relative path.
- requests 2.34.2 also reads `%2e` as `.`. `urljoin` also reads `..;x` as `..`. On the base path
  of a relative `Location`, `urljoin` removes empty segments.
- So the record marks a redirect target with the suffix `#<removed>` after such a `Location`. A
  later hop with a relative path, a query, or no path joins the fetched path, so it is marked too.
- A later hop with an absolute path or an authority does not read the earlier path. Its suffix
  depends only on its own `Location`.
- `urljoin` also drops an empty `;` parameter, an empty query, and an empty fragment. Node.js 22
  keeps the `;`, so it resolves a query or an empty target against another last segment.
- So the record marks a redirect target with the suffix `#?<removed>` after an empty `;`
  parameter. A later hop with a query or no path keeps this suffix.
- Node.js 22 resolves each target against a base with an empty query or fragment as `urljoin`
  does against the base without it. So these forms get no suffix.
- In an `http` or `https` `Location`, the WHATWG URL parser of Node.js 22 reads `\` as `/`. It
  reads the first segment after an empty authority as the host, as in `http:///h2.example/doc`.
- There `urljoin` keeps the host of the base, so a consumer never reads the answer that the
  transport would fetch. So the transport does not follow such a `Location`.
- The request ends with `redirect_out_of_scope`, as for a hop to a host outside the scope. RFC
  9110, section 4.2.1, says that a recipient rejects an `http` URL with an empty host.
- `redact_url` removes every other fragment, so no other record holds a suffix. A plain
  `Location` is recorded as before. An old record holds no suffix, so it replays unchanged.
- A suffix is not a change of the fetched URL. `item_url`, `identifier.negotiation`, and
  `access.restricted_fields` read the target without it. `data.context` and `resolver.linkset` do
  not resolve a target that reads the unknown part of such a base (section 8).
- A fuzzer followed chains of one to three hops with `urljoin`, Node.js 22, and requests with
  pyld 3.0.0. Its `Location` values also held empty authorities, a `\` before the first segment,
  and empty `;`, `?`, and `#` parts.
- No followed chain left the host for Node.js 22. Where the engine resolved a context target to
  one URL that an allowlist can hold, each consumer read that URL.
- The transport removes an echoed credential of the engine before redaction (section 9). Its
  marker `<removed>` holds `>`. In a `Link` value, the marker could close a target that a reader
  of the sent value reads as open.
- So a `Link` value that holds a form of a credential is recorded as `<%3Cremoved%3E>, <removed>`
  as a whole. Reading of that record stops, so `data.context` gives a fail. Only the live
  transport writes this form, so an old record replays unchanged.
- A credential-like query value is different. Redaction replaces it with a marker in place, and
  that marker shows in the recorded target. So a check sees that redaction changed the target.

Replay serves records by sequence. A replayed request that differs from the recorded one in
method, URL, or role gives `recording_mismatch`, which is an execution error.

### 10.1 Run inputs

`dppce run` writes `inputs.json` next to the recording. `dppce replay` reads it to rebuild the
inputs of the evaluation.

- The file is `JCS(RunInputsRecord)` with the schema version `dppce.runinputs/3`. The JSON
  Schema is `runinputs`.
- It holds the mode, the profile, the evaluation time, the ICS, the IXIT, the trust bundle, the
  authorization token, and the issuer statement.
- It also holds the paths of the imported files, the selected identifiers, and the test purposes
  with a supplied manual result.
- `data_root` is the absolute path of the data root of the run.
- `input_hashes` holds `sha256:<hex>` of the selected profile and of the source catalogue.
- It also holds the digest of each loaded requirement pack and test pack, shipped or imported,
  and of each bound file.
- The profile, the sources, the packs, and the test packs are compared as parsed models
  (RFC 8785). Bound files are compared as raw bytes.
- A change in a comment or in white space of a YAML pack therefore does not count as a change.
  A change in a bound file always counts.
- One function computes these values for the run manifest, for `inputs.json`, and for the
  replay check.
- The run takes the bound-file values of `inputs.json` from its manifest, so both state the
  same values.

Replay, in this order:

1. With `--data-root`, replay uses that directory. Otherwise it uses `data_root` of the record.
2. A recorded data root that is not a directory is an input error: `REPLAY.DATA_ROOT.MISSING`.
   The message names the path and asks for `--data-root`.
3. Replay loads the profile, the catalogue, and the test packs. It then computes the input
   hashes again.
4. Each difference is an input error: `REPLAY.INPUT.CHANGED`. The message names each input that
   differs, and the data root.
5. Only then does replay check the ICS, the authorization, and the manual results, and evaluate.
6. The summary states the data root and `input_check`: `pass`, or `not_run` for a record with no
   input hashes.

A different data root with the same file contents passes the check. A replay never contacts a
host, so a changed record cannot make the engine send a request or a secret.

`dppce.migrations` upgrades a `dppce.runinputs/1` record. Version 1 was written by 0.1.0rc1 and
by later versions before version 2. The step adds empty lists for the test-pack and
manual-result fields, which 0.1.0rc1 did not write. It sets `data_root` and `input_hashes` to
`null`. A replay of such a record uses `--data-root` or the default data root. It does not
compare input hashes: `input_check` is `not_run`, with `REPLAY.INPUT.NOT_RECORDED`. The decision
digest comparison still applies.

`dppce.migrations` also upgrades a `dppce.runinputs/2` record to version 3. The step changes only
the embedded trust bundle, from `dppce.trust/1` to version 2 (section 11.4). A record whose trust
bundle lists revoked serial numbers cannot be upgraded. A record whose trust bundle has a field
of the wrong shape cannot be upgraded either. Replay then gives exit code 2 with the reason code
of the migration. The decision body holds only the policy version of the trust bundle. The step
therefore does not change a decision digest.

`inputs.json` is not encrypted or signed. It keeps the trust bundle and the authorization token
in clear text, as before.

### 10.2 Record openings

A record opening discloses one record to a party that is entitled to it (ADR 0009). It holds the
plaintext of the record. Protect it as you protect the recording.

`dppce open --run RUN_DIR --keys KEYS_DIR --record ID --out FILE` writes `JCS(RecordOpening)`.
The schema version is `dppce.opening/1`, and the JSON Schema is `opening`.

- `record` holds every field of the record except the salt. `JCS(record)` is the plaintext of
  the commitment. Like the record form, it leaves out an empty `redirect_statuses`. This field is
  an addition to `dppce.opening/1`: an opening of a record from before P2-25 does not change.
- `salt` is the salt of the record, as standard base64 with padding.
- `proof` is the inclusion proof of the record commitment in the `records` tree (section 11.2).
- The command reads the recording with `read_recording`. A recording that does not authenticate
  is an input error.
- It reads `RUN_DIR/envelope.json`, or the file that `--envelope` names. The envelope must pass
  `structure`, `ordering`, `results_root`, `records_root`, and `counts`. Otherwise the reason
  code is `ENVELOPE.BODY.INVALID`.
- A record identifier that the recording does not hold gives `OPEN.RECORD.UNKNOWN`.
- A commitment that is absent from the envelope, or that differs from it, gives
  `OPEN.RECORD.NOT_IN_REPORT`.
- `--out` names a new file. The command creates it with mode 0600. An existing file gives
  `OPEN.OUTPUT.EXISTS`.
- The command writes a warning to standard error. The warning states that the file holds the
  plaintext of the record.
- Request headers are recorded without secrets (section 10). A response body can hold personal
  data.

This is the first version of the format. The verifier refuses every other version, so no
migration step exists yet.

The verifier checks an opening with `--opening FILE` (section 11.4).

## 11. Evidence

### 11.1 Canonical decision body

The decision body is serialized with RFC 8785 (JCS). Numeric constraint: every number is an
integer in the range -(2^53 - 1) to 2^53 - 1. Floats are rejected. Quantities use integer units.
Times are UTC strings `YYYY-MM-DDTHH:MM:SSZ` with ASCII digits. A time must name a moment that
exists. The models refuse a date such as `2026-02-30` and a second `60`.
`decision_digest = "sha256:" + hex(SHA-256(JCS(decision body)))`.

JCS is the canonical form of the engine's own decision body only. It does not replace the
processing rules of any credential securing specification.

Run provenance. Version 3 of the decision body adds these optional fields to the run manifest.
They are part of the signed body, so a change to one of them breaks the signature (fault E-16).
The body leaves out a field while it has its absent value: `null`, `false`, or an empty list.
A body that writes an absent value is not in the canonical form and fails the structure.

| Field | Value |
| --- | --- |
| `authorization_id` | The `authorization_id` of the validated test authorization. |
| `authorization_digest` | `sha256:<hex>` of the ASCII text of the validated authorization token. |
| `remote_read_without_authorization` | `true` if the run had no validated authorization and the operator confirmed public origins for bounded read-only access. |
| `passport_trust_hash` | Canonical digest of the operator trust bundle that the checks used. |
| `trust_anchor_fingerprints` | `sha256:<hex>` of the DER bytes of each passport trust anchor of that bundle, sorted. |
| `ca_file_digest` | `sha256:<hex>` of the raw bytes of the operator CA file (`--ca-file`). |
| `test_items` | The tested items, sorted by sample name. See below. |

A test item has `sample`, `kind`, and `value`. The kind `declared_identifier` holds the text of
the IXIT sample `identifier` or `passport_id`. A declared identifier is recorded after URL
redaction (section 10), so it holds no userinfo, no fragment, and no credential-like query
value. The kind `sample_file` holds `sha256:<hex>` of the bytes of a sample file that the run
read. A manual result is not a test item. A test item never holds a value that the system under
test returned.

A replay computes the authorization fields, the trust fields, and the test items again from
`inputs.json` and the recording. The record of run inputs does not hold the CA file or the
remote read confirmation. A replay therefore takes `ca_file_digest` and
`remote_read_without_authorization` from the manifest of the run. These two fields decide no
verdict. `dppce compare` reports a difference in a provenance field as a plan input difference.

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

An inclusion proof is `JCS(InclusionProof)`. The schema version is `dppce.proof/1`, and the JSON
Schema is `proof`.

- `label` is `results` or `records`. `leaf` is a requirement result, a test result, or a record
  commitment. Its type must fit the label.
- `key` is the key of the leaf as stated above. It must name the leaf.
- `index` is the position of the leaf in ascending order of key. `size` is the number of leaves.
- `path` holds at most 64 hashes in lowercase hexadecimal. `root` is the root of the tree.
- `decision_digest` names the report.
- `merkle.verify_inclusion` checks a proof with the algorithm of RFC 9162, section 2.1.3.2.
- This is the first version of the format. The verifier refuses every other version, so no
  migration step exists yet.

`dppce prove --envelope FILE --result KEY --out FILE` writes the proof of one result. `KEY` is
`R:` plus a requirement identifier, or `T:` plus a test purpose identifier.

- The envelope must pass the five dimensions of section 10.2. Otherwise the reason code is
  `ENVELOPE.BODY.INVALID`.
- A key that the report does not hold gives `PROVE.RESULT.UNKNOWN`. An existing `--out` file
  gives `PROVE.OUTPUT.EXISTS`.
- A proof discloses one result. The verifier checks a proof against the envelope that it names
  (section 11.4).

The file-backed log in `evidence.devlog` is a development component. It does not implement
RFC 9162 and gives no protection against equivocation.

### 11.3 Signing profile

One profile: JWS Compact Serialization (RFC 7515) with `ES256`. The allowlist is `["ES256"]`.
The payload is `JCS(attestation)`.
The verification key is a public P-256 JWK with `kty`, `crv`, `x`, and `y`. It can also have
`kid`, `use`, and `alg`. A key whose `use` is not `sig` is refused. A key whose `alg` is not
`ES256` is refused.
The protected header holds `alg`, `kid`, and
`typ: "dppce-attestation+jws"`. Keys in the repository are test keys and say so in their names.
Production keys come from a `Signer` implementation for a KMS or PKCS#11 device.
`dppce keys generate` writes a passphrase-encrypted file key for an operator without a KMS or
PKCS#11 device. Those `Signer` implementations are interfaces only in this version.

A report signature can carry RFC 3161 timestamp tokens (ADR 0015). The timestamp profile:

- The message imprint is SHA-256 over the signature value. The signature value is the
  base64url-decoded third part of the compact JWS.
- The imprint uses `id-sha256`. Any other hash algorithm is outside the profile.
- `timestamp_evidence` holds each token as standard base64 with padding (RFC 4648, section 4)
  of the DER `TimeStampToken`.
- A token binds a signature through its imprint, not through its position in the list.
- A token is at most 64 KiB, which is 87384 base64 characters. It holds at most five
  certificates. An envelope holds at most 16 tokens.
- The token is CMS `SignedData` with one signer. The signed attributes hold the content type,
  the message digest, and a signing certificate attribute of version 1 or 2.
- Digest algorithms: SHA-256, SHA-384, and SHA-512. Signature algorithms: RSA PKCS#1 v1.5 with
  2048 bits or more, and ECDSA on P-256 or P-384.
- The TSA certificate has one critical extended key usage extension, and `id-kp-timeStamping`
  is its only purpose.

`dppce timestamp imprint` prints the SHA-256 imprint of each signature in an envelope, in
hexadecimal. The operator makes a request with that imprint and sends it to a timestamp
authority of their choice. `dppce timestamp attach` adds the token of a `TimeStampResp` file to
an envelope. `attach` accepts only the status `granted` or `grantedWithMods`. The token imprint
must equal the imprint of a signature in the envelope. `attach` does not check trust.
`dppce verify` does. The engine never contacts a timestamp authority.

COSE, qualified electronic seals, and UNTP DCC export are separate profiles with their own
capability states.

#### Signing keys

`dppce keys generate --out FILE --passphrase-ref REFERENCE` writes a new P-256 key. The format is
PKCS#8 PEM, encrypted with the passphrase.

- The encryption is PBES2: PBKDF2-HMAC-SHA256 with 2048 iterations, and AES-256-CBC. The
  installed `cryptography` package sets these values. It cannot raise the iteration count for
  PKCS#8.
- 2048 iterations make a guess cheap. The passphrase must therefore have high entropy. Generate
  it, for example with `secrets.token_urlsafe(32)`. Do not use a passphrase that a person chose.
- A passphrase has 32 to 1023 bytes in UTF-8. Otherwise the reason code is
  `KEYS.PASSPHRASE.LENGTH`.
- The command creates the file with mode 0600 and never writes over a file. An existing file
  gives `KEYS.FILE.EXISTS`.
- The command prints the public JWK of the key: `kty`, `crv`, `x`, and `y`.
- The passphrase is a secret reference, as in section 9.1: `env:DPPCE_SECRET_<NAME>`, or
  `file:<name>` inside `--secrets`. No option takes the passphrase itself.
- No command prints or records a passphrase or a private key.

`dppce sign` and `dppce authorize` load a key with one set of rules:

- An encrypted key needs `--passphrase-ref`. Without it, the reason code is
  `KEYS.PASSPHRASE.MISSING`.
- A key that cannot be decrypted or read gives `KEYS.KEY.UNREADABLE`. The message holds no
  passphrase.
- An unencrypted key gives `KEYS.KEY.UNENCRYPTED`. The option `--allow-unencrypted-key` permits
  it, for test keys only.
- A key that is not on P-256 gives `KEYS.KEY.NOT_P256`.

`dppce sign` writes its result in one of two ways. The operator gives exactly one:

- `--out FILE` names a new file. The input gives `SIGN.OUTPUT.IS_INPUT`. An existing file gives
  `SIGN.OUTPUT.EXISTS`.
- `--in-place` replaces the input. The command writes a temporary file in the same directory and
  then renames it over the input.
- The replaced file keeps the mode of the input. An input that is a symbolic link gives
  `SIGN.INPUT.LINK` with `--in-place`.
- Before it signs, `sign` checks `structure`, `ordering`, `results_root`, `records_root`, and
  `counts` (section 11.4). A failure gives `ENVELOPE.BODY.INVALID`, which names each failed
  dimension. Nothing is written.

`dppce authorize --document FILE --key FILE --kid KID --out FILE` signs a
`dppce.authorization/1` document. The system owner runs it. The token is a compact JWS with
`typ: "dppce-authorization+jws"`.

- A document that is not valid gives `AUTHORIZE.DOCUMENT.INVALID`. This includes a document that
  is not its exact canonical form, for example a number as a string.
- `not_before` and `not_after` must be times `YYYY-MM-DDTHH:MM:SSZ`, and `not_before` must not
  be after `not_after`. Otherwise the code is `AUTHORIZE.PERIOD.INVALID`.
- Each endpoint must be an `http` or `https` origin. Otherwise the code is
  `AUTHORIZE.ENDPOINT.INVALID`.
- An existing `--out` file gives `AUTHORIZE.OUTPUT.EXISTS`.
- The command does not check trust. `run` validates the token against the trust bundle of the
  tester (section 9.1).

`dppce trust-bundle add-key` writes a `dppce.trust/2` bundle with one more key.

- The input is `--bundle FILE`, or a new empty bundle with `--policy-version`. Give exactly one.
  Otherwise the code is `TRUST.BUNDLE.OPTION`.
- A version 1 input is upgraded (section 11.4).
- `--public-key FILE` is a JWK. A JWK with the private member `d` gives `TRUST.KEY.PRIVATE`.
- A JWK that is not a public P-256 signing key, or not a point on the curve, gives
  `TRUST.KEY.NOT_P256`. The bundle stores `kty`, `crv`, `x`, and `y` only.
- A key identifier that the bundle already holds gives `TRUST.KEY.DUPLICATE_KID`.
- `--not-before` and `--not-after` must be real times. A time that does not exist, or a reversed
  period, gives `TRUST.KEY.PERIOD_INVALID`.
- The model rules of the bundle apply, for example `TRUST.KEY.ROLE_CONFLICT`.
- `--out` names a new file. An existing file gives `TRUST.OUTPUT.EXISTS`.

`sign --out`, `authorize`, `trust-bundle add-key`, and `prove` create each new file with mode 0600,
also under umask 0. The operator changes the mode to share a file.

#### Attestation versions and signer roles

An attestation has the version `dppce.attestation/1` or `dppce.attestation/2`. The verifier reads
both as written. An attestation is signed, so no migration rewrites it.

Version 2 adds four fields. Each field is present. A field without a value is `null`.

- `role`: `issuer` or `reviewer`. A version 1 attestation has the role `issuer`.
- `status`: the entry of the report in a status list, as `list_id` and `index`.
- `valid_until`: the last time at which the issuer states that the report is valid.
- `supersedes`: the decision digest of an earlier report that this report replaces. It differs
  from `decision_digest`.

A `reviewer` attestation has `null` for `status`, `valid_until`, and `supersedes`. Only the issuer
states the lifecycle of a report.

`dppce sign` writes version 1 when the role is `issuer` and no other version 2 field has a value.
Otherwise it writes version 2. A verifier from before this version refuses a version 2
attestation as a signature that does not verify.

Each role needs one purpose of its key in the trust bundle:

| Role | Purpose of the key |
| --- | --- |
| `issuer` | `report` |
| `reviewer` | `review` |

- The verifier reads the role from the verified payload only. It never reads the role from the
  header.
- `run` and `replay` never make a signature. A person makes a reviewer signature with
  `dppce sign --role reviewer` and a key that only that person holds.
- One public key cannot have the purpose `review` and the purpose `report`. The rule compares the
  key material, not the key identifier. Such a trust bundle is invalid: `TRUST.KEY.ROLE_CONFLICT`.
- An attestation names a key and a role, not a person. The laboratory maps the key identifier to
  a person.
- The list of signatures is not signed. A holder can remove or reorder signatures. An issuer that
  states `status` or `valid_until` states the same values in each of its signatures over the
  report.

### 11.4 Verification

`dppce verify` needs the envelope, an explicit trust bundle, and an explicit evaluation time.
It reports each dimension separately:

| Dimension | Mandatory | Passes when |
| --- | --- | --- |
| `structure` | yes | The envelope matches the schema. |
| `ordering` | yes | Result and record keys are strictly ascending. |
| `results_root` | yes | The recomputed root and count equal the stated ones. |
| `records_root` | yes | The recomputed root equals the stated one. |
| `counts` | yes | Verdict counts and coverage totals equal the recomputed ones. Each path verdict, requirement verdict and its reason, the overall outcome and its reason, and each claim level follow from the report (sections 4 and 7). The coverage figures that the report holds data for are recomputed. Each count by authority class, review status, and testability is a known value, not negative, at least the count of the results with it, and the counts sum to the total; the implementation ratio is over the total; the three ratio labels are the published ones; the placeholder count is bounded and agrees with its review status count. Only a completed step has `pass` or `fail`. |
| `signature` | yes | At least one signature with the role `issuer` verifies with a key of the trust bundle and binds the decision body. The detail names the first such key. Otherwise, the outcome is the failure of the last signature that names a key of the trust bundle. If only signatures with a different role verify, the outcome is `missing` with `SIGNATURE.ISSUER.NONE`. |
| `issuer_trust` | yes | The signing key is in the trust bundle. It is valid and not revoked at the key validity time. That time is the earliest `genTime` of a good timestamp token over the signature of that key, or else the evaluation time. A key that only the report supplies is not trusted. The attestation names the issuer that the trust bundle states for the key. `manifest.issuer.identifier` equals that issuer and is not `unspecified`. An accreditation status other than `not accredited` has a reference. The first signature with the role `issuer` that meets all of these gives `pass`. Otherwise the outcome is the problem of the last signature that verifies and binds. Each detail names the key validity time. |
| `signers` | yes | Each signature that names a key of the trust bundle verifies and binds the decision body. The trust bundle grants the purpose of its role to its key. The rules are in "Signer roles". The detail lists each signature with its key, issuer, and role. |
| `manual_results` | yes | Each completed step of the check `manual.review` has exactly one `artifact` observation with a JWS. Each record id of that observation has a commitment in the report. The JWS passes tests 2 to 14 of section 8.1 with the trust bundle of the verifier, for the purpose `manual`. The key must be valid at the evaluation time of the verifier. The signed test purpose and SUT identifier equal those of the report. The signed SUT version equals the version in the manifest, or is `null` if that version is `unknown`. The signed digest of the test purpose equals `test_purpose_digest` in the observation. The signed time is not after the evaluation time of the run. It is in the validity period of the key. The signed `kid`, role, time, and outcome equal the observation. The verdict is `pass` only for the outcome `pass`. A time that cannot be read gives `fail`. A report with no completed manual step passes. |
| `status` | when the trust policy sets `require_status`, when the operator supplies a status list, or when an issuer signature that passes `issuer_trust` names a status entry | The supplied status list passes the checks of "Report status lists", and the bit of the report is 0. |
| `validity` | when an issuer signature that passes `issuer_trust` states `valid_until` | The evaluation time is not later than the earliest `valid_until` of these signatures. |
| `timestamp` | per trust policy | At least one token in `timestamp_evidence` passes the timestamp checks below, and it binds a signature that verifies and binds. |
| `opening` | when the operator supplies `--opening` | The record opening passes the checks of "Record openings and inclusion proofs". |
| `proof` | when the operator supplies `--proof` | The inclusion proof passes the checks of "Record openings and inclusion proofs". |

`complete` is true only if every mandatory dimension passes. `timestamp` is mandatory when the
trust policy sets `require_timestamp`. `status` and `validity` are mandatory under the conditions
in the table. If mandatory status or timestamp evidence is missing or stale, `complete` is false.
`opening` and `proof` appear only when the operator supplies the file. Then they are mandatory.

In this section, a "passing issuer signature" is a signature with the role `issuer` that meets
every condition of `issuer_trust`. There can be more than one.

Verification never changes or restates the verdict about the tested system.
It shows that the report is intact, that a trusted issuer signed it, and that it agrees with
itself. It does not show that the issuer observed what the report says.
`dppce report --trust` needs `--at` too: a verification section always states its time.

`issuer_trust` binds the issuer statement of the report to the signing key (ADR 0014). The
verifier takes the issuer of a key from its own trust bundle only.

- A stated issuer that differs from the issuer of the key fails with `ISSUER.STATEMENT.MISMATCH`.
  The detail names both values.
- A signed report that states the issuer `unspecified` fails with `ISSUER.STATEMENT.UNSPECIFIED`.
  This applies also when a trust bundle names a key with that issuer.
- An accreditation status other than `not accredited` with an empty reference fails with
  `ISSUER.ACCREDITATION.NO_REFERENCE`.
- The verifier binds the identifier only. The trust bundle holds no issuer name, so the verifier
  does not check `manifest.issuer.name`.
- On a pass, the detail shows the accreditation status and the reference as the operator
  declared them.
- The engine does not validate an accreditation. The HTML report marks the issuer name and the
  accreditation fields as declared by the operator.
- The detail shows each value of the report in an escaped form, so a control character cannot
  reach a terminal.

The operator states the issuer with `--issuer-name`, `--issuer-id`, `--accreditation-status`, and
`--accreditation-reference`. The engine holds no issuer other than the default `unspecified`.
`plan` and `run` refuse an accreditation status other than `not accredited` without a reference:
`ISSUER.ACCREDITATION.NO_REFERENCE`, exit code 2. `replay` reads the recorded statement as written.

`manual_results` reads only the envelope. The JWS in the observation is sufficient, so the verifier needs no recording.
It does not check `expected_evidence`, because the report does not hold the test pack. The engine checks it at run time (section 8.1).
For the same reason, it cannot recompute the digest of the test purpose. A party with the test pack can recompute it.
The rule applies to the steps that name the check `manual.review`.

#### Trusted timestamps

The verifier checks each token in this order (ADR 0015). The first failure gives the reason code.

1. Above the size limit: `TIMESTAMP.TOKEN.TOO_LARGE`. Not base64, or not a DER
   `TimeStampToken`: `TIMESTAMP.TOKEN.MALFORMED`.
2. More than five certificates in the token: `TIMESTAMP.TOKEN.TOO_LARGE`.
3. A critical extension in `TSTInfo`: `TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION`.
4. Signer count, algorithms, or signed attributes outside the profile: `TIMESTAMP.CMS.UNSUPPORTED`.
5. No certificate of the token or of `timestamp_anchors` matches the signer: `TIMESTAMP.TSA.UNKNOWN`.
6. The key of that certificate is outside the profile or cannot be read: `TIMESTAMP.CMS.UNSUPPORTED`.
7. The signing certificate attribute does not identify that certificate: `TIMESTAMP.CMS.SIGNING_CERT`.
8. The content type, the message digest, or the signature does not verify:
   `TIMESTAMP.CMS.SIGNATURE_INVALID`.
9. The imprint algorithm is not SHA-256: `TIMESTAMP.IMPRINT.ALGORITHM`.
10. The imprint equals the imprint of no signature that verifies: `TIMESTAMP.IMPRINT.MISMATCH`.
11. The extended key usage is not as in section 11.3, or the extensions cannot be read:
    `TIMESTAMP.TSA.EKU`.
12. A key usage without digital signature or content commitment: `TIMESTAMP.TSA.KEY_USAGE`.
13. The TSA certificate is no timestamp anchor and has no path to one: `TIMESTAMP.TSA.UNTRUSTED`.
14. The path has a constraint that the engine does not evaluate: `TIMESTAMP.TSA.UNSUPPORTED_CONSTRAINT`.
15. `genTime` is after the evaluation time: `TIMESTAMP.TIME.FUTURE`.
16. A certificate of the path is outside its validity at `genTime`: `TIMESTAMP.TSA.EXPIRED`.
17. A certificate of the path is revoked at `genTime`: `TIMESTAMP.TSA.REVOKED`.

A good token gives `TIMESTAMP.OK`. The detail names the TSA subject, `genTime`, and the key of the
signature.

- One good token is enough for `pass`. Otherwise the outcome is `fail` with the code of the first
  token.
- If no signature verifies and binds, the outcome is `not_checked` with `TIMESTAMP.SIGNATURE.NONE`.
- More than 16 tokens give `fail` with `TIMESTAMP.EVIDENCE.TOO_MANY`.
- `genTime` keeps its fraction of a second. Each comparison uses the exact instant.
- A token that the verifier cannot read gives `fail`, never an error of the verifier.
- The verifier does not check the accuracy, the nonce, the policy, or the TSA name of a token.
- The verifier does no network I/O. It reads no CRL, no OCSP response, and no certificate URL.
- The certificates in a token are untrusted. Only `timestamp_anchors` are trusted for timestamps.
- A timestamp anchor is a CA certificate at the end of a path, or the TSA certificate itself as
  identical DER.
- An entry of `anchors` never ends a TSA path. An entry of `timestamp_anchors` never ends a
  passport path.

`issuer_trust` checks a key at the earliest `genTime` of a good token over the signature of that
key. Without one, it uses the evaluation time.

- Each detail states the time used. The pass text for the evaluation time does not change.
- The verifier does not use `signed_at` of the attestation, because the signer states it.
- With a good token, a report still verifies after its key expires or after a later revocation.
- The verifier checks a TSA certificate at `genTime`. A token stays good after that certificate
  expires.
- The engine cannot timestamp an archived report again.

#### Signer roles

The dimension `signers` checks each signature in the order of the envelope. The first problem of
a signature gives its reason code.

1. The key is not in the trust bundle: `SIGNER.KEY.UNKNOWN`. The signature is listed and not
   checked.
2. The signature does not verify, does not bind the decision body, or is not a compact JWS:
   `SIGNER.SIGNATURE.INVALID`.
3. The trust bundle does not grant the purpose of the declared role to the key:
   `SIGNER.ROLE.NOT_GRANTED`.
4. The key is outside its validity or revoked at its key validity time: `SIGNER.KEY.NOT_TRUSTED`.
5. The attestation names an issuer other than the issuer of the key: `SIGNER.ISSUER.MISMATCH`.

A signature with none of these problems gives `SIGNER.ROLE.OK`.

Then the verifier compares `status`, `valid_until`, and `supersedes` of all passing issuer
signatures. If they differ, the outcome is `fail` with `SIGNER.LIFECYCLE.CONFLICT`.

- A problem 2 or 3 gives `fail`.
- A problem 4 or 5 of a `reviewer` signature gives `fail`.
- A problem 4 or 5 of an `issuer` signature gives `fail` only when no passing issuer signature
  exists. `issuer_trust` owns that decision.
- Otherwise the outcome is `pass` if at least one signature is `SIGNER.ROLE.OK`.
- The outcome is `missing` for an envelope without signatures, and `not_checked` if no signature
  names a key of the trust bundle.
- The key validity time follows `issuer_trust`. It is the earliest good `genTime` over the
  signature, or else the evaluation time.
- For an issuer signature, the detail also shows `valid_until`, `supersedes`, and the status entry.
- The detail shows each value of the report in an escaped form.
- A bad reviewer signature does not change `signature` or `issuer_trust`. It makes `complete`
  false.

#### Report status lists

The issuer of reports can withdraw a report after signing it. It keeps a status list and signs
it. The operator gives the list file to the verifier with `--status-list`. The verifier does no
network I/O and never fetches a list. `run` and `replay` never read a list, and the IXIT cannot
name one.

A status list is a compact JWS with `ES256` and `typ: "dppce-status-list+jws"`. Its payload is
the RFC 8785 form of `dppce.statuslist/1`:

- `id`: the identifier of the list.
- `status_purpose`: `revocation` or `suspension`. A revocation is final. A later list can end a
  suspension.
- `issued_at`: the time at which the issuer made the list.
- `encoded_list`: the bitstring of the list.

`encoded_list` uses the bitstring encoding of the W3C Bitstring Status List v1.0, a
Recommendation of 15 May 2025:

- The bitstring is compressed with GZIP.
- The result is base64url without padding, after the multibase prefix `u`.
- Index 0 is the most significant bit of the first byte.
- Bit 1 means revoked or suspended, by the purpose of the list. Bit 0 means neither.
- `dppce` writes at least 131072 bits. The verifier reads a shorter list.

A status list is not a W3C verifiable credential. The engine implements the bitstring encoding
only.

The verifier checks in this order. The first failure gives the reason code.

1. `status_as_of` is set, and it is stale or later than the evaluation time: `fail`,
   `TRUST.SNAPSHOT.STALE`.
2. No passing issuer signature exists: `not_checked`, `STATUSLIST.REPORT.UNSIGNED`.
3. No passing issuer signature names a status entry: `STATUSLIST.REFERENCE.NONE`. The outcome is
   `missing` when `status` is mandatory, else `not_checked`.
4. The operator supplied no list: `STATUSLIST.FILE.MISSING`. The outcome is `missing`, because a
   stated entry makes `status` mandatory.
5. The file is larger than 2 MiB: `STATUSLIST.FILE.TOO_LARGE`. It is not ASCII, or after trimming
   of leading and trailing white space it is not a compact JWS: `STATUSLIST.FILE.MALFORMED`.
6. The key of the list is not in the trust bundle: `STATUSLIST.KEY.UNKNOWN`.
7. The key does not have the purpose `status`: `STATUSLIST.KEY.PURPOSE`.
8. The key is outside its validity or revoked at the evaluation time: `STATUSLIST.KEY.NOT_TRUSTED`.
9. The signature does not verify: `STATUSLIST.SIGNATURE.INVALID`.
10. The payload is not the canonical form of `dppce.statuslist/1`: `STATUSLIST.FILE.MALFORMED`.
11. The issuer of the list key differs from the issuer of the report key:
    `STATUSLIST.ISSUER.MISMATCH`.
12. `id` differs from `list_id` of the status entry: `STATUSLIST.ID.MISMATCH`.
13. `issued_at` is later than the evaluation time, or older than `status_max_age_days`:
    `STATUSLIST.TIME.STALE`.
14. The bitstring cannot be decoded: `STATUSLIST.FILE.MALFORMED`. It expands to more than 16 MiB:
    `STATUSLIST.FILE.TOO_LARGE`.
15. The index is not less than the number of bits: `STATUSLIST.INDEX.OUT_OF_RANGE`.
16. The bit is 1: `STATUSLIST.REPORT.REVOKED` or `STATUSLIST.REPORT.SUSPENDED`.

A bit of 0 gives `pass` with `STATUSLIST.REPORT.ACTIVE`. The detail names the list, its purpose,
`issued_at`, and the index.

- Steps 5 to 16 give `fail`.
- The status entry is the entry of the first passing issuer signature that names one. If the
  passing issuer signatures differ, `signers` fails with `SIGNER.LIFECYCLE.CONFLICT`.
- `status_as_of` alone never gives `pass`. Integrity checks still use it for passport
  certificates at run time.
- One status entry and one list per report. A report has either a revocation entry or a
  suspension entry, not both.

#### Validity and supersession

- `validity` compares the evaluation time with the earliest `valid_until` of the passing issuer
  signatures. An equal time passes.
- A later evaluation time gives `fail` with `VALIDITY.PERIOD.EXPIRED`. Otherwise the outcome is
  `pass` with `VALIDITY.PERIOD.OK`.
- Without `valid_until`, the outcome is `not_checked` with `VALIDITY.PERIOD.NOT_STATED`, and the
  dimension is not mandatory.
- If no passing issuer signature exists, the outcome is `not_checked` with
  `VALIDITY.REPORT.UNSIGNED`.
- `valid_until` and `issued_at` must name a time that exists. A month 13 makes the attestation or
  the list invalid. This is a model rule only. `attestation.schema.json` and
  `statuslist.schema.json` do not show it.
- `supersedes` names the decision digest of an earlier report. The `signers` detail and the HTML
  report show it.
- The verifier does not read the earlier report. To withdraw that report, the issuer sets its bit
  in a status list.
- The HTML report lists each signature with its key, role, `signed_at`, `valid_until`,
  `supersedes`, and status entry, as declared. Only the verification section shows whether a
  signature verifies.

#### Record openings and inclusion proofs

`dppce verify` and `python -m dppce.verifier` take `--opening FILE` and `--proof FILE`. They
check each file against the envelope. They do not check it against a root that the file states.

The verifier checks an opening in this order. The first failure gives the reason code.

1. The file is larger than 64 MiB: `OPENING.FILE.TOO_LARGE`.
2. The file is not strict JSON, is not a `dppce.opening/1` document, or is not its exact
   canonical form: `OPENING.FILE.MALFORMED`.
3. `HMAC-SHA256(salt, "dppce.record.v1" || 0x00 || JCS(record))` differs from the commitment of
   the proof leaf: `OPENING.COMMITMENT.MISMATCH`.
4. The embedded proof fails step 3 or step 4 of the proof checks below. The code is the code of
   that step.

A good opening gives `pass` with `OPENING.RECORD.OK`. The detail names the record identifier.

The verifier checks a proof in this order:

1. The file is larger than 1 MiB: `PROOF.FILE.TOO_LARGE`.
2. The file is not strict JSON, is not a `dppce.proof/1` document, or is not its exact canonical
   form: `PROOF.FILE.MALFORMED`.
3. `decision_digest`, `root`, or `size` differs from the report: `PROOF.REPORT.MISMATCH`. For the
   label `results`, the root and size are `results_root` and `results_count`. For `records`,
   they are `records_root` and the number of record commitments.
4. `merkle.verify_inclusion` fails with the root and the size of the report: `PROOF.PATH.INVALID`.

A good proof gives `pass` with `PROOF.LEAF.OK`. The detail names the key, and the verdict of a
result.

- Each failure gives `fail`.
- If the structure of the envelope fails, the supplied dimensions are `not_checked`.
- A proof of the label `results` is `not_checked` when the dimension `results_root` does not
  pass. The same applies to `records` and `records_root`.
- A stated root that differs from the body proves nothing about the body. The detail then is
  "Not checked because the root of the report does not match its body."
- A proof or an opening is also `not_checked` when the dimension `ordering` does not pass. The
  index of a leaf is its position in ascending key order. An unordered list gives the index no
  meaning.
- The root rule applies first. The detail of the ordering rule is "Not checked because the
  dimension ordering does not pass: an index is a position in key order."
- An opening has the label `records`. A file that fails step 1 or step 2 gives `fail` before
  these rules apply.
- The detail shows each value of a file in an escaped form.
- The verifier does no network I/O. It needs no recording and no data key.
- A proof or an opening shows that a leaf is in a tree of the report. A trusted signature over
  that report gives the leaf its trust.

#### Trust bundle version 2

`dppce.trust/2` replaces `revoked_serials` and `revoked_kids` of version 1. It adds
`timestamp_anchors`.

- Each entry of `revoked_certificates` names a serial number, its issuer, and `revoked_at`.
- The issuer is `issuer_name` or `issuer_key_id`, exactly one.
- A certificate is revoked only if its serial number and its issuer both match one entry.
- `issuer_name` is an RFC 4514 name. The verifier compares it with the issuer of the certificate
  attribute by attribute, without case folding.
- `issuer_key_id` is hexadecimal. The verifier compares it with the authority key identifier of
  the certificate. A certificate without that extension never matches a key identifier.
- Each entry of `revoked_keys` names a `kid` and `revoked_at`.
- `revoked_at` null means revoked at every time. A time means revoked at that time and later.
- Passport certificates, authorization keys, and manual keys are compared at the evaluation time.
- A TSA certificate is compared at `genTime`. A report key is compared at its key validity time.
- The same rules apply to the check `integrity.jws` (section 8).
- The purpose `review` signs reviewer attestations. A reviewer key is checked at its key validity
  time.
- The purpose `status` signs status lists. A status key is checked at the evaluation time.
- An invalid trust bundle gives exit status 2. The error message starts with the first problem of
  the bundle. For the role rule, that is the reason code `TRUST.KEY.ROLE_CONFLICT`.

`dppce.migrations` upgrades a `dppce.trust/1` bundle. Each revoked kid becomes an entry with
`revoked_at` null, so its effect does not change. The migration first checks the shape of the
version 1 fields. A wrong shape stops it with `TRUST.MIGRATION.MALFORMED`. A version 1 bundle that
lists revoked serial numbers cannot be upgraded, because the issuer of each serial is unknown.
The migration then stops with `TRUST.MIGRATION.UNSCOPED_SERIAL`. The operator writes each serial
with its issuer in a version 2 bundle. The command line and `python -m dppce.verifier` upgrade a
bundle when they load it.

`dppce trust-bundle add-key` writes a version 2 bundle (section 11.3).

## 12. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command completed. For `run` and `replay`: the overall outcome is `pass`. For `compare`: every step verdict is equal. |
| 1 | The system under test failed: the overall outcome is `fail`. For `compare`: a step verdict differs between the two envelopes. |
| 2 | Usage or input error: bad arguments, invalid file, lint findings, or an applicability rule that compares two different types. |
| 3 | Execution error: the overall outcome is `error`, or the engine failed. |
| 4 | Evidence verification failed or is incomplete. Replay digest mismatch. |
| 5 | The run completed and the overall outcome is `inconclusive`. |

Every command accepts `--json` and then writes one JSON document to standard output.
