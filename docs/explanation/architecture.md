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
| `dppce.evidence` | Canonical JSON, Merkle tree, commitments, encryption, signing, X.509 paths, and RFC 3161 timestamp tokens. | `models`, `infrastructure.interfaces` |
| `dppce.verifier` | Standalone verification of an envelope. | `models`, `evidence`, `verdicts`, `migrations` |
| `dppce.migrations` | Upgrade a stored document to the current schema version. | nothing in `dppce` |
| `dppce.infrastructure` | Transport, recorder, replay, clock, key providers, reference server. | `models`, `evidence` |
| `dppce.orchestrator` | Plan, run, replay. | all of the above except `verifier` |
| `dppce.report` | JSON and HTML rendering. | `models`, `evidence` |
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
   the manual result, the authorization, and the JWS header and payload are also parsed with
   `parse_strict`. Every body that the system under test returns is parsed with `parse_strict`.
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

Reason codes are stable and machine-readable. Format: `AREA.TOPIC.DETAIL` in upper case.
`AREA.OK` style codes mark a pass, for example `DATA.SCHEMA.OK`.

Initial registry:

| Check | Capability | Purpose |
| --- | --- | --- |
| `carrier.qr_decode` | `carrier.qr` | Decode a QR image artifact with zxing-cpp. Needs the `qr` extra. |
| `identifier.parse` | `identifier.parse` | Scheme-aware parse of the carrier payload. |
| `identifier.resolve` | `identifier.resolve` | Bounded resolution of the identifier to a passport. |
| `identifier.consistency` | `identifier.consistency` | Compares the carrier identifier with the `id` of the resolved passport. With a QR image sample, it also compares the carrier identifier with the declared sample identifier. With `compare_item`, it also compares the resolved passport with the document at the target of the `item` template. It does not read the ICS. |
| `api.contract` | `api.contract` | Response matches the pinned OpenAPI contract. |
| `data.jsonschema` | `data.jsonschema` | Document matches the pinned JSON Schema. |
| `data.context` | `data.context` | Every `@context` entry is in the pinned allowlist. |
| `data.rules` | `data.rules` | Rule pack: completeness, units, ranges, relationships, freshness. |
| `access.restricted_fields` | `access.policy` | A role gets each field that the declared policy gives it, and no field that the policy withholds from it. |
| `integrity.jws` | `integrity.jws` | Signature validity, issuer trust, and certificate validity, as separate findings. |
| `persistence.versions` | `persistence.versions` | Version history obeys the declared update rule. |
| `registry.consistency` | `registry.mock` | Registry record agrees with the passport. Passive lookup only. |
| `aas.validate` | `aas.validate` | Wrap aas-test-engines. Needs the `aas` extra. |
| `manual.review` | `manual.review` | Verify the signed result of a manual step. The engine does not perform the review. |

`identifier.resolve` takes two optional parameters. `accept` sets the `Accept` request header.
`accepted_media_types` lists the final media types that count as resolved. Without
`accepted_media_types` the check needs a final JSON object, as before. `IDENTIFIER.RESOLVED`
always means a final JSON object. A pass on another listed media type gives
`IDENTIFIER.RESOLVED.MEDIA_TYPE`. The observation summary always records the final media type.

`identifier.resolve` reports an answer with a status from 500 to 599 as `unreachable` (section 9).
Any other status except 200, 404, and 410 gives `IDENTIFIER.RESOLUTION.STATUS`.

`identifier.consistency` takes one optional parameter, `compare_item`. It is a boolean with the
default `false`. With `true`, the check also fetches the target of the `item` template. It
compares that document with the resolved passport as JSON values, as `integrity.jws` compares a
payload. The check takes the first row that applies:

1. The carrier identifier is not a URL: `blocked`, `IDENTIFIER.NOT_RESOLVABLE`.
2. The resolver answer is not a JSON object with status 200: `blocked`, `IDENTIFIER.NOT_RESOLVED`.
3. An identifier differs: `IDENTIFIER.MISMATCH`. The check does not fetch the item target.
4. With `compare_item`, the `item` template gives no URL: `blocked`, `IDENTIFIER.NO_TARGET`. The
   item target is not fetched.
5. The item target is not a JSON object with status 200: `blocked`,
   `IDENTIFIER.BINDING.NOT_COMPARABLE`.
6. The two documents are different JSON values: `IDENTIFIER.BINDING.MISMATCH`.

A transport error or a server error on either fetch gives `unreachable`. The check always uses
the `item` template, also with `item_target: resolved`, because it compares the two routes.

`identifier.parse` accepts one GS1 Digital Link form in this version. The URL starts with
`http://`, `https://`, `HTTP://`, or `HTTPS://`. The host part is not empty and holds only `A-Z`,
`a-z`, `0-9`, `.`, `-`, `:`, `[`, and `]`. So user information and an IPv6 zone identifier are
refused. The path is `/01/<GTIN>/21/<serial>`. The GTIN is 14 ASCII digits with a correct check
digit. The serial is 1 to 20 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`. The whole
URL holds only the characters that RFC 3986 permits in a URI, including `%`. Every other text
gives `IDENTIFIER.SYNTAX.INVALID`. This includes forms that GS1 permits, such as a GTIN without
a serial, a key qualifier, or a path prefix. The check reads the query and the fragment only for
their characters.

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
- A channel answers with a status from 500 to 599. This applies to every channel and every role.
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
  is not a URL. A URL that cannot be parsed is never raised: it is `policy_denied`.
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
- Methods other than `GET` and `HEAD` need a valid authorization with the matching scope.
- Limits: timeout, maximum body size (the body is truncated and flagged), maximum redirects,
  maximum request count, and minimum interval. Each limit that triggers is recorded.
- Secrets are removed from request headers before a record is created. If the tested system
  echoes a credential of the engine, its plain and percent-encoded forms are replaced with
  `<removed>` in header names and values, redirect targets, and the body, also where the body
  limit cut it. Other encodings, such as base64, are not recognized. A credential needs 12
  characters or more, so that its removal cannot change unrelated text of the evidence.
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

The shared helper `dppce.adapters.common.unusable` applies the rule. So every check that fetches
applies it in the same way.

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
- A secret reference is `env:DPPCE_SECRET_<NAME>` or `file:<name>` inside the directory that
  the operator gives with `--secrets`. No other environment variable or file can be named.
- The IXIT declares a secret reference for a role. The operator must repeat exactly that
  reference with `--role-secret ROLE=REFERENCE`. An IXIT alone can never select a secret, for
  example one that belongs to a different system that the same laboratory tests.
- A role credential is sent only to an origin that a validated authorization names. Origins
  are compared in one normal form. Role secrets for an origin that no authorization names are
  an input error, not a run without credentials.
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
  the `item` template. Otherwise `api.contract` gives `blocked` with `API.CONTRACT.PATH_MISMATCH`.
  Nothing is fetched.
- The IXIT can ask for the resolved item target (section 9.2). The system under test then selects
  that URL with a redirect. The transport checks each redirect hop. It checks the URL again when a
  check fetches it. A redirect therefore cannot add an origin that the operator did not confirm.
  The checks fetch the URL as `anonymous`, so no credential goes with it.

### 9.2 Resource templates and bound files

The IXIT gives the URL of each fetched passport resource. No adapter holds a URL path for a
passport resource.

- `IXIT.resources` maps a resource name to an endpoint name and a URL template. The names are
  `item`, `model`, `signed`, `versions`, and `registry_record`.
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
  URL, and a resolver status other than 200.
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
  These files are the contract, the policy, the schemas, and the rule packs.
  An unreadable file is recorded as `unavailable`.
- The decision body schema version is `dppce.decision/2`. In version 2, `bound_files` is
  required. A `dppce.decision/1` body has no `bound_files`. The verifier reads both versions
  as written and rejects any other pairing as a structure error. The JSON Schema lists the two
  versions. The model checks the pairing.
- A replay reads the bound files again. The input check of section 10.1 stops a replay with a
  changed bound file before it evaluates (exit code 2).
- A record of run inputs migrated from `dppce.runinputs/1` has no input hashes. For such a
  record, only the decision digest comparison applies.
- In version 2, a changed bound file gives a different decision digest. A version 1 body has no
  `bound_files`, so its digest comparison does not detect a changed bound file.

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
- A response header is recorded only if its name is in a fixed list of safe names. Each other
  value is replaced with `<removed>`. A URL in a recorded header is redacted: userinfo, the
  fragment, and credential-like query values are removed. A `Link` value keeps only its targets
  and registered relation names.

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
The payload is `JCS(attestation)`.
The verification key is a public P-256 JWK with `kty`, `crv`, `x`, and `y`. It can also have
`kid`, `use`, and `alg`. A key whose `use` is not `sig` is refused. A key whose `alg` is not
`ES256` is refused.
The protected header holds `alg`, `kid`, and
`typ: "dppce-attestation+jws"`. Keys in the repository are test keys and say so in their names.
Production keys come from a `Signer` implementation for a KMS or PKCS#11 device.

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

COSE, Bitstring Status List, qualified electronic seals, and UNTP DCC export are separate profiles
with their own capability states.

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
| `signature` | yes | At least one signature verifies with a key of the trust bundle and binds the decision body. The detail names the first such key. If no signature does, the outcome is the failure of the last signature that names a key of the trust bundle. |
| `issuer_trust` | yes | The signing key is in the trust bundle. It is valid and not revoked at the key validity time. That time is the earliest `genTime` of a good timestamp token over the signature of that key, or else the evaluation time. A key that only the report supplies is not trusted. The attestation names the issuer that the trust bundle states for the key. `manifest.issuer.identifier` equals that issuer and is not `unspecified`. An accreditation status other than `not accredited` has a reference. The first signature that meets all of these gives `pass`. Otherwise the outcome is the problem of the last signature that verifies and binds. Each detail names the key validity time. |
| `manual_results` | yes | Each completed step of the check `manual.review` has exactly one `artifact` observation with a JWS. Each record id of that observation has a commitment in the report. The JWS passes tests 2 to 14 of section 8.1 with the trust bundle of the verifier, for the purpose `manual`. The key must be valid at the evaluation time of the verifier. The signed test purpose and SUT identifier equal those of the report. The signed SUT version equals the version in the manifest, or is `null` if that version is `unknown`. The signed digest of the test purpose equals `test_purpose_digest` in the observation. The signed time is not after the evaluation time of the run. It is in the validity period of the key. The signed `kid`, role, time, and outcome equal the observation. The verdict is `pass` only for the outcome `pass`. A time that cannot be read gives `fail`. A report with no completed manual step passes. |
| `status` | per trust policy | Fresh status or revocation evidence is present and good. |
| `timestamp` | per trust policy | At least one token in `timestamp_evidence` passes the timestamp checks below, and it binds a signature that verifies and binds. |

`complete` is true only if every mandatory dimension passes. If the trust policy makes
`status` or `timestamp` mandatory and the evidence is missing or stale, `complete` is false.
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

`dppce.migrations` upgrades a `dppce.trust/1` bundle. Each revoked kid becomes an entry with
`revoked_at` null, so its effect does not change. The migration first checks the shape of the
version 1 fields. A wrong shape stops it with `TRUST.MIGRATION.MALFORMED`. A version 1 bundle that
lists revoked serial numbers cannot be upgraded, because the issuer of each serial is unknown.
The migration then stops with `TRUST.MIGRATION.UNSCOPED_SERIAL`. The operator writes each serial
with its issuer in a version 2 bundle. The command line and `python -m dppce.verifier` upgrade a
bundle when they load it.

## 12. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command completed. For `run` and `replay`: the overall outcome is `pass`. |
| 1 | The system under test failed: the overall outcome is `fail`. |
| 2 | Usage or input error: bad arguments, invalid file, lint findings, or an applicability rule that compares two different types. |
| 3 | Execution error: the overall outcome is `error`, or the engine failed. |
| 4 | Evidence verification failed or is incomplete. Replay digest mismatch. |
| 5 | The run completed and the overall outcome is `inconclusive`. |

Every command accepts `--json` and then writes one JSON document to standard output.
