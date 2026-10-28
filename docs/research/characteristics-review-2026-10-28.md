# Characteristics review of 2026-10-28

Audience: the owner, maintainers, and reviewers who plan the work after programs P2 and P3.
Purpose: list the characteristics that the engine still lacks, and the shipped characteristics that are defective. Map each one to the prior plans.
Prerequisites: read the [gap assessment of 2026-10-15](gap-assessment-2026-10-15.md), the [practical-use assessment of 2026-10-25](practical-use-assessment-2026-10-25.md), [readiness and limitations](../readiness.md), and the [architecture](../explanation/architecture.md).

AI agents made this review on 2026-10-28 at commit `981b60c`. It is not a human review and not an audit.
It states no technology readiness level and makes no statement of legal compliance.
The engine produces conformance test reports, not certificates.

This review is a reconciliation against prior plans. It is not a new plan. Program P3 is approved and has no implemented package. Its plan is an untracked review input at `.omc/research/characteristics-review-2026-10-28/p3-plan-2026-10-28.md`. The machine data of this review is at `.omc/research/characteristics-review-2026-10-28/final-ledger.json` (untracked).

## 1. Summary

The review labeled 137 characteristics: 128 ledger items (`C-01` to `C-128`) and 9 critic items (`K-01` to `K-09`).
Each item has one final label. The label comes from the verification verdict when one exists, else from the ledger.

| Final label | Count | Meaning |
| --- | --- | --- |
| `NEW` | 55 | No prior document or plan covers it. 52 are confirmed, 3 are reclassified to `NEW` (section 8). |
| `shipped_defective` | 17 | It exists but gives a wrong outcome, or code and contract disagree. All 17 are confirmed. |
| `deferred` | 29 | A deferred row or a gap identifier covers it. The ledger flags 12 as orphans with no package and no deferred row. Three more T3 items cite only a gap identifier (section 6). |
| `person_only` | 10 | Only a person or an external party can close it. |
| `planned` | 5 | A P2 or P3 package, or a roadmap row, covers it. |
| `in_flight` | 2 | Built on the wave-11 branch, not on `main`. |
| `shipped` | 18 | Works as the contract says. These items show the coverage of a lens. |
| `out_of_scope` | 1 | Outside the engine scope (section 8). |

### 1.1 Gaps by dimension

| Dimension | Defects | To add | Planned or in flight | Deferred or person-only | Main gap |
| --- | --- | --- | --- | --- | --- |
| Regulatory coverage | 0 | 3 | 1 | 4 | Applicability rests on supplier ICS facts that no check compares with the passport. |
| Identifiers and carriers | 3 | 5 | 2 | 5 | Linkset anchor text match, compressed carriers, non-GTIN keys. |
| Data semantics | 0 | 8 | 1 | 2 | Rule packs are weak: units, dates, decimals, item-to-model consistency. |
| Access and authentication | 2 | 3 | 1 | 6 | OAuth token expiry, one client certificate per run. |
| Security, trust, and evidence | 0 | 9 | 1 | 4 | Trust entries have no scope; revocation evidence is typed, not imported. |
| Operations and service | 3 | 4 | 0 | 8 | Retention and purge faults; no platform matrix, logging, or resume. |
| Reporting and usability | 1 | 3 | 0 | 3 | `--json` error contract; no CI recipe for `dppce run`. |
| Extension and interoperability | 0 | 4 | 0 | 1 | No profile overlay, no extension point, no public API policy. |
| Assurance and validation | 2 | 6 | 1 | 4 | No evidence fault for timestamps; validation record not bound to a release. |
| Contract drift | 5 | 2 | 0 | 0 | Section 2 import table, section 9 defaults, step verdict model. |
| Honest states | 1 | 3 | 0 | 0 | Capability state not in the report; coverage counts unanswered steps. |
| Critic items | 0 | 5 | 0 | 2 | Evaluation time versus acquisition time; key revocation at send time. |
| **Total** | **17** | **55** | **7** | **39** | |

### 1.2 The most important characteristics to add or fix

These are the 10 confirmed `NEW` and `shipped_defective` items with final severity `major`.
Five of them rest on a code read only. The column "Evidence" says which.

| Id | Label | Characteristic | Evidence |
| --- | --- | --- | --- |
| C-02 | `NEW` | Compare the ICS facts that decide applicability with the values that the passport publishes. | Probe: one earlier placing date turns the eu-battery/draft pack to 32 `false`, 4 `unknown`. |
| C-10 | `shipped_defective` | `resolver.linkset` gives a false fail when the resolver returns a case-normalized anchor. | Loopback probe |
| C-40 | `shipped_defective` | `access.oauth2` ignores `expires_in`. A token that expires mid-run gives a fail that blames the system under test. | Loopback probe |
| C-124 | `NEW` | Record the capability state of each step in the signed report. A reviewed claim must not rest on an experimental check without notice. | Code read only |
| C-55 | `NEW` | Scope trust anchors and authorization keys to a system under test or an issuer. | Code read only |
| C-57 | `NEW` | Import CA-signed CRL and OCSP evidence offline, and record its digest. | Code read only |
| C-58 | `NEW` | Accept an approval in an imported pack only with a signed review record. | Code read only |
| C-30 | `NEW` | Check that an item passport and the model passport that it names agree. | Code read only |
| C-95 | `NEW` | Import a profile from an external directory without a copy of the whole data root. | CLI probe |
| C-103 | `NEW` | Seed evidence faults for the verifier dimensions timestamp, validity, and structure. | Probe of the fault catalogue |

Three further items have a wide effect at low cost:

- C-122: execution coverage counts steps that got no answer.
- K-01: key revocation is not checked at send time.
- C-123: a deep member turns a schema fail into `blocked`.

The largest orphan is C-01 (Annex XIII data points are manual only). Its ledger severity is `blocker`, and no P2 or P3 package covers it.

## 2. Method

**Lenses.** Ten finder agents each reviewed one lens of `main` at `981b60c`:

- contract drift
- honest states
- regulatory coverage
- identifiers, carriers, and registry
- data semantics
- security, trust, and evidence
- access, authentication, and dataspace
- operations, scale, and persistence
- usability, reporting, and extension
- assurance and validation

A merge step made 128 ledger items from 138 raw findings. A critic agent added 9 items and a note on blind spots.

**Verification.** Verifier agents gave a verdict to each item whose ledger label was `NEW` or `shipped_defective`. In total 84 items have a verdict: 69 confirmed, 12 reclassified, 2 refuted, 1 out of scope. The other 53 items carry a prior label and were not in the verification scope. No verification batch failed.

**Models.** The workflow script sets the model of each agent. Opus at high effort ran six finders: contract drift, honest states, regulatory coverage, identifiers, data semantics, and security. Sonnet at medium effort ran the other four finders. Opus at high effort ran the merge, the verifiers, the critic, and the synthesis.

**What ran.** The finders and verifiers ran these kinds of commands. This page quotes their results and names the agent role that ran them:

- `uv run dppce capabilities`, `uv run dppce plan`, `uv run dppce report`, `uv run dppce catalogue lint`, and `--help` reads.
- Small in-process or loopback probes, `uv run python -I probes/<name>.py`, in the untracked review directory.
- One `uv run pytest` of a probe file, and one `uv run pytest` of three test files (assurance finder).
- Web reads of public pages by the regulatory, identifier, data, security, and access finders. Some facts come from search snippets only (section 9).

The synthesis agent that wrote this page ran only `probes/synth_counts.py` and a JSON parse. Every count on this page comes from that script or from the ledger data.

**Check after synthesis.** The orchestrating session did these checks on 2026-10-28, after the page was written:

- It recomputed the label counts, the verdict counts, and the 28 severity reductions from the arrays in `final-ledger.json`. They agree with this page.
- It ran the probes for C-10, C-11, C-40, C-45, and C-123 again. Each gave the outcome that section 3 states.
- It ran `dppce plan --json` with missing input files (C-88): exit 2, zero bytes on standard output.
- It read the newest committed method-validation record (C-102): `fault_catalogue_version` is 0.5.0, and the catalogue is 0.14.0.

**What did not run.** These checks are "not run":

- the full test suite, `uv run just check`, and `uv run just validate`
- `python -m validation.run` and `pytest -m validation`
- the mutation run (`mutmut`)
- a test of a real system under test
- Docker and the Compose reference system
- any run on Windows or on Python 3.14

## 3. Defects in shipped characteristics

All 17 items have the verdict "confirmed" and the final label `shipped_defective`. Severity is the verifier's final severity.

| Id | Characteristic | Evidence | Probe | Severity | Closable by |
| --- | --- | --- | --- | --- | --- |
| C-10 | `resolver.linkset` compares the anchor as exact text. A case-normalized anchor gives a false fail. A carrier with a query attribute also fails. | `adapters/resolver.py:150`; `architecture.md:934` states "exact text", so the fix is a contract edit. | `test_idc_anchor_probe.py`: upper-case scheme and query attribute fail `RESOLVER.LINKSET.ANCHOR`; control passes. | major | mixed |
| C-40 | OAuth `expires_in` is not read and no token is renewed. An expired token gives `ACCESS.ENTITLEMENT.REFUSED`, a fail. | `infrastructure/transport.py:511-575`; architecture 9.3 documents the limit; the capability row lists renewal as a promotion criterion. | `access_probe.py` P4: 401 `invalid_token` gives fail. | major | agent |
| C-11 | A compressed GS1 Digital Link carrier gives a fail in `resolver.linkset` but `unsupported` in every identifier check. An engine limit is reported as a defect of the system under test. | `resolver.py:150`; `identifier.py:208-214` | Same probe file: compressed carrier fails `RESOLVER.LINKSET.ANCHOR`. | minor | mixed |
| C-17 | `identifier.equivalence` claims the "GS1 canonical form" but compares scheme, authority, and key. Code and contract agree; the claim may be wrong. | `adapters/gs1.py:490-503`; `architecture.md:636-654`; `docs/reference/capabilities.md:24` | `idc_canonical.py`: brand host and `id.gs1.org` differ. GS1 URI Syntax 1.7.0 was not read. | minor | owner |
| C-45 | An access-policy path with a list index is accepted but never matches. A leak by that path is missed, and an entitled list path always fails. | `adapters/common.py:376-383`; `access.py:57-77` | `v4_access_realistic.py` R6 to R8; `access_probe.py` P6. | minor | agent |
| C-71 | An interrupted recording write leaves encrypted records that purge never lists or removes. | `evidence/recording.py:161-189`, `:332` | `ops_partial_recording.py`: `r0001.enc` stays after `purge`. | minor | agent |
| C-72 | `delete_after` counts from the `--at` evaluation time. The contract says acquisition date plus retention. | `cli.py:826`; `architecture.md:1725` | Code read only | minor | agent |
| C-79 | Purge turns an open failure into "nothing to purge" and exits 0. This is certain on Windows and possible on POSIX. | `evidence/recording.py:364-366`; `cli.py:1484-1498` | `v7_purge_open_failure.py` (Windows simulated by a patched `os.open`). | minor | agent |
| C-88 | With `--json`, an input or execution error writes nothing to standard output. Section 12 promises one JSON document. | `architecture.md:2554`; `cli.py:1876-1887` | `dppce plan --json` with missing files: exit 2, empty standard output. | minor | agent |
| C-100 | The configured mutation run does not complete on `main`. Wall-clock tests fail under the mutation runner. | `.github/workflows/mutation.yml`; `pyproject.toml:158-161` | Branch record read only; mutation not run. | minor | agent |
| C-107 | The how-to and readiness say all expected outcomes were written before the checks. The fault catalogue header lists exceptions. | `docs/how-to/run-the-method-validation.md:11-12`; `docs/readiness.md:125` | Code read only | minor | agent |
| C-113 | The GS1 syntax dictionary ignores `--data-root` and is not in `bound_files`. | `adapters/gs1.py:134-139`; `orchestrator/run.py:260-277` | Code read only | minor | agent |
| C-114 | Transport defaults are not rate-limited and the User-Agent has no contact. Section 9 says they are and it has. | `architecture.md:1399-1400`; `models/declarations.py:166-169` | Code read only | minor | agent |
| C-115 | `TestResult` accepts `not_applicable` with every non-error execution status. Table 7.1 says the models refuse such pairs. No false pass results. | `models/testing.py:226-235`; `verifier/verify.py:93-112` | `step_verdict_model.py`: six statuses accepted. | minor | agent |
| C-116 | The section 2 import table is out of date, conflicts with rule 4, and has no general test. | `catalogue/loader.py:20`; `report/html.py:14`, `:27` | `import_rules.py`: 13 module-to-target pairs outside the table. | minor | mixed |
| C-117 | Section 2 names a `dppce.profiles` module that does not exist. | `architecture.md:31` | Directory listing | minor | mixed |
| C-123 | A `RecursionError` in schema validation discards the errors already found. A schema fail becomes `blocked` `TOO_DEEP`. | `adapters/common.py:742-759`; `data.py:716-721`; `api.py:458-463` | `hs_p4_schema_depth.py`: error kept at depth 150, lost at depth 250. | minor | agent |

## 4. Characteristics still to add

This section lists the 52 items with the verdict "confirmed" and the final label `NEW`.
Three more items have the final label `NEW` after reclassification: C-122, C-125, and K-01. Section 8 lists them.
Where the verifier narrowed an item, the text below states the narrowed scope.

### 4.1 Regulatory coverage

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-02 | An optional check compares ICS facts that decide applicability with the values in the passport. A mismatch gives a stated limitation or `inconclusive`. | The supplier writes the ICS. One self-declared date turns most draft EU entries to `false`. | mixed | T1 | major | M |
| C-03 | Draft requirement entries and a profile for Regulation (EU) 2025/2509 (toys) and (EU) 2026/405 (detergents), later (EU) 2024/3110. | The acts are adopted and require a passport. Their application dates are 2029 and 2030. | mixed | T2 | minor | L |
| C-05 | Record cookie names and third-party references on the passport view for a manual tracking judgment. | The "no registration" part works through `access.policy`. Cookie names need a change to the safe response headers. | mixed | T2 | minor | M |

### 4.2 Identifiers and carriers

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-12 | Decompress compressed GS1 Digital Link URIs, checked against pinned open vectors. | A valid compressed carrier gets `unsupported` everywhere. GS1 limits compression to closed systems. | agent | T2 | minor | M |
| C-18 | A closed list of ICS `carriers` values, or a lint that reports an unknown value. | `['QR']` makes the mandatory carrier entry `not_applicable`, and no carrier check runs. | mixed | T1 | minor | S |
| C-19 | Classify primary keys other than GTIN, and build invalid check-digit variants for every key. | Other keys get `unsupported` or `blocked`, so a resolver's refusal of a wrong key is never judged. | mixed | T2 | minor | S |
| C-20 | Record the symbology identifier, error-correction level, and content type of each QR symbol. | A reviewer cannot tell GS1 mode from a plain QR code. The decoder already exposes the values. | agent | T1 | minor | S |
| C-21 | Check the GLN check digit on operator and facility fields, and check syntax on the registry record side. | Pattern rules cover EORI and LEI structure on the passport, but not these two cases. | mixed | T2 | minor | M |

### 4.3 Data semantics

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-30 | Check that the model reference of an item resolves and that inherited fields agree. | An item can name a model that contradicts it, and every check passes. The batch document kind is gap D3-02. | mixed | cross | major | M |
| C-26 | `data.rules` reports how many rules judged a present value. Lint warns when a rule field is not a path of the pinned schema. | A misspelled field makes a rule hold by absence, and `DATA.RULES.OK` overstates the evidence. | agent | T1 | minor | S |
| C-27 | Numeric rule kinds address members by JSON Pointer and accept exact-decimal bounds. | A key that holds a dot is never judged. A bound such as 99.5 is refused. | mixed | T1 | minor | S |
| C-28 | Unit normalization or conversion, and a lint for relationship rules over fields that allow more than one unit. | Mixed units give a false pass or false fail. The shipped rule pack pins one unit. | mixed | T1 | minor | M |
| C-29 | Rule kinds for date order and for sums or counts over arrays. | A relationship rule on two dates always fails by contract. JSON Schema cannot compare two fields. | agent | cross | minor | M |
| C-31 | Validate each history version of a passport under the schema of its own data-model version. | `persistence.versions` compares digests only. Dispatch by declaration already works in one schema. | mixed | cross | minor | M |
| C-32 | An `Accept-Language` probe that checks the served language, `Content-Language`, and `Vary`. | Section 8 says "a later package" adds it. No P2 or P3 package names it. | mixed | T2 | minor | M |
| C-37 | Range semantics for a value with a stated uncertainty under a declared decision rule. | A value of 99 ± 5 passes a maximum of 100. A laboratory cannot state a decision rule. | mixed | T2 | minor | S |

### 4.4 Access and authentication

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-41 | The OAuth token request sends a declared scope, audience, or resource, and supports more client authentication methods. | Such systems give `authorization_denied`. A bearer token from outside the engine is the workaround. | agent | T2 | minor | M |
| C-46 | The manifest records that a client certificate was presented, its fingerprint and origins, and the trust-store source. | A report for a mutual-TLS system cannot show which credential reached it. A how-to also misstates what is recorded. | mixed | T1 | minor | S |
| C-47 | Each role names its own client certificate. The anonymous role presents none. | Today the anonymous role also presents the run's client certificate. | agent | T2 | minor | M |

### 4.5 Security, trust, and evidence

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-55 | Trust anchors and authorization keys carry a scope: systems, origins, or subject names. The checks enforce it. | Any authorization key can sign for any system. Any leaf under any anchor passes issuer trust. | mixed | T1 | major | M |
| C-57 | A trust-bundle command imports and verifies a DER CRL or OCSP response offline. The manifest records each digest. | Revocation entries are typed in by the operator, so status evidence cannot be audited. | agent | T1 | major | M |
| C-58 | Reviewed mode accepts an approved entry only with a signed review record that binds pack, entry, and digests. | A third-party pack can type any reviewer. Latent until a reviewer approves an entry. | mixed | T1 | major | M |
| C-56 | The trust bundle states which CAs the revocation snapshot covers. An uncovered path under `require_status` gives `blocked`. | A leaf of an uncovered CA is judged "not revoked". Build with C-57. | agent | T1 | minor | M |
| C-62 | A work bound on schema `pattern` evaluation, a lint for backtracking patterns, and a time limit for each check. | A careless imported schema and a crafted body can hang the run. | agent | T1 | minor | S |
| C-63 | Caps on envelope size and on the number of signatures and results in the standalone verifier. | Recipients verify files that they did not make. Nothing is refused today. | agent | T1 | minor | S |
| C-64 | A tunable high-cost key derivation function for signing key files. | Key files use 2048 iterations. The proposed form changes the key-file contract. | agent | T1 | minor | S |
| C-65 | A renewal timestamp over existing timestamp evidence, judged by the verifier. | Laboratories keep reports for years. The threat model lists this as open. | agent | T1 | minor | M |
| C-66 | Verify RSA-signed passports under a closed algorithm allowlist. | Today the step is `blocked`. Value is low until a family profile names RSA. | agent | T2 | minor | M |

### 4.6 Operations and service

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-73 | CI on macOS, Windows, and Linux, and on Python 3.14. A statement of supported platforms. | Replay, open, and purge use POSIX-only calls. Python 3.14 is allowed but not tested. | agent | cross | minor | M |
| C-74 | Write records as they are acquired, end in a recorded state on a signal, and bound run time and memory. | An interrupt loses the record of every request already sent. | agent | T2 | minor | L |
| C-80 | A redacted log file and progress output for long runs. | Operators cannot see why a run is slow or stuck. | agent | T2 | minor | M |
| C-81 | A documented air-gapped install from a wheelhouse. | The saved container image works offline; the wheel install needs an index. | agent | T1 | minor | S |

### 4.7 Reporting and usability

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-86 | An end-to-end CI example for `dppce run` with keys, trust, evaluation time, authorization, and an exit-code policy. | No how-to tells a CI user how to treat exit code 5 (`inconclusive`). | agent | T1 | minor | M |
| C-89 | Input errors name the option and the real cause. | Some errors print a raw error number or a wrong cause. | agent | T1 | minor | S |
| C-90 | A CSV export of steps, with formula prefixes neutralized. | Issuers and laboratories review in spreadsheets. | agent | T1 | minor | S |

### 4.8 Extension and interoperability

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-95 | Import a profile and its bound files from an external directory, like `--import-pack`. | Operators copy the whole data root, so a stale catalogue copy can run silently. | agent | T2 | major | M |
| C-94 | An extension point for a third-party check with its own capability entry. | The allowlisted registry is by design. A change needs an owner decision. | owner | T2 | minor | L |
| C-96 | A declared Python import surface, CLI flag set, and deprecation rule. | Reason codes and exit codes are declared. The Python and CLI surfaces are not. | mixed | T2 | minor | M |
| C-98 | A command that drafts lint-clean test packs, profiles, and checks. | Authors copy files by hand. | agent | T2 | minor | S |

### 4.9 Assurance and validation

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-103 | At least one evidence fault for each verifier dimension and supported evidence capability. | `evidence.rfc3161` is supported but has no method-validation fault. | agent | T1 | major | S |
| C-102 | Each release carries the validation record of its own catalogue version. A test detects a stale record. | The newest committed record is for fault catalogue 0.5.0. The catalogue is 0.14.0. | agent | T1 | minor | S |
| C-104 | A statement of fresh-run reproducibility across hosts and Python versions, with the lockfile digest. | Readiness calls replay "repeatability". Probes found no sensitivity. | agent | T1 | minor | M |
| C-105 | A map of each check to its external oracle, or the reason none exists, with negative vectors. | Some oracles are one-sided or skip in CI. | mixed | T1 | minor | M |
| C-108 | The dated record stores requirement and overall outcomes. Evidence faults run on every family envelope with a reason check. | Evidence faults tamper only the first control envelope. | agent | T1 | minor | S |
| C-110 | A packaged proficiency item with hidden faults, an answer key, and scoring. | Laboratories cannot show competence. Only two-run compare exists. | mixed | T3 | minor | M |

### 4.10 Contract drift and honest states

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| C-124 | Each step result or the manifest records the capability state. Reviewed claims need supported checks, or the report marks the exception. | No reader can tell that a reviewed pass rests on code no person promoted. Latent today. | mixed | T1 | major | M |
| C-118 | Each experimental parameter inside a supported capability has a machine-readable state and promotion criteria. | The manifest model has no field for it. Build with C-124. | agent | T1 | minor | M |
| C-119 | `persistence.versions` states its acceptance criteria. | It is the only experimental capability with empty criteria. | agent | T1 | minor | S |

### 4.11 Critic items

| Id | Characteristic | Why | Closable by | Tier | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| K-02 | The manifest states the gap between `--at` and the acquisition window, and the host clock source. | Probe: one observation set gives pass or fail with only `--at` changed. No limitation names the gap. | mixed | T1 | minor | S |
| K-03 | A command evaluates a kept recording under new stated inputs and writes a new report. | After an approval or a pack change, the laboratory must contact the system again. | mixed | T2 | minor | M |
| K-04 | Each record holds the peer address, TLS version, and the digest of the server certificate chain. | A reader cannot show which server served an observation. This changes a protected record model. | mixed | T1 | minor | M |
| K-06 | A tool-neutral set of expected requirement verdicts for other implementers. | Vectors may carry requirement identifiers only and must mark draft status. | mixed | T3 | minor | M |

## 5. Already planned or in flight

| Id | Characteristic | Covered by | Note |
| --- | --- | --- | --- |
| C-06 | `legal_as_of` in the manifest and report | P3-08 (D6-12) | Add `legal_as_of` to the P3-08 scope. |
| C-13 | Remaining GS1 Resolver behaviors | D4-07, gap roadmap A2-5 | Residual after P2-05. No P2 or P3 package. The CORS leg is now agent-closable. |
| C-14 | Registry method guard and loopback registry | P3-12 | |
| C-42 | Scope-to-method map in transport | P3-01 (V1) | |
| C-59 | Data Integrity proofs, trusted lists, external signing | P3-05, P3-06, P3-07, P3-14, P3-16 | |
| C-34 | `data.jsonld` and `data.shacl` | P2-27, wave-11 branch | Branch code read, not run. |
| C-112 | Mutation survivors classified | P2-19, wave-11 branch | Does not fix C-100. |

Related scope notes for planned packages:

- P3-04 and P3-09 add digests to approvals and packs. They do not add the signature check of C-58.
- P2-29 and P3-17 refresh the validation record once. They do not add the guard of C-102.

## 6. Deferred and person-only items

"Gap id only" means that the gap assessment names the item, but no P2 or P3 package and no deferred row covers it.
The 12 orphan rows are the most actionable part of this section. Section 7 takes the agent-buildable ones forward.

| Id | Item | Final label | Prior reference | Covering row |
| --- | --- | --- | --- | --- |
| C-01 | Annex XIII data points: schema path, automated step, completeness trace | `deferred` | D3-04 | Gap id only (orphan); ledger severity `blocker` |
| C-33 | Open battery content data models | `deferred` | D3-09, D3-04 | Gap id only (orphan) |
| C-43 | Probe that a role without change rights is refused a write | `deferred` | D5-10(3) | Gap id only (orphan) |
| C-51 | Verifiable presentation as an access credential | `deferred` | D5-05(6) | Gap id only (orphan) |
| C-53 | More leak channels | `deferred` | D5-04 | Gap id only (orphan) |
| C-67 | `image_digest` in the manifest | `deferred` | D7-11 | Gap id only (orphan) |
| C-91 | PDF/A or signed HTML report | `deferred` | D6-11 | Gap id only (orphan) |
| C-92 | Report in other EU languages | `deferred` | D6-13 | Gap id only (orphan) |
| C-97 | Pack engine-version range and signing | `deferred` | D7-12 | Gap id only (orphan); P3-09 partial |
| C-99 | Fault for every executed test purpose and for `manual.review` | `deferred` | D8-03 | Gap id only (orphan) |
| C-101 | Adapters inside the mutation and coverage gates | `deferred` | D8-07, O1-9 | Gap id only (orphan) |
| C-111 | Randomized fuzzing of adapter parsers | `deferred` | D8-07 | Gap id only (orphan) |
| C-08 | Profile for portable and SLI batteries | `deferred` | Scope §6 | Out-of-scope list |
| C-15 | Official EU registry, customs, portal | `deferred` | D5-08, OQ-013 | P2 §7; P3 §8 |
| C-22 | NFC, RFID, EPC carriers | `deferred` | D4-10 | P2 §7; P3 §8; P3-15 |
| C-23 | Data Matrix and several carriers | `deferred` | D4-12 | P2 §7 `carrier.symbols` |
| C-49 | Dataspace negotiation, DCP, ODRL | `deferred` | D3-08 | P2 §7 dataspace catalog row |
| C-52 | Dataspace catalog check | `deferred` | — | P2 §7 |
| C-60 | KMS and PKCS#11 key providers | `deferred` | D6-07 | P2 §7 T3 row |
| C-68 | Transparency log | `deferred` | D6-10 | P2 §7 T3 row |
| C-75 | Campaigns and sampling | `deferred` | D7-04, D4-12 | P2 §7 T3 row |
| C-76 | Scheduled acquisition and persistence | `deferred` | D7-05 | P2 §7 T3 row |
| C-77 | Shared budgets across runs | `deferred` | D7-02 | Gap id only (T3) |
| C-78 | Service mode | `deferred` | D7-01 | P2 §7 T3 row |
| C-83 | Migration of all stored documents | `deferred` | D7-10 | Gap id only (T3) |
| C-84 | Purge record and artifact retention | `deferred` | D7-06, D7-07 | Gap id only (T3) |
| C-106 | Runs against independent family servers | `deferred` | D8-04 | P2 §7 |
| K-05 | Reachability of linked documents | `deferred` | — | P2 §7 digest-binding row |
| K-07 | Web view versus machine passport | `deferred` | — | P2 §7 `data.html_parity` |
| C-04 | Legal and source re-check; battery guidance edition | `person_only` | D2-12, D2-13, OQ-006, OQ-008, OQ-009 | P2 §8 |
| C-07 | Evaluation-time fact | `person_only` | OQ-014, D1-09 | Owner contract decision |
| C-16 | ISO/IEC 15459 identifiers | `person_only` | OQ-012, D4-08 | P2 §8 |
| C-24 | Print quality grade | `person_only` | D4-11 | Device and protected standards |
| C-35 | UNTP input profile | `person_only` | D3-10, OD-P3-27 | P3 §9 |
| C-44 | Access groups of Battery Regulation Art. 77 | `person_only` | OQ-006, D5-01 | Human reading of the Art. 77(9) act |
| C-61 | Independent security audit | `person_only` | D8-06 | P2 §8 |
| C-82 | PyPI publication | `person_only` | Gap assessment §4 | Owner governance row |
| C-85 | Compose reference system run | `person_only` | BL-003 | P2 §8 |
| C-87 | Screen-reader review of the report | `person_only` | D6-16 | P2 §8 |

C-04 needs a person before the next release. On 2026-10-28 the regulatory finder fetched two public listing pages: the Commission feedback record of initiative 16473 and the Commission DPP resources page. The listings show:

- A draft Art. 77(9) implementing act of 2026-10-19, with feedback open to 2026-11-16.
- Battery data-point guidance V3.2 of 2026-10-19. The catalogue records V2.0.

These facts come from the listing metadata only. No agent read the two documents (section 9). No engine verdict becomes false, but the catalogue source records are out of date.

## 7. Proposed order

These are candidate packages for a later program. They are proposals, not approved work.
Each row names the protected files that it is expected to touch. The list comes from the verdict text. A package that adds a check also touches the section 8 table of `docs/explanation/architecture.md`.

### 7.1 Agent-buildable

An agent can build these packages after the owner approves each named protected edit, diff first. The items marked `mixed` in section 4 are the ones that need such an edit.

| Package | Items | Protected files expected |
| --- | --- | --- |
| Q-01 Honest outcomes and retention | C-123, C-11 (parse gate before the anchor rule), C-71, C-72, C-79, C-88, C-89, C-113, C-45 | `architecture.md` only if C-113 adds the dictionary to the bound-file list; `src/dppce/models/` only if the C-45 path rule is in a model |
| Q-02 Contract text alignment | C-114, C-115, C-116, C-117, C-119, C-107, and the how-to drift of C-46 | `architecture.md` (sections 2 and 9); `src/dppce/models/` (`testing.py`); `pyproject.toml` if a lint enforces the import rules |
| Q-03 Validation evidence | C-103, C-108, C-102, C-104, C-105 (agent part), C-99, C-111, C-100 | `validation/fault-catalogue.yaml`; `pyproject.toml` (C-100) |
| Q-04 Revocation and verifier bounds | C-57, C-56, C-63, C-62, C-65 | `src/dppce/models/` (`trust.py`, `results.py`); `architecture.md` (section 11); `validation/fault-catalogue.yaml` |
| Q-05 Rule-pack expressiveness | C-26, C-27, C-28, C-29, C-37 | `architecture.md` (`data.rules` rows); `validation/fault-catalogue.yaml` |
| Q-06 Identifier and carrier additions | C-12, C-20, C-21, C-13 (D4-07 residual), C-19 (invalid-variant part) | `architecture.md` (section 8); `validation/fault-catalogue.yaml` |
| Q-07 Operator tooling | C-73, C-74, C-80, C-81, C-67, C-86, C-90, C-95, C-98 | `pyproject.toml` (C-73 classifiers); `architecture.md` for a profile import rule (C-95) |
| Q-08 Access and OAuth | C-40, C-41, C-47, C-46, C-43, C-51, C-53 | `architecture.md` (sections 8 and 9.3); `src/dppce/models/` (`declarations.py`, `results.py`); `validation/fault-catalogue.yaml` (C-43) |
| Q-08a Archival report | C-91, C-92 | `architecture.md` (section 11) if the report binds to the decision digest |

### 7.2 Owner decisions first, then agent work

| Package | Items | Decision | Protected files expected |
| --- | --- | --- | --- |
| Q-09 Run provenance | C-124, C-118, C-122, C-125, K-01, K-02, K-04, K-03 | Record capability state; redefine execution coverage; check key revocation at send time | `src/dppce/models/` (`testing.py`, `results.py`); `src/dppce/verdicts/aggregate.py` (claim level); `architecture.md` (sections 7.5, 8, 11, and line 2524) |
| Q-10 Identifier wording | C-10, C-17, C-19 (key-to-level mapping) | Anchor normalization; meaning of "canonical form" | `architecture.md` (anchor rule and `identifier.equivalence`) |
| Q-11 Trust scope and approvals | C-55, C-58, C-64, C-66 | Scoped trust entries; signed review records; key-file format; RSA allowlist | `src/dppce/models/` (`trust.py`, `catalogue.py`); `architecture.md` (sections 11 and 11.3) |
| Q-12 Applicability and data model | C-02, C-18, C-30, C-31, C-32, C-05 | ICS cross-check outcome; carrier vocabulary; batch kind (D3-02); tracking record | `src/dppce/models/` (`declarations.py`); `architecture.md` (section 8); `validation/fault-catalogue.yaml` |
| Q-13 Extension surface | C-94, C-96, C-97 | Extension point; public API and deprecation policy | `architecture.md` (section 2); `pyproject.toml` if entry points are used |
| Q-14 Governance | C-82, C-101 | PyPI publication; mutation scope | `pyproject.toml` |

### 7.3 External parties

| Package | Items | Who |
| --- | --- | --- |
| Q-15 Legal re-check and reviewer reading | C-04, C-03, C-44, C-16, C-01 interpretations, C-33 (a person confirms that no standard text is embedded) | An appointed reviewer (OQ-002); no agent reads protected standards |
| Q-16 Independent assurance | C-61, C-87, C-106, C-110, K-06 | Auditor, accessibility reviewer, laboratories |
| Q-17 Outside specifications | C-15, C-35, C-24 | Commission interface specification; UNTP license; barcode verifier device |

## 8. Reclassified, out-of-scope, and refuted findings

| Id | Original label | Verdict | Final label | Reason |
| --- | --- | --- | --- | --- |
| C-122 | `shipped_defective` | reclassified | `NEW` | Code matches the contract; section 8 defines `unreachable` as completed. Execution coverage still counts steps that got no answer or were never sent. Only the coverage figure overstates. |
| C-125 | `shipped_defective` | reclassified | `NEW` | The report shows the exclusions. The gap is presentation: mark a pack whose every requirement was excluded. |
| K-01 | `shipped_defective` | reclassified | `NEW` | Code matches `architecture.md:2524`, which compares keys at the evaluation time. Probe: a revoked owner key still allows a run with an earlier `--at`. |
| C-13 | `NEW` | reclassified | `planned` | D4-07 already asks for every resolver behavior. No package yet. |
| C-36 | `NEW` | reclassified | `shipped` | JSON Schema `minLength` and a `pattern` rule already count empty values as missing. |
| C-39 | `shipped_defective` | refuted | `shipped` | Architecture 8.2 documents the case. Residue (not counted): a non-fetch channel that answers 404 counts as clean, with no positive control. |
| C-48 | `NEW` | refuted | `shipped` | A user token can be supplied as a bearer secret. The remaining problem is C-40. |
| C-49 | `NEW` | reclassified | `deferred` | The P2 §7 dataspace row and the capability criteria cover it. |
| C-50 | `NEW` | out of scope | `out_of_scope` | No legal basis for an access-logging duty is located. A step needs a catalogue requirement. |
| C-82 | `NEW` | reclassified | `person_only` | The gap assessment records PyPI publication as an owner decision. |
| C-97 | `NEW` | reclassified | `deferred` | D7-12 names it. Add the engine-version range to D7-12. |
| C-99 | `shipped_defective` | reclassified | `deferred` | Facts reproduce, but no contract text ties "supported" to fault coverage. D8-03 holds it. |
| C-101 | `NEW` | reclassified | `deferred` | D8-07 and readiness declare the gate scope. |
| C-109 | `NEW` | reclassified | `shipped` | External oracles and independent test paths mitigate the common-mode risk (D8-01). |
| K-05 | `NEW` | reclassified | `deferred` | Part of the deferred digest-binding row. Plain links with no digest are a residue. |

## 9. Limits of this review

**Items with no verdict.** No verification batch failed. 53 items have no verdict because they carry a prior label and were not in the verification scope. Their labels come from the ledger only:
`C-01`, `C-04`, `C-06`, `C-07`, `C-08`, `C-09`, `C-14`, `C-15`, `C-16`, `C-22`, `C-23`, `C-24`, `C-25`, `C-33`, `C-34`, `C-35`, `C-38`, `C-42`, `C-43`, `C-44`, `C-51`, `C-52`, `C-53`, `C-54`, `C-59`, `C-60`, `C-61`, `C-67`, `C-68`, `C-69`, `C-70`, `C-75`, `C-76`, `C-77`, `C-78`, `C-83`, `C-84`, `C-85`, `C-87`, `C-91`, `C-92`, `C-93`, `C-106`, `C-111`, `C-112`, `C-120`, `C-121`, `C-126`, `C-127`, `C-128`, `K-07`, `K-08`, `K-09`.

**Code read only.** These claims rest on a code read, not a probe:
`C-21`, `C-30`, `C-41`, `C-46`, `C-47`, `C-55`, `C-57`, `C-58`, `C-65`, `C-66`, `C-72`, `C-73`, `C-74`, `C-80`, `C-81`, `C-94`, `C-96`, `C-113`, `C-114`, `C-124`.

**Partial runs.**

- C-79 simulates Windows by a patched `os.open`. No Windows run.
- C-34 and C-112: the wave-11 branch was read, not run.
- C-100: the mutation record on the branch was read; mutation was not run.
- C-105: the skipped oracle test was reported by the assurance finder; the verifier did not run it.

**Severity.** Verifiers lowered the severity of 28 items. Finder severities ran high. The final severity on this page is the verifier's where one exists.

**Sources not read.** GS1 Digital Link URI Syntax 1.7.0 and GS1 Resolver 1.2.1 were not read in verification. So C-10, C-11, and C-17 do not rest on the GS1 texts. Also not read:

- the battery data-point guidance V3.2 (header only)
- the Art. 77(9) draft act of 2026-10-19
- Dataspace Protocol 2025-1 and DCP (search snippets only)
- Battery Pass v1.2, the IDTA 02035 parts, and UNTP 0.7
- W3C Bitstring Status List and VC-JOSE-COSE

No agent read the text of an EN, ISO, IEC, DIN, or ETSI document.

**Modules with thin coverage.** No lens opened these modules, or only one item touched them:

- `adapters/pointer.py`, `aas_api.py`, `jose.py`, `did.py`, `status_list.py`
- `aas.py` beyond IDTA 02099-1, `negotiation.py`, `api.py`, `manual.py`
- `report/hints.py`, `compare.py`, `migrations.py`, `testdefs/`
- the evidence commitment and Merkle code, and the verifier co-signature path

**Readers represented thinly.** No browser lens represented the customs integrator or the end user. The critic considered three topics but did not raise them, because no agent probed them:

- WCAG conformance of the web view of the system under test
- isolation between tenants
- a fully offline operator run

**Not probeable here.** The agents could not probe these:

- reviewed mode, because no test pack permits it
- a real system under test (D8-02)
- Docker and Compose (BL-003)
- mutation, Windows, Python 3.14, and the full validation matrix

**Synthesis.** The synthesis agent condensed some verdict reasons in the machine data. Identifiers, labels, severities, probes, and references are unchanged.
