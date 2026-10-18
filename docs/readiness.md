# Readiness and limitations

Audience: a decision maker, an assessor, or a laboratory that considers using the engine.
Purpose: state what was shown, by which command, and what was not shown.
Prerequisites: read [what the engine tests and what it does not claim](explanation/scope-and-legal-mapping.md).

**Version 0.1.0rc1 is a release candidate. It is a GitHub pre-release with tag `v0.1.0rc1`. No package is published on PyPI.**
Section 2 records the run of the release workflow.
The source repository is public at https://github.com/hadijannat/dpp-conformance-engine since
2026-10-15; the owner made it public.
This page states no technology readiness level. It makes no statement of legal compliance,
product safety, data truth, or accreditation. The outputs of the engine are conformance test
reports. They are not certificates.

Each figure on this page comes from a command that ran in the development sessions of
2026-10-14, 2026-10-15, and 2026-10-18. Most ran on one macOS host. The table names the others:
GitHub Actions, and Docker Desktop of the owner. The commit is named next to each figure. A
development agent ran or read the commands. No human has repeated them.

The rows at commit `8b3bfff` describe the source on `main` after the T1 work of 2026-10-18. They
do not describe the released files of `v0.1.0rc1`. The version string is still `0.1.0rc1`.

A development agent wrote this page. No person has reviewed it.

## 1. Summary

| Dimension | What exists | What is missing |
| --- | --- | --- |
| Engineering | Typed core (mypy strict), fast test suite, core line and branch coverage gate, reproducible replays. Mutation testing of the verdict, evidence, verifier, transport, redaction, and authorization code. Continuous integration runs on GitHub (Linux, Python 3.12 and 3.13). A GitHub pre-release with signed build provenance. | No independent rebuild of the release commit by a second party. The scan, documentation, and DCO jobs of PR #2 are not on `main`. |
| Security | Threat model, policy-enforcing transport, encrypted recordings, signed reports, a standalone verifier. Key commands: `dppce keys generate`, `authorize`, `trust-bundle add-key`, `open`, and `prove`. Six agent review records (section 3); every finding is fixed or recorded. The brief permits two review rounds. No record states how the agent reviews of 2026-10-18 relate to that limit. | No independent human security audit. The engine verifies RFC 3161 timestamps but obtains none. Keys are files: no key management service and no PKCS#11 device. |
| Interoperability | JSON Schemas for every contract. Checks for carrier, identifier, API contract, data, access, integrity, persistence, registry, and AAS. | No test against a real DPP system or a second implementation. The optional AAS test engine was not run. |
| Legal mapping | A source catalogue with 128 records. 36 draft interpretations of Regulation (EU) 2023/1542. 8 placeholders for EN standards. | No interpretation is approved. No human reviewer has read the drafts. No EN, ISO, IEC, or DIN text is in the repository, by design. |
| Operations | Command line with stable exit codes, retention and purge of recordings, key commands, documented how-to guides. | No key management service or hardware security module. No multi-user deployment. |
| Accessibility | The HTML report uses semantic tables, headings, and text labels for each verdict. WCAG 2.2 AA is the target. An agent checked structure, contrast, the first focus, and reflow at 320 pixels (`docs/reference/accessibility.md`). An axe-core scan found 0 violations. | No manual review by a person and no screen reader review. |
| Validation in a relevant environment | Method validation against a synthetic reference system: seeded faults, valid controls, boundary cases, evidence faults, and replays. | No validation against a real system or real data. The reference system and the checks come from the same project. |

## 2. Results of the commands

| Command | Result | Commit |
| --- | --- | --- |
| `uv run just check` (format, lint, mypy strict, fast tests) | Format: 134 files already formatted. Lint: all checks passed. mypy: no issues in 61 source files. 2540 tests passed, 97 deselected (the slow validation tests). | `8b3bfff` |
| `uv run pytest -m validation` | 97 passed. | `8b3bfff` |
| `uv run just cov` | Core packages: 99 percent (3996 statements, 42 missed; 1154 branches, 29 partial). All modules: 97 percent (6628 statements, 196 missed; 2000 branches, 93 partial). Gate: 90 percent on the core packages. | `8b3bfff` |
| `uv run just mutation` (that is, `uv run mutmut run`; mutmut 3.8.0) | 5731 mutants in 20 mutated files of the verdict, evidence, verifier, transport, redaction, and authorization code. 4886 killed, 22 timed out, 823 survived, 0 with no tests. All 330 mutants of `dppce.verdicts` are killed. The survivors of this run are not classified. No record in `validation/records/` describes this run; its logs are on the development host only. `validation/records/mutation-2026-10-18.md` classifies the survivors of the earlier runs of 2026-10-18. | `8b3bfff` |
| `uv run python -m validation.run` | Seeded faults: 93 of 93 fault and profile combinations detected for the intended reason. Valid controls: 0 of 48 executed control steps did not pass, and 3 of 3 controls passed with every planned step completed. Boundary cases: 9 of 9 as expected. Evidence faults: 15 of 15 failed on the named dimension, 0 not run. Replays: 15 of 15 with the same decision digest. Record: `validation/records/method-validation-20261018T212047Z.json`. | `8b3bfff`, clean working tree |
| `uv run dppce catalogue lint` | 0 errors, 2 warnings, 36 informational findings (unresolved points of the drafts). Warning CAT006: no NFC check is registered (`TP-NFC-001`). Warning CAT018: in `TP-EU-INTEGRITY-JWS`, a step with an applicability that reads a fact can leave its path. | `8b3bfff` |
| Clean installation: `uv build --wheel`, then install the wheel alone in a new virtual environment | The wheel installs with 18 packages. `dppce --version` gives `0.1.0rc1`. The bundled catalogue lints with 0 errors. `python -m dppce.verifier --help` runs. The wheel holds 102 files and no test or fixture file. `dppce.testdefs` and the bundled test packs are run-time files. | `8b3bfff` |
| `uv run just sbom` | A CycloneDX 1.6 SBOM with 111 components in `dist/sbom.cdx.json` (not committed). It describes the development environment, not only the runtime dependencies of the wheel. It was not run again after commit `49b7dac` added `asn1crypto`. | `9066e64` |
| `reuse lint` (REUSE 3.3) | 346 of 346 files have copyright and license information. Compliant. With the method validation record added, 347 of 347. | `8b3bfff`, `a7ef327` |
| `uv run just docs` (strict build) | Built with no warning. The ADR pages and the gap assessment are outside the navigation; the build reports that as information. | `8b3bfff` |
| `scripts/gen_schemas.py --check` and `scripts/gen_reference_docs.py --check` | 19 schemas and 5 reference pages agree with the source. | `8b3bfff` |
| `uvx pip-audit` over `uv export --all-extras --all-groups` (dependency vulnerability scan, 2026-10-15) | pip-audit 2.10.1: no known vulnerabilities in the 111 locked packages. The scan sends package names and versions to the vulnerability databases. It was not run again after commit `49b7dac` added `asn1crypto`. | `a2c72ef` |
| `uv run just style` (Vale, the project rules in `styles/STE`) | 0 errors, 0 warnings, 729 suggestions in 61 files. Suggestions include forms in -ing and passive voice. On 2026-10-15, the first run found a defect in `.vale.ini` and 7 sentences of more than 25 words; both are fixed. The rule for long procedure steps counts whole list items, so it is a suggestion. | `8b3bfff` |
| Container image scan: Trivy 0.56.2 (`aquasec/trivy`), vulnerability database of 2026-10-15, run by the owner | `--severity HIGH,CRITICAL --ignore-unfixed`: 0 findings in the Debian 13.7 base (87 packages) and in the Python packages. The secret scan reported nothing. Lower severities and findings with no fix were not in scope of this scan. | `832d15f` |
| Container build and smoke test (Docker Desktop, run by the owner; the agent read the output) | `docker build -t dppce:0.1.0rc1 .` builds. In the image, `dppce --version` gives `0.1.0rc1`, `dppce catalogue lint` gives 0 errors, 1 warning, and 36 informational findings, and the process runs as `uid=10001(dppce)`. Commit `832d15f` pins the base images by the index digests that this build resolved; the owner confirmed them with `docker buildx imagetools inspect`. The rebuild of the pinned Dockerfile gives the same image manifest (`sha256:c9020b87...`) and image config (`sha256:89372e3c...`) as the first build. | `ef3ced8`, `832d15f` |
| GitHub Actions `scorecard` (run 38709214957, public repository) | The analysis runs and publishes. These checks were below the maximum. Code review 0: no reviewed changesets. Branch protection 0: added later. SAST 0: CodeQL is added after this run. Best-practices badge 0. Fuzzing 0: the Hypothesis property tests are not counted. Maintained 0: the repository is new. Security policy 4: private reporting is added later. Pinned dependencies 8: the base image has a tag, not a digest (BL-005). After the later changes, the run on `c733185` leaves 4 open Scorecard alerts: code review, maintained, fuzzing, and the best-practices badge. | `9c7b2b0`, `c733185` |
| Repository settings (2026-10-15, with the approval of the owner) | Private vulnerability reporting is enabled; `SECURITY.md` points to it. Branch `main` is protected: the checks of `ci` and `codeql` must pass before a merge, and force pushes and deletion are blocked. Reviews are not required, because there is one maintainer. | none |
| GitHub Actions `codeql` (Python, security-extended queries) | 0 open alerts. The first analysis found two. A TLS context did not state its minimum version (high). The reference server built a header value from the request path (medium). Both are fixed. Later, commits `d012334`, `12f57c8`, and `b7b744c` name CodeQL alerts 13 to 16 and change the code for each. This page does not record the alert state after them. | `2c0c6ab` |
| GitHub Actions `release` (run 38722322047, tag `v0.1.0rc1`, 2026-10-15) | All three jobs passed on the first run. They built the sdist, the wheel, and the SBOM, and signed build provenance for the packages and the image. The image is `ghcr.io/hadijannat/dpp-conformance-engine:v0.1.0rc1` with digest `sha256:09055b7e140659ec37ce05491c9bda8fc66549018901813d4a5a58596502b3ce`. The package page shows it as public. `gh attestation verify` passed for the wheel, the sdist, the SBOM, and the image. Each attestation is SLSA provenance v1 for tag `v0.1.0rc1`, commit `6573e4c`, and `release.yml`. The wheel of the run installs alone in a new environment. There, `dppce --version` gives `0.1.0rc1` and the catalogue lints with 0 errors. The three files are assets of the GitHub pre-release, with the same SHA-256 values. | `6573e4c` |
| GitHub Actions `ci` (run 38708494167, Linux) | Fast gates on Python 3.12 and 3.13 pass: format, lint, types, schema sync, and catalogue lint. 1270 tests passed with no network except loopback. Core coverage is 98 percent. Core without optional extras: 1236 passed. Method validation job: 63 passed. Its record shows 60/60 faults, 0/39 false positives, 8/8 boundary cases, 12/12 evidence faults, and 15/15 replays. The first two runs failed on defects of the workflow and of the transport on Linux; both are fixed. This page does not record a CI run of `8b3bfff`. | `4c2928e` |

A check that is not in this table was not run in these sessions. A manual accessibility review
is "not run".

### 2.1 Core packages of the coverage gate

The gate in `justfile` (`core`) covers these paths and no others:

- `src/dppce/applicability.py`, `src/dppce/migrations.py`
- `src/dppce/models/`, `src/dppce/catalogue/`, `src/dppce/verdicts/`, `src/dppce/orchestrator/`
- `src/dppce/evidence/`, `src/dppce/verifier/`, `src/dppce/testdefs/`
- `src/dppce/infrastructure/`: `transport.py`, `replay.py`, `redaction.py`, `authorization.py`,
  `keys.py`, `clock.py`, `resources.py`

The command line, the adapters, the HTML report, and the reference server are outside the gate.
Their coverage is in the "all modules" figure only.

## 3. Reviews

AI agents did each review below. An agent review is not a human approval and not an audit.

| Record | Subject | Outcome |
| --- | --- | --- |
| `validation/records/review-evidence-security-2026-10-13.md` | Evidence, transport, access, integrity, recording | 17 findings. All fixed, with a regression test each in `tests/test_review_findings.py`. |
| `validation/records/review-verdicts-and-planning-2026-10-14.md` | Applicability, planning, verdicts, coverage, report | 9 findings. All fixed or reworded, with tests in `tests/test_review_verdicts.py`. |
| `validation/records/review-eu-battery-draft-2026-10-14.md` | The 36 draft interpretations of Regulation (EU) 2023/1542 | 17 findings. Applied to the drafts. Three open questions filed (OQ-021 to OQ-023). Every entry stays `draft-needs-review`. |
| `validation/records/review-round-2-2026-10-14.md` | Round 2: every fix of round 1, then the fixes of round 2 | 48 findings of six areas and 14 findings of four follow-up reviews. Each finding was checked by skeptics who tried to refute it: 52 confirmed for the reviewed code, 2 refuted, 8 informational. All are handled, with tests in `tests/test_review_round2.py`. |
| `validation/records/review-adapters-2026-10-18.md` | Adapters, transport scrub, clock, validation controls | 31 findings. Each was checked by a skeptic with a reproducing test: 30 confirmed and fixed, 1 refuted. An agent check of the fixes found 6 more: 5 fixed, 1 fixed in part. Tests in `tests/test_review_adapters.py` and `tests/test_validation_controls.py`. |
| `validation/records/review-key-tooling-2026-10-18.md` | Key tooling (D6-08) and four follow-ups | Seven stages. The record states that their counts must not be added. Adversarial review: 15 distinct findings, 14 confirmed and 1 refuted, 13 fixed. Agent security review: 3 findings and 7 notes; the 3 findings and 2 notes are fixed, 5 notes are not changed. Review of the fixes: 8 findings, all fixed. Review of the follow-ups: 4 findings, all fixed. One confirmed documentation finding is open (docs1-DOC-2). No agent review covers the file mode commits `12f57c8` and `b7b744c`. |

An automated review of each commit also ran. It found four gaps in the fixes of round 1 and
round 2: two fixed in commit `072b9c3`, one in `d6a7122`, and one in `59e148f`.

## 4. Evidence that is missing

These items block a claim that the engine is ready for use on a real system:

1. A human review of the draft interpretations, with a review record for each approved entry
   (OQ-002). Until then, no result from the EU pack is `pass` or `fail`.
2. A test run against a real DPP system, with a signed authorization of its owner. No real
   system was contacted.
3. An independent human security audit.
4. An accessibility review of the HTML report by a person, with a screen reader.
5. A DCO sign-off on each commit that a development agent made. Commit `a6283be` of the owner
   certifies the 87 commits up to `a1522ad` (OQ-018). Later sign-off commits of the owner
   certify the agent commits up to `f1ee709`. The last of them on `main` is `91a6629`. The 95
   agent commits and the merge commit `dfd03b1` after it, up to `8b3bfff`, have no sign-off yet.
   Each newer agent commit needs one too.
6. A key management service or a PKCS#11 device, and a timestamp authority that the operator
   selects. `dppce keys generate` writes an encrypted key file, but keys stay files on the host.
   The capabilities `keys.kms` and `keys.pkcs11` are interfaces only (gap D6-07, tier T3). The
   verifier checks RFC 3161 tokens (ADR 0015). `dppce timestamp attach` adds a token that the
   operator obtained. No command contacts a timestamp authority.

## 5. Records that can support a laboratory quality system

A testing laboratory that works to ISO/IEC 17025:2017 decides for itself which records its
procedures need. The engine does not make a laboratory competent, and it gives no
accreditation. The engine produces these records, which a laboratory can evaluate:

| Record | Where |
| --- | --- |
| The version of the engine, of each dependency, and of each catalogue, profile, and test pack, as hashes | Run manifest in each report |
| The trace from a source provision to the check that tests it | `dppce catalogue trace` |
| The method validation: seeded faults, expected outcomes stated before the checks, detection and false positives with numerators and denominators | `validation/fault-catalogue.yaml`, `validation/records/` |
| Repeatability: a replay of a recording gives the same decision digest | `dppce replay --times 5` |
| The integrity and the origin of a report | Signature, Merkle roots, and `python -m dppce.verifier` |
| The limits of each result | Limitations, exclusions, and retained problems in each report |
| Retention and deletion of observations | `dppce purge` |

The [laboratory records](reference/laboratory-records.md) page lists each output and the records that the engine does not produce.

## 6. Known limitations

- Read [the threat model](explanation/threat-model.md), section 6, for the open risks.
- Read [the open questions](open-questions.md) for each decision that a human must make.
- The access check shows enforcement of the policy that the owner declares. It cannot find a
  value that a system hides on purpose.
- The integrity check supports ES256 with an `x5c` certificate path only. Each other token
  gives `inconclusive`.
- The illustrative pack is synthetic. A result from it makes no normative statement.
- Key files use the fixed PKCS#8 parameters of the installed `cryptography` package:
  PBKDF2-HMAC-SHA256 with 2048 iterations, and AES-256-CBC. A generated passphrase of 32 bytes
  compensates. The shipped TEST-ONLY report key is not encrypted. The tutorial, the README, and
  the rig pass `--allow-unencrypted-key`.
- The 823 mutants that survived at `8b3bfff` are not classified. Some of them can show a gap
  in the tests.
- Each agent review record lists its open items. For example, the paragraph on the standalone
  verifier in the command-line reference omits `--status-list`, `--opening`, and `--proof`.
