# Readiness and limitations

Audience: a decision maker, an assessor, or a laboratory that considers using the engine.
Purpose: state what was shown, by which command, and what was not shown.
Prerequisites: read [what the engine tests and what it does not claim](explanation/scope-and-legal-mapping.md).

**Version 0.1.0rc1 is a release candidate. It is not released or tagged, and no package is published.**
The source repository is public at https://github.com/hadijannat/dpp-conformance-engine since
2026-10-15; the owner made it public.
This page states no technology readiness level. It makes no statement of legal compliance,
product safety, data truth, or accreditation. The outputs of the engine are conformance test
reports. They are not certificates.

Each figure on this page comes from a command that ran in the development session of
2026-10-14 on one macOS host. The commit is named next to each figure. A development agent
ran the commands. No human has repeated them.

## 1. Summary

| Dimension | What exists | What is missing |
| --- | --- | --- |
| Engineering | Typed core (mypy strict), fast test suite, core line and branch coverage gate, mutation testing of the verdict and evidence code, reproducible replays. Continuous integration runs on GitHub (Linux, Python 3.12 and 3.13). | The container image has never been built. The release workflow has never run. |
| Security | Threat model, policy-enforcing transport, encrypted recordings, signed reports, a standalone verifier. Two agent review rounds (the maximum that the brief permits); every finding is fixed or recorded. | No independent human security audit. No trusted timestamp. Keys are files. |
| Interoperability | JSON Schemas for every contract. Checks for carrier, identifier, API contract, data, access, integrity, persistence, registry, and AAS. | No test against a real DPP system or a second implementation. The optional AAS test engine was not run. |
| Legal mapping | A source catalogue with 128 records. 36 draft interpretations of Regulation (EU) 2023/1542. 8 placeholders for EN standards. | No interpretation is approved. No human reviewer has read the drafts. No EN, ISO, IEC, or DIN text is in the repository, by design. |
| Operations | Command line with stable exit codes, retention and purge of recordings, documented how-to guides. | No key management service or hardware security module. No multi-user deployment. |
| Accessibility | The HTML report uses semantic tables, headings, and text labels for each verdict. WCAG 2.2 AA is the target. An agent checked structure, contrast, the first focus, and reflow at 320 pixels (`docs/reference/accessibility.md`). | No manual review by a person, no screen reader review, and no accessibility scanner. The Vale style rules did not run. |
| Validation in a relevant environment | Method validation against a synthetic reference system: seeded faults, valid controls, boundary cases, evidence faults, and replays. | No validation against a real system or real data. The reference system and the checks come from the same project. |

## 2. Results of the commands

| Command | Result | Commit |
| --- | --- | --- |
| `uv run just check` (format, lint, mypy strict, fast tests) | Format, lint, and type check clean. 1270 tests passed, 63 deselected (the slow validation tests). | `d149ee8` |
| `uv run pytest -m validation` | 63 passed. | `d149ee8` |
| `uv run just cov` | Core packages: 98 percent (2620 statements, 37 missed; 716 branches, 17 partial). All modules: 93 percent (4246 statements, 260 missed). Gate: 90 percent on the core packages. | `d149ee8` |
| `uv run just mutation` | 1499 mutants of the verdict and evidence code: 1320 killed, 3 timed out, 176 survived. 1323 of 1499 detected. Each survivor is classified in `validation/records/mutation-2026-10-14.md`; none of them changes a verdict. | `d149ee8` |
| `uv run python -m validation.run` | Seeded faults: 60 of 60 fault and profile combinations detected for the intended reason. Valid controls: 0 of 39 executed steps did not pass. Boundary cases: 8 of 8 as expected. Evidence faults: 12 of 12 failed on the named dimension, 0 not run. Replays: 15 of 15 with the same decision digest. Record: `validation/records/method-validation-20261014T214902Z.json`. | `3284ce2`, clean working tree |
| `uv run dppce catalogue lint` | 0 errors, 1 warning (`TP-NFC-001`: no NFC check is registered), 36 informational findings (unresolved points of the drafts). | `d149ee8` |
| Clean installation: `uv build --wheel`, then install the wheel alone in a new virtual environment | The wheel installs. `dppce --version` gives `0.1.0rc1`. The bundled catalogue lints with 0 errors. `python -m dppce.verifier` runs. The wheel holds no test and no fixture. | `d149ee8` |
| `uv run just sbom` | A CycloneDX 1.6 SBOM with 111 components in `dist/sbom.cdx.json` (not committed). It describes the development environment, not only the runtime dependencies of the wheel. | `9066e64` |
| `reuse lint` (REUSE 3.3) | 248 of 248 files have copyright and license information. Compliant. | `d149ee8` |
| `uv run just docs` (strict build) | Built with no warning. The ADR pages are outside the navigation; the build reports that as information. | `d149ee8` |
| `uvx pip-audit` over `uv export --all-extras --all-groups` (dependency vulnerability scan, 2026-10-15) | pip-audit 2.10.1: no known vulnerabilities in the 111 locked packages. The scan sends package names and versions to the vulnerability databases. | `a2c72ef` |
| `uv run just style` (Vale 3.22.0, the project rules in `styles/STE`) | 0 errors, 0 warnings. Suggestions remain (forms in -ing, passive voice, long list items); `just style` prints their current count. The first run found a defect in `.vale.ini` and 7 sentences of more than 25 words; both are fixed. The rule for long procedure steps counts whole list items, so it is a suggestion. | The commit that records this row |
| Container build | Not run. Docker commands are blocked by the permission settings of the session. | none |
| GitHub Actions `scorecard` (run 38709214957, public repository) | The analysis runs and publishes. These checks were below the maximum. Code review 0: no reviewed changesets. Branch protection 0: added later. SAST 0: CodeQL is added after this run. Best-practices badge 0. Fuzzing 0: the Hypothesis property tests are not counted. Maintained 0: the repository is new. Security policy 4: private reporting is added later. Pinned dependencies 8: the base image has a tag, not a digest (BL-005). | `9c7b2b0` |
| Repository settings (2026-10-15, with the approval of the owner) | Private vulnerability reporting is enabled; `SECURITY.md` points to it. Branch `main` is protected: the checks of `ci` and `codeql` must pass before a merge, and force pushes and deletion are blocked. Reviews are not required, because there is one maintainer. | none |
| GitHub Actions `codeql` (Python, security-extended queries) | 0 open alerts. The first analysis found two: a TLS context without a stated minimum version (high) and a header value of the reference server built from the request path (medium). Both are fixed. | `2c0c6ab` |
| GitHub Actions `ci` (run 38708494167, Linux) | Fast gates on Python 3.12 and 3.13 pass: format, lint, types, schema sync, and catalogue lint. 1270 tests passed with no network except loopback. Core coverage is 98 percent. Core without optional extras: 1236 passed. Method validation job: 63 passed. Its record shows 60/60 faults, 0/39 false positives, 8/8 boundary cases, 12/12 evidence faults, and 15/15 replays. The first two runs failed on defects of the workflow and of the transport on Linux; both are fixed. | `4c2928e` |

A check that is not in this table was not run in this session. The release workflow, the
container build, and a manual accessibility review are "not run".

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

Each review below was done by an AI model that did not write the code under review. An agent
review is not a human approval and not an audit.

| Record | Subject | Outcome |
| --- | --- | --- |
| `validation/records/review-evidence-security-2026-10-13.md` | Evidence, transport, access, integrity, recording | 17 findings. All fixed, with a regression test each in `tests/test_review_findings.py`. |
| `validation/records/review-verdicts-and-planning-2026-10-14.md` | Applicability, planning, verdicts, coverage, report | 9 findings. All fixed or reworded, with tests in `tests/test_review_verdicts.py`. |
| `validation/records/review-eu-battery-draft-2026-10-14.md` | The 36 draft interpretations of Regulation (EU) 2023/1542 | 17 findings. Applied to the drafts. Three open questions filed (OQ-021 to OQ-023). Every entry stays `draft-needs-review`. |
| `validation/records/review-round-2-2026-10-14.md` | Round 2: every fix of round 1, then the fixes of round 2 | 48 findings of six areas and 14 findings of four follow-up reviews. Each finding was checked by skeptics who tried to refute it: 52 confirmed for the reviewed code, 2 refuted, 8 informational. All are handled, with tests in `tests/test_review_round2.py`. |

An automated review of each commit also ran. It found four gaps in the fixes of round 1 and
round 2: two fixed in commit `072b9c3`, one in `d6a7122`, and one in `59e148f`.

## 4. Evidence that is missing

These items block a claim that the engine is ready for use on a real system:

1. A human review of the draft interpretations, with a review record for each approved entry
   (OQ-002). Until then, no result from the EU pack is `pass` or `fail`.
2. A test run against a real DPP system, with a signed authorization of its owner. No real
   system was contacted.
3. An independent human security audit.
4. A run of the release workflow.
5. A build and a scan of the container image (OQ-004).
6. An accessibility review of the HTML report by a person, with a screen reader.
7. A sign-off on each commit under the DCO by the copyright holder (OQ-018).
8. A trusted timestamp on a report (BL-004), and a key management service.

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

## 6. Known limitations

- Read [the threat model](explanation/threat-model.md), section 6, for the open risks.
- Read [the open questions](open-questions.md) for each decision that a human must make.
- The access check shows enforcement of the policy that the owner declares. It cannot find a
  value that a system hides on purpose.
- The integrity check supports ES256 with an `x5c` certificate path only. Each other token
  gives `inconclusive`.
- The illustrative pack is synthetic. A result from it makes no normative statement.
