# Laboratory records

Audience: laboratory quality staff and assessors.
Purpose: list what the engine produces and where to find it, and list what it does not produce.
Prerequisites: read [operate the engine in a laboratory](../how-to/operate-in-a-laboratory.md).

A testing laboratory can work to ISO/IEC 17025:2017 General requirements for the competence of
testing and calibration laboratories.
This page does not map the engine to that standard. It does not state the requirements of
that standard.
A laboratory decides which records its procedures need.
The engine gives no accreditation. A report is a conformance test report, not a certificate.

## 1. Outputs that the engine produces

| Output | Produced by | Where |
| --- | --- | --- |
| Run manifest: the versions and the input hashes | `dppce run` | `envelope.json` |
| Verdicts, exclusions, retained problems, coverage, and limitations | `dppce run` | `envelope.json`, `report.html` |
| Decision digest | `dppce run` (output); `dppce sign` (attestation) | Output of the run; inside each signature in `envelope.json` after signing |
| Signatures | `dppce sign` | `envelope.json` |
| Run inputs, in clear text | `dppce run` | `inputs.json` |
| Encrypted recording with the delete-after date | `dppce run` | `recording/` |
| Replay result | `dppce replay` | Output only |
| Verification result | `dppce verify`, `python -m dppce.verifier`, `dppce report --trust` | Output only, or the verification section of the HTML report |
| Coverage | `dppce coverage` | Output only |
| Trace from a source provision to a check | `dppce catalogue trace` | Output only |
| Lint findings | `dppce catalogue lint` | Output only |
| Capability manifest | `dppce capabilities` | Output only |
| Purge list | `dppce purge` | Output only |
| Method-validation record | `python -m validation.run` | `validation/records/` |

## 2. Inputs that the engine records or checks

| Input | Made by | How the engine uses it |
| --- | --- | --- |
| Fault catalogue | Written by hand, `validation/fault-catalogue.yaml` | The method validation reads it. |
| Authorization token | Issued by the system owner | The engine validates it and copies it into `inputs.json`. |
| Signed manual result | Signed by the person who performed the step | The engine checks it. Its observation is in the report. |
| Trust bundle | Chosen by the operator | The engine verifies signatures with it and copies it into `inputs.json`. |

## 3. Outputs of the release pipeline

| Output | Made by | Where |
| --- | --- | --- |
| Build provenance and SBOM | The workflow `release.yml`, not `dppce` | Release assets. See [install and verify a release](../how-to/install-and-verify-a-release.md). |

## 4. Outputs that the engine does not keep

The engine writes these outputs to the terminal only. Keep them yourself:

- the replay result
- the verification result, unless you render the HTML report with `--trust`
- the coverage, the trace, the lint findings, and the capability manifest
- the purge list

## 5. Records that the engine does not produce

Each item names a limit of the engine:

- The person who operated a run. The report names an issuer. The verifier checks that the
  issuer identifier matches the signing key (ADR 0014). The operator declares the name and the
  accreditation fields. No field names the operator.
- The permission of the owner for read-only access. `--allow-remote-host` is a confirmation only.
- The person who performed a manual step. A manual result names a role.
- How and from where you got a trusted key, and each change to the trust bundle.
- The signed human approval record of an interpretation (ADR 0007).
- The review and signature of a report or of a method-validation record by a person.
  `human_review_and_signature` is always `null`.
- The stored results of replay, verification, purge, lint, and coverage.
- Storage, backup, and access control for run directories, keys, and `inputs.json`.
- The deletion of copies outside the run directory.
- A manual accessibility review of the HTML report. It is "not run".

A laboratory can need more records. This list names only the gaps that follow from what the
engine does.
