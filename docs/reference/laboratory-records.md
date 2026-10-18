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

This page describes the unreleased source after the release `v0.1.0rc1`.
[Install and verify a release](../how-to/install-and-verify-a-release.md#the-release-and-the-unreleased-source)
lists the differences that affect a laboratory.

## 1. Outputs that the engine produces

| Output | Produced by | Where |
| --- | --- | --- |
| Run manifest: the versions and the input hashes | `dppce run` | `envelope.json` |
| Verdicts, exclusions, retained problems, coverage, and limitations | `dppce run` | `envelope.json`, `report.html` |
| Decision digest | `dppce run` (output); `dppce sign` (attestation) | Output of the run; inside each signature of the signed file |
| Signatures, each with the role `issuer` or `reviewer` | `dppce sign` | The new file at `--out`, or `envelope.json` with `--in-place` |
| Encrypted signing key and its public JWK | `dppce keys generate` | The key file at `--out`, with mode 0600; the JWK in the output only |
| Signed test authorization | `dppce authorize`, run by the system owner | The new file at `--out` |
| Trust bundle with one more key | `dppce trust-bundle add-key` | The new file at `--out` |
| Record opening (`dppce.opening/1`): the salt and the plaintext of one record | `dppce open` | The new file at `--out`, with mode 0600. It holds plaintext. |
| Inclusion proof (`dppce.proof/1`) of one result | `dppce prove` | The new file at `--out` |
| Run inputs (`dppce.runinputs/3`), in clear text | `dppce run` | `inputs.json` |
| Encrypted recording with the delete-after date | `dppce run` | `recording/` |
| Signature imprints for a timestamp request | `dppce timestamp imprint` | Output only |
| Report with an attached timestamp token | `dppce timestamp attach` | A new envelope file at `--out` |
| Replay result | `dppce replay` | Output only |
| Verification result, with the dimensions `signers`, `status`, and `validity` | `dppce verify`, `python -m dppce.verifier`, `dppce report --trust` | Output only, or the verification section of the HTML report |
| Verification result, with the dimensions `opening` and `proof` | `dppce verify`, `python -m dppce.verifier` | Output only |
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
| Trust bundle, version `dppce.trust/2` | Chosen by the operator | The engine checks signatures, signer roles, revoked keys and certificates, status lists, and timestamps against it. It copies the bundle into `inputs.json`. |
| Timestamp token | Issued by a timestamp authority that the operator selects | The verifier checks it against `timestamp_anchors` of the trust bundle. |
| Status list (`dppce.statuslist/1`) | Signed by the issuer of reports, outside the engine | The operator supplies the file with `--status-list`. The verifier checks it against a key with the purpose `status`. The engine does not copy it. |
| Reviewer signature | Made by a reviewer with `dppce sign --role reviewer` | `dppce sign` adds it to the file at `--out`, or to the input with `--in-place`. The verifier checks it in the dimension `signers`. |

## 3. Outputs of the release pipeline

| Output | Made by | Where |
| --- | --- | --- |
| Build provenance and SBOM | The workflow `release.yml`, not `dppce` | Release assets. See [install and verify a release](../how-to/install-and-verify-a-release.md). |

## 4. Outputs that the engine does not keep

The engine writes these outputs to the terminal only. Keep them yourself:

- the replay result
- the verification result, unless you render the HTML report with `--trust`
- the signature imprints
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
- The source and the date of each revocation entry and each timestamp anchor in the trust bundle.
- A timestamp token. The engine never contacts a timestamp authority.
- A status list, and a copy of the list that a verification used. The engine never fetches a list.
- The person who holds a reviewer key. A reviewer signature names a key and a role, not a person.
- The signed human approval record of an interpretation (ADR 0007).
- The review and signature of a method-validation record by a person.
  `human_review_and_signature` is always `null`.
- The stored results of replay, verification, purge, lint, and coverage.
- Storage, backup, and access control for run directories, keys, and `inputs.json`.
- The deletion of copies outside the run directory.
- A manual accessibility review of the HTML report. It is "not run".

A laboratory can need more records. This list names only the gaps that follow from what the
engine does.
