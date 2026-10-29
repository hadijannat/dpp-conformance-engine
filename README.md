# DPP Conformance Engine (DPP-CE)

[![ci](https://github.com/hadijannat/dpp-conformance-engine/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hadijannat/dpp-conformance-engine/actions/workflows/ci.yml?query=branch%3Amain)
[![codeql](https://github.com/hadijannat/dpp-conformance-engine/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/hadijannat/dpp-conformance-engine/actions/workflows/codeql.yml)
[![release](https://img.shields.io/github/v/release/hadijannat/dpp-conformance-engine?include_prereleases&sort=semver)](https://github.com/hadijannat/dpp-conformance-engine/releases)

Audience: system owners, developers, testing laboratories, authorities, report recipients, and people new to Digital Product Passports.
Purpose: explain what the engine does, and help you produce and verify your first conformance test report.
Prerequisites: none for this overview. For the demo: Git, Python 3.12 or later, and [uv](https://docs.astral.sh/uv/).

DPP-CE is an open-source, vendor-neutral conformance test engine for Digital Product Passport (DPP) systems.
It tests how a DPP system behaves against a catalogue of traceable requirements.
The owner of a system can find gaps before others rely on it.
A recipient can check that a signed report is intact and who signed it.

> **Release candidate 0.1.0rc1. Not for production use.**
> The engine writes **conformance test reports**, not certificates.
> A report makes no statement of legal compliance, product safety, or data truth.
> It repeats the accreditation status that the operator declares. The engine does not check that status.
> Today the engine ships synthetic example rules and draft interpretations of the Batteries Regulation.
> No person has reviewed the drafts. Read the [limitations](#limitations-and-readiness).

[Why](#why-this-exists) · [Who it is for](#who-it-is-for) · [Quick start](#quick-start) ·
[Check a report](docs/how-to/verify-a-report.md) · [Results](#what-a-result-means) ·
[Your own system](#test-your-own-system) · [Expectations](#what-people-expect-and-where-dpp-ce-stands) · [Guides](#documentation)

<p align="center">
  <img src="docs/images/test-areas.svg" width="880" alt="Seven parts of a DPP system that the engine observes: data carrier, identifier, interface, data, access, integrity, and lifecycle.">
</p>

The engine observes seven parts of a DPP system:

- **Data carrier:** a supplied QR image decodes to one symbol.
- **Identifier:** the identifier has its declared syntax, resolves, and is the same in each place.
- **Interface:** a response matches the API contract that the system owner pins.
- **Data:** a document matches a pinned schema, a context allowlist, and a rule pack.
- **Access:** a role gets no field that the declared access policy withholds.
- **Integrity:** a signature is valid, its issuer is trusted, and its X.509 certificate is valid.
- **Lifecycle:** the version history follows the declared update rule, and a mock registry record agrees with the passport.

The [scope page](docs/explanation/scope-and-legal-mapping.md#1-what-the-engine-tests) gives the same list. Checks are deterministic code.

## Why this exists

A Digital Product Passport gives access to data about a product, a batch, or a product model.
A data carrier on the product, such as a QR code, leads to it.
Several EU regulations set up a passport, for example:

- Regulation (EU) 2023/1542, the Batteries Regulation, requires a **battery passport** from 2027-02-18. The duty covers light means of transport (LMT) batteries, industrial batteries above 2 kWh, and electric vehicle batteries.
- Regulation (EU) 2024/1781, the Ecodesign for Sustainable Products Regulation (ESPR), sets the **digital product passport**. A product group gets this duty only through a delegated act.

The legal pack of this engine holds draft interpretations of the Batteries Regulation only.

Manufacturers, software vendors, and service providers now build DPP systems.
Before others rely on a system, its owner needs to know how the system behaves.
A recipient of a test result needs evidence that the recipient can check without the tester.

DPP-CE addresses both needs with versioned requirements, deterministic checks, encrypted recordings, and signed reports.
It tests the DPP system itself. It does not contact the EU DPP registry or its testing environment.
The Commission [announced the registry and the testing environment](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en) on 2026-07-20.
A market surveillance authority decides whether a report helps its own checks. A report never replaces them.
The [scope and legal mapping](docs/explanation/scope-and-legal-mapping.md) explains how the engine relates to each regulation.

## Who it is for

| You are | You want to | Start here |
| --- | --- | --- |
| New to DPPs | Learn what a passport is and what the engine tests | [Why this exists](#why-this-exists), then [scope and legal mapping](docs/explanation/scope-and-legal-mapping.md). Look up project terms in the [glossary](docs/reference/glossary.md). |
| A system owner or a vendor | Find gaps before others test your system | [Quick start](#quick-start), then [test your own system](#test-your-own-system) |
| A developer or an integrator | Run checks in CI and read machine-readable results | [Command line](docs/reference/cli.md), [CI formats](docs/how-to/verify-a-report.md#use-a-report-in-ci), [schemas](docs/reference/schemas.md) |
| A testing laboratory | Run, keep, replay, and verify runs under your own procedures | [Operate in a laboratory](docs/how-to/operate-in-a-laboratory.md), [laboratory records](docs/reference/laboratory-records.md) |
| An assessor | Inspect the method and its evidence | [Architecture](docs/explanation/architecture.md), [method validation](docs/how-to/run-the-method-validation.md), [readiness](docs/readiness.md) |
| An authority or a report recipient | Check a report that you received | [Verify a report](docs/how-to/verify-a-report.md) |
| A decision maker | Know what a result means and does not mean | [What a result means](#what-a-result-means), [readiness](docs/readiness.md) |
| A researcher | Cite or study the method | [Cite](#cite), [source audit](docs/research/source-audit.md) |
| A contributor | Change code, checks, or documentation | [Contribute](#contribute) |

## What you can do

- Trace a requirement from its source provision to its test purposes and executable checks.
- Check identifiers, QR codes, API responses, JSON data, and digital signatures.
- Check that each role gets only the data that the declared access policy allows.
- Keep encrypted recordings, and replay them offline to reproduce the decision digest.
- Compare two runs: the plan inputs, and each step that changed.
- Read HTML and JSON reports, or export JUnit XML and SARIF for CI tools.
- Sign a report. A recipient checks it with a standalone verifier and its own trust bundle.

No language model takes part at run time. Versioned data and deterministic code select checks and calculate verdicts.

## How a run works

Two input files describe the system and the test:

- **ICS (Implementation Conformance Statement):** what the system owner declares about the system.
- **IXIT (Implementation eXtra Information for Testing):** endpoints, sample files, and other inputs that the tester needs.

The engine treats both files as untrusted input.
The **operator** is the person who runs the engine.
The operator supplies the **trust bundle**, the explicit list of keys and anchors that the operator trusts.
The operator also confirms each private host and each secret reference.

<p align="center">
  <img src="docs/images/run-lifecycle.svg" width="880" alt="One run: plan and run take the ICS, the IXIT, and the operator inputs. Only the run reaches the system under test, through the policy-enforcing transport. Replay, signing, and verification work offline.">
</p>

The steps below follow the pipeline. The diagram puts replay, export, and signing in one column, because each one reads the run outputs on its own.

1. **Plan:** select requirements and test steps from the profile, the packs, the ICS, and the IXIT. It sends no request.
2. **Run:** send the planned requests through one policy-enforcing transport. Only this step contacts the system under test.
3. **Record:** the run writes an encrypted recording, the run inputs, the JSON report, and the HTML report.
4. **Replay:** evaluate the recording again offline. Compare the decision digest, the SHA-256 digest of the decision body.
5. **Export:** render the JSON report as HTML, or export it as JUnit XML or SARIF.
6. **Sign and verify:** sign the report separately. A recipient checks it with the standalone verifier and its own trust bundle.

`dppce run` does steps 1 to 3 in one command. `dppce plan` does step 1 alone.
Replay does not test the system again. Verification says nothing new about the system under test.

## Quick start

This demo tests a local reference system with synthetic data. The run contacts only this local system.
The fixture keys and tokens are published test values, named `TEST-ONLY-...`.

### 1. Install from source

You need Git, Python 3.12 or later, and [uv](https://docs.astral.sh/uv/).
The demo needs the source checkout, which includes [unreleased changes](CHANGELOG.md#unreleased).
For the published release, use the [release installation guide](docs/how-to/install-and-verify-a-release.md).

```bash
git clone https://github.com/hadijannat/dpp-conformance-engine.git
cd dpp-conformance-engine
uv sync --all-extras
```

### 2. Start the reference system

Run every command from the repository root. Keep this terminal open:

```bash
uv run python -m dppce.infrastructure.reference_server --port 8765
```

Keep the port 8765. The fixture IXIT names it.

### 3. Run the battery example

Open a second terminal in the same directory:

```bash
uv run dppce run \
  --mode illustrative \
  --profile battery/ev \
  --ics fixtures/reference/ev.ics.yaml \
  --ixit fixtures/reference/ev.ixit.yaml \
  --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json \
  --secrets fixtures/reference/secrets \
  --allow-private-host http://127.0.0.1:8765 \
  --role-secret legitimate_interest=file:TEST-ONLY-legitimate_interest.token \
  --role-secret authority=file:TEST-ONLY-authority.token \
  --issuer-name "synthetic test laboratory" --issuer-id urn:example:test-lab \
  --at 2026-10-13T12:00:00Z \
  --keys ./runs/keys --create-data-key --out ./runs/ev-1
```

The command exits with code `0` and prints three lines.
Each live run records new times and new salted commitments, so its digest changes. A replay of the same recording gives the same digest.

```text
overall pass: Every applicable mandatory requirement in the selected catalogue passed.
digest sha256:<64 hexadecimal characters>
run runs/ev-1
```

What the options do:

- `--mode illustrative` assesses the synthetic rules only. The result makes no statement about a law.
- `--at` fixes the evaluation time. The freshness rule of the fixture depends on it.
- `--allow-private-host` and `--role-secret` are confirmations from the operator. Without them, the engine refuses the host and the secrets.
- `--secrets` names the directory that holds the token files.
- `legitimate_interest` and `authority` are role names of the synthetic access policy. They do not encode the access rights of the Regulation.
- `--issuer-id` must match the issuer of the signing key in the trust bundle.

If you did not start the reference system, or did not install with `--all-extras`, the run gives `inconclusive` and exit code `5`.
Fix the cause, delete `runs/ev-1`, and run the command again.

### 4. Read the report

Open `runs/ev-1/report.html` in a browser. Start with the summary, then read the results and the exclusions.

<p align="center">
  <img src="docs/images/report-summary.png" width="880" alt="Top of the HTML report from the demo. It shows the overall outcome pass, the requirement counts, and a box that says the report is not a certificate.">
</p>

The image shows the top of `report.html` from this demo, captured on 2026-10-29. The data are synthetic, and the mode is `illustrative`.
The summary names the system, the profile, and the mode. It gives the overall outcome and the requirement counts.
The one `inconclusive` result is a recommended manual step, so it does not change the overall outcome.
The 44 exclusions are the draft and placeholder requirements that `illustrative` mode leaves out. The counts change when the catalogue changes.

| Output | Contents |
| --- | --- |
| `runs/ev-1/report.html` | Readable report: verdicts, coverage, reasons, exclusions, and next steps |
| `runs/ev-1/envelope.json` | JSON report, unsigned until you sign it |
| `runs/ev-1/inputs.json` | Run inputs and their digests, in clear text |
| `runs/ev-1/recording/` | Encrypted records and a clear-text index, for replay |
| `runs/ev-1/envelope.signed.json` | Signed JSON report, after step 5 |
| `runs/keys/` | Local data key that decrypts the recording |

A run never overwrites an earlier run. For another run, choose a directory that does not exist yet.
Keep the data key to replay a recording.
The [first-run tutorial](docs/tutorials/first-run.md#8-see-a-failure) shows how to introduce a fault and read the failure.

### 5. Replay, sign, and verify

Replay the recording five times. Each replay must reproduce the decision digest of the run. You can stop the reference system first:

```bash
uv run dppce replay --run ./runs/ev-1 --keys ./runs/keys --times 5
```

The output includes `5 replays: match`, and the exit code is `0`.

Sign the JSON report with the published test signing key:

```bash
uv run dppce sign --envelope ./runs/ev-1/envelope.json \
  --key fixtures/reference/trust/TEST-ONLY-report-signing.key.pem \
  --kid TEST-ONLY-report-key-1 --issuer urn:example:test-lab \
  --allow-unencrypted-key --out ./runs/ev-1/envelope.signed.json
```

The fixture key is not encrypted, so the demo needs `--allow-unencrypted-key`.
For your own reports, `dppce keys generate` writes a signing key that a passphrase encrypts.

Verify the signed report with the standalone verifier:

```bash
uv run python -m dppce.verifier ./runs/ev-1/envelope.signed.json \
  --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json --at 2026-10-14T00:00:00Z
```

The verifier prints one outcome for each check, called a dimension, and `"complete": true`.
The demo signature names no status entry, states no validity period, and has no timestamp.
The demo trust bundle requires none of them, so `status`, `validity`, and `timestamp` show `not_checked`.
A real recipient uses its own trust bundle and gets the issuer key through its own channel, never from the report.
For your own reports, use the time at which you rely on the report.
[Verify a report](docs/how-to/verify-a-report.md) explains each dimension.

## What a result means

<p align="center">
  <img src="docs/images/verdicts.svg" width="880" alt="Five verdicts with symbols: pass, fail, inconclusive, not applicable, and error. The overall outcome uses applicable mandatory requirements only: fail, then error, then inconclusive, then pass.">
</p>

The table and the text below describe the diagram.

| Verdict | Meaning |
| --- | --- |
| `pass` | At least one assessment path passed, and no valid observation failed. |
| `fail` | A valid observation or a declaration contradicts a selected requirement. |
| `inconclusive` | The evidence cannot establish an outcome. For example, applicability is unknown or a step did not run. |
| `not_applicable` | The requirement does not apply to the declared system. |
| `error` | An execution error prevented an outcome, and no other path passed or failed. |

The overall outcome uses the applicable mandatory requirements only.
`fail` comes first, then `error`, then `inconclusive`, then `pass`. An empty run cannot pass.
A requirement with unknown applicability is `inconclusive`. It stays outside the overall outcome, and the report counts it.
Recommended and optional requirements do not change the overall outcome.
Absent information never becomes `not_applicable`. An unavailable check never becomes `pass`.
The [verdict truth table](docs/reference/verdict-truth-table.md) lists every case.

### Execution modes and claim levels

The **execution mode** decides which requirements a run can assess.
The **claim level** says what you can cite a result as.

| Mode | A run can assess | Claim level of a result |
| --- | --- | --- |
| `illustrative`, the default | Synthetic rules only | `illustrative` |
| `exploratory` | Draft interpretations, synthetic rules, and placeholders | `diagnostic`; `illustrative` for a synthetic rule; `none` for a placeholder |
| `reviewed` | Requirements with a human approval record only | `reviewed` |

A run lists each requirement that its mode leaves out as an exclusion, with a reason code.

### Packs

A **pack** is a versioned set of requirements with a scope statement.

| Pack | Content | What a result means |
| --- | --- | --- |
| `illustrative/core` | Synthetic rules for the battery reference system | `illustrative`; no normative statement |
| `family/illustrative` | Synthetic web, GS1 resolver, AAS, and credential rules | `illustrative`; no normative statement |
| `family/oauth` | One synthetic rule: each role gets only what the declared access policy allows | `illustrative`; no normative statement |
| `eu-battery/draft` | Draft interpretations of Regulation (EU) 2023/1542 that a development agent (an AI coding assistant) wrote | `diagnostic` in `exploratory` mode; excluded in `illustrative` and `reviewed` modes |
| `en-jtc24/placeholders` | Bibliographic placeholders for eight EN standards of CEN/CLC/JTC 24 "Digital Product Passport - Framework and System" | No clause assessed; optional, so the overall outcome does not change |

No shipped requirement has the status `approved`. Only a human reviewer can approve an interpretation.
Without a signed manual result, no verdict from `eu-battery/draft` is `pass` or `fail`, in any mode.
See [how to import an approved pack](docs/how-to/import-an-approved-pack.md).

<details>
<summary>Trace a requirement from its source to a verdict</summary>

<p align="center">
  <img src="docs/images/traceability.svg" width="880" alt="Traceability: a requirement cites a source record and holds its interpretation and applicability rule. It names test purposes and checks. Step verdicts roll up to the overall outcome.">
</p>

A requirement cites a source record. It holds its interpretation, its applicability rule, and its review status.
Its assessment paths name test purposes. Each test purpose names one registered check.
A step verdict goes into the path verdict, the requirement verdict, and the overall outcome.
Each observation names its encrypted records. The report holds a salted commitment to each record.
Two Merkle roots bind the results and the records.

Print the chain from source to check for each requirement in the catalogue:

```bash
uv run dppce catalogue trace
```

</details>

<details>
<summary>Exit codes</summary>

| Code | Meaning |
| --- | --- |
| `0` | The command completed. For `run` and `replay`, the overall outcome is `pass`. For `compare`, every step verdict is equal. |
| `1` | The overall outcome is `fail`. For `compare`, a step verdict changed. |
| `2` | Usage or input error. A catalogue lint error also gives this code. |
| `3` | Execution error: the overall outcome is `error`, or the engine failed. |
| `4` | Report verification failed or is incomplete, or a replay did not reproduce the recorded digest. |
| `5` | The run completed, and the overall outcome is `inconclusive`. |

A replay can reproduce a `fail` or `inconclusive` outcome. It then returns the same exit code as the run.

</details>

## Profiles

A **profile** selects packs, test packs, and resources for one product type or one passport technology.

| Profile | For | Packs |
| --- | --- | --- |
| `battery/ev` | Electric vehicle battery passports; used in the demo | `illustrative/core`, `eu-battery/draft`, `en-jtc24/placeholders` |
| `battery/lmt` | Light means of transport battery passports | Same as `battery/ev` |
| `battery/industrial` | Industrial battery passports | Same as `battery/ev` |
| `family/web` | Web passports with HTML or JSON representations | `family/illustrative` |
| `family/gs1-resolver` | GS1 Digital Link identifiers and resolver behavior | `family/illustrative` |
| `family/aas` | Asset Administration Shell (AAS) files and API responses | `family/illustrative` |
| `family/credentials` | Signed credentials, issuer keys, and status information | `family/illustrative` |
| `family/oauth` | Passport views behind OAuth 2.0 client credentials | `family/oauth` |

The three battery profiles differ only in their product category.
Profiles combine supported checks, experimental checks, and manual steps.
Some capabilities are planned but not built (`interface_only`). A step that needs one stays `inconclusive`.
The [capability manifest](docs/reference/capabilities.md) gives the state and the limits of each capability.
A profile does not cover a law or a standard. The scope statement of each pack says what the pack covers.

Show the capabilities of your installation:

```bash
uv run dppce capabilities
```

## Test your own system

Get the permission of the system owner before any test, also for read-only access.
Read [test a real system](docs/how-to/test-a-real-system.md) before you connect to one.

**Web, GS1 resolver, AAS, and credential passports.** Draft an ICS and an IXIT for a family profile:

```bash
uv run dppce init --family web --out ./my-system
```

The `--family` option accepts `web`, `gs1-resolver`, `aas`, and `credentials`.
The command writes a draft ICS and IXIT with review comments. It grants no trust, permission, or authorization.
Then follow [draft the files for your own system](docs/tutorials/test-your-own-system.md).

**Battery passports.**

1. Copy `fixtures/reference/ev.ics.yaml` and `fixtures/reference/ev.ixit.yaml`. Declare your system, as [write an ICS and an IXIT](docs/how-to/write-an-ics-and-an-ixit.md) shows.
2. Copy the data root. Write a profile that binds your own API contract and access policy, and give the copy with `--data-root`.
3. For role credentials or probes, ask the owner to sign an authorization with `dppce authorize`.
4. Run with `--mode exploratory`. No draft entry gives `pass` or `fail` until a person signs a manual result for it (`--manual-result`).

The shipped battery profiles pin a synthetic schema. [Test a real system](docs/how-to/test-a-real-system.md) shows each step.
Role credentials, TLS client authentication, and access probes need a signed authorization that names the origin.
The operator supplies the trust bundle and confirms each origin and each secret reference.

## What people expect, and where DPP-CE stands

A development agent collected these expectations from public sources on 2026-10-29.
The sources are EU law and Commission pages, industry and research projects, and published studies. No person has reviewed the collection.
The table compares the main expectations with this version.

| People expect | Asked by | DPP-CE today |
| --- | --- | --- |
| An open test suite that runs locally and in CI | Developers, service providers | **Yes.** Open-source command line tool. Exit codes separate `fail` from `inconclusive`. JUnit XML and SARIF export. |
| Evidence that a recipient can check alone | Authorities, laboratories | **Yes, for the report.** Signed reports and a standalone verifier. A replay needs the data key of the operator. |
| Honest outcomes and bounded claims | Assessors, laboratories | **Yes.** `inconclusive` in place of a false `pass`. No certificate and no statement of legal compliance. |
| Results tied to a pinned schema or rule version | Developers, service providers | **Partly.** Each run binds its schemas and rule packs by digest. The shipped schemas are synthetic. |
| Checks of access tiers and signatures | Authorities, service providers | **Partly.** Checks a declared access policy and signatures. The EU act on access for persons with a legitimate interest was a draft in October 2026. |
| Pre-submission checks of the EU registry | Economic operators | **No.** The engine never contacts the EU registry and does not run its checks. It checks the HTTPS and identifier rules of the passport host. Its registry check reads a mock only. |
| Completeness against a battery data model | Economic operators, authorities | **No.** The battery profiles use a synthetic schema. Annex XIII entries are manual steps. |
| Interpretations that a person approved | Assessors, laboratories | **Not yet.** A development agent wrote all EU battery entries. No person has reviewed them. |
| Validation against real systems and other implementations | Researchers, developers | **Not yet.** No run against a real system or a second implementation. The method validation uses the synthetic reference system. |
| Availability over time | Service providers, repairers | **No.** One run cannot show availability over time. The engine has no back-up check. |
| Certification | Service providers | **Out of scope.** A conformance test report is not a certificate. |

### Related tools

DPP-CE is independent of the tools below. Each description summarizes the tool's own page, read on 2026-10-29.

- [BatteryPass-Ready](https://thebatterypass.eu/battery-pass-ready/faq/): a test and learning platform for battery passport solutions, free during its project phase. Its FAQ says that it is not a certification system.
- [EU DPP registry](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en): the Commission's registry, with a testing environment for economic operators.
- [CIRPASS-2 DPP validator](https://github.com/CIRPASS-2/dpp-validator): a service that checks passport payloads against a JSON Schema or a SHACL template. It calls itself exploratory and not normative.
- [UNTP tests](https://github.com/uncefact/tests-untp): test suites and a reference implementation for the UN Transparency Protocol.

## Limitations and readiness

- The method validation uses synthetic systems only. The reference system and the checks come from the same project.
- The battery profiles use a synthetic schema. No Annex XIII data point gets an automated check.
- Applicability rests on the facts that the ICS declares. The engine does not compare them with the passport.
- No interpretation has human approval. The project has no interpretation reviewer yet. See [governance](GOVERNANCE.md).
- A development agent (an AI coding assistant) wrote the draft interpretations.
- No independent human security audit and no screen-reader accessibility review exist yet.
- The [readiness record](docs/readiness.md) names the command and the commit of each recorded result. It also says which records no person has reviewed.
- The Python import surface is not a stable API yet. Use the command line and the JSON report.
- The package is not on PyPI. The [release guide](docs/how-to/install-and-verify-a-release.md) lists the release files and the container image.

## Documentation

| Your next task | Guide |
| --- | --- |
| Find any page | [Documentation index](docs/index.md) |
| Learn the terms and the inputs | [Glossary](docs/reference/glossary.md), [write an ICS and an IXIT](docs/how-to/write-an-ics-and-an-ixit.md) |
| Find commands and check limits | [Command line](docs/reference/cli.md), [capability manifest](docs/reference/capabilities.md), [reason codes](docs/reference/reason-codes.md) |
| Understand the design | [Architecture contract](docs/explanation/architecture.md), [decision records](docs/adr/README.md), [threat model](docs/explanation/threat-model.md) |
| Inspect the synthetic system | [Reference system and data formats](docs/reference/reference-system.md) |
| Check the scope and the sources | [Scope and legal mapping](docs/explanation/scope-and-legal-mapping.md), [source audit](docs/research/source-audit.md) |
| See open work | [Open questions](docs/open-questions.md), [backlog](docs/backlog.md), [task state](TASKS.md) |

## Get help

- Report a bug with the **Bug report** issue template.
- Propose, question, or correct an interpretation with the **Requirement interpretation** template.
- Report a vulnerability through the private channel in [SECURITY.md](SECURITY.md). Do not open a public issue.

## Contribute

Code, documentation, test fixtures, and interpretation reviews are welcome.
Read [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md), the [DCO](DCO.md), and [GOVERNANCE.md](GOVERNANCE.md).

```bash
uv sync --all-extras
uv run pre-commit install
uv run just check
```

For changes to checks, verdict rules, or evidence code, also run the full method validation:

```bash
uv run just validate
```

Tests use local fixtures and loopback servers only. They never contact a real DPP system or a third-party service.
To add a check, read [add a check and a test pack](docs/how-to/add-a-check-and-a-test-pack.md).
Documentation follows the [writing style](docs/reference/writing-style.md).

## Cite

GitHub's "Cite this repository" button reads [CITATION.cff](CITATION.cff).
The unreleased source also reports the version `0.1.0rc1`, so cite the version and the commit.

## License

Code: [Apache-2.0](LICENSES/Apache-2.0.txt).
Documentation, this README, and its images: [CC-BY-4.0](LICENSES/CC-BY-4.0.txt).
See [NOTICE](NOTICE) and [REUSE.toml](REUSE.toml) for attribution and file-level assignments.
Third-party materials keep their own licenses.
This repository contains no text of any EN, ISO, IEC, or DIN standard.
