# dpp-conformance-engine

An open-source, vendor-neutral conformance test engine for Digital Product Passports (DPP).
The first profiles are for battery passports. The core does not depend on a product type.

> **Status: release candidate 0.1.0rc1. Not for production use.**
> The engine produces **conformance test reports**. A report is **not a certificate**.
> It does not show that product data are true, that a product is safe, or that all legal
> obligations are met. The issuer of a report is **not accredited** unless the report says so.

## What it does

- Reads a catalogue of requirements. Each requirement traces to a source provision, an
  interpretation, an applicability rule, test purposes, and executable checks.
- Plans a run from the declarations of the system owner (ICS) and the test information (IXIT).
- Runs the checks through one policy-enforcing transport and records each exchange, encrypted.
- Aggregates verdicts with a published truth table: `pass`, `fail`, `inconclusive`,
  `not_applicable`, `error`.
- Replays a recording and reproduces the same verdicts and the same decision digest.
- Writes a JSON report and an accessible HTML report, and signs the report. A standalone verifier
  checks it. The verifier needs neither the engine nor the tested system.

## What the shipped catalogue is, and is not

| Pack | Content | What a result means |
| --- | --- | --- |
| `illustrative/core` | Synthetic rules for the local reference system | It shows how the engine behaves. It makes no normative claim. |
| `eu-battery/draft` | Agent-authored **draft** interpretations of Regulation (EU) 2023/1542 | A diagnostic outcome. No human has approved these interpretations. |
| `en-jtc24/placeholders` | One placeholder for each of eight EN standards | Nothing is assessed. No text of a standard is in this repository. |

No requirement in this repository has the status `approved`. A reviewed claim needs a pack
that a human maintainer writes, reviews, and imports. See
[how to import an approved pack](docs/how-to/import-an-approved-pack.md).

## Quick start

Prerequisites: Python 3.12 or later, and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-extras
```

Start the local reference system. All its data are synthetic.

```bash
uv run python -m dppce.infrastructure.reference_server --port 8765
```

In a second terminal, run the EV battery profile against it.

```bash
uv run dppce run \
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
  --keys ./runs/keys --out ./runs/ev-1
```

The issuer identifier must equal the issuer of the signing key in the trust bundle.
Otherwise a signed report does not verify as complete.

Replay the recording, sign the report with the test key, and verify it.

```bash
uv run dppce replay --run ./runs/ev-1 --keys ./runs/keys --times 5
```

```bash
uv run dppce sign --envelope ./runs/ev-1/envelope.json \
  --key fixtures/reference/trust/TEST-ONLY-report-signing.key.pem \
  --kid TEST-ONLY-report-key-1 --issuer urn:example:test-lab
```

```bash
uv run python -m dppce.verifier ./runs/ev-1/envelope.json \
  --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json --at 2026-10-14T00:00:00Z
```

Open `./runs/ev-1/report.html` to read the report.
The keys and tokens under `fixtures/reference` are test values. Each name starts with `TEST-ONLY-`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command completed. For `run` and `replay`: the overall outcome is `pass`. |
| 1 | The system under test failed. |
| 2 | Usage or input error. |
| 3 | Execution error in the engine. |
| 4 | Report verification failed or is incomplete, or a replay digest differs. |
| 5 | The run completed and the overall outcome is `inconclusive`. |

## Safety rules of the engine

- The default target is an offline fixture or the local reference system.
- A real system needs prior authorization from its owner, also for read-only access.
  Writes, tampering, fuzzing, and access probes need a signed authorization.
- The ICS and the IXIT are untrusted input. The operator supplies the trust bundle and confirms
  each non-public host and each secret reference.
- Tests in this repository never contact a real DPP system or a third-party service.

## Documentation

- [Architecture and engineering contract](docs/explanation/architecture.md)
- [Reference system and data formats](docs/reference/reference-system.md)
- [Source audit](docs/research/source-audit.md) and [open questions](docs/open-questions.md)
- [Readiness and limitations](docs/readiness.md)
- [Architecture decision records](docs/adr/README.md)
- [Current task state](TASKS.md)

## Development

```bash
uv run just check
```

```bash
uv run just validate
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability as [SECURITY.md](SECURITY.md) says.

## License

Code: Apache-2.0. Documentation in `docs/`: CC-BY-4.0. See `LICENSES/`, `NOTICE`, and `REUSE.toml`.
Third-party software keeps its own license. This repository contains no text of any EN, ISO,
IEC, or DIN standard.
