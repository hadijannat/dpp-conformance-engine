# Tutorial: your first run

Audience: new users.
Purpose: run the engine one time from plan to verified report, on synthetic data.
Prerequisites: Python 3.12 or later, [uv](https://docs.astral.sh/uv/), and a clone of the repository.

You test the local reference system. All its data are synthetic.
The keys and tokens in `fixtures/reference` are test values. Each name starts with `TEST-ONLY-`.
Nothing in this tutorial contacts a different machine.

## 1. Install

```bash
uv sync --all-extras
```

## 2. Start the reference system

Use a first terminal. Keep it open.

```bash
uv run python -m dppce.infrastructure.reference_server --port 8765
```

## 3. Look at the plan

Use a second terminal. The plan shows what a run selects. It contacts nothing.

```bash
uv run dppce plan \
  --profile battery/ev \
  --ics fixtures/reference/ev.ics.yaml \
  --ixit fixtures/reference/ev.ixit.yaml \
  --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json \
  --at 2026-10-13T12:00:00Z
```

## 4. Run

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

The command prints the overall outcome and the decision digest. The exit code is `0`.
The issuer identifier must equal the issuer of the signing key in the trust bundle.
Otherwise the signed report of step 7 does not verify as complete.
The options `--allow-private-host`, `--secrets`, and `--role-secret` are confirmations.
The engine does not let the IXIT file decide these things alone.

The time in `--at` is the evaluation time. The fixture data are fresh at that time.
A later evaluation time makes the freshness rule fail. That is the correct result.

## 5. Read the report

Open `runs/ev-1/report.html`. It starts with a summary in plain language.
Find these parts:

- the notice that the report is not a certificate;
- the issuer and its accreditation status, which is "not accredited";
- the coverage figures, each with its numerator and its denominator;
- the requirement results and the test step results;
- the exclusions: requirements that illustrative mode does not assess.

## 6. Replay

```bash
uv run dppce replay --run ./runs/ev-1 --keys ./runs/keys --times 5
```

A replay evaluates the encrypted recording again. It does not contact the reference system.
Each replay gives the same decision digest as the run.

## 7. Sign and verify

Sign the report with the test key.

```bash
uv run dppce sign --envelope ./runs/ev-1/envelope.json \
  --key fixtures/reference/trust/TEST-ONLY-report-signing.key.pem \
  --kid TEST-ONLY-report-key-1 --issuer urn:example:test-lab
```

Verify it with the standalone verifier.

```bash
uv run python -m dppce.verifier ./runs/ev-1/envelope.json \
  --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json --at 2026-10-14T00:00:00Z
```

The verifier reports each dimension separately. `status` and `timestamp` are `not_checked`,
because the test trust policy does not need them and the report carries no such evidence.

## 8. See a failure

Stop the reference system. Start it again with one seeded fault.

```bash
uv run python -m dppce.infrastructure.reference_server --port 8765 --fault leak_export
```

Run again with a new output directory. Change `--out ./runs/ev-1` to `--out ./runs/ev-2`.
The exit code is `1`. The report shows `ACCESS.LEAK.EXPORT` for the access test steps TP-ACCESS-001 and TP-ACCESS-002.

## What you learned

- A run needs explicit confirmations from the operator.
- A report states its scope, its limits, and what it left out.
- A replay reproduces the decision digest.
- Verification is separate from the verdict about the tested system.

Next: [declare your own system](../how-to/write-an-ics-and-an-ixit.md).
