# Tutorial: draft the files for your own system

Audience: operators who prepare a first test of a passport system.
Purpose: draft an ICS and an IXIT with `dppce init`, then run them against the local reference system.
Prerequisites: the [first run](first-run.md) tutorial, Python 3.12 or later, [uv](https://docs.astral.sh/uv/), and a clone of the repository.

`dppce init` drafts two files for a family profile from the shipped examples.
The ICS says what the system declares. The IXIT says what the test needs.
Both drafts are untrusted input, as every ICS and IXIT is.
`init` writes no confirmation, no secret, no trust choice, and no authorization.
You give each of these on the command line yourself.

This tutorial uses the family profile `family/web` and the local reference system.
All its data are synthetic. Nothing in this tutorial contacts a different machine.

## 1. Install

```bash
uv sync --all-extras
```

## 2. Start the reference system

Use a first terminal. Keep it open.

```bash
uv run python -m dppce.infrastructure.reference_server --port 8765
```

## 3. Draft the files

Use a second terminal.

```bash
uv run dppce init --family web --out ./my-system
```

The command writes `my-system/web.ics.yaml` and `my-system/web.ixit.yaml` with mode 0600.
It refuses to replace a file that exists. Add `--force` to replace it.
It also prints the next commands. Each value in angle brackets is a placeholder.
A step marked `decide` needs a decision by a person.

## 4. Review the drafts

Open the two files. A `# review:` comment stands above each field.
The comment says what you must check or replace.

For the reference system, keep the values as they are.
For a real system, do these things:

- Replace each synthetic value, for example the name and the identifier of the system.
- Declare only the features that the system implements.
- Delete `origin_override`. It sends each request to the loopback reference system.
- Name the hosts of the system in `allowed_hosts`.
- Put the sample files of the system next to the IXIT.

A carrier identifier fills some fields for you. The engine parses it offline.

```bash
uv run dppce init --family gs1-resolver --carrier https://id.example.test/01/09506000134352/21/EV0001 --out ./my-carrier
```

The command fills the identifier scheme, the granularity, and the public origin.
It removes the synthetic samples of the example. A missing sample makes its step inconclusive.
It never makes the step pass or fail.

## 5. Look at the plan

The plan shows what a run selects. It contacts nothing.

```bash
uv run dppce plan --profile family/web --ics ./my-system/web.ics.yaml --ixit ./my-system/web.ixit.yaml
```

## 6. Run

```bash
uv run dppce run --profile family/web --ics ./my-system/web.ics.yaml --ixit ./my-system/web.ixit.yaml --trust fixtures/reference/trust/TEST-ONLY-trust-bundle.json --allow-private-host http://127.0.0.1:8765 --issuer-name "synthetic test laboratory" --issuer-id urn:example:test-lab --at 2026-10-13T12:00:00Z --keys ./runs/keys --create-data-key --out ./runs/web-1
```

The command prints the overall outcome and the decision digest. The exit code is `0`.
The trust bundle is a TEST-ONLY bundle. It fits the reference system only.

## 7. What you must decide

`init` cannot make these decisions. A person makes each of them for each run.

| Decision | Who decides | Where |
| --- | --- | --- |
| Which keys the test host trusts: report, passport signer, system owner | the operator | `--trust`, a bundle from `dppce trust-bundle add-key` |
| Which key signs the conformance test reports | the operator | `dppce keys generate` |
| Each loopback or private origin to contact | the operator | `--allow-private-host ORIGIN` |
| Each public origin to contact | the system owner permits it, the operator confirms it | `--allow-remote-host ORIGIN` or `--authorization` |
| Role secrets, writes, and authorized origins | the system owner | `dppce authorize` |
| The issuer of the conformance test report | the operator | `--issuer-name` and `--issuer-id` |
| How long the recording stays | the operator | `--retention-days` |

## What you learned

- `dppce init` drafts the ICS and the IXIT. You still review each field.
- The drafts cannot trust a key, confirm a host, or select a secret.
- The run needs explicit confirmations from a person.

Next: [test a real system with authorization](../how-to/test-a-real-system.md).
