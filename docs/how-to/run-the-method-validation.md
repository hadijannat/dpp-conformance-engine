# How to run the method validation

Audience: assessors and contributors.
Purpose: reproduce the validation of the checks against seeded faults.
Prerequisites: an installed development environment with the `qr` extra.

## What it does

`validation/fault-catalogue.yaml` lists seeded faults, valid controls, boundary cases, and
evidence faults. Each entry states the expected outcome. The expected outcomes were written
before the checks existed.

A fault counts as detected only if the named test step gives the expected verdict with the
expected reason code. A crash of the runner is not a detection.

## Steps

1. Run the fault matrix as tests.

```bash
uv run pytest -m validation
```

2. Write a dated record.

```bash
uv run python -m validation.run
```

3. Read the record in `validation/records/`. Each figure has a numerator and a denominator.

## How to read the record

| Field | Meaning |
| --- | --- |
| `fault_detection` | Seeded fault and profile combinations that were detected for the intended reason |
| `false_positives_on_controls` | Executed steps of the unmodified reference system that did not pass |
| `boundary_cases` | Cases that must not be reported as a failure, with the expected outcome |
| `evidence_faults` | Changed reports that failed verification on the named dimension |
| `replays` | Replays that gave the same decision digest |
| `reviewer` | The human who reviewed the record. `null` means that nobody did. |
| `environment.git.uncommitted_changes` | `true` means that the record does not describe a committed state. |

## Limits

The reference system is synthetic, and the same project wrote it and the checks.
A detection shows that a check finds a known kind of fault. It does not show that the check
finds every fault of that kind. The record is not accreditation.
