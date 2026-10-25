# How to run the method validation

Audience: assessors and contributors.
Purpose: reproduce the validation of the checks against seeded faults.
Prerequisites: an installed development environment with the `qr` and `aas` extras
(`uv sync --all-extras`).

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
   The field `human_review_and_signature` is always `null`. The engine never fills it.

## Family profiles

The validation also runs the family profiles. Each family control names one family profile.
The rig uses the shipped example ICS and IXIT in `profiles/family/examples/`. The trust bundle,
keys, issuer, evaluation time, and loopback origin are the same as for the battery runs.

| Control | Profile |
| --- | --- |
| `C-FAMILY-WEB` | `family/web` |
| `C-FAMILY-GS1` | `family/gs1-resolver` |
| `C-FAMILY-VC` | `family/credentials` |
| `C-FAMILY-AAS` | `family/aas`, with the synthetic file `fixtures/aas/environment-valid.json` |

`C-FAMILY-AAS` needs the optional `aas` extra. Without it, the AAS check gives `unsupported`,
and the control does not pass.

A family control passes only if every executed step of its profile passes. Its executed steps
count in `false_positives_on_controls`. Its result counts in `controls` and `replays`.

### The per-case field `profiles`

A fault entry can name the profiles that it runs under. Use full profile ids.

```yaml
  - id: F-50
    fault: example_flag
    test_purpose: TP-GS1-RESOLVE-001
    profiles: [family/gs1-resolver]
    expected: {verdict: fail, reason_code: EXAMPLE.REASON}
```

An entry without `profiles` runs under the catalogue-level `profiles`, the battery profiles.
A boundary case runs once, so it names at most one profile. More than one is a catalogue error.

Each listed profile must plan the test purpose of the entry. If a profile does not plan it,
the validation stops with a catalogue error. It never skips the case.

## How to read the record

| Field | Meaning |
| --- | --- |
| `fault_detection` | Seeded fault and profile combinations that were detected for the intended reason |
| `false_positives_on_controls` | Executed steps of the unmodified reference system that did not pass |
| `controls` | Valid controls whose run passed with every planned step completed. A step that stops completing counts against its control. A planned skip (`PLAN.SKIPPED`) does not. |
| `boundary_cases` | Cases that must not be reported as a failure, with the expected outcome |
| `evidence_faults` | Changed reports that failed verification on the named dimension |
| `replays` | Replays that gave the same decision digest |
| `reviewer` | The human who reviewed the record. `null` means that nobody did. |
| `environment.git.uncommitted_changes` | `true` means that the record does not describe a committed state. |

## Limits

The reference system is synthetic, and the same project wrote it and the checks.
A detection shows that a check finds a known kind of fault. It does not show that the check
finds every fault of that kind. The record is not accreditation.
