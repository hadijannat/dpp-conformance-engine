# How to operate the engine in a laboratory

Audience: laboratory staff who operate the engine.
Purpose: run, keep, replay, verify, and purge, and know the limits of each result.
Prerequisites: an engine that you [installed and verified](install-and-verify-a-release.md).
The permission of the system owner ([test a real system](test-a-real-system.md)).
A trust bundle of version `dppce.trust/2` that you control. A key directory apart from the run
directories.

The engine produces conformance test reports. A report is not a certificate.
The engine gives no accreditation. Your laboratory procedures decide which records you keep.
See [laboratory records](../reference/laboratory-records.md).

This page describes the unreleased source after the release `v0.1.0rc1`.
That release does not have all of these functions.
See [the release and the unreleased source](install-and-verify-a-release.md#the-release-and-the-unreleased-source).

## 1. Before a run

1. Keep the output of `dppce --version`.
2. Keep the output of `dppce capabilities --json`. It shows the state of each check.

## 2. Run

1. Give each run a new `--out` directory.
2. Keep the `--keys` directory apart from the run directories.
3. Set `--retention-days N` from 0 to 3650. You decide the period.
4. Without `--retention-days`, the engine uses the value that the IXIT asks for.

An answer with a status from 500 to 599 is no answer, like a transport error.
Most checks then give `TRANSPORT.SERVER_ERROR`. The step is `inconclusive` by default.
The [reference system page](../reference/reference-system.md) names the exceptions.

The run directory holds these files:

| File | Content |
| --- | --- |
| `envelope.json` | The JSON report: decision body and signatures. |
| `report.html` | The HTML report. |
| `inputs.json` | The run inputs (`dppce.runinputs/3`) in clear text, with the trust bundle and the authorization token. Protect this file. |
| `recording/` | The encrypted records of the run, with the delete-after date. |

## 3. Sign

`dppce sign` signs an envelope with a local P-256 key in a PEM file.
Its help text says "development and tests". This version has no key management service.
Protect the key file. Do not claim more for the signature than this.

## 4. Replay

1. Replay the recording five times.

```bash
dppce replay --run RUN_DIR --keys KEYS_DIR --times 5 --json
```

2. Read the exit code. `4` means that a decision digest differs.
3. Exit code `2` with `REPLAY.INPUT.CHANGED` means that an input differs from the run.
4. Exit code `2` with `REPLAY.DATA_ROOT.MISSING` means that the recorded data root is missing.
5. Exit code `2` with `TRUST.MIGRATION.UNSCOPED_SERIAL` or `TRUST.MIGRATION.MALFORMED` means
   that the recorded trust bundle cannot be upgraded.
6. Other exit codes follow the overall outcome, as for `dppce run`.
7. Keep the output. The engine does not store a replay result.

## 5. Verify

1. Verify the signed report against your trust bundle.

```bash
dppce verify --envelope RUN_DIR/envelope.json --trust TRUST.json --at TIME --json
```

2. Read the exit code. `0` means complete. `4` means failed or incomplete. `2` means bad input.
3. Keep the output. The engine does not store a verification result.

`--at` sets the evaluation time.
The verifier checks the signing key at the earliest `genTime` of a good timestamp over its signature.
Without such a timestamp, it checks the key at the evaluation time.
The detail of `issuer_trust` names this key validity time.
A version 1 trust bundle is upgraded when the verifier loads it.
A version 1 bundle that lists revoked serial numbers gives exit code `2`.

The standalone verifier `python -m dppce.verifier` gives the same result.
See [verify a report](verify-a-report.md).

### Add a trusted timestamp

The engine never contacts a timestamp authority. You get the token yourself.

1. Print the imprint of each signature with `dppce timestamp imprint`.
2. Get a token for the imprint from a timestamp authority that you select.
3. Attach the token with `dppce timestamp attach`. It writes a new file at `--out`.
4. Keep that file. It is the report with the timestamp.
5. List the authority in `timestamp_anchors` of your trust bundle, and verify the new file.

[Verify a report](verify-a-report.md) gives the commands.

## 6. Retention and purge

1. List the recordings whose retention period has ended.

```bash
dppce purge --runs RUNS_DIR --keys KEYS_DIR
```

2. Add `--yes` to delete them. Add `--at TIME` to set the reference time.
3. Keep the output. The engine writes no purge log.

`dppce purge` deletes a recording only under the conditions of the
[architecture contract](../explanation/architecture.md), section 10.
It deletes the `recording/` directory only.
It does not delete `inputs.json`, `envelope.json`, or `report.html`.
It does not delete copies in other places.
After a purge, a replay is not possible. The signed report still verifies.

## 7. Limits of each result

| Result | What it shows | What it does not show |
| --- | --- | --- |
| Verdict and claim level | The outcome of each step under the rules of the selected mode. | A legal decision, product safety, or the truth of the data. |
| Replay | The same recording gives the same decision digest. | A new measurement of the system. |
| Verification | The report is intact. A key in your trust bundle signed it. The key was valid at the key validity time. | Anything new about the tested system. |
| Timestamp | A timestamp authority in your `timestamp_anchors` states that the signature existed at `genTime`. | That the time of the authority is correct. |
| Method-validation record | Seeded faults on a synthetic system, with numerators and denominators. | A result on a real system. `human_review_and_signature` is always `null`. |
| Purge | The recording is deleted. | The deletion of other files or of copies. |

The [reason-code catalogue](../reference/reason-codes.md) lists each reason code and its effect.
