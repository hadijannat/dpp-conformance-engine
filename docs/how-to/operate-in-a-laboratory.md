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
3. Name the data key with `--data-key-id`. The default is `local-data-key-1`.
4. Give `--create-data-key` on the first run only. Without it, a missing key gives
   `KEYS.DATA_KEY.UNAVAILABLE`, and the run sends no request.
5. Set `--retention-days N` from 0 to 3650. You decide the period.
6. Without `--retention-days`, the engine uses the value that the IXIT asks for.

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
This version has no key management service. Protect the key file.
Do not claim more for the signature than this.

### Make a signing key

1. Generate a passphrase of at least 32 bytes, for example with `secrets.token_urlsafe(32)`.
   Do not use a passphrase that a person chose.
2. Put it in an environment variable whose name starts with `DPPCE_SECRET_`.
   Or put it in a file in a secrets directory, and give that directory with `--secrets`.
3. Generate the key:

```bash
dppce keys generate --out lab.key.pem --passphrase-ref env:DPPCE_SECRET_LAB_PASSPHRASE > lab.jwk.json
```

4. Add `lab.jwk.json` to your trust bundle with `dppce trust-bundle add-key` and the purpose `report`.

The key file has mode 0600. It is PKCS#8 PEM, encrypted with PBES2.
PBES2 here is PBKDF2-HMAC-SHA256 with 2048 iterations and AES-256-CBC.
The installed `cryptography` package sets these values.
2048 iterations make a guess cheap, so the passphrase must have high entropy.
No option takes the passphrase itself. No command prints it.

### Sign an envelope

```bash
dppce sign --envelope RUN_DIR/envelope.json --key lab.key.pem --kid lab-key-1 \
  --issuer ISSUER --passphrase-ref env:DPPCE_SECRET_LAB_PASSPHRASE --out RUN_DIR/envelope.signed.json
```

- Give `--out NEW_FILE` or `--in-place`, exactly one. `sign` never writes over a file by default.
- `--in-place` keeps the mode of the input. It refuses a symbolic link (`SIGN.INPUT.LINK`).
- `sign` refuses an unencrypted key (`KEYS.KEY.UNENCRYPTED`). `--allow-unencrypted-key` is for
  TEST-ONLY keys.
- `sign` first checks the body of the envelope. A body that fails gives `ENVELOPE.BODY.INVALID`.

`--role` declares the role of a signature: `issuer` (the default) or `reviewer`.
Only an issuer signature can state the lifecycle of the report:

| Option | Statement |
| --- | --- |
| `--valid-until` | The last time at which the report is valid. |
| `--supersedes` | The decision digest of an earlier report that this report replaces. |
| `--status-list-id` and `--status-index` | The entry of the report in a status list. Give both or neither. |

The engine has no command that writes a status list. The issuer makes and signs the list with
other means.

### Add a reviewer signature

1. Sign the envelope as the issuer first.
2. Give the signed envelope to the reviewer.
3. The reviewer signs it with `dppce sign --role reviewer` and a key that only the reviewer holds.
4. For `--issuer`, the reviewer gives the issuer that the trust bundle states for the reviewer key.
5. Record which person holds the reviewer key. The signature names a key and a role, not a person.

`dppce sign` adds the new signature after the signatures that the envelope already has.
`run` and `replay` never make a signature.

## 4. Replay

1. Replay the recording five times.

```bash
dppce replay --run RUN_DIR --keys KEYS_DIR --times 5 --json
```

2. Read the exit code. `4` means that a decision digest differs, or that the replay did not use
   every recorded record. A request that does not match its record also gives `4`. The output
   field `every_record_replayed` tells which cause applies.
3. Exit code `2` with `REPLAY.INPUT.CHANGED` means that an input differs from the run.
4. Exit code `2` with `REPLAY.DATA_ROOT.MISSING` means that the recorded data root is missing.
5. Exit code `2` with `TRUST.MIGRATION.UNSCOPED_SERIAL` or `TRUST.MIGRATION.MALFORMED` means
   that the recorded trust bundle cannot be upgraded.
6. Other exit codes follow the overall outcome, as for `dppce run`.
7. Keep the output. The engine does not store a replay result.

## 5. Verify

1. Verify the signed report against your trust bundle. This is the file that `sign` wrote.

```bash
dppce verify --envelope RUN_DIR/envelope.signed.json --trust TRUST.json --at TIME --json
```

2. If the issuer keeps a status list, add `--status-list LIST_FILE`. Also give the list to
   `dppce report --trust`.
3. Read the exit code. `0` means complete. `4` means failed or incomplete. `2` means bad input.
4. Keep the output. The engine does not store a verification result.
5. Keep the status list file that you used. The engine does not copy it.

`--at` sets the evaluation time.
The engine never fetches a status list. You get the file from the issuer.
Your trust bundle must give the key of the list the purpose `status`.

These dimensions of the output need the most attention:

| Dimension | When it is mandatory | What it checks |
| --- | --- | --- |
| `signers` | Always | Each signature that names a key of your trust bundle verifies. The key has the purpose of the declared role. |
| `status` | When your policy sets `require_status`, you supply a list, or the report names a status entry | The status list is usable, and it does not set the bit of the report. |
| `validity` | When the issuer states `valid_until` | The evaluation time is not later than `valid_until`. |
| `opening` | When you supply `--opening` | The record opening matches its commitment, and the report holds that commitment. |
| `proof` | When you supply `--proof` | The inclusion proof leads from its result to a root of the report. |

- A fresh `status_as_of` date alone does not pass `status`. A report that names a status entry
  is not complete without a usable list.
- `signature` and `issuer_trust` consider only signatures with the role `issuer`.
- A reviewer key needs the purpose `review`. One key cannot have the purposes `review` and
  `report` (`TRUST.KEY.ROLE_CONFLICT`).
- A bad reviewer signature makes the verification incomplete. It does not change `signature`.
- `opening` or `proof` is `not_checked` when the root of its tree does not match the body.

`dppce open` writes the opening of one record. `dppce prove` writes the proof of one result.
An opening holds the plaintext of a record. Give it only to a party that is entitled to it.

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
| Verification | The report is intact. A key in your trust bundle signed it as the issuer. The key was valid at the key validity time. | Anything new about the tested system. |
| Status | The status list that you supplied does not withdraw the report. | The status in a list that you did not supply. |
| Reviewer signature | A key with the purpose `review` signed the report. | Which person reviewed it, or what that person checked. |
| Timestamp | A timestamp authority in your `timestamp_anchors` states that the signature existed at `genTime`. | That the time of the authority is correct. |
| Record opening | The salt and the plaintext give a commitment that the report holds. | That the response was true, or more than this one record. |
| Inclusion proof | The report holds this result at this position. | Anything about the other results. A trusted signature over the report gives the result its trust. |
| Method-validation record | Seeded faults on a synthetic system, with numerators and denominators. | A result on a real system. `human_review_and_signature` is always `null`. |
| Purge | The recording is deleted. | The deletion of other files or of copies. |

The [reason-code catalogue](../reference/reason-codes.md) lists each reason code and its effect.
