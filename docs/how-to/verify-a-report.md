# How to verify a report

Audience: report recipients, authorities, and assessors.
Purpose: check that a report is intact and comes from an issuer that you trust.
Prerequisites: the signed report file that `dppce sign` wrote (for example `envelope.signed.json`),
and a trust bundle that **you** control.

Verification tells you whether the report is intact and who signed it.
It tells you nothing new about the tested system.

## Steps

1. Get the public key of the issuer through a channel that you trust.
   Do not take the key from the report.
2. Write a trust bundle with `dppce trust-bundle add-key`. Give each key an issuer, the purpose
   `report`, and a validity period.

```bash
dppce trust-bundle add-key --policy-version my-policy-1 --out my-trust-bundle.json \
  --kid lab-key-1 --issuer urn:example:test-lab --purpose report --public-key lab.jwk.json \
  --not-before 2026-01-01T00:00:00Z --not-after 2027-01-01T00:00:00Z
```

   Add a key to an existing bundle with `--bundle` in place of `--policy-version`.
3. Choose the evaluation time. Use the time at which you rely on the report.
4. Run the verifier.

```bash
python -m dppce.verifier envelope.signed.json --trust my-trust-bundle.json --at 2026-10-14T00:00:00Z
```

5. Read the exit code. `0` means that every mandatory dimension passed. `4` means that the
   verification failed or is incomplete. `2` means that an input file is not usable.
6. Read each dimension in the output.

## The dimensions

| Dimension | A failure means |
| --- | --- |
| `structure` | The file is not a valid report, has a repeated key, or is not in exact canonical form. |
| `ordering` | A result or a record is repeated or moved. |
| `results_root` | A result was added, removed, or changed. |
| `records_root` | A record commitment was changed. |
| `counts` | The stated counts or the overall outcome do not match the results. |
| `signature` | No signature with the role `issuer` verifies with a key of your trust bundle and binds this report. |
| `issuer_trust` | The signing key is not in your trust bundle, or it is expired or revoked at the key validity time. Or the stated issuer identifier differs from the issuer of the key, or is `unspecified`. Or an accreditation status other than `not accredited` has no reference. The detail names the key validity time: the `genTime` of a trusted timestamp over the signature, or else the evaluation time. |
| `manual_results` | A completed manual step has no committed record or no signed result. Or the performer key is not in your trust bundle for the purpose `manual`, or is expired or revoked. Or the signed outcome differs from the report. Or the step states no test purpose digest. Or the signed test purpose digest or SUT version differs from the report. Or the review time is outside the key validity period or after the evaluation time. |
| `signers` | A signature names a key of your trust bundle but does not verify. Or your trust bundle does not give its key the purpose of its declared role. Or a reviewer key is expired, revoked, or of a different issuer. Or the issuer signatures state different lifecycle values. |
| `status` | The status list sets the bit of the report, or the list is not usable. Or the report names a status entry, a list is supplied, or your policy needs status, and no usable list is supplied. |
| `validity` | The issuer states a `valid_until` time that is before the evaluation time. |
| `timestamp` | No token is good, or your policy needs a trusted timestamp and the report has none. The detail names the reason code of the first token. |
| `opening` | The record opening that you supplied does not match its commitment, or the report does not hold that commitment. `not_checked` means that `records_root` or `ordering` failed. |
| `proof` | The inclusion proof that you supplied names a different report, or its path does not lead to the root. `not_checked` means that the root of its tree or `ordering` failed. |

To check manual steps, your trust bundle must hold the keys of the performers with the purpose `manual`.
To check timestamps, list the certificate of each timestamp authority that you trust in
`timestamp_anchors`. Use the certificate of its CA, or the authority certificate itself.

## Use a report in CI

Audience: platform engineers who run `dppce` in a CI system.
Purpose: give a CI system the steps of a report as JUnit XML or SARIF.
Prerequisites: a report file. The formats render an existing report and do not verify it.

1. Render JUnit XML.

```bash
dppce report --envelope envelope.json --format junit --out report.xml
```

2. Render SARIF 2.1.0.

```bash
dppce report --envelope envelope.json --format sarif --out report.sarif
```

The JUnit file has one testsuite for the profile and one testcase for each step.
The class name of a testcase is the test purpose identifier.
A failed step is a failure. A step with an execution error is an error.

A step that is inconclusive, blocked, unsupported, not run, or not applicable is `skipped`.
The message holds the reason code and a hint. A property holds the execution status.
No such step is ever a pass.

The SARIF file has one result for each failed step and each inconclusive step.
The rule identifier is the reason code. A failed step has the level `error`.
An inconclusive step has the level `warning`. The location is the test purpose identifier.

Both files also show the overall verdict. A verdict that is not a pass gives a case named `overall` in JUnit.
In SARIF, it gives a result with the rule `DECISION.OVERALL.` and the verdict name, for example `DECISION.OVERALL.INCONCLUSIVE`.
An excluded test purpose is a skipped testcase in JUnit.

Both files hold no payload value and no observation field.
They show the reason code, the hint, and the step message.

## Check the status of a report

The issuer can withdraw a report after signing it. It then sets the bit of the report in a signed
status list.

1. Get the status list file from the issuer. The engine never fetches it.
2. Add the status key of the issuer to your trust bundle with the purpose `status`.
3. Run the verifier with the list.

```bash
python -m dppce.verifier envelope.signed.json --trust my-trust-bundle.json --at 2026-10-14T00:00:00Z \
  --status-list status-list.jws
```

4. Read the dimension `status`. `STATUSLIST.REPORT.ACTIVE` means that the bit of the report is 0.

A report that names a status entry is not complete without a usable list.

## Check one result or one record

An inclusion proof shows that a report holds one result. A record opening discloses one record.

1. Get the proof from the issuer. The issuer writes it with `dppce prove`:

```bash
dppce prove --envelope envelope.signed.json --result R:ILL-DATA-001 --out result.proof.json
```

2. Run the verifier with the proof. Add `--opening FILE` to check a record opening.

```bash
python -m dppce.verifier envelope.signed.json --trust my-trust-bundle.json --at 2026-10-14T00:00:00Z \
  --proof result.proof.json
```

3. Read the dimension `proof`. `PROOF.LEAF.OK` names the key and the verdict of the result.

The verifier checks each file against the envelope, not against a root that the file states.
A trusted signature over the report gives the result its trust.

## Check a reviewer signature

A reviewer signs a report after the issuer. Give the key of the reviewer the purpose `review` in
your trust bundle. Never give one key the purposes `review` and `report`. The dimension `signers`
lists each signature with its key and its declared role.

## Add a trusted timestamp to a report

The engine never contacts a timestamp authority. You get the token yourself.

1. Print the imprint of each signature.

```bash
dppce timestamp imprint --envelope envelope.signed.json
```

2. Make a request with the hexadecimal imprint. One way is OpenSSL:

```bash
openssl ts -query -digest <hex> -sha256 -cert -out request.tsq
```

3. Send `request.tsq` to a timestamp authority of your choice. Keep its response as
   `response.tsr`.
4. Attach the token to a copy of the report. The command does not verify the token.

```bash
dppce timestamp attach --envelope envelope.signed.json --response response.tsr --out stamped.json
```

5. Verify `stamped.json` with a trust bundle that lists the authority in `timestamp_anchors`.

## Limits

- The verifier does no network I/O. Key revocation comes from your trust bundle. Report status
  comes from the status list file that you supply.
- The engine does not validate an accreditation. The verifier shows the stated status and reference.
- The verifier does not check the issuer name.
- A report carries a trusted timestamp only if the operator attaches one. The engine cannot
  timestamp an archived report again.
- A good timestamp keeps a report valid after its key expires. A token stays good after the
  certificate of its authority expires.
- You need the encrypted recording and its data key for a replay. The report alone holds
  commitments, not observations.
