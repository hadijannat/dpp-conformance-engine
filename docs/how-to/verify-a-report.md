# How to verify a report

Audience: report recipients, authorities, and assessors.
Purpose: check that a report is intact and comes from an issuer that you trust.
Prerequisites: the report file (`envelope.json`), and a trust bundle that **you** control.

Verification tells you whether the report is intact and who signed it.
It tells you nothing new about the tested system.

## Steps

1. Get the public key of the issuer through a channel that you trust.
   Do not take the key from the report.
2. Write a trust bundle. Use `fixtures/reference/trust/TEST-ONLY-trust-bundle.json` as a model
   for the format. Give each key an issuer, the purpose `report`, and a validity period.
3. Choose the evaluation time. Use the time at which you rely on the report.
4. Run the verifier.

```bash
python -m dppce.verifier envelope.json --trust my-trust-bundle.json --at 2026-10-14T00:00:00Z
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
| `signature` | No signature verifies with a key of your trust bundle and binds this report. |
| `issuer_trust` | The signing key is not in your trust bundle, or it is expired or revoked at the key validity time. Or the stated issuer identifier differs from the issuer of the key, or is `unspecified`. Or an accreditation status other than `not accredited` has no reference. The detail names the key validity time: the `genTime` of a trusted timestamp over the signature, or else the evaluation time. |
| `manual_results` | A completed manual step has no committed record or no signed result. Or the performer key is not in your trust bundle for the purpose `manual`, or is expired or revoked. Or the signed outcome differs from the report. Or the step states no test purpose digest. Or the signed test purpose digest or SUT version differs from the report. Or the review time is outside the key validity period or after the evaluation time. |
| `status` | Your policy needs fresh status evidence, and it is missing or stale. |
| `timestamp` | No token is good, or your policy needs a trusted timestamp and the report has none. The detail names the reason code of the first token. |

To check manual steps, your trust bundle must hold the keys of the performers with the purpose `manual`.
To check timestamps, list the certificate of each timestamp authority that you trust in
`timestamp_anchors`. Use the certificate of its CA, or the authority certificate itself.

## Add a trusted timestamp to a report

The engine never contacts a timestamp authority. You get the token yourself.

1. Print the imprint of each signature.

```bash
dppce timestamp imprint --envelope envelope.json
```

2. Make a request with the hexadecimal imprint. One way is OpenSSL:

```bash
openssl ts -query -digest <hex> -sha256 -cert -out request.tsq
```

3. Send `request.tsq` to a timestamp authority of your choice. Keep its response as
   `response.tsr`.
4. Attach the token to a copy of the report. The command does not verify the token.

```bash
dppce timestamp attach --envelope envelope.json --response response.tsr --out stamped.json
```

5. Verify `stamped.json` with a trust bundle that lists the authority in `timestamp_anchors`.

## Limits

- The verifier does no network I/O. Revocation comes from the snapshot in your trust bundle.
- The engine does not validate an accreditation. The verifier shows the stated status and reference.
- The verifier does not check the issuer name.
- A report carries a trusted timestamp only if the operator attaches one. The engine cannot
  timestamp an archived report again.
- A good timestamp keeps a report valid after its key expires. A token stays good after the
  certificate of its authority expires.
- You need the encrypted recording and its data key for a replay. The report alone holds
  commitments, not observations.
