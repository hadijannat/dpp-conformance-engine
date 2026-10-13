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
| `signature` | No signature verifies and binds this report. |
| `issuer_trust` | The signing key is not in your trust bundle, is expired, or is revoked. |
| `status` | Your policy needs fresh status evidence, and it is missing or stale. |
| `timestamp` | Your policy needs a trusted timestamp. This version cannot validate one. |

## Limits

- The verifier does no network I/O. Revocation comes from the snapshot in your trust bundle.
- A report from this version carries no trusted timestamp.
- You need the encrypted recording and its data key for a replay. The report alone holds
  commitments, not observations.
