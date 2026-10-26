# Synthetic identity samples

Audience: contributors and assessors.
Purpose: name the synthetic samples that the cross-family identity test purposes read.
Prerequisites: none.

The project wrote each file in this directory by hand. Each file is synthetic and `TEST-ONLY`.
`scripts/gen_fixtures.py` does not write them. The rows of `validation/cases.py` copy them
into the rig as IXIT samples.

| File | Sample | Use |
| --- | --- | --- |
| `TEST-ONLY-vc-subject.json` | `vc_json` | The control `C-FAMILY-VC`: the `credentialSubject` `id` is the carrier identifier. |
| `TEST-ONLY-vc-subject-differs.json` | `vc_json` | `F-67`: the `credentialSubject` `id` has another serial. |
| `TEST-ONLY-gs1-declared.json` | `gs1_declared` | The control `C-FAMILY-GS1`: the `id` is the carrier identifier. |
| `TEST-ONLY-gs1-padded-gtin.json` | `gs1_declared` | `B-17`: the `id` has the GTIN in 13-digit form and the same serial. |
| `TEST-ONLY-gs1-serial-differs-padded.json` | `gs1_declared` | `F-68`: the `id` has the GTIN in 13-digit form and another serial. |

The credential samples are not signed. `TP-VC-CONSISTENCY-001` reads the subject only.
