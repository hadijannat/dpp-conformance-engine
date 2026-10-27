# Recording from commit f114b50

Audience: maintainers of the recording format.
Purpose: prove that a recording from before record hop statuses still opens with the same commitments.
Prerequisites: none.

## Content

This directory holds the output of one `dppce run` at commit f114b50. The run used the profile
`family/gs1-resolver` against the synthetic local reference system on a loopback port. The
sample `gs1_declared` was `fixtures/reference/samples/TEST-ONLY-gs1-declared.json`, and the
data key identifier was `TEST-ONLY-data-key-1`. The evaluation time was 2026-10-13T12:00:00Z.
The run gave the overall verdict pass and the decision digest
`sha256:6bb7dfe16661e291f291b7d548e482f72484eacd8c2728ad6e7838d08dbf6997`.

- `envelope.json`: the unsigned evidence envelope of the run.
- `recording/`: the encrypted recording. Record `r0001` follows one redirect.
- `TEST-ONLY-keys/TEST-ONLY-data-key-1.key`: the data key of the recording. It is a test key.
  It protects nothing.

The run directory files `inputs.json` and `report.html` are not kept. The test
`tests/test_redirect_hops.py` reads this directory. It does not change it.
