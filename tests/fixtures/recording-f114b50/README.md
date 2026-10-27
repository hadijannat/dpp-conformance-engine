# Recording from commit f114b50

Audience: maintainers of the recording format.
Purpose: prove that a recording from before record hop statuses still opens with the same commitments.
Prerequisites: none.

## Content

This directory holds the output of one `dppce run` at commit f114b50. The run used the profile
`family/gs1-resolver` against the synthetic local reference system on a loopback port. The
evaluation time was 2026-10-13T12:00:00Z. The run gave the overall verdict pass and the decision
digest `sha256:221faaa0d983c3c710239ae4bdcd227747c2b7bbb36d64831a7adc3fc114aa1b`.

- `envelope.json`: the unsigned evidence envelope of the run.
- `recording/`: the encrypted recording. Record `r0001` follows one redirect.
- `TEST-ONLY-keys/local-data-key-1.key`: the data key of the recording. It is a test key. It
  protects nothing.

The run directory files `inputs.json` and `report.html` are not kept. The test
`tests/test_redirect_hops.py` reads this directory. It does not change it.
