# JCS test data

Audience: contributors and reviewers.
Purpose: name the source and the license of the files in this directory.
Prerequisites: none.

The files in `input/` and `output/` are unchanged copies of `testdata/input/*.json` and
`testdata/output/*.json` of the GitHub repository `cyberphone/json-canonicalization`. The
copies come from commit `32a48195b9b20fe67b1795e39e4509f14d860b45`.

Copyright 2018 Anders Rundgren. The files are licensed under the Apache License, Version 2.0.
The `LICENSE` file of the repository at the same commit gives this license. A copy of the
license is in `LICENSES/Apache-2.0.txt` of this repository.

The test `tests/test_external_vectors.py` reads these files. `catalogue/sources.yaml` holds
one record for each file with its SHA-256.

Do not edit these files. Git does not convert their line endings (see `.gitattributes`).
