# x509-limbo path validation test data

Audience: contributors and reviewers.
Purpose: name the source and the license of the files in this directory.
Prerequisites: none.

The 14 files in `online/` are unchanged copies of `limbo/_assets/online/*.limbo.json` of the
GitHub repository `C2SP/x509-limbo`. The copies come from commit
`1080e565f26e544bbe9cf99953be8a57c08e7e20`. They were retrieved on 2026-10-26 with the GitHub
contents API. Each file holds one test case in the Limbo format: a valid chain of a live website.
The Git blob of each copy equals the upstream object at the commit.

Copyright The Python Cryptographic Authority and individual contributors. The files are licensed
under the Apache License, Version 2.0. The `README.md` of the repository at the same commit states
this license. Its `pyproject.toml` names the holder. Its `LICENSE` file is the unfilled template.
A copy of the license is in `LICENSES/Apache-2.0.txt` of this repository.

The file `limbo.json` of the repository holds the full suite. It has about 41 MB, so this
directory does not hold it. The description of each case is one generated sentence.

SHA-256 of each file:

| File | SHA-256 |
| --- | --- |
| `online/akamai.com.limbo.json` | `48ffafd3ae64bbb84ab60d0052abae02d20f0cf662b30abdc060b624c0292644` |
| `online/amazon.com.limbo.json` | `2464c86e50cbc1a0ff4599f8ccf695006e5b1393e1e7a4ff1fceccef4b6d88b7` |
| `online/apple.com.limbo.json` | `82f8dea9311a32200454651da49804730c163062f0289500139fa73ac62f337a` |
| `online/aws.amazon.com.limbo.json` | `8a429e5994de2edcd5880e1928e7135d366cfc66276aa6f4c355b6bb9774eb33` |
| `online/bing.com.limbo.json` | `ae9ca5f69b1c88f7b07ba7ca7bf3dd4fabd590e0c008032b37425417163ab3bd` |
| `online/cloudflare.com.limbo.json` | `7b84b67abc7b6443ff9046498dbf0bf7d71e100d6f1d603183e58189cb0adae1` |
| `online/docs.python.org.limbo.json` | `f198ef184a4fce96ed1c97c0129bc01828673d1407f9c3e25f353ea932f221d8` |
| `online/facebook.com.limbo.json` | `a1d8d24bd9c168b84068c5b3c6fad2be3ed488aa57559694198bd21dbb86c8eb` |
| `online/fastly.com.limbo.json` | `90c3e94d52f8ef3873a8bd234c08c55d7098f6e948bd0b7cfc46dd24c0c96915` |
| `online/google.com.limbo.json` | `6fd98a85002aa15800423346bfba7cfc00c9137f2a36d41a4e9092595f904281` |
| `online/microsoft.com.limbo.json` | `7038ee4e48b5312e52a711b2eb0cc8c5a82dc49869c5a0d091e3099dbf55bc21` |
| `online/s3.amazonaws.com.limbo.json` | `dfecb15ddb31f543b4596dc1b23db1235931ebe4bb8190aa58872221231c99f8` |
| `online/stackoverflow.com.limbo.json` | `f359f52390b00d0a9acf67a586e3d323c4046a8c20b6083111839b84a57594dc` |
| `online/storage.googleapis.com.limbo.json` | `8ea30ee357c48c522a959693a27819bd8f756da5bdce4e3e474de4ec274e7e0e` |

The test `tests/test_external_vectors.py` reads these files. It gives each chain to the path code
of the engine. `catalogue/sources.yaml` holds one record for each file.

The path code ignores the validation time, the host name, and the key usage. The test claims only
the signature path and the certificate authority constraints of these valid chains. It claims
nothing about rejected cases.

Do not edit these files. Git does not convert their line endings (see `.gitattributes`).
