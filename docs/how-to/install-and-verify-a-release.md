# How to install and verify a release

Audience: operators and laboratory staff who install a release.
Purpose: install the wheel or the container image, and verify its build provenance first.
Prerequisites: Python 3.12 or later with `uv` or `pip`, or Docker. The GitHub CLI with the
`gh attestation` command. Network access to GitHub.

Verify the build provenance of a file before you install it.
The commands on this page are the commands that the [readiness page](../readiness.md),
section 2, records for `v0.1.0rc1`. This documentation change did not run them again.

## 1. What a release holds

| Item | Where |
| --- | --- |
| Wheel, sdist, and SBOM (`sbom.cdx.json`) | Assets of the GitHub pre-release `v0.1.0rc1` of `hadijannat/dpp-conformance-engine` |
| Container image | `ghcr.io/hadijannat/dpp-conformance-engine:v0.1.0rc1` |
| Image digest | `sha256:09055b7e140659ec37ce05491c9bda8fc66549018901813d4a5a58596502b3ce` |

The workflow `release.yml` signed build provenance for each item. The format is SLSA provenance v1.
The package is not published on PyPI.

### The release and the unreleased source

This page describes the release `v0.1.0rc1`.
The [operate page](operate-in-a-laboratory.md) and the [laboratory records](../reference/laboratory-records.md)
page describe the unreleased source after `v0.1.0rc1`.
That source reports the same version string, `0.1.0rc1`.
The section Unreleased of `CHANGELOG.md` records changes after that release.
These changes are not in `v0.1.0rc1`, and they affect a laboratory:

- The replay input check and the data-root check (`REPLAY.INPUT.CHANGED`, `REPLAY.DATA_ROOT.MISSING`).
- The issuer binding of [ADR 0014](../adr/0014-the-issuer-statement-of-a-report-is-bound-to-the-signing-key.md).
  With the unreleased source, give `--issuer-id` to `dppce run`.
- The trust bundle version `dppce.trust/2`. Each revoked serial number names its issuer, and each
  revocation has a `revoked_at` time. `v0.1.0rc1` reads version 1 only.
- The unreleased source upgrades a version 1 trust bundle when it loads it. It refuses a bundle
  that lists revoked serial numbers (`TRUST.MIGRATION.UNSCOPED_SERIAL`).
- The run-inputs file `inputs.json` with version `dppce.runinputs/3`. `v0.1.0rc1` writes version 1.
- The decision body `dppce.decision/2`. The verifier of `v0.1.0rc1` rejects it.
- RFC 3161 timestamps (ADR 0015) and the commands `dppce timestamp imprint` and
  `dppce timestamp attach`.
- An answer with a status from 500 to 599 counts as no answer. Most checks then give
  `TRANSPORT.SERVER_ERROR`, and the step is `inconclusive` by default.
- An answer with the status 429 counts as no answer too. The checks then give
  `TRANSPORT.RATE_LIMITED`, also `integrity.jws`, and the step is `inconclusive` by default.
- Signed report status lists ([ADR 0016](../adr/0016-report-status-lists-validity-and-signer-roles-are-stated-in-the-attestation.md)).
  `dppce verify`, `dppce report`, and `python -m dppce.verifier` read a list with `--status-list`.
- The attestation version `dppce.attestation/2` with `role`, `status`, `valid_until`, and
  `supersedes`. The verifier of `v0.1.0rc1` refuses a signature with version 2.
- Reviewer signatures with `dppce sign --role reviewer`, and the trust purposes `review` and `status`.
- The verifier dimensions `signers` and `validity`. The dimension `status` passes only with a
  supplied status list that does not withdraw the report.

If you install the engine from source, keep the commit and the output of `dppce --version`.

## 2. Verify and install the wheel

1. Download the wheel from the release.

```bash
gh release download v0.1.0rc1 --repo hadijannat/dpp-conformance-engine --pattern '*.whl'
```

2. Verify the build provenance of the wheel. The command contacts GitHub.

```bash
gh attestation verify <wheel file> --repo hadijannat/dpp-conformance-engine
```

3. Stop if the verification fails. Do not install the file.
4. Install the wheel into a new virtual environment. The extras `qr` and `aas` are optional.

```bash
uv venv
uv pip install '<wheel file>[qr,aas]'
```

5. Activate the virtual environment.

```bash
source .venv/bin/activate
```

6. Check the installation.

```bash
dppce --version
dppce capabilities
dppce catalogue lint
```

`dppce capabilities` shows the state of each optional dependency.
A capability without its dependency gives `unsupported`, never `pass`.

## 3. Verify and run the container image

1. Verify the build provenance of the image by its digest. The command contacts GitHub.

```bash
gh attestation verify oci://ghcr.io/hadijannat/dpp-conformance-engine@sha256:<digest> \
  --repo hadijannat/dpp-conformance-engine
```

2. Pull the image by its digest, not by its tag. A tag can move. A digest cannot.

```bash
docker pull ghcr.io/hadijannat/dpp-conformance-engine@sha256:<digest>
```

3. Run the image once to check it.

```bash
docker run --rm ghcr.io/hadijannat/dpp-conformance-engine@sha256:<digest> --version
```

The image runs as uid 10001 and writes only to mounted volumes.
For a run, the mounted directory must be writable by uid 10001.
This project has not tested a run with a mounted volume.
This page therefore gives no volume example and no `--user` option.

## 4. What the verification shows

The verification shows which workflow, tag, and commit built the file.
It does not show that the code is free of defects.
Build provenance is not a certificate. It is not a conformance test report.

Keep the output of each verification as a laboratory record.
Add `--format json` to `gh attestation verify` to get a file that you can keep.
See [laboratory records](../reference/laboratory-records.md).

## 5. Fixtures and the tutorial

The wheel holds no test and no fixture.
The [tutorial](../tutorials/first-run.md) uses the local reference system, so it needs a clone of
the repository.
