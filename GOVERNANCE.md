# Governance

Audience: contributors, users, and assessors.
Purpose: say who decides what, and what a decision does not mean.
Prerequisites: none.

## Roles

| Role | Who | Decides |
| --- | --- | --- |
| Maintainer and copyright holder | Hadi Jannatabadi | Releases, licenses, scope, and who can approve interpretations |
| Interpretation reviewer | Not appointed (OQ-002) | Whether a requirement interpretation becomes `approved` |
| Contributor | Anyone who follows `CONTRIBUTING.md` | Nothing alone; proposes changes |

## What needs a human decision

- A change of license.
- A release, a push to a public remote, and each publication of an artifact.
- The promotion of a requirement interpretation to `approved`.
- Contact with a real system under test, and the use of real credentials.
- A change of the authorized scope of a test.

A development agent can prepare each of these. It cannot make the decision.

## Release approval

The `release` workflow publishes from jobs that use the GitHub environment `release`. The owner
creates this environment and its required reviewers in the repository settings. This page does
not state that the environment exists.

A gate job stops the release when one of these conditions is true:

- The environment has no required reviewer (`RELEASE.ENVIRONMENT.UNPROTECTED`).
- The tag is not `v` followed by the version in `pyproject.toml` (`RELEASE.TAG.VERSION_MISMATCH`).
- The `ci` workflow did not pass for the tagged commit on `main` (`RELEASE.CI.NOT_PASSED`).

A scan job then scans a build of the tagged commit with Trivy. A high or critical finding with a
fix stops the release before the approval.

To make a release:

1. Push the commit to `main` first.
2. Wait until the `ci` run for that commit passes. Then push the tag.
3. Tag only a commit that has its own `ci` run on `main`.
4. If the gate stops with `RELEASE.CI.NOT_PASSED`, rerun the `ci` run for that commit. Then rerun
   the `release` workflow.

## Normative content

Requirement interpretations follow the lifecycle in the
[architecture contract](docs/explanation/architecture.md), section 4, and
[ADR 0007](docs/adr/0007-only-a-documented-human-approval-makes-an-interpretation-approved.md).
Agreement between agents is not a human approval. A human approval is not accreditation.

## Changes to the engine contract

A change to the verdict rules, the evidence format, or the transport policy needs a new
architecture decision record. The same change also updates the contract.

## Reports

A report states its issuer and the accreditation status of that issuer. This project is not an
accredited body. Nothing in this repository gives a report the standing of a certificate.
