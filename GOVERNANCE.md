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

## Normative content

Requirement interpretations follow the lifecycle in the
[architecture contract](docs/explanation/architecture.md), section 4, and
[ADR 0007](docs/adr/0007-only-a-documented-human-approval-makes-an-interpretation-approved.md).
Agreement between agents is not a human approval. A human approval is not accreditation.

## Changes to the engine contract

A change to the verdict rules, the evidence format, or the transport policy needs a new
architecture decision record and an update of the contract in the same change.

## Reports

A report states its issuer and the accreditation status of that issuer. This project is not an
accredited body. Nothing in this repository gives a report the standing of a certificate.
