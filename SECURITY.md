# Security policy

Audience: people who find a vulnerability, and operators of the engine.
Purpose: say how to report a vulnerability and what the project does with a report.
Prerequisites: none.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.0rc1 | Yes. It is a release candidate and is not for production use. |

## How to report

Do not open a public issue for a vulnerability.
Use the private vulnerability reporting of the repository host when the repository is public.
A dedicated security contact does not exist yet. See the open question OQ-008.

Include: the affected version or commit, how to reproduce the problem, and the effect.

## What happens next

These are targets of a small volunteer project. They are not a service agreement.

1. The maintainer acknowledges the report.
2. The maintainer confirms or rejects the finding and tells the reporter.
3. A fix is prepared in private, with a test that fails without the fix.
4. The fix is released with an entry in `CHANGELOG.md`. The reporter is credited if the
   reporter agrees.

## Scope notes for this engine

- The engine sends requests to systems that the operator names. Server-side request forgery,
  credential disclosure, and wrong handling of untrusted input files are in scope.
- The verifier decides whether a report can be trusted. A report that verifies when it must
  not is a vulnerability.
- A verdict that is better than the evidence supports (a false `pass`) is a security defect.
- The keys and tokens under `fixtures/reference` are test values and are public on purpose.
  Their presence is not a finding.

## Known limitations

See [docs/explanation/threat-model.md](docs/explanation/threat-model.md) and
[docs/readiness.md](docs/readiness.md). No independent security audit has been done.
