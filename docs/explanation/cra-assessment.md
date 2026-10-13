# Cyber Resilience Act: applicability and readiness notes

Audience: the maintainer, and anyone who plans to distribute or operate the engine.
Purpose: record how Regulation (EU) 2024/2847 could apply to this project, and what exists.
Prerequisites: none.

**This page is not legal advice and makes no statement of legal compliance.**
It is an engineering self-assessment by the project. The source audit read the provisions that
it cites through a summarizing tool. The wording here is paraphrase. A lawyer has not reviewed it.

## Source and dates

Regulation (EU) 2024/2847 was published on 20 November 2024 and entered into force on
10 December 2024. It applies in phases. The audit recorded these dates from Article 71(2):

| Date | What applies |
| --- | --- |
| 11 June 2026 | Chapter IV, on the notification of conformity assessment bodies |
| 11 September 2026 | Article 14, on the reporting of actively exploited vulnerabilities and severe incidents |
| 11 December 2027 | The rest of the Regulation |

See `catalogue/sources.yaml` for the source record and its verification level.

## Which role could this project have?

The answer depends on facts that this repository does not decide.

| Question | Why it matters | State |
| --- | --- | --- |
| Is the engine made available on the market in the course of a commercial activity? | Article 3(22) defines making available by commercial activity. | Open: OQ-020. The engine is free and open-source software and is not published. |
| Does a person place it on the market under a name or a trademark? | Article 3(13) defines the manufacturer. | Open: OQ-020. |
| Does a legal person support its development for commercial use on a sustained basis? | Article 3(14) defines the open-source software steward, and Article 24 gives stewards lighter duties. | Open: no such legal person exists today. |
| Does an organization integrate the engine in a product? | Article 13(5) asks a manufacturer for due diligence on third-party components. | That duty is on the integrator. The artifacts below support it. |

## What exists that supports the relevant duties

| Topic | Artifact | State |
| --- | --- | --- |
| Vulnerability handling policy | `SECURITY.md` | Written. No dedicated contact exists (OQ-019). |
| Secure development | Strict typing, lint, tests, an automated review of each commit, the [threat model](threat-model.md) | In use during development. No independent audit. |
| Component inventory | `uv.lock` with hashes; `uv run just sbom` writes a CycloneDX SBOM | The tool ran locally: CycloneDX 1.6. No SBOM is published. |
| Dependency licenses | `docs/reference/dependency-licenses.md` | Generated from the environment. |
| Dependency updates | `.github/dependabot.yml` | Configured. Not active: the repository is not on a host. |
| Build provenance | `.github/workflows/release.yml` | Configured. Never executed. |
| Secret scanning | `.gitleaks.toml` and a pre-commit hook | Configured. Not run. |
| Support period | none | Not defined. |
| Reporting of exploited vulnerabilities | none | No process exists. |

## What is missing before any claim

- A decision on the role of the project and of its maintainer under the Regulation.
- A security contact and a documented handling process with a named person.
- A defined support period and an update policy for released versions.
- A vulnerability scan of the dependencies as part of each release.
- A legal review of this page.
