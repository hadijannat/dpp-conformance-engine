# Tasks

Audience: maintainers and any agent that resumes the work.
Purpose: show what is done, what the evidence is, and what to do next.
Prerequisites: read `state/progress.json` for the cycle counter and the limits.

A check that was not executed is marked **not run**. It is never marked passed.

## Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| M0 | Audit: inventory, routing, source audit, scope, risks, reuse decisions | in progress |
| M1 | Foundation: structure, community files, schemas, CLI, CI, docs, style checks, capability manifest | not started |
| M2 | Semantics: lifecycle, packs, ICS and IXIT validation, planning, applicability, coverage, verdicts | not started |
| M3 | Vertical slice: three battery profiles, plan to report, core adapters | not started |
| M4 | Evidence: encryption, canonical body, signing, scope binding, standalone verifier | not started |
| M5 | Method validation: faults, controls, replays, property and mutation tests, readiness | not started |
| M6 | Release candidate: documentation, clean install, SBOM, workflows, capability report | not started |

## M0 work log

- [x] Workspace inventory. Result: empty apart from `.remember/` (session tooling, ignored by git).
- [x] Toolchain probe. Result: see `docs/research/tool-model-routing.md`.
- [x] Model routing probe. Result: four aliases accepted delegation.
- [ ] Source audit, research pass 1.
- [ ] Source audit, research pass 2 (adversarial check of high-risk claims).
- [ ] Scope statement, risk register, and reuse decisions.

## Commands executed

| Command | Exit status | Note |
| --- | --- | --- |
| `uv --version` | 0 | `uv 0.9.24` |
| `python3 --version` | 0 | `Python 3.12.3` |
| `git --version` | 0 | `git version 2.51.2` |
| `just --version` | 127 | not installed |
| `vale --version` | 127 | not installed |
| `docker --version` | declined | not probed |
| `brew install just vale` | 1 | Xcode license not accepted |
| `git init -b main` | 0 | local repository created |

## Resume instructions

1. Read `state/progress.json`. Do not exceed `session.max_cycles`.
2. Read `docs/open-questions.md` and `docs/backlog.md`.
3. Continue with the first unchecked item in the work log of the milestone that is in progress.
