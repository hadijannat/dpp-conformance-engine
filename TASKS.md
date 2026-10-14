# Tasks

Audience: maintainers and any agent that resumes the work.
Purpose: show what is done, what the evidence is, and what to do next.
Prerequisites: read `state/progress.json` for the cycle counter and the limits.

A check that was not executed is marked **not run**. It is never marked passed.

## Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| M0 | Audit: inventory, routing, source audit, scope, risks, reuse decisions | complete |
| M1 | Foundation: structure, community files, schemas, CLI, CI, docs, style checks, capability manifest | blocked: CI never ran (nothing is pushed); Vale cannot be installed (OQ-005) |
| M2 | Semantics: lifecycle, packs, ICS and IXIT validation, planning, applicability, coverage, verdicts | complete; no interpretation approved (needs a human, OQ-002) |
| M3 | Vertical slice: three battery profiles, plan to report, core adapters | complete |
| M4 | Evidence: encryption, canonical body, signing, scope binding, standalone verifier | complete |
| M5 | Method validation: faults, controls, replays, property and mutation tests, readiness | complete |
| M6 | Release candidate: documentation, clean install, SBOM, workflows, capability report | blocked: no release or publication without the approval of the user; workflows and container never ran |

"Complete" means that the local gates ran and passed for the milestone. It does not mean that
a human reviewed the work. The evidence for each figure is in `docs/readiness.md`.

## M0 work log

- [x] Workspace inventory. Result: empty apart from `.remember/` (session tooling, ignored by git).
- [x] Toolchain probe. Result: see `docs/research/tool-model-routing.md`.
- [x] Model routing probe. Result: four aliases accepted delegation.
- [ ] Source audit, research pass 1. Running. Raw results: `docs/research/raw/<group>.json`.
- [ ] Source audit, research pass 2 (adversarial check of high-risk claims). Running.
- [ ] Build `catalogue/sources.yaml` and `docs/research/source-audit.md` from the raw results.
- [ ] Scope statement, risk register, and reuse decisions.

## Implementation work log (cycle 3, coordinator)

Written and committed. Gates on this code: `uv run just check` exit 0.

- [x] `dppce.models`: 14 contracts with generated JSON Schemas. Sync test and migration test pass.
- [x] `dppce.applicability`: three-valued evaluator.
- [x] `dppce.verdicts`: step, path, requirement, and overall precedence; coverage summary.
- [x] `dppce.orchestrator`: deterministic planner; run and evaluate core (one path for live and replay).
- [x] `dppce.catalogue`: safe loaders, lint rules CAT001 to CAT015, trace matrix.
- [x] `dppce.evidence`: canonical JSON, Merkle tree, encrypted recording, salted commitments, JWS ES256, envelope.
- [x] `dppce.verifier`: standalone verifier with separate dimensions; `python -m dppce.verifier`.
- [x] `dppce.infrastructure`: policy transport, redaction, replay, clocks, key providers, authorization.
- [x] `dppce.report`: self-contained HTML report. Manual accessibility review: not run.
- [x] `dppce.cli`: plan, run, replay, report, sign, verify, catalogue lint, catalogue trace, coverage, capabilities, purge.
- [x] `dppce.adapters.capabilities`: capability manifest with 29 entries.
- [ ] `dppce.adapters`: the 13 checks of the contract. Not started. No check is registered yet.
- [ ] Reference DPP server, fixtures, profiles, illustrative pack, test pack. Not started.
- [ ] End-to-end run. Not possible yet: no check and no profile exists.

Security findings from the automated commit review, all fixed in the cycle they were found:

1. Verifier parser differential (repeated key, coerced type, defaulted field).
2. SSRF through NAT64, 6to4, Teredo, and multicast addresses.
3. Secrets in recorded headers and URLs; caller headers forwarded across origins.
4. The IXIT could select the trust bundle, arbitrary secrets, files outside its directory, and private hosts.

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
| `uvx --from 'reuse[charset-normalizer]' reuse download Apache-2.0 CC-BY-4.0` | 0 | license texts from SPDX |
| `uv sync` | 0 | 44 packages installed |
| `uv sync --all-extras` | 0 | zxing-cpp 3.1.1, pillow 12.3.0, aas-test-engines 1.0.3 added |
| `uv run python scripts/gen_schemas.py --check` | 0 | 14 schemas; checked |
| `uv run just check` | 0 | ruff format, ruff check, mypy --strict (46 files), pytest: 162 passed |

## State at the end of the session (2026-10-14)

All fast gates pass. Every finding of the three agent reviews is fixed or filed as an open
question. The figures below come from commands that ran in this session.

| Check | Result | Commit |
| --- | --- | --- |
| `uv run just check` | format, lint, mypy strict clean; 1200 passed, 63 deselected | `9066e64` |
| `uv run pytest -m validation` | 63 passed | `9066e64` |
| `uv run just cov` | core packages 98 percent (gate 90); all modules 93 percent | `9066e64` |
| `uv run just mutation` | 1157 of 1321 mutants detected; 164 survivors classified in `validation/records/mutation-2026-10-14.md` | `9066e64` |
| `uv run python -m validation.run` | 60/60 faults, 0/39 false positives, 8/8 boundary, 12/12 evidence faults, 15/15 replays | `b7d3acf` (clean tree) |
| `uv run dppce catalogue lint` | 0 errors, 1 warning, 36 info | `9066e64` |
| `uv run just docs` | strict build passes | the commit that adds `docs/readiness.md` |

Reviews (agent reviews, not human approvals):

- `validation/records/review-evidence-security-2026-10-13.md`: 17 findings, all fixed.
- `validation/records/review-verdicts-and-planning-2026-10-14.md`: 9 findings, all fixed.
- `validation/records/review-eu-battery-draft-2026-10-14.md`: 17 findings, applied to the
  drafts; OQ-021 to OQ-023 filed. Every entry stays `draft-needs-review`.

### Not done, and why

- [ ] Human review of the draft interpretations (OQ-002). An agent must not approve.
- [ ] Push, CI, release, Scorecard, and publication. Each needs the approval of the user.
- [ ] Container build and scan (OQ-004). Vale style checks (OQ-005). Manual accessibility review.
- [ ] Dependency vulnerability scan. Not run.
- [ ] DCO sign-off on the commits (OQ-018). An agent must not sign for a person.
- [ ] A test against a real system. Needs a signed authorization of its owner and the approval of the user.
- [ ] Mutation survivors "not tested: the exact size limit of a token" (3). Low value; listed in the record.

### Resume commands

```bash
git status --short
uv run just check
uv run pytest -m validation
uv run just cov
uv run dppce catalogue lint
uv run just docs
```

## Resume instructions

1. Read `state/progress.json`. Do not exceed `session.max_cycles`.
2. Read `docs/open-questions.md` and `docs/backlog.md`.
3. Continue with the first unchecked item in the work log of the milestone that is in progress.
