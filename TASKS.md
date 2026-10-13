# Tasks

Audience: maintainers and any agent that resumes the work.
Purpose: show what is done, what the evidence is, and what to do next.
Prerequisites: read `state/progress.json` for the cycle counter and the limits.

A check that was not executed is marked **not run**. It is never marked passed.

## Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| M0 | Audit: inventory, routing, source audit, scope, risks, reuse decisions | in progress: research running |
| M1 | Foundation: structure, community files, schemas, CLI, CI, docs, style checks, capability manifest | in progress: code done; community files, CI, docs site, and style checks not started |
| M2 | Semantics: lifecycle, packs, ICS and IXIT validation, planning, applicability, coverage, verdicts | in progress: code done; packs and exhaustive verdict tests not started |
| M3 | Vertical slice: three battery profiles, plan to report, core adapters | in progress: orchestrator, transport, report, and CLI done; adapters, reference system, and profiles not started |
| M4 | Evidence: encryption, canonical body, signing, scope binding, standalone verifier | in progress: implemented and tested; independent security review not done |
| M5 | Method validation: faults, controls, replays, property and mutation tests, readiness | not started; fault catalogue with expected outcomes is written |
| M6 | Release candidate: documentation, clean install, SBOM, workflows, capability report | not started |

No milestone is complete. A milestone is complete only after the full quality gates run.

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

## Resume instructions

1. Read `state/progress.json`. Do not exceed `session.max_cycles`.
2. Read `docs/open-questions.md` and `docs/backlog.md`.
3. Continue with the first unchecked item in the work log of the milestone that is in progress.
