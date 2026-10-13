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

## State at the stop of 2026-10-14 (usage limit reached)

The last commit is green for the committed files. The working tree holds uncommitted work of
two delegated tasks that may be incomplete. Do not commit it before the checks below pass.

### Open defects: fix these first

Independent security review (Fable), report: `validation/records/review-evidence-security-2026-10-13.md`.
The review is an agent review. It is not a human approval and not an audit. All findings are **open**.

- F-01 high: `integrity.jws` reports engine limits (algorithm not in the allowlist, unknown header
  parameter, non-P-256 leaf, HTTP 4xx or 5xx on `/signed`, a body that is not a JWS) as
  `INTEGRITY.SIGNATURE.INVALID`, which is a fail of the tested system. Only `BAD_SIGNATURE` may fail.
- F-02 high: `integrity.jws` applies the engine's integer-only canonical form to the third-party
  payload. A float, a different key order, or white space gives `INTEGRITY.PAYLOAD.MISMATCH`.
- F-03 high: an access probe for a role with no attached credential is sent as anonymous, is
  recorded under the role, and can pass.
- More findings, including F-17: read the report file. The task result was truncated in the session.

Independent core tests (`tests/core/`, committed): 782 passed, 10 failed. The 10 failures are
kept on purpose. Each one documents a defect in the code or a gap in the contract. Do not skip them.

- `aggregate()` drops a path with no step, or with unknown applicability, from `retained` when a
  different path passes (2 tests). Contract section 7.3 says that hidden problems stay in `retained`.
- `claim_level(reviewed, illustrative, approved)`: the contract table and the code disagree (1 test).
  Decide and state it in section 4: an illustrative requirement never gives a reviewed claim.
- A placeholder requirement can pass if a mapped test passes (1 test). Contract section 4 says
  that its verdict is `inconclusive`.
- The lint does not report an ordering comparison whose operand type does not fit the declared
  fact type, for example an integer fact compared with a date (3 tests).
- The ICS migration accepts an infinite capacity (3 tests).

Fast gate at this commit: format, lint, and types pass. Tests: **1069 passed, 10 failed**.
`uv run just check` exits 1 because of those 10 tests.

### Not done

- [ ] Fix the defects above. Add a regression test for each. Run `uv run just check`.
- [x] Catalogue task output committed: 128 source records, 36 draft interpretations of
      Regulation (EU) 2023/1542 (none approved), 8 EN placeholders, 41 test purposes for the draft
      pack (5 automated, 36 manual). `uv run dppce catalogue lint`: 0 errors. 21 content tests pass.
      No draft entry can get `pass` or `fail` in this version: each path has a manual step, and
      the engine has no input for a manual result (OQ-015).
- [ ] Independent review of the draft legal interpretations and of the verdict and planner code.
- [ ] Coverage of the core packages: not measured again with `tests/core`. Run `uv run just cov`. Gate: 90.
- [ ] Mutation testing (`uv run just mutation`): not run.
- [ ] Method-validation record from a clean commit (`uv run python -m validation.run`): none stored.
- [ ] `uv run just docs`: not run. `docs/readiness.md`: not written. The README links to it.
- [ ] Never executed: CI, release, and scorecard workflows; container build; Vale; manual
      accessibility review.

### Resume commands

```bash
git status --short
uv run just check
uv run dppce catalogue lint
uv run pytest tests/core
```

The delegated tasks ran as workflow `wf_0c3db9e9-d6b`. If their files are incomplete, run the
workflow again from its script with `resumeFromRunId`.

## Resume instructions

1. Read `state/progress.json`. Do not exceed `session.max_cycles`.
2. Read `docs/open-questions.md` and `docs/backlog.md`.
3. Continue with the first unchecked item in the work log of the milestone that is in progress.
