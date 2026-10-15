# Tasks

Audience: maintainers and any agent that resumes the work.
Purpose: show what is done, what the evidence is, and what to do next.
Prerequisites: read `state/progress.json` for the cycle counter and the limits.

A check that was not executed is marked **not run**. It is never marked passed.

## Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| M0 | Audit: inventory, routing, source audit, scope, risks, reuse decisions | complete |
| M1 | Foundation: structure, community files, schemas, CLI, CI, docs, style checks, capability manifest | complete: CI runs green on GitHub; Vale runs through uvx |
| M2 | Semantics: lifecycle, packs, ICS and IXIT validation, planning, applicability, coverage, verdicts | complete; no interpretation approved (needs a human, OQ-002) |
| M3 | Vertical slice: three battery profiles, plan to report, core adapters | complete |
| M4 | Evidence: encryption, canonical body, signing, scope binding, standalone verifier | complete |
| M5 | Method validation: faults, controls, replays, property and mutation tests, readiness | complete |
| M6 | Release candidate: documentation, clean install, SBOM, workflows, capability report | blocked: no release or tag without the approval of the user; the release workflow and the container build never ran |

"Complete" means that the local gates ran and passed for the milestone. It does not mean that
a human reviewed the work. The evidence for each figure is in `docs/readiness.md`.

## M0 work log

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State at the end of the session" below. Do not resume work from this section._

- [x] Workspace inventory. Result: empty apart from `.remember/` (session tooling, ignored by git).
- [x] Toolchain probe. Result: see `docs/research/tool-model-routing.md`.
- [x] Model routing probe. Result: four aliases accepted delegation.
- [ ] Source audit, research pass 1. Running. Raw results: `docs/research/raw/<group>.json`.
- [ ] Source audit, research pass 2 (adversarial check of high-risk claims). Running.
- [ ] Build `catalogue/sources.yaml` and `docs/research/source-audit.md` from the raw results.
- [ ] Scope statement, risk register, and reuse decisions.

## Implementation work log (cycle 3, coordinator)

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State at the end of the session" below. Do not resume work from this section._

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

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State at the end of the session" below. Do not resume work from this section._

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

## State at the end of the session (2026-10-15)

All fast gates pass. Both review rounds that the brief permits are complete. Every finding is
fixed or filed as an open question. The figures below come from commands that ran in this
session. The full table with evidence is in `docs/readiness.md`, section 2.

| Check | Result | Commit |
| --- | --- | --- |
| `uv run just check` | format, lint, mypy strict clean; 1270 passed, 63 deselected | `d149ee8` |
| `uv run pytest -m validation` | 63 passed | `d149ee8` |
| `uv run just cov` | core packages 98 percent (gate 90); all modules 93 percent | `d149ee8` |
| `uv run just mutation` | 1323 of 1499 mutants detected; 176 survivors classified in `validation/records/mutation-2026-10-14.md` | `d149ee8` |
| `uv run python -m validation.run` | 60/60 faults, 0/39 false positives, 8/8 boundary, 12/12 evidence faults, 15/15 replays | `3284ce2` (clean tree) |
| `uv run dppce catalogue lint` | 0 errors, 1 warning, 36 info | `d149ee8` |
| `uv run just docs` | strict build passes | `d149ee8` |

Reviews (agent reviews, not human approvals):

- `validation/records/review-evidence-security-2026-10-13.md`: 17 findings, all fixed.
- `validation/records/review-verdicts-and-planning-2026-10-14.md`: 9 findings, all fixed.
- `validation/records/review-eu-battery-draft-2026-10-14.md`: 17 findings, applied to the
  drafts; OQ-021 to OQ-023 filed. Every entry stays `draft-needs-review`.
- `validation/records/review-round-2-2026-10-14.md`: 48 findings and 14 findings of the
  follow-up reviews of the fixes; all handled. This was the last review round that the brief
  permits for milestones M2 and M4.

### Not done, and why

- [ ] Human review of the draft interpretations (OQ-002). An agent must not approve.
- [x] Push and CI (2026-10-15): private repository created and pushed with the approval of the user; CI green
      at `4c2928e`. The owner made the repository public.
- [ ] Release and tag. Each needs the approval of the user.
- [ ] OQ-021 to OQ-023 on the draft EU pack, and the scoping of revocation serial numbers by issuer
      (a change of the trust bundle format). Each needs a decision of a person.
- [x] Container build and smoke test (2026-10-15, run by the owner): builds; version, catalogue lint, and the
      unprivileged user are as expected.
- [x] Pinning the base images by digest (BL-005), 2026-10-15. The pinned rebuild gives the same image.
- [ ] Container image scan.
- [ ] An accessibility review by a person, a screen reader review, and an accessibility scanner
      (an agent did the checks in `docs/reference/accessibility.md`).
- [x] Dependency vulnerability scan (2026-10-15): no known vulnerabilities in 111 packages.
- [x] Vale style checks (2026-10-15): 0 errors, 0 warnings; suggestions remain.
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
3. Continue with the list "Not done, and why" in "State at the end of the session".
