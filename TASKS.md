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
| M6 | Release candidate: documentation, clean install, SBOM, workflows, capability report | complete: GitHub pre-release `v0.1.0rc1` on 2026-10-15 with the approval of the owner; release workflow green; not on PyPI |
| M7 | T1 technical readiness: the agent-buildable T1 packages of `docs/research/gap-assessment-2026-10-15.md`, section 6.2 | in progress: the work of 2026-10-18 is on `main` up to `8b3bfff`; see "State after the T1 program (2026-10-18)" |
| M8 | P2 practical-use program: `docs/research/practical-use-assessment-2026-10-25.md` | in progress: waves 1 to 3 on main (d19a8f9), wave 4 integrated |

"Complete" means that the local gates ran and passed for the milestone. It does not mean that
a human reviewed the work. The evidence for each figure is in `docs/readiness.md`.

## M0 work log

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State after the T1 program (2026-10-18)" below. Do not resume work from this section._

- [x] Workspace inventory. Result: empty apart from `.remember/` (session tooling, ignored by git).
- [x] Toolchain probe. Result: see `docs/research/tool-model-routing.md`.
- [x] Model routing probe. Result: four aliases accepted delegation.
- [ ] Source audit, research pass 1. Running. Raw results: `docs/research/raw/<group>.json`.
- [ ] Source audit, research pass 2 (adversarial check of high-risk claims). Running.
- [ ] Build `catalogue/sources.yaml` and `docs/research/source-audit.md` from the raw results.
- [ ] Scope statement, risk register, and reuse decisions.

## Implementation work log (cycle 3, coordinator)

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State after the T1 program (2026-10-18)" below. Do not resume work from this section._

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
"State after the T1 program (2026-10-18)" below. Do not resume work from this section._

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

_Historical log, closed. It shows the state at the time it was written. The current state is in
"State after the T1 program (2026-10-18)" below. Do not resume work from this section._

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
- [x] Release candidate (2026-10-15, approved by the owner): tag `v0.1.0rc1`, release workflow run 38722322047 green,
      attestations verified, GitHub pre-release with the wheel, the sdist, and the SBOM. Not published on PyPI.
- [ ] OQ-021 to OQ-023 on the draft EU pack. Each needs a decision of a person.
- [ ] The scoping of revocation serial numbers by issuer is implemented as trust bundle version 2
      (D8-10, ADR 0015, proposed). A person must confirm the format.
- [x] Container build and smoke test (2026-10-15, run by the owner): builds; version, catalogue lint, and the
      unprivileged user are as expected.
- [x] Pinning the base images by digest (BL-005), 2026-10-15. The pinned rebuild gives the same image.
- [x] Container image scan (2026-10-15, Trivy 0.56.2): 0 high or critical findings with a fix.
- [x] Accessibility scanner (axe-core 4.10.2, 2026-10-15): 0 violations on both reports.
- [ ] An accessibility review by a person and a screen reader review.
- [x] Dependency vulnerability scan (2026-10-15): no known vulnerabilities in 111 packages.
- [x] Vale style checks (2026-10-15): 0 errors, 0 warnings; suggestions remain.
- [x] DCO sign-off (2026-10-15, by the owner): commit `a6283be` certifies the 87 commits up to `a1522ad` (OQ-018).
      A later commit of an agent needs the sign-off of the person who submits it.
- [ ] A test against a real system. Needs a signed authorization of its owner and the approval of the user.
- [ ] Mutation survivors "not tested: the exact size limit of a token" (3). Commit `31ac1e8` adds a test for the
      exact limit. Mutation testing was not run again, so the record still lists them.

## State after the T1 program (2026-10-18)

A development agent wrote this section from the git history and the records in
`validation/records/`. No person has reviewed it.

The remote-tracking branch `origin/main` is at `8b3bfff`. The branch `final/2026-10-18` adds two
records and this update. It is not pushed.

### What landed

All work is of 2026-10-18. Each row is on `main`, except where the row states otherwise.

| Work | Commits | Content |
| --- | --- | --- |
| T0 corrections and waves 1 to 3 | up to `f1ee709` | See `state/progress.json`, cycles 19 to 23. |
| Wave 4 | `f7b66c9` to `6602f8c` | A server error counts as no answer. The resolved passport binds to the API item target (D4-05). A selected approved entry excludes the draft that it supersedes. Lint rule CAT023. A severity column in the HTML report. RFC 3161 timestamps and trust bundle version 2 (D6-01, D6-02, D8-10). |
| W5-docs | `c87e52c` to `5aaca24` | A reason-code catalogue from the source literals. A human review field of the validation record, which the engine never fills. Operator, laboratory, and contributor guides. |
| W5-evidence | `4ad5625` to `f8ac8f5` | Report status lists, signer roles, and attestation version 2 (D6-03, the report part of D8-14, ADR 0016). Evidence faults E-14 and E-15. |
| W5-mut | `f3191b3` to `dbc88e0` | The mutation record of 2026-10-18 and tests for the survivors in the verifier and the verdicts. |
| D8-05 adapter review | `4e48f6b` to `ec2a1ad`, and `dae6117` | The fixes of `validation/records/review-adapters-2026-10-18.md`. `dae6117` refuses a stamp of a moment that does not exist. |
| D6-08 key tooling | `0403e5f` to `5f22f66` | `dppce keys generate`, `authorize`, `trust-bundle add-key`, `open`, and `prove`. The contracts `dppce.opening/1` and `dppce.proof/1`. The review fixes. |
| W6-mut2 | `b7c0410` to `5037d12`, merge commit `dfd03b1` | Mutation tests of round 3 for the transport, redaction, and authorization code. |
| CI and CodeQL fixes | `d012334`, `12f57c8`, `b7b744c` | A TEST-ONLY PKI that Python 3.13 accepts, and a TLS 1.2 minimum (CodeQL alert 13). `12f57c8` sets mode 0644 for new output files (CodeQL alert 14) and adjusts the in-place mode test (alert 15). `b7b744c` sets mode 0600, as the owner decided (alert 14), and adjusts the test again (alert 16). |
| Follow-ups | `83a08a4`, `7077837`, `1019a8d`, `5fe675d`, `2311513`, `8b3bfff` | Port 0 is never the default port. `Observation.acquired_at` uses `Stamp`. The mutmut configuration deselects the reason-code page test. A proof or an opening is `not_checked` when ordering fails. |
| Records | `a7ef327`, `8394f36`, on `final/2026-10-18` only | The method validation record at `8b3bfff`. The review record of the key tooling. |
| W5-CI (PR #2) | `c71169c` to `b2eb10e`, on branch `ci/scans-and-release-gates` only | Scan, documentation, and DCO jobs, and release gates. |

### Checks at `8b3bfff`

A development agent ran these commands. The full table with evidence is in
`docs/readiness.md`, section 2.

| Check | Result | Commit |
| --- | --- | --- |
| `uv run just check` | format, lint, mypy strict clean; 2540 passed, 97 deselected | `8b3bfff` |
| `uv run pytest -m validation` | 97 passed | `8b3bfff` |
| `uv run just cov` | core packages 99 percent (gate 90); all modules 97 percent | `8b3bfff` |
| `uv run just mutation` | 5731 mutants: 4886 killed, 22 timed out, 823 survived; survivors not classified | `8b3bfff` |
| `uv run python -m validation.run` | 93/93 faults, 0/48 false positives, 3/3 controls, 9/9 boundary, 15/15 evidence faults, 15/15 replays | `8b3bfff` (clean tree) |
| `uv run dppce catalogue lint` | 0 errors, 2 warnings, 36 info | `8b3bfff` |
| `uv run just docs` | strict build passes | `8b3bfff` |

Records of 2026-10-18. They are agent records, not human approvals.

- `validation/records/review-adapters-2026-10-18.md`
- `validation/records/review-key-tooling-2026-10-18.md`
- `validation/records/mutation-2026-10-18.md`
- `validation/records/method-validation-20261018T125030Z.json` (at `715fdb5`)
- `validation/records/method-validation-20261018T212047Z.json` (at `8b3bfff`)

The owner decisions of 2026-10-18 are in `state/progress.json`, milestone M7, and in the two
review records.

### Not done, and why

- [ ] Approval of the draft interpretations (OQ-002). Only a person can approve. An agent must
      not approve.
- [ ] OQ-016 and the other readings of a reviewer. A person must decide which observation
      contradicts a provision.
- [ ] A test against a real system. It needs a signed authorization of its owner and the
      approval of the user.
- [ ] An independent audit. An agent review is not an audit.
- [ ] Commission acts that are not adopted (OQ-006, OQ-007, OQ-013). The affected entries stay
      `inconclusive` until the acts exist.
- [ ] Content of EN, ISO, IEC, and DIN standards. CLAUDE.md rule 5 keeps it out of the
      repository. The EN entries stay placeholders.
- [ ] KMS and PKCS#11 providers (D6-07). The gap assessment puts D6-07 in tier T3. The
      capabilities `keys.kms` and `keys.pkcs11` stay `interface_only`.
- [ ] The open mutation survivors. The run at `8b3bfff` left 823 survivors, and nobody has
      classified them. The open lists of `validation/records/mutation-2026-10-18.md` stay open.
- [ ] PR #2 (branch `ci/scans-and-release-gates`, head `b2eb10e`). It waits for the DCO sign-off
      of the owner.
- [ ] DCO sign-off of the agent commits after `91a6629`. An agent must not sign off for a person.
- [ ] Push of `final/2026-10-18` (`a7ef327`, `8394f36`, and this update). It is not pushed.
- [ ] The open items of `validation/records/review-key-tooling-2026-10-18.md`: docs1-DOC-2, the
      rest of INT-4 (protected files), `not_checked` after `structure`, and the notes SR-N2,
      SR-N5, SR-N6, and SR-N7.
- [ ] The limit of two review rounds. No record states how the agent reviews of 2026-10-18
      relate to it.

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
2. Read `docs/open-questions.md`, `docs/backlog.md`, and `docs/readiness.md`.
3. Run the resume commands on a clean working tree.
4. Continue with the list "Not done, and why" in "State after the T1 program (2026-10-18)".
5. Do not do an item that needs a person. Report it to the owner.
