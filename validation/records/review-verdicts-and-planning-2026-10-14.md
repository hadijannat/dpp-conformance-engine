# Review of applicability, planning, verdicts, coverage, and the report

Audience: maintainers, assessors, and the person who ratifies the ADRs.
Purpose: report what an independent agent review found in the code that decides a verdict,
with reproductions, so that each item can be fixed or accepted on record.
Prerequisites: read `docs/explanation/architecture.md` sections 4 to 7 and 12, ADRs 0002, 0004,
0007, and 0010, and `docs/reference/verdict-truth-table.md`.

## Status

| Field | Value |
| --- | --- |
| Reviewer | An AI model: Claude, model identifier `claude-fable-5-1` |
| Date | 2026-10-14 |
| Commit reviewed | `ae33dcc5649eaab955d9cfa5f1039d6451d387d7` |
| Nature of this record | An agent review. It is not a human approval. It is not an audit. |

The reviewer did not write the code under review. Every reproduction ran on in-memory
catalogues and fake acquirers. No script contacted a network host.

The working tree held uncommitted edits from another task during this review. Every file in
scope was identical to commit `ae33dcc`. `src/dppce/cli.py` was modified in the tree, but its
diff did not touch `_VERDICT_EXIT`, `_INPUT_ERRORS`, `main`, or the `--times` argument.
`docs/explanation/architecture.md` had no content diff against the commit.

The one question of this review: can the engine report a verdict that is better than the
evidence supports, or hide a problem from the reader of a report?

## Scope

Reviewed in full:

- `src/dppce/applicability.py`, `src/dppce/models/expr.py`
- `src/dppce/orchestrator/plan.py`, `src/dppce/orchestrator/run.py`
- `src/dppce/verdicts/aggregate.py`, `src/dppce/verdicts/coverage.py`
- `src/dppce/models/catalogue.py` (lifecycle rules), `models/testing.py`, `models/results.py`
- `src/dppce/catalogue/lint.py`
- `src/dppce/report/html.py`
- `src/dppce/cli.py`: the mapping from an outcome to an exit code only
- `testpacks/battery-core.yaml`, `testpacks/eu-battery-draft.yaml`,
  `catalogue/packs/illustrative-core.yaml`, `catalogue/packs/eu-battery-draft.yaml`,
  `catalogue/packs/en-jtc24-placeholders.yaml`

Read for context only: `src/dppce/catalogue/loader.py`, `src/dppce/testdefs/registry.py`,
`src/dppce/evidence/envelope.py` (`verdict_counts`, `build_decision`), the profiles, and
`tests/core/`.

Not reviewed for security: `src/dppce/adapters/`, `src/dppce/infrastructure/`,
`src/dppce/evidence/`, and the rest of `src/dppce/cli.py`. Another task edits those files.
`validation/records/review-evidence-security-2026-10-13.md` covers them. Nothing from that
record is repeated here.

## Method

1. Read the contract and the ADRs. Treated each of the ten rules (a to j) as a hypothesis.
2. Read each file in scope in full. Listed every suspected way to obtain `pass`,
   `not_applicable`, or an overall `pass` without evidence, and every place where a problem
   could leave the report.
3. Built small in-memory catalogues with `tests/core/builders.py` (read, not edited) and the
   fake checks that `tests/core/test_run_core.py` registers (`tests_core.passes`, `fails`,
   `unreachable`, `raises`, `fetches`). Called `build_plan`, `make_plan`, `execute`,
   `aggregate`, `summarize`, `overall_verdict`, `evaluate`, `render`, and `lint` directly.
4. Ran the shipped catalogue, profiles, and test packs through the real planner and the real
   check registry for each of the three profiles and the three modes.
5. Ran each script with `uv run python` from the repository root. Marked a finding
   "reproduced" only when a script ran and showed the behavior.
6. Ran `uv run pytest tests/core` once to record its state.

The scripts live outside the repository. Each section quotes the part that matters.

### Attack matrix

One line per case, from one script. `overall` is `overall_verdict` of the aggregated results.

| Case | Overall | Requirement verdicts | Notes |
| --- | --- | --- | --- |
| One step shared by parents with applicability true, false, unknown | pass | R-1 pass, R-2 not_applicable, R-3 inconclusive | Step ran once. |
| Path with no step | inconclusive | inconclusive | |
| Only step has applicability false | inconclusive | inconclusive | Exclusion `STEP.NOT_APPLICABLE` recorded. |
| Step applicability unknown | inconclusive | inconclusive | Step `skipped`. |
| Step not permitted in mode | inconclusive | inconclusive | Step `not_run`; exclusion `MODE.NOT_PERMITTED`. |
| Step not defined for profile | inconclusive | inconclusive | Step `not_run`; exclusion `PROFILE.NOT_SELECTED`. |
| Path names an undefined step | inconclusive | inconclusive | Step `not_run`, check `unavailable`. |
| Requirement in two selected packs | `PlanError` | | |
| Superseded old, draft new | pass | R-NEW pass | R-OLD excluded `STATUS.SUPERSEDED`. |
| Approved illustrative rule, illustrative and exploratory | pass | pass, claim `illustrative` | |
| Approved illustrative rule, reviewed | inconclusive | none planned | Exclusion `MODE.ILLUSTRATIVE_NOT_REVIEWABLE`. |
| Recommended and optional fail, mandatory passes | pass | R-REC fail, R-OPT fail, R-1 pass | Both failures stay in the results. |
| Only a recommended requirement, it passes | inconclusive | pass | An empty mandatory scope cannot pass. |
| `declared_support` false, mandatory, test passes | fail | fail | Conflict recorded. |
| `declared_support` unknown, mandatory, test passes | pass | pass | No conflict. |
| `declared_support` false, recommended, test passes | inconclusive | pass | No conflict: rule g covers mandatory only. |
| Every requirement not applicable | inconclusive | not_applicable | |
| Reviewed mode excludes every requirement | inconclusive | none planned | |
| Check raises | error | error | Reason `ENGINE.CHECK_EXCEPTION`. |
| Replayed request differs from the record | error | error | Reason `REPLAY.RECORDING_MISMATCH`. |
| Extra result for a step the plan did not list | fail | fail | The extra result is ignored. |
| Placeholder with applicability true, exploratory | inconclusive | inconclusive | Planned, not excluded. |
| Five shuffles of packs, requirements, and purposes | | | Identical plan JSON. |

## Findings

| Id | Severity | Component | Title | Reproduced |
| --- | --- | --- | --- | --- |
| V-01 | medium | orchestrator/plan.py, orchestrator/run.py, catalogue/lint.py | A test purpose id in two selected test packs is planned from one copy and executed with the other | yes |
| V-02 | medium | models/testing.py, catalogue/lint.py | `on_unreachable: fail` is not restricted to an approved test method | yes |
| V-03 | medium | orchestrator/plan.py, verdicts/aggregate.py | A deciding step dropped by its own applicability leaves no trace on the requirement result, and the remaining steps can pass | yes |
| V-04 | low | cli.py | `replay --times 0` reports a match and exits with the original outcome without replaying | yes |
| V-05 | low | models/testing.py, verdicts/aggregate.py | The result models do not tie a verdict to its execution status, and `aggregate` trusts the result | yes |
| V-06 | low | catalogue/lint.py, orchestrator/plan.py | Supersession is not cross-checked: a stale approved requirement is assessed next to its successor | yes |
| V-07 | info | cli.py | An `ApplicabilityError` at run time is exit code 3, not 2 | yes |
| V-08 | info | report/html.py | The summary calls every requirement result "assessed", including not-applicable ones and placeholders | no |
| V-09 | info | catalogue/packs/illustrative-core.yaml, testpacks/battery-core.yaml | Two illustrative requirements are passed by a check that does not test the property they state | no |

### V-01. A test purpose id in two selected test packs is planned from one copy and executed with the other

Severity: medium. Component: `src/dppce/orchestrator/plan.py` (the test pack loop in
`build_plan`), `src/dppce/orchestrator/run.py` (`_purposes`), `src/dppce/catalogue/lint.py`.

Description. `build_plan` raises `PlanError` when two selected test packs define the same
purpose id only if both copies are permitted in the mode and profile. If one copy is excluded
(`MODE.NOT_PERMITTED` or `PROFILE.NOT_SELECTED`), the planner keeps the other copy and records
the exclusion. `run._purposes` then builds a last-wins dictionary over every purpose of every
selected test pack, with no mode or profile filter. `execute` takes the check name from the
plan but the `verdict_rules`, `params`, `requirements`, and `severity` from that dictionary.
When the excluded copy comes from the later test pack, the step runs the planned check with the
other copy's parameters and rules. `lint` builds the same last-wins dictionary and has no
finding for a duplicate purpose id. The outcome depends on the order of `profile.testpacks`.

The actor is a test pack author or an operator who adds a test pack. It is not the supplier
of the tested system.

Reproduction.

```python
# uv run python - <<'EOF'   (from the repository root)
import sys; sys.path.insert(0, ".")
import tests.core.test_run_core as core          # registers tests_core.* checks
from pathlib import Path
from dppce.models import IXIT, ExecutionMode
from dppce.orchestrator.run import RunInputs, execute, make_plan
from dppce.verdicts import aggregate, overall_verdict
from tests.core import builders as b
from tests.support import AT

req = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
a = b.purpose("T-1", stimulus={"check": "tests_core.fails"},
              verdict_rules={"on_check_failed": "fail"}, permitted_modes=["exploratory"])
bb = b.purpose("T-1", requirements=["R-OTHER"], stimulus={"check": "tests_core.passes"},
               verdict_rules={"on_check_failed": "inconclusive"}, permitted_modes=["illustrative"])
for order in (["tp/a", "tp/b"], ["tp/b", "tp/a"]):
    inputs = RunInputs(mode=ExecutionMode.EXPLORATORY, profile=b.profile(testpacks=order),
        catalogue=b.catalogue(b.pack(req)),
        testpacks={"tp/a": b.purposes_pack(a, testpack_id="tp/a"), "tp/b": b.purposes_pack(bb, testpack_id="tp/b")},
        ics=b.ics(), ixit=IXIT(schema_version="dppce.ixit/1"), data_root=Path("."), evaluation_time=AT)
    plan = make_plan(inputs); results = execute(plan, inputs, core.FakeAcquirer())
    rr = aggregate(plan, {"R-1": req}, results); t = results["T-1"]
    print(order, plan.steps[0].check, [(e.id, e.reason_code) for e in plan.exclusions])
    print("  ", t.execution_status.value, t.verdict.value, t.reason_code, t.requirement_ids,
          "R-1:", rr[0].verdict.value, "overall:", overall_verdict(rr)[0].value)
EOF
```

Observed output.

```text
['tp/a', 'tp/b'] tests_core.fails [('T-1', 'MODE.NOT_PERMITTED')]
   completed inconclusive TESTS.CORE.NOT_OK ('R-OTHER',) R-1: inconclusive overall: inconclusive
['tp/b', 'tp/a'] tests_core.fails [('T-1', 'MODE.NOT_PERMITTED')]
   completed fail TESTS.CORE.NOT_OK ('R-1',) R-1: fail overall: fail
```

The same completed, not-passed check gives `inconclusive` or `fail`. In the first order the
valid failing observation does not establish `fail`, and the result names a requirement that
the plan never assessed. In both orders the exclusion list says that `T-1` was excluded while
`T-1` ran. `lint` on the same inputs returned no finding.

Recommendation. In `build_plan`, raise `PlanError` on a duplicate purpose id across selected
test packs before the mode and profile filter. In `run`, derive the purpose for each step from
the same filtered mapping that the planner used, or carry the purpose's identity (test pack id
and hash) in `PlannedStep`. Add a lint error for a purpose id that two test packs define.

### V-02. `on_unreachable: fail` is not restricted to an approved test method

Severity: medium. Component: `src/dppce/models/testing.py` (`VerdictRules`),
`src/dppce/catalogue/lint.py`, `src/dppce/orchestrator/plan.py`.

Description. The `VerdictRules` docstring, section 9 of the contract, ADR 0010, and rule f say
that a connectivity failure is not proof of a breach unless an approved test method says so.
Nothing in the code represents "approved test method". A test purpose has no review status.
The model accepts `on_unreachable: fail` on any purpose. `lint` has no rule for it. The planner
does not check it. A draft, illustrative test purpose can therefore turn an unreachable system
into a `fail` of the requirement and an overall `fail` (exit code 1).

The shipped content is clean: `battery-core.yaml` uses the defaults and
`eu-battery-draft.yaml` sets `inconclusive` for both rules on every automated step.

Reproduction.

```python
# uv run python - <<'EOF'
import sys; sys.path.insert(0, ".")
import tests.core.test_run_core as core
from pathlib import Path
from dppce.catalogue.lint import lint
from dppce.models import IXIT, ExecutionMode
from dppce.orchestrator.run import RunInputs, execute, make_plan
from dppce.verdicts import aggregate, overall_verdict
from tests.core import builders as b
from tests.support import AT

req = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])   # draft, illustrative
t = b.purpose("T-1", stimulus={"check": "tests_core.unreachable"},
              verdict_rules={"on_check_failed": "fail", "on_unreachable": "fail"})
print("lint:", lint(b.catalogue(b.pack(req)), {b.PROFILE_ID: b.profile()},
                    {"tp/a": b.purposes_pack(t)}, {"tests_core.unreachable"}) or "no finding")
inputs = RunInputs(mode=ExecutionMode.EXPLORATORY, profile=b.profile(), catalogue=b.catalogue(b.pack(req)),
    testpacks={"tp/a": b.purposes_pack(t)}, ics=b.ics(), ixit=IXIT(schema_version="dppce.ixit/1"),
    data_root=Path("."), evaluation_time=AT)
plan = make_plan(inputs); results = execute(plan, inputs, core.FakeAcquirer())
rr = aggregate(plan, {"R-1": req}, results)
print(results["T-1"].verdict.value, rr[0].verdict.value, rr[0].review_status.value, overall_verdict(rr)[0].value)
EOF
```

Observed output.

```text
lint: no finding
fail fail draft-needs-review fail
```

Recommendation. Add a lint error: `on_unreachable: fail` is allowed only when every
requirement that the purpose names has review status `approved` and an authority class other
than `illustrative`. Consider a second barrier in `execute` or `step_verdict`: treat
`on_unreachable: fail` as `inconclusive` unless the run mode is `reviewed`. A model constraint
needs a contract change, because `VerdictRules` has no view of the requirement.

### V-03. A deciding step dropped by its own applicability leaves no trace on the requirement result

Severity: medium. Component: `src/dppce/orchestrator/plan.py` (`kept` in `build_plan`),
`src/dppce/verdicts/aggregate.py` (`retained`).

Description. Section 6 says a step whose applicability is `false` is left out of its path with
a reason. The planner records the exclusion `STEP.NOT_APPLICABLE` and removes the step from
`PlannedPath.tests`. The path then holds the remaining steps only. If those steps pass, the
requirement passes. `RequirementResult.retained` holds nothing about the dropped step, because
`aggregate` builds `retained` from `path.tests`. `PathResult.steps` also omits it. A reader of
the requirement row in the report sees a `pass` with no "Also:" note; only the exclusions table
at the end mentions the step.

The step applicability expression reads `ics.*`, which the supplier of the tested system
writes. A test pack whose manual step has an ICS-dependent applicability therefore gives the
supplier a switch that turns a mixed path into an automated one. The shipped test packs do not
have such a step: every manual step is `const: true`, and the one ICS-dependent automated step
(`TP-EU-INTEGRITY-JWS`) leaves a manual step behind when it is dropped. The hazard is in the
engine and the authoring rules, not in the shipped content. A missing fact behaves correctly:
it gives `unknown`, the step is `skipped`, and the requirement is `inconclusive`.

Reproduction.

```python
# uv run python - <<'EOF'
import sys; sys.path.insert(0, ".")
import tests.core.test_run_core as core
from pathlib import Path
from dppce.models import IXIT, ExecutionMode
from dppce.orchestrator.run import RunInputs, execute, make_plan
from dppce.verdicts import aggregate, overall_verdict
from tests.core import builders as b
from tests.support import AT

req = b.requirement("R-1", assessment_paths=[b.path("p1", "T-AUTO", "T-MANUAL")])
auto = b.purpose("T-AUTO", stimulus={"check": "tests_core.passes"})
manual = b.purpose("T-MANUAL", manual=True, stimulus={"check": "manual.review"},
                   applicability=b.feature("marking_visible", True))
for feat in ({}, {"marking_visible": "unknown"}, {"marking_visible": False}):
    inputs = RunInputs(mode=ExecutionMode.EXPLORATORY, profile=b.profile(), catalogue=b.catalogue(b.pack(req)),
        testpacks={"tp/a": b.purposes_pack(auto, manual)}, ics=b.ics(features=feat),
        ixit=IXIT(schema_version="dppce.ixit/1"), data_root=Path("."), evaluation_time=AT)
    plan = make_plan(inputs); results = execute(plan, inputs, core.FakeAcquirer())
    r = aggregate(plan, {"R-1": req}, results)[0]
    print(feat, r.paths[0].steps, r.verdict.value, r.retained,
          [(e.id, e.reason_code) for e in plan.exclusions], overall_verdict([r])[0].value)
EOF
```

Observed output.

```text
{} ('T-AUTO', 'T-MANUAL') inconclusive ('p1/T-MANUAL: inconclusive (PLAN.SKIPPED)',) [] inconclusive
{'marking_visible': 'unknown'} ('T-AUTO', 'T-MANUAL') inconclusive ('p1/T-MANUAL: inconclusive (PLAN.SKIPPED)',) [] inconclusive
{'marking_visible': False} ('T-AUTO',) pass () [('T-MANUAL', 'STEP.NOT_APPLICABLE')] pass
```

Recommendation. Keep the dropped step visible on the result: add a `retained` entry such as
`p1/T-MANUAL: left out (STEP.NOT_APPLICABLE)`, or a `left_out` field on `PathResult` (a
change in `models/`, so a contract change). Add a lint warning for a manual step, or any step
of a legal-obligation requirement, whose applicability is not a constant. Consider a planner
rule that a path whose manual step is dropped cannot pass, and state it in section 6.

### V-04. `replay --times 0` reports a match and exits with the original outcome without replaying

Severity: low. Component: `src/dppce/cli.py`, `cmd_replay` and the `--times` argument.

Description. `--times` is `type=int, default=1` with no lower bound. With `0` or a negative
number the loop runs zero times, `digests` is empty, `all([])` is `True`, and `complete` stays
`True`. The command prints `0 replays: match` and returns the exit code of the original
overall outcome. No evaluation took place, yet the output says that the recording replays.

Reproduction. A script built a decision with `evaluate`, wrote `inputs.json` and
`envelope.json` into a temporary run directory, replaced `read_recording`, `_build_inputs`,
and `evaluate` in `dppce.cli` with stubs that count calls, and called `cmd_replay` with
`times=0` and `times=1`. `argparse` also accepted `--times 0` and `--times -3`.

Observed output.

```text
0 replays: match
--times 0: evaluate called 0 time(s); exit code 1 (original overall fail)
--times 1: evaluate called 1 time(s); exit code 1 (original overall fail)
```

Recommendation. Reject `--times < 1` with `UsageError`. `cli.py` is under edit by another task;
the change is one condition.

### V-05. The result models do not tie a verdict to its execution status, and `aggregate` trusts the result

Severity: low. Component: `src/dppce/models/testing.py` (`CheckOutcome`, `TestResult`),
`src/dppce/verdicts/aggregate.py`.

Description. The task asked to confirm that `CheckOutcome` forbids `passed=True` with a status
other than `completed`. It does: the validator rejects every such pair, and it rejects
`completed` with `passed=None`. Two gaps remain. `CheckOutcome` accepts `completed`,
`passed=True`, `unreachable=True`, and `step_verdict` gives `pass` for it. `TestResult` has no
validator: `execution_status=skipped` with `verdict=pass` is accepted. `aggregate` reads
`result.verdict` and never compares it with the plan's `planned_status` or step applicability.
A hand-built plan with a `skipped` step of `unknown` applicability and a result that says
`pass` gives the requirement `pass`. None of this is reachable through `evaluate`, because
`execute` derives every verdict from the status. It matters for a report that another tool
assembles, and for the verifier, which does not re-derive requirement verdicts.

Reproduction. One script: `CheckOutcome(status=skipped, passed=True)` raised
`'passed' is set if and only if the check completed`; `CheckOutcome(completed, passed=True,
unreachable=True)` was accepted and `step_verdict` returned `pass`; `TestResult(skipped, pass)`
was accepted; `aggregate` of that result over a plan whose step is `skipped` with `unknown`
applicability returned `pass`.

Recommendation. Contract change in `models/`: a `TestResult` validator that allows `pass` and
`fail` only with `completed`, and `error` only with `error`; a `CheckOutcome` rule that
`unreachable` implies `passed is False`. In `aggregate`, treat a result whose step the plan
lists with a `planned_status` as `inconclusive` whatever its verdict says.

### V-06. Supersession is not cross-checked

Severity: low. Component: `src/dppce/catalogue/lint.py` (CAT010), `src/dppce/orchestrator/plan.py`.

Description. The planner excludes a requirement only when its own `review_status` is
`superseded` or `withdrawn`. The lifecycle rules and `lint` check that `superseded_by` and
`supersedes` name an existing requirement, not that the named requirement has the matching
status. An approved requirement that carries `superseded_by: R-NEW` while its status stays
`approved` is planned and can pass. Its draft successor is planned too. In reviewed mode the
stale approved one would be the only one assessed. Nothing warns.

Reproduction. The matrix row "stale approved old with superseded_by, draft new" gave
`R-NEW=pass, R-OLD=pass`, no exclusion. `lint` on the same pair, with `R-NEW.supersedes =
["R-OLD"]`, returned no finding.

Recommendation. Lint error: a requirement with `superseded_by` must have status `superseded`;
a requirement named in `supersedes` must have status `superseded`; an `approved` requirement
must not be named in `supersedes` of another entry unless it is superseded.

### V-07. An `ApplicabilityError` at run time is exit code 3, not 2

Severity: info. Component: `src/dppce/cli.py`, `_INPUT_ERRORS` and `main`.

Description. Section 5 calls a type mismatch in a comparison "a catalogue defect". Section 12
gives exit code 2 to "bad arguments, invalid file, lint findings". `ApplicabilityError` is a
`ValueError` and is not in `_INPUT_ERRORS`. `main` reports it as `execution error` with exit
code 3. The outcome stays honest: no verdict is produced. The classification is off.

Reproduction. `issubclass(ApplicabilityError, cli._INPUT_ERRORS)` is `False`; `main` with a
handler that raises `ApplicabilityError` returned 3, with `RuntimeError` returned 3, with
`UsageError` returned 2. The verdict map is `pass 0, fail 1, inconclusive 5, not_applicable 5,
error 3`. An engine error is never 1.

Recommendation. Add `ApplicabilityError` to `_INPUT_ERRORS`, or state in section 12 that a
run-time applicability defect is exit code 3.

### V-08. The summary calls every requirement result "assessed"

Severity: info. Component: `src/dppce/report/html.py`, `_summary`.

Description. The sentence "Of N assessed requirements: ... do not apply" uses
`len(decision.requirement_results)`. That count includes requirements with applicability
`false` or `unknown` and placeholders, which were not assessed. The numbers that follow are
correct and the figures carry their meaning, so no reader is misled about a verdict. The word
is wrong. Not reproduced by a dedicated script; the hostile-text page rendered the sentence
with the counts that the code reads.

Recommendation. Say "Of N planned requirements" or "requirement results".

### V-09. Two illustrative requirements are passed by a check that does not test the property they state

Severity: info. Component: `catalogue/packs/illustrative-core.yaml`, `testpacks/battery-core.yaml`.

Description. `TP-ID-001` (parse the identifier) is the only step of `ILL-ID-001` and of
`ILL-EV-ONLY-001` ("Rule for the EV category only"). `TP-DATA-004` (apply the rule pack) is the
only step of `ILL-DATA-004` and of `ILL-CAPACITY-001` ("Rule above a capacity threshold"). The
second requirement of each pair states a property that the shared check does not examine. The
paraphrases say that these entries demonstrate applicability, the pack is illustrative, and the
claim level is `illustrative` in every mode. In a normative pack the same pattern would let a
check pass a requirement that it does not test. Not reproduced: by reading.

Related, with a stated reason: `eu-battery-draft.yaml` sets `on_check_failed: inconclusive` on
every automated step, so a failed automated check (also an observed access leak in
`TP-EU-ACCESS-ANON`) does not make the requirement `fail`. The file header and each `purpose`
field state why. The reader sees the step's reason code. The requirement verdict is
`inconclusive` either way, because every path holds a manual step. This is a content choice,
recorded here so that a reviewer can accept or change it.

Recommendation. Lint warning when a test purpose is the only step of more than one
requirement. Give the two demonstration requirements their own demonstration step, or state in
their paraphrase that the pass rests on the rule pack.

## The ten rules

| Rule | Upheld | How checked |
| --- | --- | --- |
| a. A valid failing observation establishes fail; errors and gaps are retained | yes, in the engine | `requirement_verdict` puts `_FAIL` before `_PASS`; matrix rows with fail; `test_aggregate_keeps_*` read. V-01 shows a configuration where the failing step is not read with its own rules. |
| b. With no established failure, an execution defect yields error | yes | Matrix rows "check raises" and "replay mismatch"; `path_verdict` and `requirement_verdict` order. |
| c. Unknown applicability or missing, blocked, skipped, unsupported, insufficient evidence yields inconclusive | yes | `step_verdict` maps every non-completed status to inconclusive; matrix rows for unknown step, unknown parent, mode and profile exclusion, undefined step, empty path. |
| d. Pass needs resolved applicability and every required step passed; a reviewed claim needs approval | yes | `path_verdict` requires every step `pass`; `requirement_verdict` requires applicability `true`; reviewed barrier returned inconclusive for a draft on a forced plan; shipped reviewed runs plan nothing. |
| e. not_applicable needs positively established non-applicability and a recorded reason | yes | Only `Tri.FALSE` gives `_NA`; `applicability_reason` carries the evaluated comparison; a missing fact gave `unknown` and `inconclusive` in V-03 and the matrix. |
| f. Zero steps cannot pass; an empty run cannot pass; manual unavailable is inconclusive; connectivity failure is not a breach unless an approved method says so | partly | First three hold (matrix rows, `overall_verdict`, `manual_unavailable` in V-03). The last clause has no gate: V-02. |
| g. An ICS declaration cannot waive a verified mandatory obligation; conflicts are detected | yes, for mandatory | Matrix row `declared_support` false, mandatory: conflict and fail. For recommended and optional no conflict is recorded; the requirement runs normally. |
| h. Missing information must not become false or not_applicable | yes | `_compare` returns unknown for a missing path, `None`, and the string `unknown`; `All`/`AnyOf` Kleene order; V-03 and matrix rows. |
| i. Every percentage has numerator and denominator; coverage is of the selected catalogue; placeholders, unknowns, exclusions, missing manual shown | yes | `Ratio` holds both; `_ratio` prints both and refuses a percentage for a zero denominator; four hand-counted cases below; the HTML lists each count. |
| j. An unavailable adapter never returns pass | yes | `_planned_status` gives `unsupported` for a missing, `interface_only`, `unsupported`, or unavailable check; `step_verdict` gives inconclusive for it; shipped `TP-NFC-001` is `unsupported` (lint CAT006). |

### Coverage counted by hand

Four runs through `evaluate` with fake checks. Each figure was counted from the definitions in
section 7.5 before the run. In each run `sum(by_verdict) == total` and
`sum(by_applicability) == total`.

| Case | Hand count | Engine |
| --- | --- | --- |
| A. seven requirements: pass, fail, not applicable, unknown, recommended manual, placeholder (unknown), superseded | total 7; implementation 5/7; execution 2/3; passing 1/2; placeholders 1; unknown 2; excluded 1; manual missing 1 | same |
| B. two requirements in reviewed mode, none approved | total 2; implementation 2/2; execution 0/0; passing 0/0; excluded 2 | same |
| C. one requirement with two paths (one completed, one skipped), one with a declared-support conflict | total 2; implementation 2/2; execution 2/2; passing 1/2 | same |
| D. empty catalogue | 0/0 in every ratio | same |

Note on A: the superseded requirement counts in the implementation numerator because its path
is executable. Section 7.5 defines that ratio over all requirements, so this is as written.

### Shipped content through the real planner

For each profile (`battery/ev`, `battery/industrial`, `battery/lmt`) and each mode, with an ICS
that makes the EU draft requirements applicable (category of the profile, 3000 Wh, dates in
2027):

| Mode | Planned | Excluded | Mandatory requirements with a path of executable steps only |
| --- | --- | --- | --- |
| illustrative | 18 (`illustrative/core`) | 44 `MODE.NOT_ILLUSTRATIVE` | 12 or 13 `ILL-*` (13 for `ev`, where `ILL-EV-ONLY-001` applies) |
| exploratory | 62 | 0 | the same `ILL-*` only |
| reviewed | 0 | 62 `MODE.NOT_APPROVED` | none |

No `EUBAT-*` requirement can reach `pass` in any mode: every path holds a `manual: true` step,
which is planned `manual_unavailable`. `lint` on the shipped data gave one warning (CAT006,
`TP-NFC-001`, check not registered) and 36 informational CAT012 findings. No error.

### HTML report with hostile text

A run with `</td><script>alert(1)</script><img src=x onerror=alert(2)>"' onmouseover="x" &amp;`
in `sut.name`, `sut.identifier`, `sut.version`, `sut.operator`, the issuer fields, a
characteristic value (which reaches `applicability_reason`), `superseded_by` (which reaches an
exclusion reason), the pack `scope_statement`, and a check message, with 200,000 extra
characters in the message. The page held no `<script` and no `<img`; the parser found only
the tags and attributes that the renderer writes; `&lt;script&gt;` and `&quot;` were present;
the long message rendered in full. Escaping held.

## What holds up

- Precedence: `step_verdict`, `path_verdict`, `requirement_verdict`, and `overall_verdict`
  gave the published outcome in every matrix row.
- A planned step with no result is `inconclusive`; a result for an unlisted step is ignored.
- A shared step runs once and does not make a non-applicable or unknown parent pass.
- A requirement in two selected packs and a permitted duplicate purpose id raise `PlanError`;
  the loader rejects a duplicate pack id, so an imported pack cannot replace a shipped one.
- The plan is identical under five shuffles of packs, requirements, and purposes.
- The reviewed-mode barrier in `requirement_verdict` checks review status only. An approved
  illustrative rule gave `pass` with claim level `none` on a hand-forced plan. Through
  `evaluate` it cannot happen: `mode_exclusion` removes it first with
  `MODE.ILLUSTRATIVE_NOT_REVIEWABLE`.
- `CheckOutcome` rejects `passed` on a status other than `completed`.
- An exception in a check is `error`, never `fail`; the message holds the exception type only.
- The exit code map has no path from `error` to 1.

## Contract gaps

1. Section 6: "A test purpose runs only in a mode that its `permitted_modes` lists." The check
   that runs can take its parameters and verdict rules from a copy that the mode does not
   permit (V-01).
2. `VerdictRules` docstring, section 9, ADR 0010: "Only an approved test method may set
   `on_unreachable` to `fail`." No gate exists (V-02).
3. Section 7.3: "Each other problem that the precedence hides is kept in `retained`." A step
   left out for applicability `false` is not (V-03).
4. Section 12 and section 5: a run-time applicability defect is a catalogue defect, yet it exits
   with 3 (V-07).
5. Section 4, mode table: exploratory mode lists "draft-needs-review or approved, and
   illustrative ones". A placeholder is not excluded in exploratory mode; it is planned with
   verdict `inconclusive`, as the same section says further down. The table should say so.
6. Section 7.3, step 6: the second barrier does not check `authority_class`. Only the planner
   does. Reachable only with a forged plan.
7. Section 7.4: "Results for `recommended` and `optional` requirements are reported
   separately." The HTML has a modality column; its summary sentence counts all modalities
   together.
8. `run._MODE_LIMITATIONS[EXPLORATORY]` says the interpretations are drafts that no human has
   approved. An imported approved pack run in exploratory mode gets claim level `diagnostic`,
   and the sentence is then wrong.

## Not reviewed

- `src/dppce/adapters/`, `src/dppce/infrastructure/`, `src/dppce/evidence/`, and `cli.py`
  beyond the exit code map, for security or otherwise. See the record of 2026-10-13.
- `src/dppce/verifier/`. Its `counts` dimension does not re-derive requirement verdicts; that
  gap is already on record there.
- The legal reading of any entry in `eu-battery-draft.yaml`, and the content of any EN
  standard behind `en-jtc24-placeholders.yaml`.
- `uv run just check`, `uv run just validate`, `uv run mypy`, `uv run ruff`: not run.
- The full test suite: not run. `tests/core` only, once.
- The JSON Schemas, the migrations, and the generated truth-table page as a build artifact
  (`just reference` was not run).

## Commands run

| Command | Result |
| --- | --- |
| `git rev-parse HEAD` | `ae33dcc5649eaab955d9cfa5f1039d6451d387d7` |
| `uv run python repro_v01_shadow.py` | exit 0; output under V-01 |
| `uv run python repro_v02_v03_models.py` | exit 0; output under V-02, V-03, V-05 |
| `uv run python repro_matrix.py` | exit 0; the attack matrix table |
| `uv run python repro_coverage.py` | exit 0; the four coverage cases; every invariant assertion held |
| `uv run python repro_shipped.py` | exit 0; the shipped content table and the lint counts |
| `uv run python repro_html.py` | exit 0; the HTML section |
| `uv run python repro_exit.py` | exit 0; output under V-07 |
| `uv run python repro_replay_times.py` | exit 0; output under V-04 |
| `uv run pytest tests/core -q -p no:cacheprovider` | first run: the last six progress lines (54% to 100%) held dots only; the summary line and the exit status were lost to the output filter |
| `uv run pytest tests/core --collect-only -p no:cacheprovider` | `792 tests collected in 0.59s` |
| `uv run pytest tests/core -p no:cacheprovider` | second run of the same subset, to capture the summary: `792 passed in 2.38s`, exit 0. The full suite was not run. |

The scripts are not part of the repository. Each finding quotes the part of its script that
matters, and each quoted script runs from the repository root.

## Overall assessment

This record makes no claim that the engine is correct.

The verdict core held under every direct attack that was tried. The precedence tables, the
three-valued applicability, the empty-run rule, the unavailable-adapter rule, the coverage
ratios, and the HTML escaping behaved as the contract says. The shipped content cannot give a
legal-obligation requirement a `pass` in any mode.

Three items can make a report read better than the evidence, or hide a problem, and each needs
content or configuration that the shipped files do not contain: a duplicate test purpose id
across test packs (V-01), a draft test method that sets `on_unreachable: fail` (V-02), and a
step with an ICS-dependent applicability that removes the deciding step from a path (V-03).
V-01 is a defect in the engine. V-02 and V-03 are missing guards around rules that the
contract states. The rest are robustness and wording items.

A human maintainer must decide each item. An agent review is not an approval.
