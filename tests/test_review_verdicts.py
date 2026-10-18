"""Regression tests for the findings of the independent review of verdicts and planning.

Report: validation/records/review-verdicts-and-planning-2026-10-14.md. Each test names its
finding. The one question behind them: can a report read better than its evidence, or hide a
problem from its reader?
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import tests.core.test_run_core as core  # registers the synthetic tests_core.* checks
from dppce import cli
from dppce.applicability import ApplicabilityError
from dppce.catalogue.lint import lint
from dppce.models import IXIT, CheckOutcome, ExecutionMode, TestResult, Verdict
from dppce.orchestrator.plan import PlanError  # noqa: TID251 - the planner is the unit under test
from dppce.orchestrator.run import (  # noqa: TID251 - the run core is the unit under test
    RunInputs,
    execute,
    make_plan,
)
from dppce.testdefs.registry import NoParams
from dppce.verdicts import aggregate, overall_verdict, step_verdict
from dppce.verdicts.aggregate import VerdictRules
from tests.core import builders as b
from tests.support import AT

CHECKS = dict.fromkeys(("tests_core.passes", "tests_core.fails", "tests_core.unreachable"), NoParams)


def inputs(requirements: list[Any], testpacks: dict[str, Any], tmp_path: Path, **changes: Any) -> RunInputs:
    fields: dict[str, Any] = {
        "mode": ExecutionMode.EXPLORATORY,
        "profile": b.profile(testpacks=list(testpacks)),
        "catalogue": b.catalogue(b.pack(*requirements)),
        "testpacks": testpacks,
        "ics": b.ics(),
        "ixit": IXIT(schema_version="dppce.ixit/1"),
        "data_root": tmp_path,
        "evaluation_time": AT,
    }
    return RunInputs(**(fields | changes))


def codes(findings: list[Any], severity: str) -> set[str]:
    return {f.code for f in findings if f.severity == severity}


# -- V-01: one identifier names one test purpose -------------------------------------------------


@pytest.mark.parametrize("order", [["tp/a", "tp/b"], ["tp/b", "tp/a"]])
def test_v01_a_purpose_id_in_two_selected_test_packs_is_refused_in_each_order(
    order: list[str], tmp_path: Path
) -> None:
    """The copy that the mode excludes must not supply the rules of the step that runs."""
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    runs = b.purpose(
        "T-1",
        stimulus={"check": "tests_core.fails"},
        verdict_rules={"on_check_failed": "fail"},
        permitted_modes=["exploratory"],
    )
    excluded = b.purpose(
        "T-1",
        requirements=["R-OTHER"],
        stimulus={"check": "tests_core.passes"},
        verdict_rules={"on_check_failed": "inconclusive"},
        permitted_modes=["illustrative"],
    )
    testpacks = {
        "tp/a": b.purposes_pack(runs, testpack_id="tp/a"),
        "tp/b": b.purposes_pack(excluded, testpack_id="tp/b"),
    }
    run_inputs = inputs([requirement], testpacks, tmp_path, profile=b.profile(testpacks=order))
    with pytest.raises(PlanError, match="more than once"):
        make_plan(run_inputs)
    findings = lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, testpacks, CHECKS)
    assert "CAT016" in codes(findings, "error")


# -- V-02: only an approved test method calls an unreachable system a failure -----------------


def test_v02_a_draft_test_method_cannot_turn_an_unreachable_system_into_a_failure(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    strict = b.purpose(
        "T-1",
        stimulus={"check": "tests_core.unreachable"},
        verdict_rules={"on_check_failed": "fail", "on_unreachable": "fail"},
    )
    testpacks = {"tp/a": b.purposes_pack(strict)}
    run_inputs = inputs([requirement], testpacks, tmp_path)
    assert "CAT017" in codes(
        lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, testpacks, CHECKS), "error"
    )
    plan = make_plan(run_inputs)
    results = execute(plan, run_inputs, core.FakeAcquirer())
    (result,) = aggregate(plan, {"R-1": requirement}, results)
    assert results["T-1"].verdict is Verdict.INCONCLUSIVE
    assert (result.verdict, overall_verdict([result])[0]) == (Verdict.INCONCLUSIVE, Verdict.INCONCLUSIVE)


def test_v02_the_lint_rule_accepts_an_approved_normative_requirement(tmp_path: Path) -> None:
    approved = b.requirement(
        "R-1",
        assessment_paths=[b.path("p1", "T-1")],
        authority_class="guidance",
        source=b.CITED,
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
    )
    strict = b.purpose(
        "T-1", stimulus={"check": "tests_core.unreachable"}, verdict_rules={"on_unreachable": "fail"}
    )
    testpacks = {"tp/a": b.purposes_pack(strict)}
    run_inputs = inputs([approved], testpacks, tmp_path)
    findings = lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, testpacks, CHECKS)
    assert "CAT017" not in {f.code for f in findings}


# -- V-03: a step that left its path stays visible --------------------------------------------


def test_v03_a_step_that_its_applicability_left_out_is_named_next_to_the_verdict(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-AUTO", "T-MANUAL")])
    auto = b.purpose("T-AUTO", stimulus={"check": "tests_core.passes"})
    manual = b.purpose(
        "T-MANUAL",
        manual=True,
        stimulus={"check": "manual.review"},
        applicability=b.feature("marking_visible", True),
    )
    testpacks = {"tp/a": b.purposes_pack(auto, manual)}

    def run(features: dict[str, Any]) -> Any:
        run_inputs = inputs([requirement], testpacks, tmp_path, ics=b.ics(features=features))
        plan = make_plan(run_inputs)
        (result,) = aggregate(plan, {"R-1": requirement}, execute(plan, run_inputs, core.FakeAcquirer()))
        return result

    assert run({}).verdict is Verdict.INCONCLUSIVE, "a missing fact never removes a step"
    assert run({"marking_visible": "unknown"}).verdict is Verdict.INCONCLUSIVE
    switched = run({"marking_visible": False})
    assert switched.paths[0].steps == ("T-AUTO",)
    assert switched.retained == ("p1/T-MANUAL: left out (STEP.NOT_APPLICABLE)",)

    run_inputs = inputs([requirement], testpacks, tmp_path)
    findings = lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, testpacks, CHECKS)
    assert [f.location for f in findings if f.code == "CAT018"] == ["T-MANUAL"]


# -- V-04: zero replays prove nothing ------------------------------------------------------------


@pytest.mark.parametrize("times", ["0", "-3"])
def test_v04_replay_needs_one_evaluation_or_more(
    times: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["replay", "--run", str(tmp_path), "--keys", str(tmp_path), "--times", times]) == 2
    assert "--times" in capsys.readouterr().err


# -- V-05: a verdict is tied to its execution status ------------------------------------------


def result_fields(**changes: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "test_purpose_id": "T-1",
        "requirement_ids": ("R-1",),
        "check": "tests_core.passes",
        "applicability": "true",
        "applicability_reason": "synthetic",
        "execution_status": "completed",
        "verdict": "pass",
        "severity": "major",
        "reason_code": "SYNTHETIC.RESULT",
        "message": "synthetic",
    }
    return fields | changes


@pytest.mark.parametrize(
    ("status", "verdict"),
    [
        ("skipped", "pass"),
        ("blocked", "pass"),
        ("manual_unavailable", "pass"),
        ("unsupported", "fail"),
        ("not_run", "fail"),
        ("error", "pass"),
        ("error", "inconclusive"),
        ("completed", "error"),
        ("skipped", "error"),
    ],
)
def test_v05_a_step_result_obeys_the_step_verdict_table(status: str, verdict: str) -> None:
    with pytest.raises(ValidationError):
        TestResult.model_validate(result_fields(execution_status=status, verdict=verdict))


def test_v05_passed_and_unreachable_contradict_each_other() -> None:
    with pytest.raises(ValidationError, match="unreachable"):
        CheckOutcome(status="completed", passed=True, unreachable=True, reason_code="X.Y", message="m")
    with pytest.raises(ValidationError, match="unreachable"):
        CheckOutcome(status="blocked", unreachable=True, reason_code="X.Y", message="m")
    for rules in (VerdictRules(), VerdictRules(on_unreachable="fail")):
        assert step_verdict(core.COMPLETED, True, True, rules) is Verdict.INCONCLUSIVE


def test_v05_a_result_for_a_step_that_the_plan_does_not_run_is_not_evidence(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    # No fact for the feature: the step applicability is unknown, so the plan does not run it.
    purpose = b.purpose(
        "T-1", stimulus={"check": "tests_core.passes"}, applicability=b.feature("not_declared", True)
    )
    run_inputs = inputs([requirement], {"tp/a": b.purposes_pack(purpose)}, tmp_path)
    plan = make_plan(run_inputs)
    assert plan.steps[0].planned_status is not None
    forged = {"T-1": TestResult.model_validate(result_fields())}
    (result,) = aggregate(plan, {"R-1": requirement}, forged)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.retained == ("p1/T-1: inconclusive (RESULT.NOT_PLANNED)",)


# -- V-06: supersession is checked from both sides ----------------------------------------------


def test_v06_a_stale_entry_next_to_its_successor_is_a_lint_error(tmp_path: Path) -> None:
    old = b.requirement(
        "R-OLD",
        authority_class="guidance",
        source=b.CITED,
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
        superseded_by="R-NEW",
    )
    new = b.requirement("R-NEW", supersedes=["R-OLD"])
    run_inputs = inputs([old, new], {"tp/a": b.purposes_pack()}, tmp_path)
    findings = lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, run_inputs.testpacks, CHECKS)
    stale = {(f.location, f.message) for f in findings if f.code == "CAT010"}
    assert {location for location, _ in stale} == {"pack/a/R-OLD", "pack/a/R-NEW"}

    # The documented import: an approved entry supersedes a draft that stays in its shipped pack.
    draft = b.requirement("R-DRAFT")
    successor = b.requirement("R-NEW", supersedes=["R-DRAFT"])
    run_inputs = inputs([draft, successor], {"tp/a": b.purposes_pack()}, tmp_path)
    findings = lint(run_inputs.catalogue, {b.PROFILE_ID: run_inputs.profile}, run_inputs.testpacks, CHECKS)
    assert not [f for f in findings if f.code == "CAT010"]


# -- V-07: an applicability defect is an input error -------------------------------------------


def test_v07_an_applicability_defect_exits_as_an_input_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def defect(_: Any) -> int:
        raise ApplicabilityError("cannot compare a string with an integer")

    monkeypatch.setattr(cli, "cmd_capabilities", defect)
    assert cli.main(["capabilities"]) == 2
    assert capsys.readouterr().err.startswith("error: cannot compare")
