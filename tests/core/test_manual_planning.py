"""Planning and coverage of manual steps with and without a supplied manual result.

Expected values come from docs/explanation/architecture.md: section 6 (row 4 of the planning
table: a manual step without a supplied result is ``manual_unavailable``, and the reason text
does not change) and section 7.5 (a step with the check ``manual.review`` is not executable
by a capability). Nothing here reaches a network.
"""

from __future__ import annotations

from pathlib import Path

from dppce.models import IXIT, CapabilityState, ExecutionMode, ExecutionStatus, TestPurpose
from dppce.orchestrator.plan import CheckInfo, build_plan  # noqa: TID251 - the planner is the unit under test
from dppce.orchestrator.run import RunInputs, evaluate  # noqa: TID251 - the run core is the unit under test
from tests.core import builders as b
from tests.core import test_run_core as core  # registers the tests_core checks
from tests.support import AT, ArtifactAcquirer

OLD_REASON = "The step is a manual review. No manual result is available."
CHECKS = {
    "manual.review": CheckInfo(state=CapabilityState.SUPPORTED, available=True),
    "probe.ok": CheckInfo(state=CapabilityState.SUPPORTED, available=True),
}


def _plan(
    *purposes: TestPurpose, manual_results: frozenset[str] = frozenset()
) -> dict[str, tuple[ExecutionStatus | None, str]]:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", *(p.id for p in purposes))])
    plan = build_plan(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(),
        packs={"pack/a": b.pack(requirement)},
        testpacks={"tp/a": b.purposes_pack(*purposes)},
        ics=b.ics(),
        checks=CHECKS,
        manual_results=manual_results,
    )
    return {s.test_purpose_id: (s.planned_status, s.planned_reason) for s in plan.steps}


def test_a_supplied_manual_result_is_executed_and_a_missing_one_keeps_the_old_reason() -> None:
    manual = b.purpose("T-1", manual=True, stimulus={"check": "manual.review"})
    assert _plan(manual, manual_results=frozenset({"T-1"})) == {"T-1": (None, "")}
    status, reason = _plan(manual)["T-1"]
    assert status is ExecutionStatus.MANUAL_UNAVAILABLE
    # Byte for byte: an old recording must replay to the same decision digest.
    assert reason == OLD_REASON


def test_a_result_for_a_manual_step_with_another_check_is_not_executed() -> None:
    manual = b.purpose("T-1", manual=True, stimulus={"check": "probe.ok"})
    status, reason = _plan(manual, manual_results=frozenset({"T-1"}))["T-1"]
    assert (status, reason) == (ExecutionStatus.MANUAL_UNAVAILABLE, OLD_REASON)


def test_a_non_manual_step_with_check_manual_review_is_not_counted_for_implementation_coverage(
    tmp_path: Path,
) -> None:
    odd = b.purpose("T-ODD", requirements=["R-1"], stimulus={"check": "manual.review"})
    auto = b.purpose("T-AUTO", requirements=["R-2"], stimulus={"check": "tests_core.passes"})
    requirements = [
        b.requirement("R-1", assessment_paths=[b.path("p1", "T-ODD")]),
        b.requirement("R-2", assessment_paths=[b.path("p1", "T-AUTO")]),
    ]
    inputs = RunInputs(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(),
        catalogue=b.catalogue(b.pack(*requirements)),
        testpacks={"tp/a": b.purposes_pack(odd, auto)},
        ics=b.ics(),
        ixit=IXIT(schema_version="dppce.ixit/1"),
        data_root=tmp_path,
        evaluation_time=AT,
    )
    decision = evaluate(inputs, ArtifactAcquirer())
    assert core.CAPABILITY == "data.rules"
    # Only R-2 has a path of steps that a capability can execute.
    assert decision.coverage.implementation.numerator == 1
    odd_result = next(t for t in decision.test_results if t.test_purpose_id == "T-ODD")
    assert odd_result.verdict.value != "pass", "a step without a supplied result never passes"
