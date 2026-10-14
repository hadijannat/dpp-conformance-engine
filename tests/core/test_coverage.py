"""Coverage of the selected catalogue.

Every expected number is counted by hand from the definitions in
docs/explanation/architecture.md, section 7.5. The inputs are built by hand, so that the
figures do not depend on the planner or on the aggregation.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from dppce.models import (
    CoverageSummary,
    ExecutionStatus,
    Plan,
    Ratio,
    Requirement,
    RequirementResult,
    TestResult,
)
from dppce.verdicts.coverage import summarize
from tests.core import builders as b

COMPLETED = "completed"


def planned(exclusions: Sequence[tuple[str, str]] = ()) -> Plan:
    """A plan that holds only what the summary reads: the exclusions, as (kind, id)."""
    return Plan(
        schema_version="dppce.plan/1",
        mode="exploratory",
        profile_id=b.PROFILE_ID,
        requirements=(),
        steps=(),
        exclusions=[
            {"kind": kind, "id": ident, "reason_code": "SYNTHETIC.EXCLUDED", "reason": "synthetic"}
            for kind, ident in exclusions
        ],
        conflicts=(),
    )


def outcome(
    requirement: Requirement, applicability: str, verdict: str, **paths: Sequence[str]
) -> RequirementResult:
    """The result of one requirement. ``paths`` maps a path id to its steps; all paths are applicable."""
    return RequirementResult(
        requirement_id=requirement.id,
        pack_id="pack/a",
        authority_class=requirement.authority_class,
        modality=requirement.modality,
        review_status=requirement.review_status,
        testability=requirement.testability,
        applicability=applicability,
        applicability_reason="synthetic",
        verdict=verdict,
        verdict_reason="synthetic",
        claim_level="diagnostic",
        paths=[
            {"path_id": path_id, "applicability": "true", "verdict": "inconclusive", "steps": list(steps)}
            for path_id, steps in paths.items()
        ],
    )


def steps(**statuses: str) -> dict[str, TestResult]:
    """Step results by test purpose id. A key uses ``_`` where the id has ``-``."""
    results = {}
    for key, status in statuses.items():
        test_id = key.replace("_", "-")
        results[test_id] = TestResult(
            test_purpose_id=test_id,
            requirement_ids=(),
            check="probe.ok",
            applicability="true",
            applicability_reason="synthetic",
            execution_status=ExecutionStatus(status),
            # Section 7.1: the status "error" gives the verdict "error". The model enforces it.
            verdict={COMPLETED: "pass", "error": "error"}.get(status, "inconclusive"),
            severity="major",
            reason_code="SYNTHETIC.RESULT",
            message="synthetic",
        )
    return results


def summary(
    requirements: Sequence[Requirement],
    results: Sequence[RequirementResult],
    step_results: dict[str, TestResult],
    executable: Sequence[str],
    exclusions: Sequence[tuple[str, str]] = (),
) -> CoverageSummary:
    return summarize(
        scope_statement="Synthetic scope.",
        requirements=requirements,
        plan=planned(exclusions),
        results=results,
        test_results=step_results,
        executable_tests=frozenset(executable),
    )


def fraction(ratio: Ratio) -> tuple[int, int]:
    return ratio.numerator, ratio.denominator


def one_path(requirement_id: str, *tests: str, **changes: Any) -> Requirement:
    return b.requirement(requirement_id, assessment_paths=[b.path("p1", *tests)], **changes)


def test_each_figure_of_a_mixed_catalogue_is_counted_by_hand() -> None:
    passed = one_path("R-1", "T-1", "T-2")
    failed = one_path("R-2", "T-3")
    manual = one_path("R-3", "T-4", modality="recommended", testability="manual")
    unknown = one_path("R-4", "T-5")
    placeholder = b.requirement("R-5", review_status="placeholder", authority_class="guidance")
    excluded = one_path("R-6", "T-6", review_status="withdrawn")
    absent = one_path("R-7", "T-7")
    requirements = [passed, failed, manual, unknown, placeholder, excluded, absent]
    results = [
        outcome(passed, "true", "pass", p1=["T-1", "T-2"]),
        outcome(failed, "true", "fail", p1=["T-3"]),
        outcome(manual, "true", "inconclusive", p1=["T-4"]),
        outcome(unknown, "unknown", "inconclusive", p1=["T-5"]),
        outcome(placeholder, "true", "inconclusive"),
        outcome(absent, "false", "not_applicable", p1=["T-7"]),
    ]
    step_results = steps(
        T_1=COMPLETED,
        T_2=COMPLETED,
        T_3=COMPLETED,
        T_4="manual_unavailable",
        T_5="skipped",
        T_7="unsupported",
    )
    # T-4 is a manual review and T-7 has no supported capability. The other steps are executable.
    executable = ["T-1", "T-2", "T-3", "T-5", "T-6"]
    got = summary(
        requirements, results, step_results, executable, [("requirement", "R-6"), ("test_purpose", "T-9")]
    )

    assert got.scope_statement == "Synthetic scope."
    assert got.total_requirements == 7
    # Implementation: R-1, R-2, R-4, and the excluded R-6 have a fully executable path. Over all 7.
    assert fraction(got.implementation) == (4, 7)
    # Execution: R-1, R-2, R-3, R-5 are applicable. Every step completed for R-1 and R-2 only.
    assert fraction(got.execution) == (2, 4)
    # Passing: R-1, R-2, R-5 are applicable and mandatory. R-1 passed.
    assert fraction(got.passing) == (1, 3)
    assert got.placeholders == 1
    assert got.unknown_applicability == 1
    assert got.excluded == 1, "an exclusion of a test purpose is not an excluded requirement"
    assert got.manual_missing == 1
    assert got.by_review_status == {"draft-needs-review": 5, "placeholder": 1, "withdrawn": 1}
    assert got.by_authority_class == {"guidance": 1, "illustrative": 6}
    assert got.by_testability == {"automated": 6, "manual": 1}
    assert sum(got.by_applicability.values()) == 7, "each requirement is counted, also the excluded one"
    assert (got.by_applicability["true"], got.by_applicability["false"], got.by_applicability["unknown"]) == (
        4,
        1,
        1,
    )
    assert sum(got.by_verdict.values()) == 7
    assert {
        v: got.by_verdict.get(v, 0) for v in ("pass", "fail", "inconclusive", "not_applicable", "error")
    } == {
        "pass": 1,
        "fail": 1,
        "inconclusive": 3,
        "not_applicable": 1,
        "error": 0,
    }


def test_each_ratio_carries_a_label_that_does_not_claim_a_law_or_a_standard() -> None:
    got = summary([one_path("R-1", "T-1")], [], {}, ["T-1"])
    for ratio in (got.implementation, got.execution, got.passing):
        assert ratio.of.strip()
        for claim in ("law", "legal", "regulation", "standard"):
            assert claim not in ratio.of.lower()
    assert len({got.implementation.of, got.execution.of, got.passing.of}) == 3, "each denominator is named"


def test_an_empty_catalogue_gives_zero_over_zero_everywhere() -> None:
    got = summary([], [], {}, [])
    assert [fraction(r) for r in (got.implementation, got.execution, got.passing)] == [(0, 0)] * 3
    counts = (
        got.total_requirements,
        got.placeholders,
        got.unknown_applicability,
        got.excluded,
        got.manual_missing,
    )
    assert counts == (0, 0, 0, 0, 0)
    assert (got.by_applicability, got.by_verdict, got.by_review_status) == ({}, {}, {})


def test_no_applicable_requirement_gives_denominators_of_zero_for_execution_and_passing() -> None:
    first, second = one_path("R-1", "T-1"), one_path("R-2", "T-2")
    results = [
        outcome(first, "false", "not_applicable", p1=["T-1"]),
        outcome(second, "unknown", "inconclusive", p1=["T-2"]),
    ]
    got = summary([first, second], results, steps(T_1=COMPLETED, T_2=COMPLETED), ["T-1", "T-2"])
    assert fraction(got.implementation) == (2, 2)
    assert fraction(got.execution) == (0, 0), (
        "a completed step of a requirement that is not applicable is not counted"
    )
    assert fraction(got.passing) == (0, 0)
    assert got.unknown_applicability == 1


def test_no_applicable_mandatory_requirement_gives_a_passing_denominator_of_zero() -> None:
    recommended = one_path("R-1", "T-1", modality="recommended")
    optional = one_path("R-2", "T-2", modality="optional")
    results = [
        outcome(recommended, "true", "pass", p1=["T-1"]),
        outcome(optional, "true", "pass", p1=["T-2"]),
    ]
    got = summary([recommended, optional], results, steps(T_1=COMPLETED, T_2=COMPLETED), ["T-1", "T-2"])
    assert fraction(got.execution) == (2, 2)
    assert fraction(got.passing) == (0, 0)


def test_implementation_counts_a_requirement_with_one_fully_executable_path() -> None:
    two_paths = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-2"), b.path("p2", "T-3")])
    partial = one_path("R-2", "T-1", "T-2")
    none = one_path("R-3", "T-2")
    got = summary([two_paths, partial, none], [], {}, ["T-1", "T-3"])
    # R-1: p2 is executable. R-2: T-2 is not executable, so its only path is not. R-3: no executable step.
    assert fraction(got.implementation) == (1, 3)
    both = summary([two_paths, partial, none], [], {}, ["T-1", "T-2", "T-3"])
    assert fraction(both.implementation) == (3, 3), "a requirement with two executable paths is counted once"
    assert fraction(summary([two_paths, partial, none], [], {}, []).implementation) == (0, 3)


def test_implementation_counts_excluded_requirements_and_placeholders_in_the_denominator() -> None:
    kept = one_path("R-1", "T-1")
    withdrawn = one_path("R-2", "T-2", review_status="withdrawn")
    placeholder = b.requirement("R-3", review_status="placeholder")
    got = summary([kept, withdrawn, placeholder], [], {}, ["T-1"], [("requirement", "R-2")])
    assert fraction(got.implementation) == (1, 3)
    assert (got.placeholders, got.excluded, got.total_requirements) == (1, 1, 3)


@pytest.mark.parametrize(
    "status", [s.value for s in ExecutionStatus if s is not ExecutionStatus.COMPLETED] + ["no result"]
)
def test_execution_needs_every_step_of_one_path_to_complete(status: str) -> None:
    requirement = one_path("R-1", "T-1", "T-2")
    result = outcome(requirement, "true", "inconclusive", p1=["T-1", "T-2"])
    step_results = steps(T_1=COMPLETED) if status == "no result" else steps(T_1=COMPLETED, T_2=status)
    got = summary([requirement], [result], step_results, ["T-1", "T-2"])
    assert fraction(got.execution) == (0, 1), status
    assert fraction(got.implementation) == (1, 1), "executable, but not executed"


def test_execution_counts_a_requirement_once_when_one_of_its_paths_completed() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1"), b.path("p2", "T-2", "T-3")])
    result = outcome(requirement, "true", "pass", p1=["T-1"], p2=["T-2", "T-3"])
    one = summary([requirement], [result], steps(T_1="skipped", T_2=COMPLETED, T_3=COMPLETED), [])
    assert fraction(one.execution) == (1, 1)
    both = summary([requirement], [result], steps(T_1=COMPLETED, T_2=COMPLETED, T_3=COMPLETED), [])
    assert fraction(both.execution) == (1, 1)
    neither = summary([requirement], [result], steps(T_1="error", T_2=COMPLETED, T_3="blocked"), [])
    assert fraction(neither.execution) == (0, 1)


def test_passing_counts_applicable_mandatory_requirements_with_verdict_pass() -> None:
    verdicts = ["pass", "pass", "fail", "error", "inconclusive"]
    mandatory = [one_path(f"R-{i}", f"T-{i}") for i in range(len(verdicts))]
    recommended = one_path("R-8", "T-8", modality="recommended")
    absent = one_path("R-9", "T-9")
    results = [outcome(r, "true", v) for r, v in zip(mandatory, verdicts, strict=True)]
    results += [
        outcome(recommended, "true", "pass"),
        outcome(absent, "false", "not_applicable"),
    ]
    got = summary([*mandatory, recommended, absent], results, {}, [])
    assert fraction(got.passing) == (2, 5)
    assert fraction(got.execution) == (0, 6), "the six applicable requirements, none executed"


def test_a_missing_manual_assessment_is_counted_once_for_each_requirement() -> None:
    two = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-2"), b.path("p2", "T-3")])
    one = one_path("R-2", "T-4")
    none = one_path("R-3", "T-5")
    results = [
        outcome(two, "true", "inconclusive", p1=["T-1", "T-2"], p2=["T-3"]),
        outcome(one, "true", "inconclusive", p1=["T-4"]),
        outcome(none, "true", "pass", p1=["T-5"]),
    ]
    step_results = steps(
        T_1="manual_unavailable",
        T_2="manual_unavailable",
        T_3=COMPLETED,
        T_4="manual_unavailable",
        T_5=COMPLETED,
    )
    got = summary([two, one, none], results, step_results, [])
    assert got.manual_missing == 2
    assert fraction(got.execution) == (2, 3), "R-1 through its second path, and R-3"


def test_unknown_applicability_and_exclusions_are_counted_and_shown() -> None:
    requirements = [one_path(f"R-{i}", f"T-{i}") for i in range(5)]
    results = [outcome(r, "unknown", "inconclusive") for r in requirements[:3]]
    got = summary(requirements, results, {}, [], [("requirement", "R-3"), ("requirement", "R-4")])
    assert (got.total_requirements, got.unknown_applicability, got.excluded) == (5, 3, 2)
    assert sum(got.by_applicability.values()) == 5
    assert got.by_applicability["unknown"] == 3
    assert sum(got.by_verdict.values()) == 5
    assert got.by_verdict["inconclusive"] == 3
