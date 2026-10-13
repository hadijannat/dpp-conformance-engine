"""Coverage of the selected catalogue. Pure.

Implements docs/explanation/architecture.md, section 7.5. Every ratio keeps its numerator
and its denominator. No figure here is coverage of a law or of a whole standard.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence

from dppce.models import (
    CoverageSummary,
    ExecutionStatus,
    Modality,
    Plan,
    Ratio,
    Requirement,
    RequirementResult,
    ReviewStatus,
    TestResult,
    Tri,
    Verdict,
)

_OF = "requirements in the selected catalogue"


def _counts(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def summarize(
    *,
    scope_statement: str,
    requirements: Sequence[Requirement],
    plan: Plan,
    results: Sequence[RequirementResult],
    test_results: Mapping[str, TestResult],
    executable_tests: frozenset[str],
) -> CoverageSummary:
    """Summarize all known requirements, including the excluded ones.

    ``executable_tests`` holds the test purposes that a supported or experimental capability
    can execute in this installation.
    """
    excluded = sum(1 for e in plan.exclusions if e.kind == "requirement")
    implemented = sum(
        1
        for r in requirements
        if any(p.tests and all(t in executable_tests for t in p.tests) for p in r.assessment_paths)
    )

    def completed(result: RequirementResult) -> bool:
        return any(
            p.applicability is Tri.TRUE
            and p.steps
            and all(
                (step := test_results.get(t)) is not None
                and step.execution_status is ExecutionStatus.COMPLETED
                for t in p.steps
            )
            for p in result.paths
        )

    def manual_missing(result: RequirementResult) -> bool:
        return any(
            (step := test_results.get(t)) is not None
            and step.execution_status is ExecutionStatus.MANUAL_UNAVAILABLE
            for p in result.paths
            for t in p.steps
        )

    applicable = [r for r in results if r.applicability is Tri.TRUE]
    mandatory = [r for r in applicable if r.modality is Modality.MANDATORY]
    return CoverageSummary(
        scope_statement=scope_statement,
        total_requirements=len(requirements),
        by_authority_class=_counts([r.authority_class.value for r in requirements]),
        by_review_status=_counts([r.review_status.value for r in requirements]),
        by_applicability=_counts([r.applicability.value for r in results] + ["excluded"] * excluded),
        by_testability=_counts([r.testability.value for r in requirements]),
        by_verdict=_counts([r.verdict.value for r in results] + ["excluded"] * excluded),
        implementation=Ratio(numerator=implemented, denominator=len(requirements), of=_OF),
        execution=Ratio(
            numerator=sum(1 for r in applicable if completed(r)),
            denominator=len(applicable),
            of="applicable " + _OF,
        ),
        passing=Ratio(
            numerator=sum(1 for r in mandatory if r.verdict is Verdict.PASS),
            denominator=len(mandatory),
            of="applicable mandatory " + _OF,
        ),
        placeholders=sum(1 for r in requirements if r.review_status is ReviewStatus.PLACEHOLDER),
        unknown_applicability=sum(1 for r in results if r.applicability is Tri.UNKNOWN),
        excluded=excluded,
        manual_missing=sum(1 for r in results if manual_missing(r)),
    )
