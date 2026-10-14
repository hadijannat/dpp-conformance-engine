"""Verdict aggregation. Pure functions that implement the published truth table.

The table is in docs/explanation/architecture.md, section 7. Each function below names
the subsection that it implements. Change the table and the code in the same commit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from dppce.models import (
    AuthorityClass,
    ClaimLevel,
    ExecutionMode,
    ExecutionStatus,
    Modality,
    PathResult,
    Plan,
    Requirement,
    RequirementResult,
    ReviewStatus,
    TestResult,
    Tri,
    Verdict,
    VerdictRules,
)

_PASS, _FAIL, _ERROR = Verdict.PASS, Verdict.FAIL, Verdict.ERROR
_INCONCLUSIVE, _NA = Verdict.INCONCLUSIVE, Verdict.NOT_APPLICABLE


def step_verdict(
    status: ExecutionStatus, passed: bool | None, unreachable: bool, rules: VerdictRules
) -> Verdict:
    """Section 7.1. Only a completed check can pass or fail."""
    if status is ExecutionStatus.ERROR:
        return _ERROR
    if status is not ExecutionStatus.COMPLETED or passed is None:
        return _INCONCLUSIVE
    if passed:
        # "Passed" and "unreachable" contradict each other. A contradiction is not a pass.
        return _INCONCLUSIVE if unreachable else _PASS
    rule = rules.on_unreachable if unreachable else rules.on_check_failed
    return _FAIL if rule == "fail" else _INCONCLUSIVE


def path_verdict(applicability: Tri, steps: Sequence[Verdict]) -> Verdict:
    """Section 7.2. Every step of a path is required. A path with no step cannot pass."""
    if applicability is Tri.FALSE:
        return _NA
    if applicability is Tri.UNKNOWN:
        return _INCONCLUSIVE
    for decisive in (_FAIL, _ERROR):
        if decisive in steps:
            return decisive
    if not steps or any(v is not _PASS for v in steps):
        return _INCONCLUSIVE
    return _PASS


def requirement_verdict(
    applicability: Tri,
    conflict: bool,
    paths: Sequence[Verdict],
    mode: ExecutionMode,
    review_status: ReviewStatus,
) -> tuple[Verdict, str]:
    """Section 7.3. Returns the verdict and the reason for it."""
    if applicability is Tri.FALSE:
        return _NA, "The requirement does not apply."
    if applicability is Tri.UNKNOWN:
        return _INCONCLUSIVE, "The applicability is unknown."
    if conflict:
        return (
            _FAIL,
            "The owner declares the feature as not implemented. A declaration cannot waive a requirement.",
        )
    if not paths:
        return _INCONCLUSIVE, "No assessment path is defined."
    live = [v for v in paths if v is not _NA]
    if not live:
        return _INCONCLUSIVE, "No permitted assessment path is declared as implemented."
    if _FAIL in live:
        return _FAIL, "A valid failing observation exists."
    if _PASS in live:
        if mode is ExecutionMode.REVIEWED and review_status is not ReviewStatus.APPROVED:
            return _INCONCLUSIVE, "The interpretation is not approved. Reviewed mode cannot claim a pass."
        return _PASS, "Every required step of an assessment path passed."
    if _ERROR in live:
        return _ERROR, "An execution defect prevented the assessment."
    return _INCONCLUSIVE, "The assessment evidence is missing or insufficient."


def overall_verdict(results: Sequence[RequirementResult]) -> tuple[Verdict, str]:
    """Section 7.4. Uses applicable mandatory requirements only. An empty run cannot pass."""
    scope = [r.verdict for r in results if r.modality is Modality.MANDATORY and r.applicability is Tri.TRUE]
    if not scope:
        return _INCONCLUSIVE, "No applicable mandatory requirement was assessed. An empty run cannot pass."
    for decisive, reason in (
        (_FAIL, "At least one applicable mandatory requirement failed."),
        (_ERROR, "At least one applicable mandatory requirement had an execution error."),
        (_INCONCLUSIVE, "At least one applicable mandatory requirement is inconclusive."),
    ):
        if decisive in scope:
            return decisive, reason
    return _PASS, "Every applicable mandatory requirement in the selected catalogue passed."


def claim_level(
    mode: ExecutionMode, authority_class: AuthorityClass, review_status: ReviewStatus
) -> ClaimLevel:
    """Section 4. What a result may be cited as."""
    if authority_class is AuthorityClass.ILLUSTRATIVE:
        return ClaimLevel.NONE if mode is ExecutionMode.REVIEWED else ClaimLevel.ILLUSTRATIVE
    if mode is ExecutionMode.REVIEWED:
        return ClaimLevel.REVIEWED if review_status is ReviewStatus.APPROVED else ClaimLevel.NONE
    if mode is ExecutionMode.EXPLORATORY and review_status in (ReviewStatus.DRAFT, ReviewStatus.APPROVED):
        return ClaimLevel.DIAGNOSTIC
    return ClaimLevel.NONE


def aggregate(
    plan: Plan,
    requirements: Mapping[str, Requirement],
    test_results: Mapping[str, TestResult],
) -> tuple[RequirementResult, ...]:
    """Build one result per planned requirement, sorted by requirement identifier."""
    conflicts = {c.requirement_id for c in plan.conflicts}
    not_run = {s.test_purpose_id for s in plan.steps if s.planned_status is not None}
    out: list[RequirementResult] = []
    for planned in sorted(plan.requirements, key=lambda p: p.requirement_id):
        requirement = requirements[planned.requirement_id]
        path_results: list[PathResult] = []
        retained: list[str] = []
        defined = {p.id: p.tests for p in requirement.assessment_paths}
        for path in planned.paths:
            verdicts: list[Verdict] = []
            for test_id in path.tests:
                result = test_results.get(test_id)
                # A planned step with no result is missing evidence. It is never a pass.
                verdict = result.verdict if result is not None else _INCONCLUSIVE
                code = result.reason_code if result is not None else "RESULT.MISSING"
                if test_id in not_run and verdict in (_PASS, _FAIL):
                    # The plan says that this step does not run. A result that says otherwise
                    # did not come from this plan and is not evidence.
                    verdict, code = _INCONCLUSIVE, "RESULT.NOT_PLANNED"
                verdicts.append(verdict)
                if verdict is not _PASS:
                    retained.append(f"{path.path_id}/{test_id}: {verdict.value} ({code})")
            # A step that the planner left out is no longer in the path, and the steps that
            # remain can pass. Keep it visible next to the verdict (section 7.3).
            for test_id in defined.get(path.path_id, ()):
                if test_id not in path.tests:
                    retained.append(f"{path.path_id}/{test_id}: left out (STEP.NOT_APPLICABLE)")
            outcome = path_verdict(path.applicability, verdicts)
            # A gap of the path itself has no step entry above. Keep it, so that a pass of a
            # different path cannot hide it (section 7.3).
            if path.applicability is Tri.UNKNOWN:
                retained.append(f"{path.path_id}: {outcome.value} (PATH.APPLICABILITY_UNKNOWN)")
            elif path.applicability is Tri.TRUE and not path.tests:
                retained.append(f"{path.path_id}: {outcome.value} (PATH.NO_STEP)")
            path_results.append(
                PathResult(
                    path_id=path.path_id,
                    applicability=path.applicability,
                    verdict=outcome,
                    steps=path.tests,
                )
            )
        conflict = planned.requirement_id in conflicts
        verdict, reason = requirement_verdict(
            planned.applicability,
            conflict,
            [p.verdict for p in path_results],
            plan.mode,
            requirement.review_status,
        )
        out.append(
            RequirementResult(
                requirement_id=requirement.id,
                pack_id=planned.pack_id,
                authority_class=requirement.authority_class,
                modality=requirement.modality,
                review_status=requirement.review_status,
                testability=requirement.testability,
                applicability=planned.applicability,
                applicability_reason=planned.applicability_reason,
                verdict=verdict,
                verdict_reason=reason,
                claim_level=claim_level(plan.mode, requirement.authority_class, requirement.review_status),
                paths=tuple(path_results),
                retained=tuple(retained),
            )
        )
    return tuple(out)
