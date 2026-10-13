"""Verdict aggregation, checked cell by cell against oracles written from the contract.

Each oracle below is a transcription of one subsection of docs/explanation/architecture.md,
section 7 (and section 4 for the claim level). The oracles do not read the implementation.
Where the contract does not decide a cell, the oracle says so and the test asserts only the
bounds that the contract does state.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from typing import Any

import pytest

from dppce.models import (
    AuthorityClass,
    ClaimLevel,
    ExecutionMode,
    ExecutionStatus,
    Modality,
    Plan,
    PlannedPath,
    PlannedRequirement,
    Requirement,
    RequirementResult,
    ReviewStatus,
    TestResult,
    Tri,
    Verdict,
    VerdictRules,
)
from dppce.verdicts import (
    aggregate,
    claim_level,
    overall_verdict,
    path_verdict,
    requirement_verdict,
    step_verdict,
)
from tests.core import builders as b

PASS, FAIL, ERROR = Verdict.PASS, Verdict.FAIL, Verdict.ERROR
INCONCLUSIVE, NOT_APPLICABLE = Verdict.INCONCLUSIVE, Verdict.NOT_APPLICABLE
T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN
COMPLETED = ExecutionStatus.COMPLETED

ALL_RULES = [
    VerdictRules(on_check_failed=failed, on_unreachable=unreachable)
    for failed in ("fail", "inconclusive")
    for unreachable in ("inconclusive", "fail")
]
STEP_VERDICTS = (PASS, FAIL, ERROR, INCONCLUSIVE)


def tuples(values: Sequence[Any], longest: int) -> list[tuple[Any, ...]]:
    return [combo for size in range(longest + 1) for combo in itertools.product(values, repeat=size)]


# --- 7.1 Step verdict ----------------------------------------------------------------------


def step_oracle(
    status: ExecutionStatus, passed: bool | None, unreachable: bool, rules: VerdictRules
) -> Verdict | None:
    """Section 7.1. ``None`` means that the table does not decide the cell."""
    if status is ExecutionStatus.ERROR:
        return ERROR
    if status is not COMPLETED:
        return INCONCLUSIVE
    if passed is None:
        return None  # no row: a completed check always carries a result
    if passed and unreachable:
        return None  # the row "passed" and a row "unreachable" both match
    if passed:
        return PASS
    rule = rules.on_unreachable if unreachable else rules.on_check_failed
    return FAIL if rule == "fail" else INCONCLUSIVE


STEP_CELLS = list(itertools.product(ExecutionStatus, (True, False, None), (True, False), ALL_RULES))


def test_step_verdict_matches_the_table_in_every_cell() -> None:
    assert len(STEP_CELLS) == 7 * 3 * 2 * 4
    undecided = 0
    for status, passed, unreachable, rules in STEP_CELLS:
        cell = (status.value, passed, unreachable, rules.on_check_failed, rules.on_unreachable)
        actual = step_verdict(status, passed, unreachable, rules)
        expected = step_oracle(status, passed, unreachable, rules)
        if expected is None:
            undecided += 1
            continue
        assert actual is expected, cell
    assert undecided == 12, "completed with no result (8 cells), and passed with unreachable (4 cells)"


def test_step_verdict_stays_inside_the_stated_bounds_in_every_cell() -> None:
    for status, passed, unreachable, rules in STEP_CELLS:
        cell = (status.value, passed, unreachable, rules.on_check_failed, rules.on_unreachable)
        actual = step_verdict(status, passed, unreachable, rules)
        assert actual in STEP_VERDICTS, cell
        if actual is PASS:
            assert (status, passed) == (COMPLETED, True), cell
        if actual is FAIL:
            assert status is COMPLETED, cell
            assert passed is not True or (unreachable and rules.on_unreachable == "fail"), cell
        assert (actual is ERROR) == (status is ExecutionStatus.ERROR), cell


# --- 7.2 Path verdict ----------------------------------------------------------------------


def path_oracle(applicability: Tri, steps: Sequence[Verdict]) -> Verdict:
    """Section 7.2. First match wins."""
    if applicability is F:
        return NOT_APPLICABLE
    if applicability is U:
        return INCONCLUSIVE
    if FAIL in steps:
        return FAIL
    if ERROR in steps:
        return ERROR
    if len(steps) == 0:
        return INCONCLUSIVE
    if INCONCLUSIVE in steps:
        return INCONCLUSIVE
    assert all(step is PASS for step in steps)
    return PASS


def test_path_verdict_matches_the_precedence_for_every_tuple_of_up_to_three_steps() -> None:
    cells = list(itertools.product(Tri, tuples(STEP_VERDICTS, 3)))
    assert len(cells) == 3 * (1 + 4 + 16 + 64)
    for applicability, steps in cells:
        assert path_verdict(applicability, steps) is path_oracle(applicability, steps), (applicability, steps)


# --- 7.3 Requirement verdict ---------------------------------------------------------------


def alternatives_oracle(paths: Sequence[Verdict]) -> Verdict:
    """Section 7.3, rules 4 and 5: paths are alternative ways to assess."""
    if len(paths) == 0:
        return INCONCLUSIVE
    remaining = [verdict for verdict in paths if verdict is not NOT_APPLICABLE]
    for decisive in (FAIL, PASS, ERROR):
        if decisive in remaining:
            return decisive
    return INCONCLUSIVE


def requirement_oracle(
    applicability: Tri,
    conflict: bool,
    paths: Sequence[Verdict],
    mode: ExecutionMode,
    review_status: ReviewStatus,
) -> Verdict:
    """Section 7.3. First match wins. Rule 6 is the second barrier on a pass."""
    if applicability is F:
        return NOT_APPLICABLE
    if applicability is U:
        return INCONCLUSIVE
    if conflict:
        return FAIL
    verdict = alternatives_oracle(paths)
    if verdict is PASS and mode is ExecutionMode.REVIEWED and review_status is not ReviewStatus.APPROVED:
        return INCONCLUSIVE
    return verdict


REQUIREMENT_CELLS = list(
    itertools.product(Tri, (True, False), tuples(tuple(Verdict), 2), ExecutionMode, ReviewStatus)
)


def test_requirement_verdict_matches_the_precedence_in_every_cell() -> None:
    assert len(REQUIREMENT_CELLS) == 3 * 2 * (1 + 5 + 25) * 3 * 5
    for cell in REQUIREMENT_CELLS:
        verdict, reason = requirement_verdict(*cell)
        assert verdict is requirement_oracle(*cell), cell
        assert reason.strip(), cell


# --- 7.4 Overall outcome -------------------------------------------------------------------


def overall_oracle(results: Sequence[RequirementResult]) -> Verdict:
    """Section 7.4. Mandatory requirements with applicability true only."""
    scope = [r.verdict for r in results if r.modality is Modality.MANDATORY and r.applicability is T]
    if len(scope) == 0:
        return INCONCLUSIVE
    for decisive in (FAIL, ERROR, INCONCLUSIVE):
        if decisive in scope:
            return decisive
    return PASS


def result(
    verdict: Verdict, modality: Modality = Modality.MANDATORY, applicability: Tri = T
) -> RequirementResult:
    return RequirementResult(
        requirement_id="R-1",
        pack_id="pack/a",
        authority_class=AuthorityClass.ILLUSTRATIVE,
        modality=modality,
        review_status=ReviewStatus.DRAFT,
        testability="automated",
        applicability=applicability,
        applicability_reason="synthetic",
        verdict=verdict,
        verdict_reason="synthetic",
        claim_level=ClaimLevel.ILLUSTRATIVE,
    )


def test_overall_verdict_matches_the_precedence_for_every_multiset_of_up_to_three_results() -> None:
    kinds = [result(*kind) for kind in itertools.product(Verdict, Modality, Tri)]
    assert len(kinds) == 45
    multisets = [combo for size in range(4) for combo in itertools.combinations_with_replacement(kinds, size)]
    assert len(multisets) == 1 + 45 + 1035 + 16215
    for results in multisets:
        cell = [(r.verdict.value, r.modality.value, r.applicability.value) for r in results]
        expected = overall_oracle(results)
        verdict, reason = overall_verdict(results)
        assert verdict is expected, cell
        assert reason.strip(), cell
        assert overall_verdict(results[::-1])[0] is expected, ("the order must not matter", cell)


# --- The rules by name ---------------------------------------------------------------------


def test_an_empty_run_cannot_pass() -> None:
    assert overall_verdict([])[0] is INCONCLUSIVE
    assert (
        overall_verdict([result(PASS, Modality.RECOMMENDED), result(PASS, Modality.OPTIONAL)])[0]
        is INCONCLUSIVE
    )
    assert overall_verdict([result(NOT_APPLICABLE, applicability=F)])[0] is INCONCLUSIVE
    assert overall_verdict([result(INCONCLUSIVE, applicability=U)])[0] is INCONCLUSIVE


@pytest.mark.parametrize("mode", list(ExecutionMode))
def test_an_applicable_requirement_with_zero_steps_cannot_pass(mode: ExecutionMode) -> None:
    assert path_verdict(T, []) is INCONCLUSIVE
    assert requirement_verdict(T, False, [], mode, ReviewStatus.APPROVED)[0] is INCONCLUSIVE
    assert (
        requirement_verdict(T, False, [path_verdict(T, [])], mode, ReviewStatus.APPROVED)[0] is INCONCLUSIVE
    )
    assert overall_verdict([result(INCONCLUSIVE)])[0] is INCONCLUSIVE


@pytest.mark.parametrize(
    "status", [ExecutionStatus.UNSUPPORTED, ExecutionStatus.NOT_RUN, ExecutionStatus.BLOCKED]
)
def test_an_unavailable_adapter_never_gives_pass(status: ExecutionStatus) -> None:
    for passed, unreachable, rules in itertools.product((True, False, None), (True, False), ALL_RULES):
        step = step_verdict(status, passed, unreachable, rules)
        assert step is INCONCLUSIVE
        assert path_verdict(T, [PASS, step]) is INCONCLUSIVE, "one unavailable step blocks the path"
    only = path_verdict(T, [INCONCLUSIVE])
    assert (
        requirement_verdict(T, False, [only], ExecutionMode.EXPLORATORY, ReviewStatus.DRAFT)[0]
        is INCONCLUSIVE
    )


def test_an_unavailable_manual_review_is_inconclusive() -> None:
    for passed, unreachable, rules in itertools.product((True, False, None), (True, False), ALL_RULES):
        assert step_verdict(ExecutionStatus.MANUAL_UNAVAILABLE, passed, unreachable, rules) is INCONCLUSIVE
    assert path_verdict(T, [PASS, INCONCLUSIVE]) is INCONCLUSIVE


def test_an_unreachable_system_is_inconclusive_by_default_and_fails_only_when_the_rule_says_so() -> None:
    default = VerdictRules()
    assert default.on_unreachable == "inconclusive"
    assert step_verdict(COMPLETED, False, True, default) is INCONCLUSIVE
    for on_check_failed in ("fail", "inconclusive"):
        lenient = VerdictRules(on_check_failed=on_check_failed, on_unreachable="inconclusive")
        strict = VerdictRules(on_check_failed=on_check_failed, on_unreachable="fail")
        assert step_verdict(COMPLETED, False, True, lenient) is INCONCLUSIVE
        assert step_verdict(COMPLETED, False, True, strict) is FAIL
    # The rule for an unreachable system does not touch a reachable one.
    assert step_verdict(COMPLETED, False, False, VerdictRules(on_unreachable="fail")) is FAIL
    lenient = VerdictRules(on_check_failed="inconclusive", on_unreachable="fail")
    assert step_verdict(COMPLETED, False, False, lenient) is INCONCLUSIVE


def test_a_check_that_raised_is_an_error_and_never_a_fail() -> None:
    for passed, unreachable, rules in itertools.product((True, False, None), (True, False), ALL_RULES):
        assert step_verdict(ExecutionStatus.ERROR, passed, unreachable, rules) is ERROR
    assert path_verdict(T, [PASS, ERROR]) is ERROR
    assert path_verdict(T, [ERROR, INCONCLUSIVE]) is ERROR
    assert requirement_verdict(T, False, [ERROR], ExecutionMode.EXPLORATORY, ReviewStatus.DRAFT)[0] is ERROR
    assert overall_verdict([result(ERROR), result(PASS)])[0] is ERROR


@pytest.mark.parametrize("review_status", list(ReviewStatus))
def test_a_pass_in_reviewed_mode_needs_an_approved_interpretation(review_status: ReviewStatus) -> None:
    approved = review_status is ReviewStatus.APPROVED
    reviewed = requirement_verdict(T, False, [PASS], ExecutionMode.REVIEWED, review_status)[0]
    assert reviewed is (PASS if approved else INCONCLUSIVE)
    # The barrier is on a pass only. It does not soften a failure.
    assert requirement_verdict(T, False, [FAIL, PASS], ExecutionMode.REVIEWED, review_status)[0] is FAIL
    for mode in (ExecutionMode.ILLUSTRATIVE, ExecutionMode.EXPLORATORY):
        assert requirement_verdict(T, False, [PASS], mode, review_status)[0] is PASS


def test_not_applicable_needs_applicability_false_and_unknown_gives_inconclusive() -> None:
    for steps in tuples(STEP_VERDICTS, 2):
        assert path_verdict(F, steps) is NOT_APPLICABLE
        assert path_verdict(U, steps) is INCONCLUSIVE, (
            "a failing value under unknown applicability is nothing"
        )
        assert path_verdict(T, steps) is not NOT_APPLICABLE
    for applicability, conflict, paths, mode, review_status in REQUIREMENT_CELLS:
        verdict = requirement_verdict(applicability, conflict, paths, mode, review_status)[0]
        assert (verdict is NOT_APPLICABLE) == (applicability is F), (applicability, conflict, paths)
        if applicability is U:
            assert verdict is INCONCLUSIVE, (conflict, paths)


def test_a_declared_non_implementation_of_an_applicable_mandatory_requirement_is_a_fail() -> None:
    for paths, mode, review_status in itertools.product(
        tuples(tuple(Verdict), 2), ExecutionMode, ReviewStatus
    ):
        assert requirement_verdict(T, True, paths, mode, review_status)[0] is FAIL, (paths, mode)
        # The conflict needs an applicable requirement.
        assert requirement_verdict(U, True, paths, mode, review_status)[0] is INCONCLUSIVE
        assert requirement_verdict(F, True, paths, mode, review_status)[0] is NOT_APPLICABLE


@pytest.mark.parametrize("other", list(Verdict))
def test_a_failing_path_makes_the_requirement_fail_even_if_a_different_path_passes(other: Verdict) -> None:
    for paths in ([FAIL, other], [other, FAIL], [FAIL, PASS, other]):
        assert requirement_verdict(T, False, paths, ExecutionMode.EXPLORATORY, ReviewStatus.DRAFT)[0] is FAIL


@pytest.mark.parametrize("other", [PASS, ERROR, INCONCLUSIVE, NOT_APPLICABLE])
def test_one_passing_path_is_enough_when_no_path_fails(other: Verdict) -> None:
    for paths in ([PASS, other], [other, PASS], [PASS]):
        assert requirement_verdict(T, False, paths, ExecutionMode.EXPLORATORY, ReviewStatus.DRAFT)[0] is PASS


def test_a_requirement_with_no_applicable_path_and_one_with_only_gaps_are_inconclusive() -> None:
    draft = (ExecutionMode.EXPLORATORY, ReviewStatus.DRAFT)
    assert requirement_verdict(T, False, [NOT_APPLICABLE, NOT_APPLICABLE], *draft)[0] is INCONCLUSIVE
    assert requirement_verdict(T, False, [NOT_APPLICABLE, INCONCLUSIVE], *draft)[0] is INCONCLUSIVE
    assert requirement_verdict(T, False, [ERROR, INCONCLUSIVE], *draft)[0] is ERROR


@pytest.mark.parametrize("ignored", [Modality.RECOMMENDED, Modality.OPTIONAL])
def test_the_overall_outcome_ignores_recommended_and_optional_requirements(ignored: Modality) -> None:
    for verdict in Verdict:
        assert overall_verdict([result(PASS), result(verdict, ignored)])[0] is PASS, verdict
        assert overall_verdict([result(FAIL), result(verdict, ignored)])[0] is FAIL, verdict
        assert overall_verdict([result(verdict, ignored)])[0] is INCONCLUSIVE, verdict


def test_the_overall_outcome_follows_fail_then_error_then_inconclusive_then_pass() -> None:
    assert overall_verdict([result(PASS), result(INCONCLUSIVE), result(ERROR), result(FAIL)])[0] is FAIL
    assert overall_verdict([result(PASS), result(INCONCLUSIVE), result(ERROR)])[0] is ERROR
    assert overall_verdict([result(PASS), result(INCONCLUSIVE)])[0] is INCONCLUSIVE
    assert overall_verdict([result(PASS), result(PASS)])[0] is PASS
    # A requirement that does not apply, or whose applicability is unknown, is outside the scope.
    assert overall_verdict([result(PASS), result(FAIL, applicability=U)])[0] is PASS
    assert overall_verdict([result(PASS), result(NOT_APPLICABLE, applicability=F)])[0] is PASS


# --- Section 4: claim level ----------------------------------------------------------------

CLOSED = (ReviewStatus.SUPERSEDED, ReviewStatus.WITHDRAWN)
INTERPRETED = (ReviewStatus.DRAFT, ReviewStatus.APPROVED)


def claim_oracle(
    mode: ExecutionMode, authority_class: AuthorityClass, review_status: ReviewStatus
) -> set[ClaimLevel] | None:
    """Section 4, first table. ``None``: the mode does not permit the requirement, so no row applies."""
    illustrative = authority_class is AuthorityClass.ILLUSTRATIVE
    if review_status in CLOSED:
        return None
    if mode is ExecutionMode.ILLUSTRATIVE:
        return {ClaimLevel.ILLUSTRATIVE} if illustrative else None
    if mode is ExecutionMode.REVIEWED:
        return {ClaimLevel.REVIEWED} if review_status is ReviewStatus.APPROVED else None
    if illustrative and review_status in INTERPRETED:
        # "diagnostic, or illustrative": both columns of the row match such a requirement.
        return {ClaimLevel.ILLUSTRATIVE, ClaimLevel.DIAGNOSTIC}
    if illustrative:
        return {ClaimLevel.ILLUSTRATIVE}
    return {ClaimLevel.DIAGNOSTIC} if review_status in INTERPRETED else None


CLAIM_CELLS = list(itertools.product(ExecutionMode, AuthorityClass, ReviewStatus))


@pytest.mark.parametrize(
    ("mode", "authority_class", "review_status"),
    CLAIM_CELLS,
    ids=[f"{m.value}/{a.value}/{s.value}" for m, a, s in CLAIM_CELLS],
)
def test_claim_level_matches_the_table_for_every_mode_authority_class_and_review_status(
    mode: ExecutionMode, authority_class: AuthorityClass, review_status: ReviewStatus
) -> None:
    assert len(CLAIM_CELLS) == 3 * 5 * 5
    actual = claim_level(mode, authority_class, review_status)
    permitted = claim_oracle(mode, authority_class, review_status)
    if permitted is not None:
        assert actual in permitted
    # Upper bounds that hold in every cell, also where the mode does not permit the requirement.
    if actual is ClaimLevel.REVIEWED:
        assert (mode, review_status) == (ExecutionMode.REVIEWED, ReviewStatus.APPROVED)
    if actual is ClaimLevel.DIAGNOSTIC:
        assert mode is ExecutionMode.EXPLORATORY
        assert review_status in INTERPRETED
    if actual is ClaimLevel.ILLUSTRATIVE:
        assert authority_class is AuthorityClass.ILLUSTRATIVE
        assert mode is not ExecutionMode.REVIEWED


# --- aggregate() ---------------------------------------------------------------------------


def step_result(test_id: str, verdict: Verdict, status: ExecutionStatus = COMPLETED) -> TestResult:
    return TestResult(
        test_purpose_id=test_id,
        requirement_ids=("R-1",),
        check="probe.ok",
        applicability=T,
        applicability_reason="synthetic",
        execution_status=status,
        verdict=verdict,
        severity="major",
        reason_code=f"SYNTHETIC.{verdict.value.upper()}",
        message="synthetic",
    )


def planned_path(path_id: str, *tests: str, applicability: Tri = T) -> PlannedPath:
    return PlannedPath(
        path_id=path_id, applicability=applicability, applicability_reason="synthetic", tests=tests
    )


def run_aggregate(
    paths: Sequence[PlannedPath],
    steps: Sequence[TestResult],
    *,
    applicability: Tri = T,
    conflict: bool = False,
    mode: ExecutionMode = ExecutionMode.EXPLORATORY,
    requirement: Requirement | None = None,
) -> RequirementResult:
    requirement = requirement or b.requirement("R-1")
    plan = Plan(
        schema_version="dppce.plan/1",
        mode=mode,
        profile_id=b.PROFILE_ID,
        requirements=(
            PlannedRequirement(
                requirement_id=requirement.id,
                pack_id="pack/a",
                applicability=applicability,
                applicability_reason="the recorded reason",
                paths=tuple(paths),
            ),
        ),
        steps=(),
        exclusions=(),
        conflicts=[{"requirement_id": requirement.id, "declared": "no", "explanation": "synthetic"}]
        if conflict
        else (),
    )
    (only,) = aggregate(plan, {requirement.id: requirement}, {s.test_purpose_id: s for s in steps})
    return only


def mentions(retained: Sequence[str], name: str) -> bool:
    return any(name in entry for entry in retained)


def test_aggregate_treats_a_planned_step_with_no_result_as_inconclusive() -> None:
    missing = run_aggregate([planned_path("p1", "T-1")], [])
    assert missing.verdict is INCONCLUSIVE
    assert [p.verdict for p in missing.paths] == [INCONCLUSIVE]
    partial = run_aggregate([planned_path("p1", "T-1", "T-2")], [step_result("T-1", PASS)])
    assert partial.verdict is INCONCLUSIVE, "a pass and a missing result do not make a pass"
    assert mentions(partial.retained, "T-2")


def test_aggregate_passes_a_requirement_only_when_every_step_of_a_path_passed() -> None:
    passed = run_aggregate(
        [planned_path("p1", "T-1", "T-2")], [step_result("T-1", PASS), step_result("T-2", PASS)]
    )
    assert passed.verdict is PASS
    assert passed.retained == ()
    assert [(p.path_id, p.verdict, p.steps) for p in passed.paths] == [("p1", PASS, ("T-1", "T-2"))]


def test_aggregate_keeps_an_error_and_a_skipped_step_of_a_failing_requirement_in_retained() -> None:
    failing = run_aggregate(
        [planned_path("p1", "T-FAIL"), planned_path("p2", "T-ERR", "T-SKIP")],
        [
            step_result("T-FAIL", FAIL),
            step_result("T-ERR", ERROR, ExecutionStatus.ERROR),
            step_result("T-SKIP", INCONCLUSIVE, ExecutionStatus.SKIPPED),
        ],
    )
    assert failing.verdict is FAIL
    assert mentions(failing.retained, "T-ERR")
    assert mentions(failing.retained, "T-SKIP")


def test_aggregate_keeps_the_disagreement_when_one_path_fails_and_a_different_path_passes() -> None:
    disagreeing = run_aggregate(
        [planned_path("p1", "T-FAIL"), planned_path("p2", "T-OK")],
        [step_result("T-FAIL", FAIL), step_result("T-OK", PASS)],
    )
    assert disagreeing.verdict is FAIL
    assert [p.verdict for p in disagreeing.paths] == [FAIL, PASS]
    assert disagreeing.retained != ()


def test_aggregate_keeps_an_error_in_a_different_path_when_one_path_passes() -> None:
    passing = run_aggregate(
        [planned_path("p1", "T-OK"), planned_path("p2", "T-ERR")],
        [step_result("T-OK", PASS), step_result("T-ERR", ERROR, ExecutionStatus.ERROR)],
    )
    assert passing.verdict is PASS
    assert mentions(passing.retained, "T-ERR")


def test_aggregate_keeps_a_skipped_step_in_a_different_path_when_one_path_passes() -> None:
    passing = run_aggregate(
        [planned_path("p1", "T-OK"), planned_path("p2", "T-SKIP")],
        [step_result("T-OK", PASS), step_result("T-SKIP", INCONCLUSIVE, ExecutionStatus.SKIPPED)],
    )
    assert passing.verdict is PASS
    assert mentions(passing.retained, "T-SKIP")


def test_aggregate_keeps_a_path_with_no_step_in_retained_when_a_different_path_passes() -> None:
    """Section 7.3, rule 5: "An error or a gap in a different path is kept in retained"."""
    passing = run_aggregate([planned_path("p1", "T-OK"), planned_path("p2")], [step_result("T-OK", PASS)])
    assert [p.verdict for p in passing.paths] == [PASS, INCONCLUSIVE]
    assert passing.verdict is PASS
    assert passing.retained != (), "the path with no executable step is a gap that the pass hides"


def test_aggregate_keeps_a_path_of_unknown_applicability_in_retained_when_a_different_path_passes() -> None:
    """Section 7.3: "Each other problem that the precedence hides is kept in retained"."""
    passing = run_aggregate(
        [planned_path("p1", "T-OK"), planned_path("p2", "T-OK", applicability=U)], [step_result("T-OK", PASS)]
    )
    assert [p.verdict for p in passing.paths] == [PASS, INCONCLUSIVE]
    assert passing.verdict is PASS
    assert passing.retained != (), "the unknown applicability of the second path is hidden by the pass"


def test_aggregate_fails_a_requirement_that_the_plan_lists_as_a_conflict() -> None:
    conflicting = run_aggregate(
        [planned_path("p1", "T-OK"), planned_path("p2", "T-ERR")],
        [step_result("T-OK", PASS), step_result("T-ERR", ERROR, ExecutionStatus.ERROR)],
        conflict=True,
    )
    assert conflicting.verdict is FAIL
    assert conflicting.applicability is T, "the requirement stays applicable"
    assert mentions(conflicting.retained, "T-ERR")


def test_aggregate_gives_not_applicable_with_the_recorded_reason_and_never_for_unknown() -> None:
    steps = [step_result("T-1", FAIL)]
    absent = run_aggregate([planned_path("p1", "T-1")], steps, applicability=F)
    assert absent.verdict is NOT_APPLICABLE
    assert "the recorded reason" in (absent.applicability_reason, absent.verdict_reason)
    unknown = run_aggregate([planned_path("p1", "T-1")], steps, applicability=U)
    assert unknown.verdict is INCONCLUSIVE, "a failing value under unknown applicability establishes nothing"


def test_aggregate_does_not_let_a_not_applicable_path_decide() -> None:
    steps = [step_result("T-FAIL", FAIL), step_result("T-OK", PASS)]
    paths = [planned_path("p1", "T-FAIL", applicability=F), planned_path("p2", "T-OK")]
    assert run_aggregate(paths, steps).verdict is PASS
    only = run_aggregate([planned_path("p1", "T-OK", applicability=F)], steps)
    assert only.verdict is INCONCLUSIVE, "no permitted path is declared as implemented"


def test_aggregate_applies_the_second_barrier_of_reviewed_mode() -> None:
    steps = [step_result("T-1", PASS)]
    draft = run_aggregate([planned_path("p1", "T-1")], steps, mode=ExecutionMode.REVIEWED)
    assert draft.verdict is INCONCLUSIVE
    approved = b.requirement("R-1", review_status="approved", approval=b.TEST_ONLY_APPROVAL)
    reviewed = run_aggregate(
        [planned_path("p1", "T-1")], steps, mode=ExecutionMode.REVIEWED, requirement=approved
    )
    assert reviewed.verdict is PASS


def test_aggregate_copies_the_separate_facts_of_each_requirement_and_sorts_by_identifier() -> None:
    first = b.requirement(
        "R-A", modality="optional", testability="manual", authority_class="guidance", source=b.CITED
    )
    second = b.requirement("R-B", review_status="placeholder")
    plan = Plan(
        schema_version="dppce.plan/1",
        mode=ExecutionMode.EXPLORATORY,
        profile_id=b.PROFILE_ID,
        requirements=tuple(
            PlannedRequirement(
                requirement_id=rid, pack_id=pack_id, applicability=applicability, applicability_reason=rid
            )
            for rid, pack_id, applicability in (("R-B", "pack/b", U), ("R-A", "pack/a", T))
        ),
        steps=(),
        exclusions=(),
        conflicts=(),
    )
    results = aggregate(plan, {"R-A": first, "R-B": second}, {})
    assert [r.requirement_id for r in results] == ["R-A", "R-B"]
    a, placeholder = results
    assert (a.pack_id, a.modality, a.testability, a.authority_class, a.review_status, a.applicability) == (
        "pack/a",
        Modality.OPTIONAL,
        first.testability,
        AuthorityClass.GUIDANCE,
        ReviewStatus.DRAFT,
        T,
    )
    assert a.claim_level is ClaimLevel.DIAGNOSTIC
    assert a.verdict is INCONCLUSIVE, "no assessment path is defined"
    assert (placeholder.pack_id, placeholder.review_status, placeholder.applicability) == (
        "pack/b",
        ReviewStatus.PLACEHOLDER,
        U,
    )
    assert placeholder.verdict is INCONCLUSIVE
