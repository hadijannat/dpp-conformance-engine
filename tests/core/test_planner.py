"""Planning: mode exclusions, conflicts, and the planned status of each step.

Every expected value comes from docs/explanation/architecture.md, sections 4 and 6.
The oracle for the second table of section 6 is a transcription of that table.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

import pytest
from pydantic import ValidationError

from dppce.models import (
    CapabilityState,
    ExecutionMode,
    ExecutionStatus,
    Plan,
    PlannedStep,
    Requirement,
    RequirementResult,
    Scope,
    TestPurpose,
    TestResult,
    Tri,
    Verdict,
)
from dppce.orchestrator.plan import (  # noqa: TID251 - the planner is the unit under test
    CheckInfo,
    PlanError,
    build_plan,
    mode_exclusion,
)
from dppce.verdicts import aggregate
from tests.core import builders as b

T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN
SKIPPED, BLOCKED = ExecutionStatus.SKIPPED, ExecutionStatus.BLOCKED
UNSUPPORTED, MANUAL = ExecutionStatus.UNSUPPORTED, ExecutionStatus.MANUAL_UNAVAILABLE
LEFT_OUT = "left out of its path"

SUPPORTED = CheckInfo(state=CapabilityState.SUPPORTED, available=True)
CHECKS = {"probe.ok": SUPPORTED}
# How a test declares a fact so that an expression on it gives each of the three values.
DECLARED: dict[Tri, bool | str] = {T: True, F: False, U: "unknown"}
NORMATIVE: dict[str, Any] = {"authority_class": "guidance", "source": b.CITED}
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)+$")


def plan_for(
    requirements: Sequence[Requirement],
    purposes: Sequence[TestPurpose],
    *,
    mode: str = "exploratory",
    features: Mapping[str, bool | str] | None = None,
    checks: Mapping[str, CheckInfo] = CHECKS,
    granted: frozenset[Scope] = frozenset(),
) -> Plan:
    return build_plan(
        mode=ExecutionMode(mode),
        profile=b.profile(),
        packs={"pack/a": b.pack(*requirements)},
        testpacks={"tp/a": b.purposes_pack(*purposes)},
        ics=b.ics(features=dict(features or {})),
        checks=checks,
        granted_scopes=granted,
    )


def step_of(plan: Plan, test_id: str) -> PlannedStep | None:
    found = [s for s in plan.steps if s.test_purpose_id == test_id]
    assert len(found) <= 1, "a step is planned once"
    return found[0] if found else None


def executed(plan: Plan) -> list[str]:
    return [s.test_purpose_id for s in plan.steps if s.planned_status is None]


def exclusion_codes(plan: Plan, kind: str) -> dict[str, str]:
    return {e.id: e.reason_code for e in plan.exclusions if e.kind == kind}


def assess(
    plan: Plan, requirements: Sequence[Requirement], passing: Sequence[str]
) -> dict[str, RequirementResult]:
    """Aggregate the plan as if each executed step in ``passing`` passed and each other one failed."""
    results = {}
    for step in plan.steps:
        ran = step.planned_status is None
        verdict = Verdict.INCONCLUSIVE
        if ran:
            verdict = Verdict.PASS if step.test_purpose_id in passing else Verdict.FAIL
        results[step.test_purpose_id] = TestResult(
            test_purpose_id=step.test_purpose_id,
            requirement_ids=(),
            check=step.check,
            applicability=step.applicability,
            applicability_reason=step.applicability_reason,
            execution_status=ExecutionStatus.COMPLETED if ran else step.planned_status,
            verdict=verdict,
            severity="major",
            reason_code="SYNTHETIC.RESULT",
            message="synthetic",
        )
    return {r.requirement_id: r for r in aggregate(plan, {r.id: r for r in requirements}, results)}


# --- Section 6, second table ---------------------------------------------------------------

CHECK_STATES: dict[str, CheckInfo | None] = {
    "unregistered": None,
    "supported": SUPPORTED,
    "experimental": CheckInfo(state=CapabilityState.EXPERIMENTAL, available=True),
    "interface_only": CheckInfo(state=CapabilityState.INTERFACE_ONLY, available=True),
    "unsupported": CheckInfo(state=CapabilityState.UNSUPPORTED, available=True),
    "not_installed": CheckInfo(state=CapabilityState.SUPPORTED, available=False),
}
ABOVE_READ = (Scope.WRITE, Scope.TAMPER, Scope.FUZZ, Scope.ACCESS_PROBE)


class Cell(NamedTuple):
    """One combination of the inputs that the second table of section 6 reads."""

    step: Tri
    parent: Tri
    manual: bool
    check: str
    scope: Scope
    granted: frozenset[Scope] = frozenset()


def planned_oracle(cell: Cell) -> ExecutionStatus | str | None:
    """Section 6, second table. The conditions are tested in the order of the rows."""
    if cell.step is F:
        return LEFT_OUT
    if cell.parent is not T:
        return SKIPPED
    if cell.step is U:
        return SKIPPED
    if cell.manual:
        return MANUAL
    if cell.check not in ("supported", "experimental"):
        return UNSUPPORTED
    if cell.scope in ABOVE_READ and cell.scope not in cell.granted:
        return BLOCKED
    return None


def plan_cell(cell: Cell) -> Plan:
    info = CHECK_STATES[cell.check]
    return plan_for(
        [b.requirement("R-1", applicability=b.feature("parent"), assessment_paths=[b.path("p1", "T-1")])],
        [b.purpose("T-1", applicability=b.feature("step"), manual=cell.manual, requires_scope=cell.scope)],
        features={"parent": DECLARED[cell.parent], "step": DECLARED[cell.step]},
        checks={} if info is None else {"probe.ok": info},
        granted=cell.granted,
    )


def assert_cell(cell: Cell, expected: ExecutionStatus | str | None) -> None:
    plan = plan_cell(cell)
    step = step_of(plan, "T-1")
    in_path = "T-1" in plan.requirements[0].paths[0].tests
    if expected == LEFT_OUT:
        assert step is None, cell
        assert not in_path, cell
        left_out = [e for e in plan.exclusions if (e.kind, e.id) == ("test_purpose", "T-1")]
        assert len(left_out) == 1, cell
        assert left_out[0].reason.strip(), cell
        return
    assert step is not None, cell
    assert in_path, cell
    assert step.planned_status is expected, cell
    if expected is not None:
        assert step.planned_reason.strip(), cell


def test_planned_status_matches_the_table_in_every_cell() -> None:
    cells = 0
    for step, parent, manual, check, scope in itertools.product(Tri, Tri, (False, True), CHECK_STATES, Scope):
        other = Scope.TAMPER if scope is Scope.WRITE else Scope.WRITE
        for granted in (frozenset[Scope](), frozenset({scope}), frozenset({other})):
            cell = Cell(step, parent, manual, check, scope, granted)
            assert_cell(cell, planned_oracle(cell))
            cells += 1
    assert cells == 3 * 3 * 2 * 6 * 6 * 3


READ, WRITE = Scope.READ, Scope.WRITE
TABLE_ROWS = [
    ("row1-step-not-applicable", Cell(F, T, False, "supported", READ), LEFT_OUT),
    ("row2-parent-not-applicable", Cell(T, F, False, "supported", READ), SKIPPED),
    ("row2-parent-unknown", Cell(T, U, False, "supported", READ), SKIPPED),
    ("row3-step-unknown", Cell(U, T, False, "supported", READ), SKIPPED),
    ("row4-manual", Cell(T, T, True, "supported", READ), MANUAL),
    ("row5-not-in-registry", Cell(T, T, False, "unregistered", READ), UNSUPPORTED),
    ("row5-interface-only", Cell(T, T, False, "interface_only", READ), UNSUPPORTED),
    ("row5-unsupported", Cell(T, T, False, "unsupported", READ), UNSUPPORTED),
    ("row5-dependency-not-installed", Cell(T, T, False, "not_installed", READ), UNSUPPORTED),
    ("row6-scope-not-granted", Cell(T, T, False, "supported", WRITE), BLOCKED),
    ("row7-supported-is-executed", Cell(T, T, False, "supported", READ), None),
    ("row7-experimental-is-executed", Cell(T, T, False, "experimental", READ), None),
    ("row1-wins-over-row2", Cell(F, F, False, "supported", READ), LEFT_OUT),
    ("row1-wins-over-row4", Cell(F, T, True, "supported", READ), LEFT_OUT),
    ("row1-wins-over-row5", Cell(F, T, False, "unregistered", READ), LEFT_OUT),
    ("row1-wins-over-row6", Cell(F, T, False, "supported", WRITE), LEFT_OUT),
    ("row2-wins-over-row4", Cell(T, U, True, "supported", READ), SKIPPED),
    ("row2-wins-over-row5", Cell(T, F, False, "unregistered", READ), SKIPPED),
    ("row2-wins-over-row6", Cell(T, F, False, "supported", WRITE), SKIPPED),
    ("row3-wins-over-row4", Cell(U, T, True, "supported", READ), SKIPPED),
    ("row3-wins-over-row5", Cell(U, T, False, "interface_only", READ), SKIPPED),
    ("row3-wins-over-row6", Cell(U, T, False, "supported", WRITE), SKIPPED),
    ("row4-wins-over-row5", Cell(T, T, True, "unregistered", READ), MANUAL),
    ("row4-wins-over-row6", Cell(T, T, True, "supported", WRITE), MANUAL),
    ("row5-wins-over-row6", Cell(T, T, False, "interface_only", WRITE), UNSUPPORTED),
]


@pytest.mark.parametrize(
    ("cell", "expected"), [row[1:] for row in TABLE_ROWS], ids=[row[0] for row in TABLE_ROWS]
)
def test_each_row_of_the_table_and_the_earlier_row_wins(
    cell: Cell, expected: ExecutionStatus | str | None
) -> None:
    assert_cell(cell, expected)


@pytest.mark.parametrize("scope", ABOVE_READ)
def test_a_scope_above_read_needs_a_grant_of_that_scope(scope: Scope) -> None:
    others = frozenset(ABOVE_READ) - {scope}
    assert_cell(Cell(T, T, False, "supported", scope), BLOCKED)
    assert_cell(Cell(T, T, False, "supported", scope, others), BLOCKED)
    assert_cell(Cell(T, T, False, "supported", scope, frozenset({Scope.READ})), BLOCKED)
    assert_cell(Cell(T, T, False, "supported", scope, frozenset({scope})), None)


@pytest.mark.parametrize("scope", [Scope.NONE, Scope.READ])
def test_a_scope_of_read_or_below_needs_no_authorization(scope: Scope) -> None:
    assert_cell(Cell(T, T, False, "supported", scope), None)


@pytest.mark.parametrize(
    "check", [name for name in CHECK_STATES if name not in ("supported", "experimental")]
)
def test_an_unavailable_adapter_never_produces_a_pass(check: str) -> None:
    requirement = b.requirement(
        "R-1", applicability=b.feature("parent"), assessment_paths=[b.path("p1", "T-1")]
    )
    plan = plan_cell(Cell(T, T, False, check, Scope.READ))
    assert executed(plan) == []
    assert assess(plan, [requirement], passing=["T-1"])["R-1"].verdict is Verdict.INCONCLUSIVE


# --- Section 4 and section 6, step 1: mode exclusions --------------------------------------

EXCLUDED = [
    ("illustrative", {**NORMATIVE}, "MODE.NOT_ILLUSTRATIVE"),
    (
        "illustrative",
        {**NORMATIVE, "review_status": "approved", "approval": b.TEST_ONLY_APPROVAL},
        "MODE.NOT_ILLUSTRATIVE",
    ),
    ("reviewed", {**NORMATIVE}, "MODE.NOT_APPROVED"),
    ("reviewed", {"authority_class": "illustrative"}, "MODE.NOT_APPROVED"),
    (
        "exploratory",
        {**NORMATIVE, "review_status": "superseded", "superseded_by": "R-9"},
        "STATUS.SUPERSEDED",
    ),
    ("exploratory", {**NORMATIVE, "review_status": "withdrawn"}, "STATUS.WITHDRAWN"),
]


@pytest.mark.parametrize(("mode", "changes", "code"), EXCLUDED, ids=[f"{m}-{c}" for m, _, c in EXCLUDED])
def test_a_requirement_that_the_mode_does_not_permit_is_an_exclusion_with_its_reason_code(
    mode: str, changes: dict[str, Any], code: str
) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")], **changes)
    plan = plan_for([requirement], [b.purpose("T-1")], mode=mode)
    listed = [e for e in plan.exclusions if e.kind == "requirement"]
    assert [(e.id, e.reason_code) for e in listed] == [("R-1", code)]
    assert listed[0].reason.strip()
    assert executed(plan) == [], "a step of an excluded requirement does not run"
    gate = mode_exclusion(ExecutionMode(mode), requirement)
    assert gate is not None
    assert gate[0] == code


PERMITTED = [
    ("illustrative", {"authority_class": "illustrative"}),
    ("exploratory", {"authority_class": "illustrative"}),
    ("exploratory", {**NORMATIVE}),
    ("exploratory", {**NORMATIVE, "review_status": "approved", "approval": b.TEST_ONLY_APPROVAL}),
    ("reviewed", {**NORMATIVE, "review_status": "approved", "approval": b.TEST_ONLY_APPROVAL}),
]


@pytest.mark.parametrize(("mode", "changes"), PERMITTED)
def test_a_requirement_that_the_mode_permits_is_planned_and_its_step_runs(
    mode: str, changes: dict[str, Any]
) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")], **changes)
    plan = plan_for([requirement], [b.purpose("T-1")], mode=mode)
    assert exclusion_codes(plan, "requirement") == {}
    assert [(r.requirement_id, r.applicability) for r in plan.requirements] == [("R-1", T)]
    assert executed(plan) == ["T-1"]
    assert mode_exclusion(ExecutionMode(mode), requirement) is None


def test_a_requirement_with_two_grounds_for_exclusion_is_listed_once_with_one_of_them() -> None:
    superseded = b.requirement("R-1", review_status="superseded", superseded_by="R-9", **NORMATIVE)
    for mode, mode_code in (("illustrative", "MODE.NOT_ILLUSTRATIVE"), ("reviewed", "MODE.NOT_APPROVED")):
        codes = [e.reason_code for e in plan_for([superseded], [], mode=mode).exclusions]
        assert len(codes) == 1
        assert codes[0] in ("STATUS.SUPERSEDED", mode_code)


def test_a_placeholder_requirement_is_inconclusive_even_if_a_mapped_test_passes() -> None:
    """Section 4: a placeholder has no tests, and its verdict is inconclusive."""
    try:
        placeholder = b.requirement(
            "R-1",
            review_status="placeholder",
            authority_class="guidance",
            assessment_paths=[b.path("p1", "T-1")],
        )
    except ValidationError:
        return  # refusing the mapped test when the pack loads also keeps the rule
    plan = plan_for([placeholder], [b.purpose("T-1")], mode="exploratory")
    if "R-1" in exclusion_codes(plan, "requirement"):
        return  # an excluded requirement gets no verdict at all
    assert assess(plan, [placeholder], passing=["T-1"])["R-1"].verdict is Verdict.INCONCLUSIVE


def test_a_placeholder_requirement_without_tests_is_inconclusive_in_exploratory_mode() -> None:
    placeholder = b.requirement("R-1", review_status="placeholder", authority_class="guidance")
    plan = plan_for([placeholder], [], mode="exploratory")
    if "R-1" not in exclusion_codes(plan, "requirement"):
        assert assess(plan, [placeholder], passing=[])["R-1"].verdict is Verdict.INCONCLUSIVE


# --- Section 6, step 1: a selected approved successor --------------------------------------

BY_SELECTED = "STATUS.SUPERSEDED_BY_SELECTED"
APPROVAL: dict[str, Any] = {"review_status": "approved", "approval": b.TEST_ONLY_APPROVAL}
CLASS: dict[str, dict[str, Any]] = {
    "normative": NORMATIVE,
    "illustrative": {"authority_class": "illustrative"},
}


def draft(cls: str = "normative", requirement_id: str = "R-OLD", **changes: Any) -> Requirement:
    fields = {"assessment_paths": [b.path("p1", "T-OLD")]} | CLASS[cls] | changes
    return b.requirement(requirement_id, **fields)


def successor(
    cls: str = "normative",
    requirement_id: str = "R-NEW",
    supersedes: Sequence[str] = ("R-OLD",),
    **changes: Any,
) -> Requirement:
    fields = CLASS[cls] | APPROVAL | changes
    return b.requirement(
        requirement_id, supersedes=list(supersedes), assessment_paths=[b.path("p1", "T-NEW")], **fields
    )


def supersession_plan(
    old: Sequence[Requirement],
    new: Sequence[Requirement],
    *,
    mode: str = "exploratory",
    selected: Sequence[str] = ("pack/a", "pack/b"),
    features: Mapping[str, bool | str] | None = None,
) -> Plan:
    """The draft is in pack/a and the successor in pack/b. ``selected`` sets the pack order."""
    return build_plan(
        mode=ExecutionMode(mode),
        profile=b.profile(packs=list(selected)),
        packs={"pack/a": b.pack(*old), "pack/b": b.pack(*new, pack_id="pack/b")},
        testpacks={"tp/a": b.purposes_pack(b.purpose("T-OLD", requirements=["R-OLD"]), b.purpose("T-NEW"))},
        ics=b.ics(features=dict(features or {})),
        checks=CHECKS,
    )


def assert_superseded(plan: Plan, *successors: str) -> None:
    (exclusion,) = [e for e in plan.exclusions if (e.kind, e.id) == ("requirement", "R-OLD")]
    assert exclusion.reason_code == BY_SELECTED
    assert REASON_CODE.match(exclusion.reason_code)
    assert all(s in exclusion.reason for s in successors)
    assert "R-OLD" not in [r.requirement_id for r in plan.requirements]
    old_step = step_of(plan, "T-OLD")
    assert old_step is not None
    assert old_step.planned_status is SKIPPED, "no applicable requirement needs the step of the draft"


@pytest.mark.parametrize(
    ("mode", "cls"),
    [
        ("exploratory", "normative"),
        ("reviewed", "normative"),
        ("illustrative", "illustrative"),
        ("exploratory", "illustrative"),
    ],
)
def test_an_approved_selected_successor_excludes_its_draft_in_each_mode(mode: str, cls: str) -> None:
    plan = supersession_plan([draft(cls)], [successor(cls)], mode=mode)
    assert_superseded(plan, "R-NEW")
    assert [r.requirement_id for r in plan.requirements] == ["R-NEW"]
    assert executed(plan) == ["T-NEW"]


@pytest.mark.parametrize("selected", [("pack/a", "pack/b"), ("pack/b", "pack/a")])
def test_a_successor_in_a_later_pack_still_excludes_the_draft(selected: tuple[str, str]) -> None:
    plan = supersession_plan([draft()], [successor()], selected=selected)
    assert_superseded(plan, "R-NEW")


class Case(NamedTuple):
    mode: str
    new_cls: str
    new_changes: dict[str, Any]
    new_selected: bool
    old_cls: str
    expected: str  # 'planned' or the exclusion code of the draft


UNAPPROVED: dict[str, Any] = {"review_status": "draft-needs-review", "approval": None}
NOT_QUALIFYING = [
    Case("exploratory", "normative", {}, False, "normative", "planned"),
    Case("exploratory", "normative", UNAPPROVED, True, "normative", "planned"),
    Case("reviewed", "illustrative", {}, True, "illustrative", "MODE.NOT_APPROVED"),
    Case("exploratory", "illustrative", {}, True, "normative", "planned"),
    Case("reviewed", "normative", {}, True, "illustrative", "MODE.NOT_APPROVED"),
    Case("exploratory", "normative", {}, True, "illustrative", "planned"),
]


@pytest.mark.parametrize("case", NOT_QUALIFYING)
def test_the_draft_keeps_its_outcome_when_the_successor_does_not_qualify(case: Case) -> None:
    mode, expected = case.mode, case.expected
    selected = ("pack/a", "pack/b") if case.new_selected else ("pack/a",)
    new = successor(case.new_cls, **case.new_changes)
    plan = supersession_plan([draft(case.old_cls)], [new], mode=mode, selected=selected)
    codes = exclusion_codes(plan, "requirement")
    if expected == "planned":
        assert "R-OLD" not in codes
        assert "R-OLD" in [r.requirement_id for r in plan.requirements]
    else:
        assert codes["R-OLD"] == expected
    assert all(e.reason_code != BY_SELECTED for e in plan.exclusions)


OLD_ENTRIES: dict[str, dict[str, Any]] = {
    "placeholder": {"review_status": "placeholder", "assessment_paths": []},
    "withdrawn": {"review_status": "withdrawn"},
    "superseded": {"review_status": "superseded", "superseded_by": "R-NEW"},
    "approved": APPROVAL,
}


@pytest.mark.parametrize("status", sorted(OLD_ENTRIES))
def test_only_a_draft_is_superseded_by_a_selected_successor(status: str) -> None:
    old = draft(**OLD_ENTRIES[status])
    alone = supersession_plan([old], [])
    plan = supersession_plan([old], [successor()])
    before, after = exclusion_codes(alone, "requirement"), exclusion_codes(plan, "requirement")
    assert after.get("R-OLD") == before.get("R-OLD")
    planned = [r.requirement_id for r in plan.requirements]
    assert ("R-OLD" in planned) == ("R-OLD" in [r.requirement_id for r in alone.requirements])
    if status == "approved":
        assert "R-OLD" in planned, "an approved entry stays planned; the lint reports CAT010"


@pytest.mark.parametrize("selected", [("pack/a", "pack/b"), ("pack/b", "pack/a")])
def test_two_successors_give_one_exclusion_with_a_sorted_reason(selected: tuple[str, str]) -> None:
    plan = supersession_plan(
        [draft(), successor(requirement_id="R-B")], [successor(requirement_id="R-A")], selected=selected
    )
    assert [e.id for e in plan.exclusions if e.kind == "requirement"] == ["R-OLD"]
    assert_superseded(plan, "R-A, R-B")


def test_a_supersedes_id_outside_the_selection_adds_no_exclusion() -> None:
    plan = supersession_plan([draft()], [successor(supersedes=["R-404"])])
    alone = supersession_plan([draft()], [successor(supersedes=[])])
    assert "R-404" not in [e.id for e in plan.exclusions]
    assert exclusion_codes(plan, "requirement") == exclusion_codes(alone, "requirement") == {}


@pytest.mark.parametrize("value", [True, False, "unknown"])
def test_supersession_ignores_the_ics(value: bool | str) -> None:
    """ADR 0011: the supplier writes the ICS, so it cannot switch the exclusion of a draft."""
    plan = supersession_plan([draft()], [successor(applicability=b.feature("x"))], features={"x": value})
    assert_superseded(plan, "R-NEW")


# --- Section 6, step 3: conflicts ----------------------------------------------------------


def conflict_plan(modality: str, applies: Tri, declared: Tri | None) -> tuple[Plan, Requirement]:
    requirement = b.requirement(
        "R-1",
        modality=modality,
        applicability=b.feature("applies"),
        declared_support=None if declared is None else b.feature("supported"),
        assessment_paths=[b.path("p1", "T-1")],
    )
    features: dict[str, bool | str] = {"applies": DECLARED[applies]}
    if declared is not None:
        features["supported"] = DECLARED[declared]
    return plan_for([requirement], [b.purpose("T-1")], features=features), requirement


def test_a_declared_non_implementation_of_an_applicable_mandatory_requirement_is_a_conflict() -> None:
    plan, requirement = conflict_plan("mandatory", T, F)
    assert [c.requirement_id for c in plan.conflicts] == ["R-1"]
    assert plan.conflicts[0].declared.strip()
    assert plan.conflicts[0].explanation.strip()
    planned = plan.requirements[0]
    assert planned.applicability is T, "the requirement stays applicable"
    assert planned.declared_support is F
    assert exclusion_codes(plan, "requirement") == {}, "a declaration is not a waiver"
    result = assess(plan, [requirement], passing=["T-1"])["R-1"]
    assert result.verdict is Verdict.FAIL, "the declaration is the failing observation"
    assert result.applicability is T


NO_CONFLICT = [
    (modality, applies, declared)
    for modality, applies, declared in itertools.product(
        ("mandatory", "recommended", "optional"), Tri, (T, F, U, None)
    )
    if (modality, applies, declared) != ("mandatory", T, F)
]


@pytest.mark.parametrize(("modality", "applies", "declared"), NO_CONFLICT)
def test_no_conflict_without_all_three_conditions(modality: str, applies: Tri, declared: Tri | None) -> None:
    plan, _ = conflict_plan(modality, applies, declared)
    assert plan.conflicts == ()
    assert plan.requirements[0].applicability is applies
    assert plan.requirements[0].declared_support is declared


# --- Steps and paths -----------------------------------------------------------------------


def test_two_requirements_share_one_step() -> None:
    first = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    second = b.requirement("R-2", applicability=b.feature("extra"), assessment_paths=[b.path("p1", "T-1")])
    shared = b.purpose("T-1", requirements=["R-1", "R-2"])
    plan = plan_for([first, second], [shared], features={"extra": False})
    assert [s.test_purpose_id for s in plan.steps] == ["T-1"], "the step is planned once"
    assert executed(plan) == ["T-1"], "one applicable parent is enough to run the step"
    assert [r.paths[0].tests for r in plan.requirements] == [("T-1",), ("T-1",)]
    results = assess(plan, [first, second], passing=["T-1"])
    assert (results["R-1"].verdict, results["R-2"].verdict) == (Verdict.PASS, Verdict.NOT_APPLICABLE)
    both = plan_for([first, second], [shared], features={"extra": True})
    results = assess(both, [first, second], passing=[])
    assert (results["R-1"].verdict, results["R-2"].verdict) == (Verdict.FAIL, Verdict.FAIL)


def test_a_shared_step_is_skipped_when_no_parent_requirement_is_applicable() -> None:
    first = b.requirement("R-1", applicability=b.feature("one"), assessment_paths=[b.path("p1", "T-1")])
    second = b.requirement("R-2", applicability=b.feature("two"), assessment_paths=[b.path("p1", "T-1")])
    plan = plan_for([first, second], [b.purpose("T-1", requirements=["R-1", "R-2"])], features={"one": False})
    step = step_of(plan, "T-1")
    assert step is not None
    assert step.planned_status is SKIPPED


def test_a_step_that_does_not_apply_is_left_out_of_its_path_and_recorded() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-2"), b.path("p2", "T-2")])
    purposes = [b.purpose("T-1"), b.purpose("T-2", applicability=b.feature("extra"))]
    plan = plan_for([requirement], purposes, features={"extra": False})
    assert [p.tests for p in plan.requirements[0].paths] == [("T-1",), ()]
    assert step_of(plan, "T-2") is None
    assert executed(plan) == ["T-1"]
    recorded = [e for e in plan.exclusions if e.kind == "test_purpose"]
    assert [e.id for e in recorded] == ["T-2"]
    assert REASON_CODE.match(recorded[0].reason_code)
    assert recorded[0].reason.strip()
    result = assess(plan, [requirement], passing=["T-1"])["R-1"]
    assert [p.verdict for p in result.paths] == [Verdict.PASS, Verdict.INCONCLUSIVE]


def test_a_path_whose_every_step_is_left_out_cannot_pass() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    plan = plan_for(
        [requirement], [b.purpose("T-1", applicability=b.feature("extra"))], features={"extra": False}
    )
    assert plan.requirements[0].paths[0].tests == ()
    assert assess(plan, [requirement], passing=["T-1"])["R-1"].verdict is Verdict.INCONCLUSIVE


def test_the_applicability_of_a_path_is_planned_and_defaults_to_true() -> None:
    requirement = b.requirement(
        "R-1",
        assessment_paths=[
            b.path("default", "T-1"),
            b.path("yes", "T-1", applicability=b.feature("yes")),
            b.path("no", "T-1", applicability=b.feature("no")),
            b.path("open", "T-1", applicability=b.feature("open")),
        ],
    )
    plan = plan_for([requirement], [b.purpose("T-1")], features={"yes": True, "no": False})
    assert [(p.path_id, p.applicability) for p in plan.requirements[0].paths] == [
        ("default", T),
        ("yes", T),
        ("no", F),
        ("open", U),
    ]
    result = assess(plan, [requirement], passing=["T-1"])["R-1"]
    assert [p.verdict for p in result.paths] == [
        Verdict.PASS,
        Verdict.PASS,
        Verdict.NOT_APPLICABLE,
        Verdict.INCONCLUSIVE,
    ]


FORBIDDEN_PURPOSES = [
    ("mode", {"permitted_modes": ["reviewed"]}),
    ("profile", {"profiles": ["other/profile"]}),
]


@pytest.mark.parametrize(("ground", "changes"), FORBIDDEN_PURPOSES, ids=[g for g, _ in FORBIDDEN_PURPOSES])
def test_a_path_that_names_a_test_purpose_that_is_not_permitted_cannot_pass(
    ground: str, changes: dict[str, Any]
) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-2")])
    plan = plan_for([requirement], [b.purpose("T-1"), b.purpose("T-2", **changes)], mode="exploratory")
    assert executed(plan) == ["T-1"], f"the {ground} does not permit T-2"
    assert plan.requirements[0].paths[0].tests == ("T-1", "T-2"), "the step stays in the path as a gap"
    assert "T-2" in exclusion_codes(plan, "test_purpose"), "the left-out test purpose is reported"
    assert REASON_CODE.match(exclusion_codes(plan, "test_purpose")["T-2"])
    result = assess(plan, [requirement], passing=["T-1", "T-2"])["R-1"]
    assert result.verdict is Verdict.INCONCLUSIVE


def test_a_path_that_names_a_test_purpose_that_no_test_pack_defines_cannot_pass() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-404")])
    plan = plan_for([requirement], [b.purpose("T-1")])
    assert executed(plan) == ["T-1"]
    assert assess(plan, [requirement], passing=["T-1", "T-404"])["R-1"].verdict is Verdict.INCONCLUSIVE


def test_a_test_purpose_runs_only_in_a_mode_that_it_lists() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    for mode in ("illustrative", "exploratory"):
        for permitted in (["illustrative"], ["exploratory"], ["illustrative", "exploratory"]):
            plan = plan_for([requirement], [b.purpose("T-1", permitted_modes=permitted)], mode=mode)
            assert executed(plan) == (["T-1"] if mode in permitted else []), (mode, permitted)


def test_a_test_purpose_that_no_applicable_requirement_names_does_not_run() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    plan = plan_for([requirement], [b.purpose("T-1"), b.purpose("T-ORPHAN")])
    assert executed(plan) == ["T-1"]


# --- Selection errors ----------------------------------------------------------------------


def build(profile_changes: dict[str, Any], packs: Sequence[Any], testpacks: Sequence[Any]) -> Plan:
    return build_plan(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(**profile_changes),
        packs={p.pack_id: p for p in packs},
        testpacks={t.testpack_id: t for t in testpacks},
        ics=b.ics(),
        checks=CHECKS,
    )


def test_an_unknown_requirement_pack_is_an_error() -> None:
    with pytest.raises(PlanError, match="pack/missing"):
        build({"packs": ["pack/a", "pack/missing"]}, [b.pack(b.requirement())], [b.purposes_pack()])


def test_an_unknown_test_pack_is_an_error() -> None:
    with pytest.raises(PlanError, match="tp/missing"):
        build({"testpacks": ["tp/missing"]}, [b.pack(b.requirement())], [b.purposes_pack()])


def test_a_requirement_that_two_selected_packs_define_is_an_error() -> None:
    """Results are keyed by requirement identifier, so two definitions cannot both be assessed."""
    packs = [b.pack(b.requirement("R-1")), b.pack(b.requirement("R-1"), pack_id="pack/b")]
    with pytest.raises(PlanError, match="R-1"):
        build({"packs": ["pack/a", "pack/b"]}, packs, [b.purposes_pack()])


def test_a_test_purpose_that_two_selected_test_packs_define_is_an_error() -> None:
    testpacks = [b.purposes_pack(b.purpose("T-1")), b.purposes_pack(b.purpose("T-1"), testpack_id="tp/b")]
    with pytest.raises(PlanError, match="T-1"):
        build({"testpacks": ["tp/a", "tp/b"]}, [b.pack(b.requirement())], testpacks)


def test_a_pack_that_the_profile_does_not_select_is_not_planned() -> None:
    packs = [b.pack(b.requirement("R-1")), b.pack(b.requirement("R-2"), pack_id="pack/b")]
    plan = build({}, packs, [b.purposes_pack()])
    assert [r.requirement_id for r in plan.requirements] == ["R-1"]
    assert [r.pack_id for r in plan.requirements] == ["pack/a"]


# --- Determinism and order -----------------------------------------------------------------

RICH_REQUIREMENTS = [
    b.requirement("R-30", assessment_paths=[b.path("p1", "T-20", "T-10"), b.path("p2", "T-40")]),
    b.requirement(
        "R-10",
        applicability=b.feature("applies"),
        declared_support=b.feature("supported"),
        assessment_paths=[b.path("p1", "T-30", "T-99")],
    ),
    b.requirement("R-20", review_status="withdrawn", assessment_paths=[b.path("p1", "T-10")]),
    b.requirement("A-40", declared_support=b.feature("supported"), assessment_paths=[b.path("p1", "T-50")]),
    b.requirement("R-05", review_status="superseded", superseded_by="R-30"),
    b.requirement("R-50", applicability=b.feature("open"), assessment_paths=[b.path("p1", "T-10")]),
]
RICH_PURPOSES = [
    b.purpose("T-40", requirements=["R-30"], manual=True),
    b.purpose("T-10", requirements=["R-30", "R-20", "R-50"]),
    b.purpose("T-30", requirements=["R-10"], requires_scope="write"),
    b.purpose("T-20", requirements=["R-30"], applicability=b.feature("supported")),
    b.purpose("T-50", requirements=["A-40"], stimulus={"check": "probe.absent"}),
    b.purpose("T-99", requirements=["R-10"], permitted_modes=["reviewed"]),
    b.purpose("B-60", requirements=["R-30"], profiles=["other/profile"]),
]
RICH_FEATURES = {"applies": True, "supported": False}


def rich_plan(requirements: Sequence[Requirement], purposes: Sequence[TestPurpose], flip: bool) -> Plan:
    packs = [b.pack(*requirements[:3]), b.pack(*requirements[3:], pack_id="pack/b")]
    testpacks = [b.purposes_pack(*purposes[:4]), b.purposes_pack(*purposes[4:], testpack_id="tp/b")]
    selected = {"packs": ["pack/a", "pack/b"], "testpacks": ["tp/a", "tp/b"]}
    if flip:
        packs, testpacks = packs[::-1], testpacks[::-1]
        selected = {name: names[::-1] for name, names in selected.items()}
    return build_plan(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(**selected),
        packs={p.pack_id: p for p in packs},
        testpacks={t.testpack_id: t for t in testpacks},
        ics=b.ics(features=RICH_FEATURES),
        checks=CHECKS,
    )


def test_the_plan_is_sorted_by_identifier() -> None:
    plan = rich_plan(RICH_REQUIREMENTS, RICH_PURPOSES, flip=False)
    assert [r.requirement_id for r in plan.requirements] == ["A-40", "R-10", "R-30", "R-50"]
    assert [c.requirement_id for c in plan.conflicts] == ["A-40", "R-10"]
    planned = [s.test_purpose_id for s in plan.steps]
    assert planned == sorted(planned)
    assert {"T-10", "T-30", "T-40", "T-50"} <= set(planned)
    for kind in ("requirement", "test_purpose"):
        listed = [e.id for e in plan.exclusions if e.kind == kind]
        assert listed == sorted(listed), kind
    assert exclusion_codes(plan, "requirement") == {"R-05": "STATUS.SUPERSEDED", "R-20": "STATUS.WITHDRAWN"}
    assert set(exclusion_codes(plan, "test_purpose")) == {"B-60", "T-20", "T-99"}
    assert all(REASON_CODE.match(e.reason_code) for e in plan.exclusions)
    statuses = {s.test_purpose_id: s.planned_status for s in plan.steps}
    assert statuses["T-10"] is None
    assert statuses["T-30"] is BLOCKED
    assert statuses["T-40"] is MANUAL
    assert statuses["T-50"] is UNSUPPORTED
    assert statuses.get("T-99") is not None, "the mode does not permit T-99, so it never runs"


def test_shuffling_packs_requirements_and_test_purposes_gives_an_identical_plan() -> None:
    reference = rich_plan(RICH_REQUIREMENTS, RICH_PURPOSES, flip=False)
    assert rich_plan(RICH_REQUIREMENTS, RICH_PURPOSES, flip=False) == reference, "the same inputs twice"
    assert rich_plan(RICH_REQUIREMENTS, RICH_PURPOSES, flip=True) == reference
    orders = 0
    # Each test pack and each pack keeps its members, in every order. Then the packs swap places.
    for head, tail in itertools.product(
        itertools.permutations(RICH_REQUIREMENTS[:3]), itertools.permutations(RICH_REQUIREMENTS[3:])
    ):
        for flip in (False, True):
            assert rich_plan([*head, *tail], RICH_PURPOSES, flip) == reference
            orders += 1
    for head, tail in itertools.product(
        itertools.permutations(RICH_PURPOSES[:4]), itertools.permutations(RICH_PURPOSES[4:])
    ):
        plan = rich_plan(RICH_REQUIREMENTS[::-1][3:] + RICH_REQUIREMENTS[::-1][:3], [*head, *tail], flip=True)
        assert plan.model_dump_json() == reference.model_dump_json()
        orders += 1
    assert orders == 6 * 6 * 2 + 24 * 6
