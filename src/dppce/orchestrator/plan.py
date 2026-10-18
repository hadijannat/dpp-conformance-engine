"""Deterministic planning. A pure function: no I/O, no clock, no randomness.

Implements docs/explanation/architecture.md, sections 4 and 6.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from dppce.applicability import Outcome, evaluate, facts_from
from dppce.evidence.manual import MANUAL_CHECK
from dppce.models import (
    ICS,
    AuthorityClass,
    CapabilityState,
    Conflict,
    Exclusion,
    ExecutionMode,
    ExecutionStatus,
    Modality,
    Plan,
    PlannedPath,
    PlannedRequirement,
    PlannedStep,
    Profile,
    Requirement,
    RequirementPack,
    ReviewStatus,
    Scope,
    TestPack,
    TestPurpose,
    Tri,
)

_EXECUTABLE = (CapabilityState.SUPPORTED, CapabilityState.EXPERIMENTAL)
_NO_AUTHORIZATION_NEEDED = (Scope.NONE, Scope.READ)


class PlanError(ValueError):
    """The selected profile, packs, and test packs do not fit together."""


@dataclass(frozen=True)
class CheckInfo:
    """What the planner needs to know about one registered check."""

    state: CapabilityState
    available: bool


def mode_exclusion(mode: ExecutionMode, requirement: Requirement) -> tuple[str, str] | None:
    """Return (reason code, reason) if the mode does not permit the requirement. Section 4."""
    status = requirement.review_status
    if status is ReviewStatus.SUPERSEDED:
        return "STATUS.SUPERSEDED", f"Superseded by {requirement.superseded_by}."
    if status is ReviewStatus.WITHDRAWN:
        return "STATUS.WITHDRAWN", "The requirement is withdrawn."
    illustrative = requirement.authority_class is AuthorityClass.ILLUSTRATIVE
    if mode is ExecutionMode.ILLUSTRATIVE and not illustrative:
        return "MODE.NOT_ILLUSTRATIVE", "Illustrative mode assesses illustrative requirements only."
    if mode is ExecutionMode.REVIEWED and status is not ReviewStatus.APPROVED:
        return (
            "MODE.NOT_APPROVED",
            f"Reviewed mode needs an approved interpretation; status is '{status.value}'.",
        )
    if mode is ExecutionMode.REVIEWED and illustrative:
        # The one case that is left: a synthetic rule that a person marked approved.
        return (
            "MODE.ILLUSTRATIVE_NOT_REVIEWABLE",
            "Reviewed mode assesses normative requirements only. An illustrative rule makes no claim.",
        )
    return None


def superseded_by_selected(
    mode: ExecutionMode, selected: Sequence[RequirementPack]
) -> dict[str, tuple[str, ...]]:
    """Map each selected draft to the selected approved requirements that supersede it. Section 6, step 1.

    It reads no ICS fact, so the supplier of the system cannot switch the exclusion (ADR 0011).
    """
    by_id = {r.id: r for p in selected for r in p.requirements}
    found: dict[str, set[str]] = {}
    for p in selected:
        for r in p.requirements:
            if r.review_status is not ReviewStatus.APPROVED or mode_exclusion(mode, r) is not None:
                continue
            synthetic = r.authority_class is AuthorityClass.ILLUSTRATIVE
            for old_id in r.supersedes:
                old = by_id.get(old_id)
                # A synthetic rule never decides what a normative draft contributes, and back.
                if (
                    old is not None
                    and old.review_status is ReviewStatus.DRAFT
                    and (old.authority_class is AuthorityClass.ILLUSTRATIVE) == synthetic
                ):
                    found.setdefault(old_id, set()).add(r.id)
    return {old: tuple(sorted(new)) for old, new in found.items()}


def _select[T](available: Mapping[str, T], wanted: Sequence[str], kind: str, profile: Profile) -> list[T]:
    missing = sorted(set(wanted) - set(available))
    if missing:
        raise PlanError(f"profile {profile.id}: {kind} not found: {', '.join(missing)}")
    return [available[name] for name in wanted]


def _planned_status(
    purpose: TestPurpose,
    outcome: Outcome,
    has_applicable_parent: bool,
    checks: Mapping[str, CheckInfo],
    granted: frozenset[Scope],
    *,
    manual_results: frozenset[str],
) -> tuple[ExecutionStatus | None, str]:
    """Section 6, second table. The order of the conditions is part of the contract."""
    if not has_applicable_parent:
        return ExecutionStatus.SKIPPED, "No applicable requirement needs this step."
    if outcome.value is Tri.UNKNOWN:
        return ExecutionStatus.SKIPPED, f"The step applicability is unknown: {outcome.reason}"
    if purpose.manual and (purpose.id not in manual_results or purpose.stimulus.check != MANUAL_CHECK):
        # The text stays byte-identical, so that an old recording replays to the same digest.
        return (
            ExecutionStatus.MANUAL_UNAVAILABLE,
            "The step is a manual review. No manual result is available.",
        )
    info = checks.get(purpose.stimulus.check)
    if info is None:
        return ExecutionStatus.UNSUPPORTED, f"The check '{purpose.stimulus.check}' is not in the registry."
    if info.state not in _EXECUTABLE:
        return ExecutionStatus.UNSUPPORTED, f"The capability state is '{info.state.value}'."
    if not info.available:
        return ExecutionStatus.UNSUPPORTED, "An optional dependency of the check is not installed."
    if purpose.requires_scope not in _NO_AUTHORIZATION_NEEDED and purpose.requires_scope not in granted:
        return (
            ExecutionStatus.BLOCKED,
            f"No valid authorization grants the scope '{purpose.requires_scope.value}'.",
        )
    return None, ""


def build_plan(  # noqa: PLR0912, PLR0915 - one linear pass over the catalogue; splitting it hides the order
    *,
    mode: ExecutionMode,
    profile: Profile,
    packs: Mapping[str, RequirementPack],
    testpacks: Mapping[str, TestPack],
    ics: ICS,
    checks: Mapping[str, CheckInfo],
    granted_scopes: frozenset[Scope] = frozenset(),
    manual_results: frozenset[str] = frozenset(),
) -> Plan:
    """Select requirements and test steps for one run. The output is sorted by identifier.

    ``manual_results`` holds the test purposes for which the operator supplied a manual result.
    """
    facts = facts_from(ics, profile)
    exclusions: dict[tuple[str, str], Exclusion] = {}

    def exclude(kind: str, ident: str, code: str, reason: str) -> None:
        exclusions.setdefault(
            (kind, ident),
            Exclusion.model_validate({"kind": kind, "id": ident, "reason_code": code, "reason": reason}),
        )

    purposes: dict[str, TestPurpose] = {}
    defined: set[str] = set()
    for testpack in _select(testpacks, profile.testpacks, "test pack", profile):
        for purpose in testpack.test_purposes:
            # Checked before the filters. Otherwise a copy that this mode excludes could still
            # supply the parameters and the verdict rules of the step that runs.
            if purpose.id in defined:
                raise PlanError(
                    f"test purpose {purpose.id} is defined more than once in the selected test packs"
                )
            defined.add(purpose.id)
            if "*" not in purpose.profiles and profile.id not in purpose.profiles:
                exclude("test_purpose", purpose.id, "PROFILE.NOT_SELECTED", f"Not defined for {profile.id}.")
            elif mode not in purpose.permitted_modes:
                exclude(
                    "test_purpose", purpose.id, "MODE.NOT_PERMITTED", f"Not permitted in {mode.value} mode."
                )
            else:
                purposes[purpose.id] = purpose

    step_outcomes = {tid: evaluate(p.applicability, facts) for tid, p in purposes.items()}
    for tid, outcome in step_outcomes.items():
        if outcome.value is Tri.FALSE:
            exclude("test_purpose", tid, "STEP.NOT_APPLICABLE", outcome.reason)

    planned: list[PlannedRequirement] = []
    conflicts: list[Conflict] = []
    seen: set[str] = set()
    needed: set[str] = set()  # steps that at least one applicable requirement path needs
    referenced: dict[str, str] = {}  # step id -> first reason it cannot run, for unknown ids

    selected = _select(packs, profile.packs, "requirement pack", profile)
    successors = superseded_by_selected(mode, selected)
    for pack in selected:
        for requirement in pack.requirements:
            if requirement.id in seen:
                raise PlanError(f"requirement {requirement.id} is defined in more than one selected pack")
            seen.add(requirement.id)
            # Before the mode gate: exclude() keeps the first code, and a reviewed plan must show this one.
            if (newer := successors.get(requirement.id)) is not None:
                reason = f"Superseded by {', '.join(newer)}: selected and approved."
                exclude("requirement", requirement.id, "STATUS.SUPERSEDED_BY_SELECTED", reason)
                continue
            if (gate := mode_exclusion(mode, requirement)) is not None:
                exclude("requirement", requirement.id, *gate)
                continue
            applies = evaluate(requirement.applicability, facts)
            declared = evaluate(requirement.declared_support, facts) if requirement.declared_support else None
            if (
                declared is not None
                and declared.value is Tri.FALSE
                and applies.value is Tri.TRUE
                and requirement.modality is Modality.MANDATORY
            ):
                conflicts.append(
                    Conflict(
                        requirement_id=requirement.id,
                        declared=declared.reason,
                        explanation="Mandatory and applicable. A declaration cannot waive it.",
                    )
                )
            paths: list[PlannedPath] = []
            for path in requirement.assessment_paths:
                path_applies = (
                    evaluate(path.applicability, facts) if path.applicability else Outcome(Tri.TRUE, "")
                )
                kept = tuple(
                    t
                    for t in path.tests
                    if step_outcomes.get(t, Outcome(Tri.TRUE, "")).value is not Tri.FALSE
                )
                for test_id in kept:
                    if test_id not in purposes:
                        referenced.setdefault(
                            test_id, "The test purpose is not available in this mode and profile."
                        )
                    if applies.value is Tri.TRUE and path_applies.value is Tri.TRUE:
                        needed.add(test_id)
                paths.append(
                    PlannedPath(
                        path_id=path.id,
                        applicability=path_applies.value,
                        applicability_reason=path_applies.reason,
                        tests=kept,
                    )
                )
            planned.append(
                PlannedRequirement(
                    requirement_id=requirement.id,
                    pack_id=pack.pack_id,
                    applicability=applies.value,
                    applicability_reason=applies.reason,
                    declared_support=declared.value if declared else None,
                    paths=tuple(paths),
                )
            )

    steps: list[PlannedStep] = []
    for tid, purpose in purposes.items():
        outcome = step_outcomes[tid]
        if outcome.value is Tri.FALSE:
            continue
        status, reason = _planned_status(
            purpose, outcome, tid in needed, checks, granted_scopes, manual_results=manual_results
        )
        steps.append(
            PlannedStep(
                test_purpose_id=tid,
                check=purpose.stimulus.check,
                applicability=outcome.value,
                applicability_reason=outcome.reason,
                planned_status=status,
                planned_reason=reason,
            )
        )
    for tid, reason in referenced.items():
        # A path names a step that cannot run here. Keep it visible as missing evidence.
        steps.append(
            PlannedStep(
                test_purpose_id=tid,
                check="unavailable",
                applicability=Tri.UNKNOWN,
                applicability_reason=reason,
                planned_status=ExecutionStatus.NOT_RUN,
                planned_reason=reason,
            )
        )

    return Plan(
        schema_version="dppce.plan/1",
        mode=mode,
        profile_id=profile.id,
        requirements=tuple(sorted(planned, key=lambda r: r.requirement_id)),
        steps=tuple(sorted(steps, key=lambda s: s.test_purpose_id)),
        exclusions=tuple(v for _, v in sorted(exclusions.items())),
        conflicts=tuple(sorted(conflicts, key=lambda c: c.requirement_id)),
    )
