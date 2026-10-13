"""Deterministic planning. A pure function: no I/O, no clock, no randomness.

Implements docs/explanation/architecture.md, sections 4 and 6.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from dppce.applicability import Outcome, evaluate, facts_from
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
    return None


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
) -> tuple[ExecutionStatus | None, str]:
    """Section 6, second table. The order of the conditions is part of the contract."""
    if not has_applicable_parent:
        return ExecutionStatus.SKIPPED, "No applicable requirement needs this step."
    if outcome.value is Tri.UNKNOWN:
        return ExecutionStatus.SKIPPED, f"The step applicability is unknown: {outcome.reason}"
    if purpose.manual:
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


def build_plan(  # noqa: PLR0912 - one linear pass over the catalogue; splitting it hides the order
    *,
    mode: ExecutionMode,
    profile: Profile,
    packs: Mapping[str, RequirementPack],
    testpacks: Mapping[str, TestPack],
    ics: ICS,
    checks: Mapping[str, CheckInfo],
    granted_scopes: frozenset[Scope] = frozenset(),
) -> Plan:
    """Select requirements and test steps for one run. The output is sorted by identifier."""
    facts = facts_from(ics, profile)
    exclusions: dict[tuple[str, str], Exclusion] = {}

    def exclude(kind: str, ident: str, code: str, reason: str) -> None:
        exclusions.setdefault(
            (kind, ident),
            Exclusion.model_validate({"kind": kind, "id": ident, "reason_code": code, "reason": reason}),
        )

    purposes: dict[str, TestPurpose] = {}
    for testpack in _select(testpacks, profile.testpacks, "test pack", profile):
        for purpose in testpack.test_purposes:
            if "*" not in purpose.profiles and profile.id not in purpose.profiles:
                exclude("test_purpose", purpose.id, "PROFILE.NOT_SELECTED", f"Not defined for {profile.id}.")
            elif mode not in purpose.permitted_modes:
                exclude(
                    "test_purpose", purpose.id, "MODE.NOT_PERMITTED", f"Not permitted in {mode.value} mode."
                )
            elif purpose.id in purposes:
                raise PlanError(f"test purpose {purpose.id} is defined in more than one test pack")
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

    for pack in _select(packs, profile.packs, "requirement pack", profile):
        for requirement in pack.requirements:
            if requirement.id in seen:
                raise PlanError(f"requirement {requirement.id} is defined in more than one selected pack")
            seen.add(requirement.id)
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
        status, reason = _planned_status(purpose, outcome, tid in needed, checks, granted_scopes)
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
