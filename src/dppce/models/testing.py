"""Profiles, declarative test purposes, plans, observations, and test results."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dppce.models.base import (
    ExecutionMode,
    ExecutionStatus,
    JsonValue,
    Model,
    Scope,
    Severity,
    Tri,
    Verdict,
)
from dppce.models.catalogue import ID_PATTERN
from dppce.models.expr import Expr


class FactSpec(Model):
    """A fact that a profile reads from the ICS ``characteristics`` map."""

    type: Literal["integer", "string", "boolean", "date"]
    description: str
    unit: str = ""


class Profile(Model):
    schema_version: Literal["dppce.profile/1"]
    id: str = Field(pattern=ID_PATTERN)
    title: str
    description: str = ""
    product_category: str
    # Item-level passport data and shared model-level data are separate documents.
    item_schema: str | None = None
    model_schema: str | None = None
    rule_packs: tuple[str, ...] = ()
    api_contract: str | None = None
    access_policy: str | None = None
    packs: tuple[str, ...]
    testpacks: tuple[str, ...]
    facts: dict[str, FactSpec] = Field(default_factory=dict)
    constants: dict[str, str | int | bool] = Field(default_factory=dict)


class Stimulus(Model):
    """Names one check from the allowlisted registry. Parameters are data, never code."""

    check: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    params: dict[str, JsonValue] = Field(default_factory=dict)


class VerdictRules(Model):
    """How a completed check maps to a verdict.

    An unreachable system is inconclusive by default. Only an approved test method may set
    ``on_unreachable`` to ``fail``, because a connectivity failure does not prove a breach.
    """

    on_check_failed: Literal["fail", "inconclusive"] = "fail"
    on_unreachable: Literal["inconclusive", "fail"] = "inconclusive"


class TestPurpose(Model):
    __test__ = False  # not a pytest class

    id: str = Field(pattern=ID_PATTERN)
    title: str
    purpose: str = ""
    requirements: tuple[str, ...] = Field(min_length=1)
    profiles: tuple[str, ...] = Field(min_length=1, description="Profile ids, or '*' for all.")
    applicability: Expr
    roles: tuple[str, ...] = ("anonymous",)
    stimulus: Stimulus
    expected_evidence: tuple[str, ...] = ()
    verdict_rules: VerdictRules = VerdictRules()
    severity: Severity = Severity.MAJOR
    permitted_modes: tuple[ExecutionMode, ...] = Field(min_length=1)
    requires_scope: Scope = Scope.READ
    manual: bool = False


class TestPack(Model):
    __test__ = False

    schema_version: Literal["dppce.testpack/1"]
    testpack_id: str = Field(pattern=ID_PATTERN)
    version: str
    title: str
    test_purposes: tuple[TestPurpose, ...]

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [t.id for t in self.test_purposes]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{self.testpack_id}: duplicate test purpose id")
        return self


class Exclusion(Model):
    """Something in the selected catalogue that was left out, and why. Always reported."""

    kind: Literal["requirement", "test_purpose"]
    id: str
    reason_code: str
    reason: str


class Conflict(Model):
    """A declared capability that contradicts an applicable requirement."""

    requirement_id: str
    declared: str
    explanation: str


class PlannedStep(Model):
    test_purpose_id: str
    check: str
    applicability: Tri
    applicability_reason: str
    # When ``planned_status`` is not None the step is not executed and gets that status.
    planned_status: ExecutionStatus | None = None
    planned_reason: str = ""


class PlannedPath(Model):
    path_id: str
    applicability: Tri
    applicability_reason: str
    tests: tuple[str, ...]


class PlannedRequirement(Model):
    requirement_id: str
    pack_id: str
    applicability: Tri
    applicability_reason: str
    declared_support: Tri | None = None
    paths: tuple[PlannedPath, ...] = ()


class Plan(Model):
    """Deterministic output of ``dppce plan``. Entries are sorted by identifier."""

    schema_version: Literal["dppce.plan/1"]
    mode: ExecutionMode
    profile_id: str
    requirements: tuple[PlannedRequirement, ...]
    steps: tuple[PlannedStep, ...]
    exclusions: tuple[Exclusion, ...]
    conflicts: tuple[Conflict, ...]


class Observation(Model):
    """A minimized record of what a check saw.

    ``summary`` holds only what the verdict needs, for example field names and status codes.
    It must not hold restricted payload values. Raw bytes stay in the encrypted recording.
    """

    id: str
    test_purpose_id: str
    kind: Literal["exchange", "artifact", "declaration", "derived"]
    acquired_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    record_ids: tuple[str, ...] = ()
    summary: dict[str, JsonValue] = Field(default_factory=dict)
    transformations: tuple[str, ...] = ()
    truncated: bool = False


class CheckOutcome(Model):
    """What a registered check returns. ``passed`` is set only when ``status`` is COMPLETED."""

    status: ExecutionStatus
    passed: bool | None = None
    unreachable: bool = False
    reason_code: str
    message: str
    observations: tuple[Observation, ...] = ()

    @model_validator(mode="after")
    def _passed_only_when_completed(self) -> Self:
        if (self.status is ExecutionStatus.COMPLETED) != (self.passed is not None):
            raise ValueError("'passed' is set if and only if the check completed")
        if self.unreachable and self.passed is not False:
            raise ValueError("'unreachable' is set only on a completed check that did not pass")
        return self


class TestResult(Model):
    __test__ = False

    test_purpose_id: str
    requirement_ids: tuple[str, ...]
    check: str
    applicability: Tri
    applicability_reason: str
    execution_status: ExecutionStatus
    verdict: Verdict
    severity: Severity
    reason_code: str
    message: str
    observations: tuple[Observation, ...] = ()

    @model_validator(mode="after")
    def _verdict_fits_the_status(self) -> Self:
        """Section 7.1. A result that a different tool assembles must obey the same table."""
        completed = self.execution_status is ExecutionStatus.COMPLETED
        if self.verdict in (Verdict.PASS, Verdict.FAIL) and not completed:
            raise ValueError("a step has 'pass' or 'fail' only if its check completed")
        if (self.verdict is Verdict.ERROR) != (self.execution_status is ExecutionStatus.ERROR):
            raise ValueError("a step has 'error' if and only if its execution status is 'error'")
        return self


class ManualResult(Model):
    """Payload of a signed manual-step result. The person who performed the step signs it.

    It names no person. The key identifier in the JWS header links it to the performer in the
    records of the laboratory. Canonical bodies hold strings only here (ADR 0006).
    """

    schema_version: Literal["dppce.manualresult/1"]
    test_purpose_id: str = Field(pattern=ID_PATTERN)
    sut_identifier: str = Field(min_length=1, max_length=512)
    # One lowercase token, such as "inspector". A token cannot carry a name or free text.
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    # Regex only, like RunManifest.evaluation_time; verify_manual_result parses it and refuses
    # an impossible date (2026-02-30) as MANUAL.RESULT.MALFORMED.
    performed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    outcome: Literal["pass", "fail"]
    # Exactly the expected_evidence items of the test purpose, same text and order.
    evidence: tuple[Annotated[str, Field(min_length=1, max_length=2000)], ...] = ()
