"""Requirement results, coverage, the run manifest, the decision body, and evidence."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from dppce.models.base import (
    AuthorityClass,
    CapabilityState,
    ClaimLevel,
    ExecutionMode,
    Modality,
    Model,
    ReviewStatus,
    Testability,
    Tri,
    Verdict,
)
from dppce.models.declarations import SutIdentity
from dppce.models.testing import Conflict, Exclusion, TestResult


class PathResult(Model):
    path_id: str
    applicability: Tri
    verdict: Verdict
    steps: tuple[str, ...]


class RequirementResult(Model):
    """Applicability, execution, modality, and review status stay separate fields."""

    requirement_id: str
    pack_id: str
    authority_class: AuthorityClass
    modality: Modality
    review_status: ReviewStatus
    testability: Testability
    applicability: Tri
    applicability_reason: str
    verdict: Verdict
    verdict_reason: str
    claim_level: ClaimLevel
    paths: tuple[PathResult, ...] = ()
    # A failure does not hide the other problems. They are kept here.
    retained: tuple[str, ...] = ()


class Ratio(Model):
    """A count with its denominator. A percentage is never stored or shown without both."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    of: str


class CoverageSummary(Model):
    """Coverage of the selected catalogue. It is not coverage of a law or of a whole standard."""

    scope_statement: str
    total_requirements: int
    by_authority_class: dict[str, int]
    by_review_status: dict[str, int]
    by_applicability: dict[str, int]
    by_testability: dict[str, int]
    by_verdict: dict[str, int]
    implementation: Ratio
    execution: Ratio
    passing: Ratio
    placeholders: int
    unknown_applicability: int
    excluded: int
    manual_missing: int


class IssuerStatement(Model):
    """Who issues the report. The default states that the issuer is not accredited."""

    name: str = "unspecified"
    identifier: str = "unspecified"
    accreditation_status: str = "not accredited"
    accreditation_reference: str = ""


class AcquisitionWindow(Model):
    first: str | None = None
    last: str | None = None


class RunManifest(Model):
    engine_version: str
    dependency_versions: dict[str, str]
    image_digest: str | None = None
    mode: ExecutionMode
    profile_id: str
    profile_hash: str
    catalogue_hash: str
    pack_hashes: dict[str, str]
    testpack_hashes: dict[str, str]
    sources_hash: str
    ics_hash: str
    ixit_sanitized_hash: str
    authorization_ref: str | None = None
    sut: SutIdentity
    evaluation_time: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    acquisition: AcquisitionWindow = AcquisitionWindow()
    seeds: dict[str, int] = Field(default_factory=dict)
    trust_policy_version: str
    issuer: IssuerStatement = IssuerStatement()
    limitations: tuple[str, ...]
    bound_files: dict[str, Annotated[str, Field(pattern=r"^(sha256:[0-9a-f]{64}|unavailable)$")]] | None = (
        Field(
            default=None,
            description="sha256 of the raw bytes of each file that the profile binds, keyed by its path "
            "under the data root. Required in dppce.decision/2. Absent in dppce.decision/1.",
        )
    )

    @model_serializer(mode="wrap")
    def _omit_absent(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        # Left out when absent, so an earlier decision body keeps its canonical bytes and digest.
        # Field(exclude_if=...) would need pydantic 2.11; the declared floor is 2.9.
        data: dict[str, Any] = handler(self)
        if self.bound_files is None:
            data.pop("bound_files", None)
        return data


class RecordCommitment(Model):
    """Salted commitment to one raw record. The salt stays in the encrypted recording."""

    record_id: str
    commitment: str = Field(pattern=r"^[0-9a-f]{64}$")


class DecisionBody(Model):
    """The canonical statement of one run. Its RFC 8785 form is what gets hashed and signed.

    Lists are sorted by identifier. The verifier rejects a body whose lists are out of order
    or hold a duplicate, so an omitted, repeated, replaced, or moved result is detected.

    Version 2 adds ``manifest.bound_files``. A version 1 body is still read and verified as written.
    """

    schema_version: Literal["dppce.decision/1", "dppce.decision/2"]
    manifest: RunManifest
    overall: Verdict
    overall_reason: str
    requirement_results: tuple[RequirementResult, ...]
    test_results: tuple[TestResult, ...]
    exclusions: tuple[Exclusion, ...]
    conflicts: tuple[Conflict, ...]
    coverage: CoverageSummary
    verdict_counts: dict[str, int]
    results_root: str = Field(pattern=r"^[0-9a-f]{64}$")
    results_count: int = Field(ge=0)
    record_commitments: tuple[RecordCommitment, ...]
    records_root: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _bound_files_match_the_version(self) -> Self:
        # A verifier of 0.1.0rc1 rejects a body with bound_files, so the field needs version 2.
        # ponytail: the JSON Schema states only the two versions, not this pairing. An if/then
        # sub-schema would be an open object, which the closed-schema test forbids.
        if (self.manifest.bound_files is not None) != (self.schema_version == "dppce.decision/2"):
            raise ValueError(
                "manifest.bound_files is required in dppce.decision/2 and absent in dppce.decision/1"
            )
        return self


class Attestation(Model):
    """Payload of the signature. It binds the digest of the whole decision body."""

    schema_version: Literal["dppce.attestation/1"]
    decision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    results_root: str
    records_root: str
    issuer: str
    signed_at: str


class EvidenceEnvelope(Model):
    """A conformance test report with its signatures. It is not a certificate."""

    schema_version: Literal["dppce.envelope/1"]
    decision: DecisionBody
    # JWS Compact Serialization. Empty until ``dppce sign`` runs.
    signatures: tuple[str, ...] = ()
    # Optional status and timestamp evidence, added by separately tested profiles.
    status_evidence: tuple[str, ...] = ()
    timestamp_evidence: tuple[str, ...] = ()


class Capability(Model):
    id: str
    adapter: str
    state: CapabilityState
    description: str
    optional_dependency: str | None = None
    available: bool = True
    acceptance_criteria: str = ""


class CapabilityManifest(Model):
    schema_version: Literal["dppce.capabilities/1"]
    engine_version: str
    capabilities: tuple[Capability, ...]


class VerificationDimension(Model):
    name: str
    outcome: Literal["pass", "fail", "missing", "not_checked"]
    detail: str


class VerificationReport(Model):
    """Result of standalone verification. It says nothing new about the tested system."""

    schema_version: Literal["dppce.verification/1"]
    evaluation_time: str
    decision_digest: str
    dimensions: tuple[VerificationDimension, ...]
    # True only when every mandatory dimension passed. A missing mandatory dimension makes it False.
    complete: bool
    note: str = "Verification of the report is separate from the verdict about the tested system."
