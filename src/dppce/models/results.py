"""Requirement results, coverage, the run manifest, the decision body, and evidence."""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal, Self

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
from dppce.models.declarations import ICS, IXIT, SutIdentity
from dppce.models.testing import Conflict, Exclusion, TestResult
from dppce.models.trust import STAMP, TrustBundle

BoundFileHash = Annotated[str, Field(pattern=r"^(sha256:[0-9a-f]{64}|unavailable)$")]


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


NOT_ACCREDITED: Final = "not accredited"


class IssuerStatement(Model):
    """Who issues the report. The default states that the issuer is not accredited."""

    name: str = "unspecified"
    identifier: str = "unspecified"
    accreditation_status: str = NOT_ACCREDITED
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
    bound_files: dict[str, BoundFileHash] | None = Field(
        default=None,
        description="sha256 of the raw bytes of each file that the profile binds, keyed by its path "
        "under the data root. Required in dppce.decision/2. Absent in dppce.decision/1.",
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


SignerRole = Literal["issuer", "reviewer"]
DIGEST: Final = r"^sha256:[0-9a-f]{64}$"
# The largest list that the verifier decodes: 16 MiB of bits.
MAX_STATUS_INDEX: Final = 16 * 1024 * 1024 * 8 - 1


class StatusReference(Model):
    """The entry of a report in a status list of its issuer: one bit of one list (section 11.4)."""

    list_id: str = Field(min_length=1, max_length=512)
    index: int = Field(ge=0, le=MAX_STATUS_INDEX)


class Attestation(Model):
    """Payload of the signature. It binds the digest of the whole decision body.

    Version 2 adds the role of the signer and the lifecycle that the issuer states. A version 1
    attestation is the issuer's and keeps its canonical bytes.
    """

    schema_version: Literal["dppce.attestation/1", "dppce.attestation/2"]
    decision_digest: str = Field(pattern=DIGEST)
    results_root: str
    records_root: str
    issuer: str
    signed_at: str
    # Version 2 only. Each is written explicitly, null when it has no value.
    role: SignerRole | None = None
    status: StatusReference | None = None
    valid_until: str | None = Field(default=None, pattern=STAMP)
    supersedes: str | None = Field(default=None, pattern=DIGEST)

    @property
    def signer_role(self) -> SignerRole:
        return self.role or "issuer"  # a version 1 attestation is the issuer's

    @property
    def lifecycle(self) -> tuple[StatusReference | None, str | None, str | None]:
        return (self.status, self.valid_until, self.supersedes)

    @model_serializer(mode="wrap")
    def _omit_in_version_1(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        # Same pattern as RunManifest._omit_absent: a /1 payload keeps its canonical bytes.
        data: dict[str, Any] = handler(self)
        if self.schema_version == "dppce.attestation/1":
            for name in ("role", "status", "valid_until", "supersedes"):
                data.pop(name, None)
        return data

    @model_validator(mode="after")
    def _fields_match_the_version(self) -> Self:
        new = (self.role, self.status, self.valid_until, self.supersedes)
        if self.schema_version == "dppce.attestation/1" and any(v is not None for v in new):
            raise ValueError("role, status, valid_until, and supersedes need dppce.attestation/2")
        if self.schema_version == "dppce.attestation/2" and self.role is None:
            raise ValueError("dppce.attestation/2 states a role")
        if self.role == "reviewer" and any(v is not None for v in new[1:]):
            raise ValueError("only the issuer states status, valid_until, and supersedes")
        if self.supersedes == self.decision_digest:
            raise ValueError("a report cannot supersede itself")
        return self


class StatusList(Model):
    """Payload of a signed status list. The issuer keeps it; the operator supplies it to the verifier."""

    schema_version: Literal["dppce.statuslist/1"]
    id: str = Field(min_length=1, max_length=512)
    status_purpose: Literal["revocation", "suspension"]
    issued_at: str = Field(pattern=STAMP)
    encoded_list: str = Field(pattern=r"^u[A-Za-z0-9_-]+$")


class EvidenceEnvelope(Model):
    """A conformance test report with its signatures. It is not a certificate."""

    schema_version: Literal["dppce.envelope/1"]
    decision: DecisionBody
    # JWS Compact Serialization. Empty until ``dppce sign`` runs.
    signatures: tuple[str, ...] = ()
    # Optional status evidence, added by a separately tested profile.
    status_evidence: tuple[str, ...] = ()
    # Each entry is standard padded base64 of a DER TimeStampToken (architecture section 11.3).
    # The dimension `timestamp` judges a malformed entry, not `structure`.
    timestamp_evidence: tuple[str, ...] = ()


class InputHashes(Model):
    """Digests of the inputs that a replay reads again: the profile, the sources, every loaded pack
    and test pack, and the bound files.
    """

    profile: str
    sources: str
    # Every loaded pack and test pack, shipped or imported, selected or not.
    packs: dict[str, str]
    testpacks: dict[str, str]
    bound_files: dict[str, BoundFileHash]


class RunInputsRecord(Model):
    """The inputs of one run, written to inputs.json so that a replay can rebuild them.

    It is not signed or encrypted. No field has a default: a writer states each value, and
    ``null`` is written explicitly.
    """

    schema_version: Literal["dppce.runinputs/3"]
    mode: ExecutionMode
    profile: str
    evaluation_time: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    ics: ICS
    ixit: IXIT
    import_packs: tuple[str, ...]
    extra_packs: tuple[str, ...]
    import_testpacks: tuple[str, ...]
    extra_testpacks: tuple[str, ...]
    trust: TrustBundle | None
    authorization_token: str | None
    issuer: IssuerStatement
    manual_results: tuple[str, ...]
    data_root: str | None = Field(
        description="Absolute path of the data root of the run. null only in a record migrated from "
        "dppce.runinputs/1."
    )
    input_hashes: InputHashes | None = Field(
        description="null only in a record migrated from dppce.runinputs/1."
    )


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
