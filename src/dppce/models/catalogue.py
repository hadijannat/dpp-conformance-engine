"""Sources, requirements, and requirement packs."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from dppce.models.base import AuthorityClass, Modality, Model, ReviewStatus, Testability
from dppce.models.expr import Expr

ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"


class Evidence(Model):
    url: str
    what_it_shows: str
    official: bool


class DatedFact(Model):
    date: str
    what: str
    basis: str = ""


class Amendment(Model):
    identifier: str
    date: str = ""
    summary: str = ""
    url: str = ""


class OjCitation(Model):
    """Publication of a standard and its citation in the Official Journal are separate facts."""

    status: Literal["cited", "not_cited", "not_located", "not_applicable"]
    reference: str = ""
    url: str = ""


class SourceRecord(Model):
    """One entry of ``catalogue/sources.yaml``."""

    id: str = Field(pattern=ID_PATTERN)
    title: str
    identifier: str
    issuing_body: str
    source_type: str
    official_url: str
    edition_or_version: str = ""
    publication_date: str | None = None
    retrieval_date: str
    legal_or_spec_status: str
    applicable_dates: tuple[DatedFact, ...] = ()
    amendment_history: tuple[Amendment, ...] = ()
    oj_citation: OjCitation = OjCitation(status="not_applicable")
    license_or_reuse_terms: str = ""
    permitted_use_basis: str
    # "substantive" means the provisions were read at the official location.
    verification_level: Literal[
        "substantive", "metadata_only", "secondary_only", "not_located", "unverified_recall"
    ]
    independent_check: Literal["confirmed", "refuted", "not_confirmed", "not_checked"] = "not_checked"
    sha256: str | None = None
    hash_note: str = "not hashed"
    evidence: tuple[Evidence, ...] = ()
    uncertainties: tuple[str, ...] = ()


class SourceRef(Model):
    """Pointer from a requirement to a provision. ``citation`` is empty for placeholders."""

    source_id: str = Field(pattern=ID_PATTERN)
    citation: str = ""
    version: str = ""


class Interpretation(Model):
    id: str = Field(pattern=ID_PATTERN)
    text: str
    status: ReviewStatus
    author_kind: Literal["agent", "human"]
    source_version: str = ""
    unresolved: tuple[str, ...] = ()


class Approval(Model):
    """A human decision. The engine never writes one of these. See ADR 0007."""

    reviewer: str = Field(min_length=1)
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    rationale: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    artifact: str = Field(min_length=1, description="Path or URL of the signed-off review record.")


class AssessmentPath(Model):
    """One permitted way to assess a requirement. Every step in a path is required.

    A requirement with more than one path offers alternatives: one passing path is enough.
    """

    id: str = Field(pattern=ID_PATTERN)
    description: str = ""
    applicability: Expr | None = None
    tests: tuple[str, ...] = ()


class Requirement(Model):
    id: str = Field(pattern=ID_PATTERN)
    title: str
    source: SourceRef
    authority_class: AuthorityClass
    modality: Modality
    paraphrase: str = ""
    applicability: Expr
    # False here means the owner declares the feature as not implemented.
    # For an applicable mandatory requirement that is a static conformance failure, not a waiver.
    declared_support: Expr | None = None
    testability: Testability
    review_status: ReviewStatus
    interpretations: tuple[Interpretation, ...] = ()
    assessment_paths: tuple[AssessmentPath, ...] = ()
    approval: Approval | None = None
    supersedes: tuple[str, ...] = ()
    superseded_by: str | None = None

    def _lifecycle_error(self) -> str | None:
        status = self.review_status
        closed = status in (ReviewStatus.SUPERSEDED, ReviewStatus.WITHDRAWN)
        normative = self.authority_class is not AuthorityClass.ILLUSTRATIVE
        interpreted = status in (ReviewStatus.DRAFT, ReviewStatus.APPROVED)
        rules: tuple[tuple[bool, str], ...] = (
            (
                status is ReviewStatus.APPROVED and self.approval is None,
                "status 'approved' needs a documented human approval",
            ),
            (
                status is not ReviewStatus.APPROVED and self.approval is not None and not closed,
                "an approval record is only valid on an approved requirement",
            ),
            (
                status is ReviewStatus.PLACEHOLDER and bool(self.paraphrase),
                "a placeholder has an empty paraphrase",
            ),
            (
                status is ReviewStatus.PLACEHOLDER and any(p.tests for p in self.assessment_paths),
                "a placeholder has no test: nobody has interpreted its source",
            ),
            (
                status is ReviewStatus.SUPERSEDED and not self.superseded_by,
                "status 'superseded' needs 'superseded_by'",
            ),
            (
                normative and interpreted and not (self.source.citation and self.source.version),
                "a normative interpretation cites a provision and a version",
            ),
            (
                self.approval is None
                and any(i.status is ReviewStatus.APPROVED for i in self.interpretations),
                "an approved interpretation needs the requirement approval record",
            ),
            (
                len({p.id for p in self.assessment_paths}) != len(self.assessment_paths),
                "duplicate assessment path id",
            ),
        )
        return next((message for broken, message in rules if broken), None)

    @model_validator(mode="after")
    def _lifecycle_rules(self) -> Self:
        if (error := self._lifecycle_error()) is not None:
            raise ValueError(f"{self.id}: {error}")
        return self


class RequirementPack(Model):
    schema_version: Literal["dppce.pack/1"]
    pack_id: str = Field(pattern=ID_PATTERN)
    version: str
    title: str
    description: str = ""
    legal_as_of: str | None = None
    # States what the pack covers, so that a coverage figure cannot be read as "all of the law".
    scope_statement: str
    requirements: tuple[Requirement, ...]

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [r.id for r in self.requirements]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{self.pack_id}: duplicate requirement id")
        return self
