"""Builders for the core tests. Every value is synthetic. Nothing here is a real requirement."""

from __future__ import annotations

from typing import Any

from dppce.catalogue import Catalogue
from dppce.models import (
    ICS,
    Profile,
    Requirement,
    RequirementPack,
    SourceRecord,
    TestPack,
    TestPurpose,
)

PROFILE_ID = "test/alpha"
ALWAYS: dict[str, Any] = {"const": "true"}
ALL_MODES = ["illustrative", "exploratory", "reviewed"]

# A fixture for the lifecycle rules only. It is not a review record: no review took place.
TEST_ONLY_APPROVAL: dict[str, str] = {
    "reviewer": "TEST-ONLY synthetic reviewer",
    "date": "2000-01-01",
    "rationale": "TEST-ONLY fixture. No review took place.",
    "source_version": "TEST-ONLY",
    "artifact": "TEST-ONLY/no-such-record",
}
# A normative (not illustrative) interpretation must cite a provision and a version.
CITED: dict[str, str] = {"source_id": "SRC-TEST", "citation": "synthetic provision A", "version": "TEST-ONLY"}


def feature(name: str, value: bool = True) -> dict[str, Any]:
    """Expression that reads ``ics.features.<name>``."""
    return {"fact": f"ics.features.{name}", "op": "eq", "value": value}


def path(path_id: str, *tests: str, applicability: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": path_id, "tests": list(tests), "applicability": applicability}


def requirement(requirement_id: str = "R-1", **changes: Any) -> Requirement:
    fields: dict[str, Any] = {
        "id": requirement_id,
        "title": f"Synthetic requirement {requirement_id}",
        "source": {"source_id": "SRC-TEST"},
        "authority_class": "illustrative",
        "modality": "mandatory",
        "applicability": ALWAYS,
        "testability": "automated",
        "review_status": "draft-needs-review",
    }
    return Requirement.model_validate(fields | changes)


def pack(*requirements: Requirement, pack_id: str = "pack/a", **changes: Any) -> RequirementPack:
    fields: dict[str, Any] = {
        "schema_version": "dppce.pack/1",
        "pack_id": pack_id,
        "version": "1",
        "title": f"Synthetic pack {pack_id}",
        "scope_statement": "Synthetic scope.",
        "requirements": requirements,
    }
    return RequirementPack.model_validate(fields | changes)


def purpose(purpose_id: str = "T-1", **changes: Any) -> TestPurpose:
    fields: dict[str, Any] = {
        "id": purpose_id,
        "title": f"Synthetic test purpose {purpose_id}",
        "requirements": ["R-1"],
        "profiles": ["*"],
        "applicability": ALWAYS,
        "stimulus": {"check": "probe.ok"},
        "permitted_modes": ALL_MODES,
    }
    return TestPurpose.model_validate(fields | changes)


def purposes_pack(*purposes: TestPurpose, testpack_id: str = "tp/a") -> TestPack:
    return TestPack(
        schema_version="dppce.testpack/1",
        testpack_id=testpack_id,
        version="1",
        title=f"Synthetic test pack {testpack_id}",
        test_purposes=purposes,
    )


def profile(**changes: Any) -> Profile:
    fields: dict[str, Any] = {
        "schema_version": "dppce.profile/1",
        "id": PROFILE_ID,
        "title": "Synthetic profile",
        "product_category": "widget",
        "packs": ["pack/a"],
        "testpacks": ["tp/a"],
    }
    return Profile.model_validate(fields | changes)


def ics(**changes: Any) -> ICS:
    fields: dict[str, Any] = {
        "schema_version": "dppce.ics/1",
        "sut": {"name": "Synthetic system", "identifier": "urn:example:sut"},
        "profile": PROFILE_ID,
    }
    return ICS.model_validate(fields | changes)


def source(source_id: str = "SRC-TEST", **changes: Any) -> SourceRecord:
    fields: dict[str, Any] = {
        "id": source_id,
        "title": f"Synthetic source {source_id}",
        "identifier": source_id,
        "issuing_body": "Synthetic body",
        "source_type": "synthetic",
        "official_url": "https://example.invalid/source",
        "retrieval_date": "2026-01-01",
        "legal_or_spec_status": "synthetic",
        "permitted_use_basis": "synthetic test data",
        "verification_level": "substantive",
    }
    return SourceRecord.model_validate(fields | changes)


def catalogue(*packs: RequirementPack, sources: tuple[SourceRecord, ...] | None = None) -> Catalogue:
    return Catalogue(
        legal_as_of="2026-01-01",
        sources=(source(),) if sources is None else sources,
        packs={p.pack_id: p for p in packs},
    )
