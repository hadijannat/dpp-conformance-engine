"""The shipped catalogue content obeys the governance rules.

These tests read the files in ``catalogue/``, ``profiles/``, and ``testpacks/``. They guard what a
schema cannot: no agent approval, no standard content, no legal claim from a draft, and a
two-way trace. They do not test the engine.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

import dppce.adapters  # noqa: F401 - the import registers the checks that the lint looks up
from dppce.applicability import evaluate
from dppce.catalogue import Catalogue, load_catalogue, load_data, load_profiles, load_testpacks
from dppce.catalogue.lint import Finding, lint
from dppce.infrastructure.resources import data_root
from dppce.models import (
    AuthorityClass,
    ExecutionMode,
    Requirement,
    ReviewStatus,
    TestPack,
    TestPurpose,
    Tri,
)
from dppce.testdefs import registry

ROOT = data_root()
EU_PACK = "eu-battery/draft"
EN_PACK = "en-jtc24/placeholders"
EU_TESTPACK = "eu-battery/draft-tests"
PROTECTED = ("european_standard", "international_standard", "national_standard")
# References in the Annex of Implementing Decision (EU) 2026/1736, and the two that it does not list.
EN_CITED = (18216, 18219, 18220, 18221, 18222, 18223)
EN_NOT_CITED = (18239, 18246)


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(ROOT)


@pytest.fixture(scope="module")
def testpacks() -> dict[str, TestPack]:
    return load_testpacks(ROOT)


@pytest.fixture(scope="module")
def findings(catalogue: Catalogue, testpacks: dict[str, TestPack]) -> list[Finding]:
    # The same call as `dppce catalogue lint`.
    return lint(catalogue, load_profiles(ROOT), testpacks, registry.names(), ROOT)


def _requirements(catalogue: Catalogue) -> list[Requirement]:
    return [r for pack in catalogue.packs.values() for r in pack.requirements]


def _purposes(testpacks: dict[str, TestPack]) -> dict[str, TestPurpose]:
    return {t.id: t for t in testpacks[EU_TESTPACK].test_purposes}


def test_the_data_root_loads(catalogue: Catalogue, testpacks: dict[str, TestPack]) -> None:
    assert {EU_PACK, EN_PACK, "illustrative/core"} <= set(catalogue.packs)
    assert EU_TESTPACK in testpacks
    assert catalogue.legal_as_of == "2026-10-13"
    assert catalogue.packs[EU_PACK].requirements, "the draft pack is not empty"
    for profile in load_profiles(ROOT).values():
        assert {EU_PACK, EN_PACK} <= set(profile.packs)
        assert EU_TESTPACK in profile.testpacks


def test_the_lint_has_no_error_and_no_one_way_trace(findings: list[Finding]) -> None:
    assert [f for f in findings if f.severity == "error"] == []
    assert [f for f in findings if f.code == "CAT005"] == [], "the trace is two-way"


def test_each_source_id_is_unique() -> None:
    # The loader rejects a duplicate, so count the raw file to keep this test meaningful.
    document = load_data(ROOT / "catalogue" / "sources.yaml")
    counts = Counter(source["id"] for source in document["sources"])
    assert [ident for ident, count in counts.items() if count > 1] == []
    assert "dppce-illustrative" in counts


def test_no_source_claims_a_hash_and_none_has_more_than_three_evidence_entries(catalogue: Catalogue) -> None:
    for source in catalogue.sources:
        assert source.sha256 is None, f"{source.id}: no artifact was hashed in the audit"
        assert len(source.evidence) <= 3, source.id


def test_every_en_requirement_is_an_empty_placeholder(catalogue: Catalogue) -> None:
    sources = {s.id: s for s in catalogue.sources}
    requirements = catalogue.packs[EN_PACK].requirements
    assert len(requirements) == 8
    for r in requirements:
        assert r.review_status is ReviewStatus.PLACEHOLDER, r.id
        assert r.authority_class is AuthorityClass.STANDARD_METHOD, r.id
        assert (r.paraphrase, r.source.citation) == ("", ""), f"{r.id}: no content of a standard"
        assert r.interpretations == (), r.id
        assert r.assessment_paths == (), r.id
        assert r.approval is None, r.id
        assert sources[r.source.source_id].source_type == "european_standard", r.id


def test_every_eu_requirement_is_an_unapproved_agent_draft(catalogue: Catalogue) -> None:
    sources = {s.id: s for s in catalogue.sources}
    for r in catalogue.packs[EU_PACK].requirements:
        assert r.review_status is ReviewStatus.DRAFT, r.id
        assert r.authority_class is AuthorityClass.LEGAL_OBLIGATION, r.id
        assert r.source.citation, f"{r.id}: a draft cites a provision"
        assert r.source.version, f"{r.id}: a draft names the version examined"
        assert sources[r.source.source_id].source_type.startswith("eu_"), r.id
        assert r.approval is None, r.id
        assert r.paraphrase, r.id
        assert len(r.interpretations) == 1, r.id
        for interpretation in r.interpretations:
            assert interpretation.author_kind == "agent", r.id
            assert interpretation.status is ReviewStatus.DRAFT, f"{r.id}: an agent cannot approve"
            assert interpretation.source_version == r.source.version, r.id


def test_no_requirement_in_a_shipped_pack_is_approved(catalogue: Catalogue) -> None:
    for r in _requirements(catalogue):
        assert r.review_status is not ReviewStatus.APPROVED, r.id
        assert r.approval is None, r.id
        assert all(i.status is not ReviewStatus.APPROVED for i in r.interpretations), r.id


def test_a_protected_standard_is_cited_only_by_placeholders(catalogue: Catalogue) -> None:
    protected = {s.id for s in catalogue.sources if s.source_type in PROTECTED}
    assert protected, "the catalogue lists protected standards"
    citing = [r for r in _requirements(catalogue) if r.source.source_id in protected]
    assert {r.source.source_id for r in citing} == {f"en-{n}-2026" for n in (*EN_CITED, *EN_NOT_CITED)}
    for r in citing:
        assert r.review_status is ReviewStatus.PLACEHOLDER, r.id
        assert (r.paraphrase, r.source.citation) == ("", ""), r.id


def test_published_and_cited_stay_separate_facts(catalogue: Catalogue) -> None:
    sources = {s.id: s for s in catalogue.sources}
    cited = {n: sources[f"en-{n}-2026"] for n in EN_CITED}
    not_cited = {n: sources[f"en-{n}-2026"] for n in EN_NOT_CITED}
    for source in (*cited.values(), *not_cited.values()):
        assert source.publication_date, f"{source.id}: published is its own fact"
        assert source.verification_level == "metadata_only", source.id
    assert {s.oj_citation.status for s in cited.values()} == {"cited"}
    assert {s.oj_citation.status for s in not_cited.values()} == {"not_located"}


def test_every_eu_test_purpose_permits_exploratory_mode_only(testpacks: dict[str, TestPack]) -> None:
    for purpose in testpacks[EU_TESTPACK].test_purposes:
        assert purpose.id.startswith("TP-EU-"), purpose.id
        assert purpose.permitted_modes == (ExecutionMode.EXPLORATORY,), purpose.id
        assert purpose.profiles == ("*",), purpose.id
        assert purpose.expected_evidence, purpose.id
        if purpose.manual:
            assert (purpose.stimulus.check, purpose.requires_scope.value) == ("manual.review", "none")
        else:
            assert purpose.stimulus.check in registry.names(), purpose.id


def test_an_automated_step_alone_can_never_pass_an_eu_requirement(
    catalogue: Catalogue, testpacks: dict[str, TestPack]
) -> None:
    purposes = _purposes(testpacks)
    for r in catalogue.packs[EU_PACK].requirements:
        # Paths are alternatives: a second, automated-only path would be a way around the manual step.
        assert len(r.assessment_paths) == 1, r.id
        steps = [purposes[t] for t in r.assessment_paths[0].tests]
        assert any(step.manual for step in steps), f"{r.id}: every path needs its manual step"
    for purpose in purposes.values():
        if not purpose.manual:
            # A draft interpretation gives diagnostics. A failed check is not a legal failure.
            assert purpose.verdict_rules.on_check_failed == "inconclusive", purpose.id
            assert purpose.verdict_rules.on_unreachable == "inconclusive", purpose.id


def _facts(category: str, capacity: int | str, placed: str, put: str) -> dict[str, Any]:
    characteristics = {
        "capacity_wh": capacity,
        "placed_on_market_date": placed,
        "put_into_service_date": put,
    }
    return {"ics": {"product_category": category, "characteristics": characteristics}, "profile": {}}


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (_facts("industrial", 2000, "2027-02-18", "unknown"), Tri.FALSE),  # greater than 2 kWh, not equal
        (_facts("industrial", 2001, "2027-02-18", "unknown"), Tri.TRUE),
        (_facts("industrial", "unknown", "2027-02-18", "unknown"), Tri.UNKNOWN),
        (_facts("lmt", 500, "2027-02-18", "unknown"), Tri.TRUE),  # the limit is for industrial batteries only
        (_facts("ev", 75000, "2027-02-17", "unknown"), Tri.UNKNOWN),  # one unknown date is not a 'no'
        (_facts("ev", 75000, "2027-02-17", "2027-02-17"), Tri.FALSE),
        (_facts("ev", 75000, "unknown", "2027-02-18"), Tri.TRUE),  # placed on the market OR put into service
        (_facts("portable", 50, "2027-03-01", "unknown"), Tri.FALSE),
        (_facts("unknown", 50, "2027-03-01", "unknown"), Tri.UNKNOWN),
    ],
)
def test_the_passport_scope_expression_follows_article_77_1(
    catalogue: Catalogue, facts: dict[str, Any], expected: Tri
) -> None:
    requirement = next(r for r in catalogue.packs[EU_PACK].requirements if r.id == "EUBAT-77-1")
    assert evaluate(requirement.applicability, facts).value is expected


def test_an_item_that_waits_for_an_unadopted_act_is_never_applicable(catalogue: Catalogue) -> None:
    requirements = {r.id: r for r in catalogue.packs[EU_PACK].requirements}
    inside = _facts("ev", 75000, "2027-03-01", "unknown")
    outside = _facts("portable", 50, "2027-03-01", "unknown")
    for ident in ("EUBAT-AXIII-1C", "EUBAT-AXIII-1D", "EUBAT-AXIII-1E", "EUBAT-78-B", "EUBAT-78-F"):
        assert evaluate(requirements[ident].applicability, inside).value is Tri.UNKNOWN, ident
        assert evaluate(requirements[ident].applicability, outside).value is Tri.FALSE, ident
