"""The shipped catalogue content obeys the governance rules.

These tests read the files in ``catalogue/``, ``profiles/``, and ``testpacks/``. They guard what a
schema cannot: no agent approval, no standard content, no legal claim from a draft, and a
two-way trace. They do not test the engine.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

import pytest

import dppce.adapters  # noqa: F401 - the import registers the checks that the lint looks up
from dppce.adapters.access import AccessPolicy
from dppce.applicability import evaluate
from dppce.catalogue import Catalogue, load_catalogue, load_data, load_model, load_profiles, load_testpacks
from dppce.catalogue.lint import Finding, lint
from dppce.infrastructure.resources import data_root
from dppce.models import (
    All,
    AuthorityClass,
    Compare,
    ExecutionMode,
    Not,
    Op,
    Requirement,
    ReviewStatus,
    Scope,
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
    return lint(catalogue, load_profiles(ROOT), testpacks, registry.param_models(), ROOT)


def _requirements(catalogue: Catalogue) -> list[Requirement]:
    return [r for pack in catalogue.packs.values() for r in pack.requirements]


def _purposes(testpacks: dict[str, TestPack]) -> dict[str, TestPurpose]:
    return {t.id: t for t in testpacks[EU_TESTPACK].test_purposes}


def test_the_data_root_loads(catalogue: Catalogue, testpacks: dict[str, TestPack]) -> None:
    assert {EU_PACK, EN_PACK, "illustrative/core"} <= set(catalogue.packs)
    assert EU_TESTPACK in testpacks
    assert catalogue.legal_as_of == "2026-10-13"
    assert catalogue.packs[EU_PACK].requirements, "the draft pack is not empty"
    profiles = load_profiles(ROOT)
    # The battery profiles only: a family profile selects no battery pack (profiles/family/).
    for profile in (profiles[name] for name in BATTERY_PROFILES):
        assert {EU_PACK, EN_PACK} <= set(profile.packs)
        assert EU_TESTPACK in profile.testpacks


def test_the_lint_has_no_error_and_no_one_way_trace(findings: list[Finding]) -> None:
    assert [f for f in findings if f.severity == "error"] == []
    assert [f for f in findings if f.code == "CAT005"] == [], "the trace is two-way"


# This pins consistency only: every entry compares the capacity with the same number. It does not
# decide how the 2 kWh limit is read. OQ-011 and OQ-023 are open decisions for a human.
CAPACITY_LITERAL_WH = 2000


def _capacity_literals(node: object) -> list[object]:
    if isinstance(node, list):
        return [v for item in node for v in _capacity_literals(item)]
    if not isinstance(node, dict):
        return []
    if node.get("fact") == "ics.characteristics.capacity_wh":
        value = node.get("value")
        return list(value) if isinstance(value, list) else [value]
    return [v for item in node.values() for v in _capacity_literals(item)]


def test_every_capacity_literal_of_the_eu_pack_is_one_constant(catalogue: Catalogue) -> None:
    literals = [
        v
        for r in catalogue.packs[EU_PACK].requirements
        for v in _capacity_literals(r.model_dump(mode="json"))
    ]
    assert literals, "the EU pack compares the capacity"
    assert all(type(v) is int for v in literals), literals
    assert set(literals) == {CAPACITY_LITERAL_WH}


def test_each_source_id_is_unique() -> None:
    # The loader rejects a duplicate, so count the raw file to keep this test meaningful.
    document = load_data(ROOT / "catalogue" / "sources.yaml")
    counts = Counter(source["id"] for source in document["sources"])
    assert [ident for ident, count in counts.items() if count > 1] == []
    assert "dppce-illustrative" in counts


def test_only_vendored_vector_records_carry_a_hash_and_none_has_more_than_three_evidence_entries(
    catalogue: Catalogue,
) -> None:
    for source in catalogue.sources:
        if source.source_type == "test_vector":
            # A vendored file under tests/vectors is hashed from the bytes in this checkout.
            data = (ROOT / source.id).read_bytes()
            assert source.sha256 == hashlib.sha256(data).hexdigest(), source.id
        else:
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
        # Changed after review F-02 (validation/records/review-eu-battery-draft-2026-10-14.md): by
        # Article 3(1)(18) a battery placed on the market cannot be put into service later. The
        # known date decides; the unknown one cannot change the answer. Was: Tri.UNKNOWN.
        (_facts("ev", 75000, "2027-02-17", "unknown"), Tri.FALSE),
        (_facts("ev", 75000, "2027-02-17", "2027-02-17"), Tri.FALSE),
        # Changed after review F-01: an unknown placing date can be before 2027-02-18, and then the
        # later service date is void. The draft accepts this trade-off (OQ-021). Was: Tri.TRUE.
        (_facts("ev", 75000, "unknown", "2027-02-18"), Tri.UNKNOWN),
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


# The cases of validation/records/review-eu-battery-draft-2026-10-14.md, section 5, after correction F-01.
_DATE_CASES = {
    "a": (_facts("ev", 75000, "2027-03-01", "unknown"), Tri.TRUE),
    "b": (_facts("ev", 75000, "2026-12-01", "unknown"), Tri.FALSE),  # no later putting into service can exist
    "c": (_facts("lmt", 500, "2027-03-01", "unknown"), Tri.TRUE),
    "d": (_facts("industrial", 2000, "2027-03-01", "unknown"), Tri.FALSE),
    "e": (_facts("industrial", 2001, "2027-03-01", "unknown"), Tri.TRUE),
    "f": (_facts("industrial", "unknown", "2027-03-01", "unknown"), Tri.UNKNOWN),
    "g": (_facts("portable", 50, "2027-03-01", "unknown"), Tri.FALSE),
    "h": (_facts("ev", 75000, "unknown", "unknown"), Tri.UNKNOWN),
    "x": (
        _facts("ev", 75000, "2026-12-01", "2027-03-01"),
        Tri.FALSE,
    ),  # the service date is void by definition
    "y": (
        _facts("ev", 75000, "unknown", "2027-03-01"),
        Tri.UNKNOWN,
    ),  # no value says 'never placed on the market'
}
_PLACED_FROM_START = Compare(fact="ics.characteristics.placed_on_market_date", op=Op.GE, value="2027-02-18")
_STATUS_ENTRIES = {"EUBAT-77-7A", "EUBAT-77-7B", "EUBAT-77-8"}


@pytest.mark.parametrize("case", _DATE_CASES)
def test_a_placing_before_the_start_date_puts_a_battery_outside_article_77_1(
    catalogue: Catalogue, case: str
) -> None:
    facts, expected = _DATE_CASES[case]
    requirement = next(r for r in catalogue.packs[EU_PACK].requirements if r.id == "EUBAT-77-1")
    assert evaluate(requirement.applicability, facts).value is expected


def test_each_entry_with_a_date_clause_reads_the_placing_date_as_documented(catalogue: Catalogue) -> None:
    """Review round 2 changed the form, not the results, of 32 entries (legal-2), and gave the three
    status entries back their 'unknown' for an earlier placing (legal-1).

    The first form of this test counted 35 entries with the clause not(placed lt 2027-02-18). That
    clause made the put-into-service date inert, so 32 entries now state the single comparison that
    they evaluate. The three entries on a change of status no longer exclude an earlier placing.
    """
    requirements = {r.id: r for r in catalogue.packs[EU_PACK].requirements}
    assert len(requirements) == 36
    assert all(r.review_status is ReviewStatus.DRAFT for r in requirements.values())
    single = {
        ident
        for ident, r in requirements.items()
        if isinstance(r.applicability, All) and _PLACED_FROM_START in r.applicability.all
    }
    assert len(single) == 32
    assert set(requirements) - single == {"EUBAT-13-7-LABELS", *_STATUS_ENTRIES}
    # A date-only entry, and an entry where a sibling 'const: unknown' hid the wrong 'true'.
    for ident in ("EUBAT-13-6", "EUBAT-78-B"):
        for case in "bx":
            facts, _ = _DATE_CASES[case]
            assert evaluate(requirements[ident].applicability, facts).value is Tri.FALSE, (ident, case)
    # An earlier placing does not settle a later change of status (OQ-010): the result stays unknown.
    for ident in _STATUS_ENTRIES:
        expression = requirements[ident].applicability
        assert isinstance(expression, All)
        assert all(not isinstance(e, Not) for e in expression.all), ident
        for case in "bx":
            facts, _ = _DATE_CASES[case]
            assert evaluate(expression, facts).value is Tri.UNKNOWN, (ident, case)


# -- access roles (gaps D5-01, D5-03, D3-06) ------------------------------------------------------

BATTERY_PROFILES = ("battery/ev", "battery/lmt", "battery/industrial")
REFERENCE_POLICY = "profiles/battery/access/reference-policy.yaml"


def test_battery_core_probes_each_declared_credentialed_role_once(testpacks: dict[str, TestPack]) -> None:
    probes = [
        p for p in testpacks["battery/core"].test_purposes if p.stimulus.check == "access.restricted_fields"
    ]
    profiles = load_profiles(ROOT)
    for name in BATTERY_PROFILES:
        for role in (r for r in profiles[name].roles if r != "anonymous"):
            found = [p for p in probes if p.stimulus.params.get("role") == role]
            assert len(found) == 1, (name, role)
            assert found[0].roles == (role,)
            assert found[0].requires_scope is Scope.ACCESS_PROBE


def test_the_reference_policy_names_declared_roles_and_marks_each_withheld_path() -> None:
    policy = load_model(ROOT / REFERENCE_POLICY, AccessPolicy)  # one entry per path, or this raises
    profiles = load_profiles(ROOT)
    for name in BATTERY_PROFILES:
        declared = set(profiles[name].roles)
        assert {role for r in policy.restricted for role in r.roles} <= declared, name
        withheld = {r.path for r in policy.restricted if not declared <= set(r.roles)}
        assert withheld <= {c.path for c in policy.canaries}, "each withheld path has a canary"
    usage_log = next(r for r in policy.restricted if r.path == "restricted.usage_log")
    assert "anonymous" not in usage_log.roles
