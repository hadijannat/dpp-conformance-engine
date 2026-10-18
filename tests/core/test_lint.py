"""The catalogue lint, rule by rule, and the trace matrix.

Each rule gets one minimal catalogue that triggers it and one that does not. The clean
baseline has no finding at all, so each test changes one thing and names the finding it expects.
Every catalogue is built in memory. Every source and every citation is synthetic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from dppce.catalogue import Catalogue
from dppce.catalogue.lint import Finding, TraceRow, lint, trace
from dppce.models import Model, Profile, Requirement, SourceRecord, TestPurpose
from dppce.testdefs.registry import NoParams
from tests.core import builders as b

KNOWN_CHECKS: dict[str, type[Model]] = {"probe.ok": NoParams}
FACTS = {
    "capacity_wh": {"type": "integer", "description": "Synthetic capacity."},
    "placed_on_market_date": {"type": "date", "description": "Synthetic date."},
    "chemistry": {"type": "string", "description": "Synthetic chemistry."},
    "removable": {"type": "boolean", "description": "Synthetic flag."},
}
APPROVED: dict[str, Any] = {"review_status": "approved", "approval": b.TEST_ONLY_APPROVAL}


def covered(requirement_id: str = "R-1", test_id: str = "T-1", **changes: Any) -> Requirement:
    """A requirement with one mapped test, so that the baseline has no finding."""
    return b.requirement(requirement_id, assessment_paths=[b.path("p1", test_id)], **changes)


def run_lint(
    requirements: Sequence[Requirement] | None = None,
    purposes: Sequence[TestPurpose] | None = None,
    *,
    sources: Sequence[SourceRecord] | None = None,
    profiles: Sequence[Profile] | None = None,
    extra_packs: Mapping[str, Sequence[Requirement]] | None = None,
    data_root: Path | None = None,
) -> list[Finding]:
    packs = [b.pack(*([covered()] if requirements is None else requirements))]
    packs += [b.pack(*members, pack_id=pack_id) for pack_id, members in (extra_packs or {}).items()]
    selected = [b.profile(facts=FACTS)] if profiles is None else profiles
    return lint(
        b.catalogue(*packs, sources=tuple([b.source()] if sources is None else sources)),
        {p.id: p for p in selected},
        {"tp/a": b.purposes_pack(*([b.purpose("T-1")] if purposes is None else purposes))},
        KNOWN_CHECKS,
        data_root,
    )


def brief(findings: Sequence[Finding]) -> list[tuple[str, str, str]]:
    return [(f.code, f.severity, f.location) for f in findings]


def codes(findings: Sequence[Finding]) -> list[str]:
    return [f.code for f in findings]


def test_the_baseline_catalogue_is_clean() -> None:
    assert run_lint() == []


def test_an_empty_catalogue_is_clean() -> None:
    assert lint(Catalogue(legal_as_of="", sources=(), packs={}), {}, {}, {}) == []


# --- CAT001 to CAT006: the trace in both directions ----------------------------------------


def test_CAT001_a_requirement_names_a_source_that_is_not_in_the_catalogue() -> None:
    found = run_lint([covered(source={"source_id": "SRC-404"})])
    assert brief(found) == [("CAT001", "error", "pack/a/R-1")]
    assert "SRC-404" in found[0].message
    assert "CAT001" not in codes(run_lint([covered(source={"source_id": "SRC-TEST"})]))


def test_CAT002_two_packs_define_the_same_requirement() -> None:
    found = run_lint(extra_packs={"pack/b": [covered()]})
    assert brief(found) == [("CAT002", "error", "pack/b/R-1")]
    assert "pack/a" in found[0].message
    other = run_lint(
        purposes=[b.purpose("T-1", requirements=["R-1", "R-2"])], extra_packs={"pack/b": [covered("R-2")]}
    )
    assert other == []


def test_CAT003_a_requirement_names_a_test_purpose_that_is_not_defined() -> None:
    found = run_lint([b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-404")])])
    assert brief(found) == [("CAT003", "error", "pack/a/R-1")]
    assert "T-404" in found[0].message
    assert "CAT003" not in codes(run_lint())


def test_CAT004_a_test_purpose_names_a_requirement_that_is_not_defined() -> None:
    found = run_lint(purposes=[b.purpose("T-1", requirements=["R-1", "R-404"])])
    assert brief(found) == [("CAT004", "error", "T-1")]
    assert "R-404" in found[0].message
    assert "CAT004" not in codes(run_lint())


def test_CAT005_the_trace_from_a_requirement_to_a_test_purpose_is_one_way() -> None:
    requirements = [covered("R-1"), covered("R-2")]
    found = run_lint(requirements, [b.purpose("T-1", requirements=["R-2"])])
    assert brief(found) == [("CAT005", "warning", "pack/a/R-1")]
    assert "T-1" in found[0].message
    assert run_lint(requirements, [b.purpose("T-1", requirements=["R-1", "R-2"])]) == []


def test_CAT005_the_trace_from_a_test_purpose_to_a_requirement_is_one_way() -> None:
    found = run_lint(purposes=[b.purpose("T-1"), b.purpose("T-2", requirements=["R-1"])])
    assert brief(found) == [("CAT005", "warning", "T-2")]
    assert "R-1" in found[0].message
    both = [b.requirement("R-1", assessment_paths=[b.path("p1", "T-1"), b.path("p2", "T-2")])]
    assert run_lint(both, [b.purpose("T-1"), b.purpose("T-2")]) == []


def test_CAT006_a_test_purpose_names_a_check_that_is_not_registered() -> None:
    found = run_lint(purposes=[b.purpose("T-1", stimulus={"check": "probe.absent"})])
    assert brief(found) == [("CAT006", "warning", "T-1")]
    assert "probe.absent" in found[0].message
    assert "CAT006" not in codes(run_lint(purposes=[b.purpose("T-1", stimulus={"check": "probe.ok"})]))
    manual = run_lint(purposes=[b.purpose("T-1", stimulus={"check": "probe.absent"}, manual=True)])
    assert manual == [], "a manual review needs no registered check"


# --- CAT007 to CAT012: governance of sources and interpretations ---------------------------

PROTECTED_TYPES = ["european_standard", "international_standard", "national_standard"]


def interpretation(author_kind: str, status: str = "draft-needs-review", **changes: Any) -> dict[str, Any]:
    return {"id": "I-1", "text": "Synthetic reading.", "status": status, "author_kind": author_kind} | changes


@pytest.mark.parametrize("source_type", PROTECTED_TYPES)
def test_CAT007_a_paraphrase_of_a_protected_standard_needs_a_human_author(source_type: str) -> None:
    protected = [b.source(source_type=source_type)]
    paraphrased = covered(paraphrase="Synthetic text. It is not taken from any document.")
    found = run_lint([paraphrased], sources=protected)
    assert brief(found) == [("CAT007", "error", "pack/a/R-1")]
    human = covered(paraphrase=paraphrased.paraphrase, interpretations=[interpretation("human")])
    assert run_lint([human], sources=protected) == []
    assert run_lint([covered()], sources=protected) == [], "no paraphrase, so nothing to protect"
    assert run_lint([paraphrased], sources=[b.source(source_type="synthetic")]) == []


@pytest.mark.parametrize("source_type", PROTECTED_TYPES)
def test_CAT007_a_placeholder_for_a_protected_standard_states_no_clause(source_type: str) -> None:
    protected = [b.source(source_type=source_type)]
    cited = b.requirement(
        "R-1", review_status="placeholder", source={"source_id": "SRC-TEST", "citation": "synthetic"}
    )
    assert brief(run_lint([cited], [], sources=protected)) == [("CAT007", "error", "pack/a/R-1")]
    silent = b.requirement("R-1", review_status="placeholder")
    assert run_lint([silent], [], sources=protected) == []
    assert run_lint([cited], [], sources=[b.source(source_type="synthetic")]) == []


@pytest.mark.parametrize("source_type", PROTECTED_TYPES)
def test_CAT007_an_agent_does_not_interpret_a_protected_standard(source_type: str) -> None:
    protected = [b.source(source_type=source_type)]
    by_agent = covered(interpretations=[interpretation("agent")])
    assert brief(run_lint([by_agent], sources=protected)) == [("CAT007", "error", "pack/a/R-1")]
    by_human = covered(interpretations=[interpretation("human")])
    assert run_lint([by_human], sources=protected) == []
    assert run_lint([by_agent], sources=[b.source(source_type="synthetic")]) == []


def test_CAT008_an_agent_authored_interpretation_is_not_approved() -> None:
    by_agent = covered(interpretations=[interpretation("agent", "approved")], **APPROVED)
    found = run_lint([by_agent])
    assert brief(found) == [("CAT008", "error", "pack/a/R-1")]
    assert "I-1" in found[0].message
    by_human = covered(interpretations=[interpretation("human", "approved")], **APPROVED)
    assert run_lint([by_human]) == []
    assert run_lint([covered(interpretations=[interpretation("agent")])]) == [], "an agent may write a draft"


def test_CAT009_a_legal_obligation_rests_on_a_legal_source_only() -> None:
    legal = covered(authority_class="legal_obligation", source=b.CITED)
    found = run_lint([legal], sources=[b.source(source_type="european_standard")])
    assert ("CAT009", "error", "pack/a/R-1") in brief(found)
    assert brief(run_lint([legal], sources=[b.source(source_type="synthetic")])) == [
        ("CAT009", "error", "pack/a/R-1")
    ]
    assert run_lint([legal], sources=[b.source(source_type="eu_regulation")]) == []
    method = covered(authority_class="standard_method", source=b.CITED)
    assert "CAT009" not in codes(run_lint([method], sources=[b.source(source_type="synthetic")]))


def test_CAT010_a_supersession_names_a_requirement_that_exists() -> None:
    forward = covered(review_status="superseded", superseded_by="R-404")
    found = run_lint([forward])
    assert brief(found) == [("CAT010", "error", "pack/a/R-1")]
    assert "R-404" in found[0].message
    backward = covered(supersedes=["R-403", "R-404"])
    assert brief(run_lint([backward])) == [("CAT010", "error", "pack/a/R-1")] * 2
    old = b.requirement("R-0", review_status="superseded", superseded_by="R-1")
    assert run_lint([old, covered(supersedes=["R-0"])]) == []


@pytest.mark.parametrize("level", ["secondary_only", "not_located", "unverified_recall"])
def test_CAT011_an_interpretation_rests_on_a_source_that_nobody_read(level: str) -> None:
    unverified = [b.source(verification_level=level)]
    found = run_lint(sources=unverified)
    assert brief(found) == [("CAT011", "warning", "pack/a/R-1")]
    assert level in found[0].message
    assert brief(run_lint([covered(**APPROVED)], sources=unverified)) == [("CAT011", "warning", "pack/a/R-1")]
    placeholder = b.requirement("R-1", review_status="placeholder")
    assert run_lint([placeholder], [], sources=unverified) == [], "a placeholder holds no interpretation"


@pytest.mark.parametrize("level", ["substantive", "metadata_only"])
def test_CAT011_does_not_fire_for_a_source_that_was_checked(level: str) -> None:
    assert run_lint(sources=[b.source(verification_level=level)]) == []


def test_CAT012_an_interpretation_has_unresolved_points() -> None:
    open_points = covered(interpretations=[interpretation("human", unresolved=["first", "second"])])
    found = run_lint([open_points])
    assert brief(found) == [("CAT012", "info", "pack/a/R-1")]
    assert "2" in found[0].message
    assert run_lint([covered(interpretations=[interpretation("human")])]) == []


# --- CAT013: facts -------------------------------------------------------------------------


def fact(path: str, op: str = "eq", value: Any = 1) -> dict[str, Any]:
    return {"fact": path, "op": op, "value": value}


def lint_expression(expression: dict[str, Any], **profile_changes: Any) -> list[Finding]:
    return run_lint([covered(applicability=expression)], profiles=[b.profile(facts=FACTS, **profile_changes)])


def test_CAT013_a_fact_is_not_under_ics_or_profile() -> None:
    found = lint_expression(fact("environment.home"))
    assert brief(found) == [("CAT013", "error", "pack/a/R-1")]
    assert "environment.home" in found[0].message
    assert lint_expression(fact("ics.product_category", value="widget")) == []
    assert lint_expression(fact("profile.id", value=b.PROFILE_ID)) == []
    assert lint_expression(fact("profile.product_category", value="widget")) == []


def test_CAT013_a_characteristic_that_the_selecting_profile_does_not_declare() -> None:
    found = lint_expression(fact("ics.characteristics.colour", value="red"))
    assert brief(found) == [("CAT013", "error", "pack/a/R-1")]
    assert "colour" in found[0].message
    assert lint_expression(fact("ics.characteristics.capacity_wh", "gt", 2000)) == []
    not_selecting = b.profile(id="test/other", packs=["pack/other"], testpacks=[])
    requirement = covered(applicability=fact("ics.characteristics.capacity_wh", "gt", 2000))
    with_other = run_lint([requirement], profiles=[b.profile(facts=FACTS), not_selecting])
    assert "CAT013" not in codes(with_other), "a profile that does not select the pack is not asked"


def test_CAT013_a_profile_constant_that_the_selecting_profile_does_not_have() -> None:
    found = lint_expression(fact("profile.threshold_wh", "eq", 2000))
    assert brief(found) == [("CAT013", "error", "pack/a/R-1")]
    assert "threshold_wh" in found[0].message
    assert lint_expression(fact("profile.threshold_wh", "eq", 2000), constants={"threshold_wh": 2000}) == []


@pytest.mark.parametrize("op", ["gt", "ge", "lt", "le"])
@pytest.mark.parametrize(("name", "operand"), [("chemistry", "b"), ("removable", True)])
def test_CAT013_an_ordering_on_a_fact_that_is_not_an_integer_or_a_date(
    op: str, name: str, operand: Any
) -> None:
    """Section 5: such a pair is a catalogue defect, and the lint reports it."""
    found = lint_expression(fact(f"ics.characteristics.{name}", op, operand))
    assert brief(found) == [("CAT013", "error", "pack/a/R-1")]
    assert name in found[0].message
    assert lint_expression(fact(f"ics.characteristics.{name}", "eq", operand)) == []


@pytest.mark.parametrize("op", ["gt", "ge", "lt", "le"])
def test_CAT013_does_not_fire_for_an_ordering_on_an_integer_or_on_a_date(op: str) -> None:
    assert lint_expression(fact("ics.characteristics.capacity_wh", op, 2000)) == []
    assert lint_expression(fact("ics.characteristics.placed_on_market_date", op, "2027-02-18")) == []


@pytest.mark.parametrize(
    ("name", "operand"),
    [("capacity_wh", "2027-02-18"), ("capacity_wh", True), ("placed_on_market_date", 20270218)],
    ids=["integer-with-date", "integer-with-boolean", "date-with-integer"],
)
def test_the_lint_reports_an_ordering_whose_operand_does_not_fit_the_fact(name: str, operand: Any) -> None:
    """Section 5: any pair other than two integers or two ISO dates is a defect that the lint reports."""
    found = lint_expression(fact(f"ics.characteristics.{name}", "gt", operand))
    assert any((f.severity, f.location) == ("error", "pack/a/R-1") for f in found), brief(found)


def test_CAT013_reads_every_expression_of_a_requirement_and_of_a_test_purpose() -> None:
    bad = fact("ics.characteristics.colour", value="red")
    nested = {"all": [b.ALWAYS, {"any": [{"not": bad}, b.ALWAYS]}]}
    places = [
        covered(applicability=nested),
        covered(declared_support=bad),
        b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", applicability=bad)]),
    ]
    for requirement in places:
        assert brief(run_lint([requirement])) == [("CAT013", "error", "pack/a/R-1")]
    in_purpose = run_lint(purposes=[b.purpose("T-1", applicability=nested)])
    assert brief(in_purpose) == [("CAT013", "error", "T-1")]


# --- CAT014 and CAT015 ---------------------------------------------------------------------


def test_CAT014_a_profile_names_a_pack_or_a_test_pack_that_is_not_found() -> None:
    missing_pack = run_lint(profiles=[b.profile(packs=["pack/a", "pack/missing"])])
    assert brief(missing_pack) == [("CAT014", "error", b.PROFILE_ID)]
    assert "pack/missing" in missing_pack[0].message
    missing_testpack = run_lint(profiles=[b.profile(testpacks=["tp/a", "tp/missing"])])
    assert brief(missing_testpack) == [("CAT014", "error", b.PROFILE_ID)]
    assert "tp/missing" in missing_testpack[0].message
    assert "CAT014" not in codes(run_lint(profiles=[b.profile()]))


def test_CAT014_a_profile_names_a_resource_file_that_is_not_found(tmp_path: Path) -> None:
    resources = {
        "item_schema": "schemas/item.json",
        "model_schema": "schemas/model.json",
        "api_contract": "contracts/api.json",
        "access_policy": "access/policy.json",
        "rule_packs": ["rules/one.json", "rules/two.json"],
    }
    selected = [b.profile(**resources)]
    found = run_lint(profiles=selected, data_root=tmp_path)
    assert brief(found) == [("CAT014", "error", b.PROFILE_ID)] * 6
    for name in ("schemas/item.json", "schemas/model.json", "contracts/api.json", "access/policy.json"):
        assert any(name in f.message for f in found), name
    for name in (
        "schemas/item.json",
        "schemas/model.json",
        "contracts/api.json",
        "access/policy.json",
        "rules/one.json",
    ):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("{}", encoding="utf-8")
    (tmp_path / "rules" / "two.json").mkdir()
    still = run_lint(profiles=selected, data_root=tmp_path)
    assert brief(still) == [("CAT014", "error", b.PROFILE_ID)], "a directory is not a resource file"
    assert "rules/two.json" in still[0].message
    assert run_lint(profiles=selected) == [], "without a data root the resource files are not checked"
    assert run_lint(profiles=[b.profile()], data_root=tmp_path) == []


@pytest.mark.parametrize(
    "status", [{"review_status": "draft-needs-review"}, APPROVED], ids=["draft", "approved"]
)
def test_CAT015_an_interpreted_requirement_has_no_test(status: dict[str, Any]) -> None:
    for paths in ([], [b.path("p1")]):
        found = run_lint([b.requirement("R-1", assessment_paths=paths, **status)], [])
        assert brief(found) == [("CAT015", "info", "pack/a/R-1")], paths
    assert "CAT015" not in codes(run_lint([covered(**status)]))


def test_CAT015_does_not_fire_for_a_requirement_with_no_interpretation() -> None:
    for status in ({"review_status": "placeholder"}, {"review_status": "withdrawn"}):
        assert run_lint([b.requirement("R-1", **status)], []) == []


# --- CAT019: check parameters --------------------------------------------------------------


def test_CAT019_params_that_do_not_fit_a_registered_check() -> None:
    stimulus = {"check": "probe.ok", "params": {"x": 1}}
    found = run_lint(purposes=[b.purpose("T-1", stimulus=stimulus)])
    assert brief(found) == [("CAT019", "error", "T-1")]
    assert "probe.ok" in found[0].message
    assert "'x'" in found[0].message
    manual = run_lint(purposes=[b.purpose("T-1", stimulus=stimulus, manual=True)])
    assert brief(manual) == [("CAT019", "error", "T-1")], "a manual step with a registered check is checked"
    absent = run_lint(purposes=[b.purpose("T-1", stimulus={"check": "probe.absent", "params": {"x": 1}})])
    assert brief(absent) == [("CAT006", "warning", "T-1")], "an unregistered check is not checked"
    assert run_lint(purposes=[b.purpose("T-1", stimulus={"check": "probe.ok", "params": {}})]) == []


# --- CAT020 and CAT021: the cited version and the source record ----------------------------


def versions(version: str, record: str, *, authority_class: str = "guidance", **source: Any) -> list[Finding]:
    cited = covered(authority_class=authority_class, source={**b.CITED, "version": version})
    return run_lint([cited], sources=[b.source(edition_or_version=record, **source)])


def test_CAT020_the_cited_version_shares_a_token_with_the_source_record() -> None:
    assert brief(versions("TEST-ONLY 1.2.0", "TEST-ONLY 1.3.0")) == [("CAT020", "error", "pack/a/R-1")]
    assert versions("TEST-ONLY 1.2.0", "TEST-ONLY 1.2.0 and 1.3.0") == []
    assert versions("TEST-ONLY 1.2.0", "TEST-ONLY edition") == [], "a record without a token is not compared"
    assert versions("TEST-ONLY 1.2.0", "TEST-ONLY 1.3.0", authority_class="illustrative") == []
    assert versions("TEST-ONLY 20260813", "TEST-ONLY 2026-08-13") == []
    found = versions("TEST-ONLY 15459-1:1999", "TEST-ONLY 15459-1:2014")
    assert brief(found) == [("CAT020", "error", "pack/a/R-1")], "a document number is not a version"
    assert "SRC-TEST" in found[0].message
    placeholder = b.requirement("R-1", authority_class="guidance", review_status="placeholder")
    empty = run_lint([placeholder], [], sources=[b.source(edition_or_version="TEST-ONLY 2026")])
    assert brief(empty) == [("CAT020", "error", "pack/a/R-1")]


def test_CAT021_a_later_version_or_amendment_is_a_warning() -> None:
    later = versions("TEST-ONLY 2026-01-01", "TEST-ONLY 2026-01-01, 2026-06-01")
    assert brief(later) == [("CAT021", "warning", "pack/a/R-1")]
    assert "2026-06-01" in later[0].message
    amended = versions(
        "TEST-ONLY 2026-01-01",
        "TEST-ONLY 2026-01-01",
        amendment_history=[{"identifier": "TEST-ONLY M1", "date": "2026-03-01"}],
    )
    assert brief(amended) == [("CAT021", "warning", "pack/a/R-1")]
    assert "TEST-ONLY M1" in amended[0].message
    assert versions("TEST-ONLY 2026-01-01", "TEST-ONLY 2025-01-01, 2026-01-01") == []
    assert versions("TEST-ONLY 2026", "TEST-ONLY 2026-01-01, 2026-06-01") == [], "no ISO date is cited"


# --- CAT022: a date literal of a legal obligation ------------------------------------------

EU_SOURCE = b.source(
    source_type="eu_regulation", applicable_dates=[{"date": "2027-02-18", "what": "TEST-ONLY"}]
)


def legal_dates(
    literal: Any, *, op: str = "ge", where: str = "applicability", **changes: Any
) -> list[Finding]:
    expression = fact("ics.characteristics.placed_on_market_date", op, literal)
    fields: dict[str, Any] = {"authority_class": "legal_obligation", "source": b.CITED, **changes}
    if where == "path":
        requirement = b.requirement(
            "R-1", assessment_paths=[b.path("p1", "T-1", applicability=expression)], **fields
        )
    else:
        requirement = covered(**{where: expression}, **fields)
    return run_lint([requirement], sources=[EU_SOURCE])


def test_CAT022_a_legal_date_literal_is_a_recorded_applicable_date() -> None:
    assert brief(legal_dates("2027-02-19")) == [("CAT022", "error", "pack/a/R-1")]
    assert "2027-02-19" in legal_dates("2027-02-19")[0].message
    assert legal_dates("2027-02-18") == []
    assert brief(legal_dates("2027-02-19", where="path")) == [("CAT022", "error", "pack/a/R-1")]
    assert brief(legal_dates("2027-02-19", where="declared_support")) == [("CAT022", "error", "pack/a/R-1")]
    assert brief(legal_dates(["2027-02-18", "2027-02-19"], op="in")) == [("CAT022", "error", "pack/a/R-1")]
    assert brief(legal_dates("2027-02-30")) == [("CAT022", "error", "pack/a/R-1")]
    full_width_year = "".join(chr(0xFF10 + int(d)) for d in "2027")
    assert "CAT022" in codes(legal_dates(f"{full_width_year}-02-19")), "full-width digits"
    assert legal_dates("2027-02-19", authority_class="illustrative") == []


# --- Order of the findings -----------------------------------------------------------------


def test_the_findings_are_sorted_with_errors_first() -> None:
    requirements = [
        b.requirement("R-2", source={"source_id": "SRC-404"}),
        b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-404")]),
    ]
    purposes = [b.purpose("T-1", stimulus={"check": "probe.absent"})]
    found = run_lint(requirements, purposes)
    assert brief(found) == [
        ("CAT001", "error", "pack/a/R-2"),
        ("CAT003", "error", "pack/a/R-1"),
        ("CAT006", "warning", "T-1"),
        ("CAT015", "info", "pack/a/R-2"),
    ]
    assert run_lint(requirements[::-1], purposes) == found, "the order of the input does not matter"
    assert all(f.message.strip() for f in found)


# --- The trace matrix ----------------------------------------------------------------------


def trace_rows(requirements: Sequence[Requirement], purposes: Sequence[TestPurpose]) -> list[TraceRow]:
    return trace(b.catalogue(b.pack(*requirements)), {"tp/a": b.purposes_pack(*purposes)})


def test_the_trace_of_a_requirement_with_two_paths_has_one_row_for_each_step() -> None:
    requirement = b.requirement(
        "R-1",
        authority_class="guidance",
        source=b.CITED,
        interpretations=[interpretation("human"), interpretation("human", id="I-2")],
        assessment_paths=[b.path("via-b", "T-2", "T-1"), b.path("via-a", "T-1")],
    )
    purposes = [b.purpose("T-1"), b.purpose("T-2", stimulus={"check": "probe.other"})]
    rows = trace_rows([requirement], purposes)
    assert [(r.path_id, r.test_purpose_id, r.check) for r in rows] == [
        ("via-a", "T-1", "probe.ok"),
        ("via-b", "T-1", "probe.ok"),
        ("via-b", "T-2", "probe.other"),
    ]
    for row in rows:
        assert (row.source_id, row.citation, row.source_version) == (
            "SRC-TEST",
            "synthetic provision A",
            "TEST-ONLY",
        )
        assert (row.requirement_id, row.pack_id) == ("R-1", "pack/a")
        assert (row.authority_class, row.review_status) == ("guidance", "draft-needs-review")
        assert row.interpretations == ("I-1", "I-2")


def test_the_trace_of_a_requirement_with_one_test_has_one_row() -> None:
    (row,) = trace_rows([covered()], [b.purpose("T-1")])
    assert (row.requirement_id, row.path_id, row.test_purpose_id, row.check) == (
        "R-1",
        "p1",
        "T-1",
        "probe.ok",
    )
    assert (row.source_id, row.citation, row.interpretations) == ("SRC-TEST", "", ())


def test_the_trace_of_a_requirement_with_no_test_has_one_row_with_no_test() -> None:
    for requirement in (
        b.requirement("R-1", review_status="placeholder"),
        b.requirement("R-1", assessment_paths=[b.path("p1")]),
    ):
        (row,) = trace_rows([requirement], [b.purpose("T-1")])
        assert (row.requirement_id, row.path_id, row.test_purpose_id, row.check) == ("R-1", "", "", "")
        assert row.review_status == requirement.review_status.value


def test_the_trace_shows_a_test_purpose_that_is_not_defined_with_no_check() -> None:
    (row,) = trace_rows([covered(test_id="T-404")], [b.purpose("T-1")])
    assert (row.test_purpose_id, row.check) == ("T-404", "")


def test_the_trace_is_sorted_by_requirement_then_path_then_test_purpose() -> None:
    catalogue = b.catalogue(
        b.pack(covered("R-3"), covered("R-1"), pack_id="pack/z"), b.pack(covered("R-2"), b.requirement("R-0"))
    )
    rows = trace(catalogue, {"tp/a": b.purposes_pack(b.purpose("T-1"))})
    assert [(r.requirement_id, r.pack_id) for r in rows] == [
        ("R-0", "pack/a"),
        ("R-1", "pack/z"),
        ("R-2", "pack/a"),
        ("R-3", "pack/z"),
    ]
    assert trace(Catalogue(legal_as_of="", sources=(), packs={}), {}) == []
