"""The requirement lifecycle, the safe loaders, the sanitized IXIT, the ICS check, and the hashes.

The lifecycle and loader rules come from docs/explanation/architecture.md, section 2 (rule 4)
and section 4. Every file here is written to a temporary directory. No shipped pack is read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from dppce.catalogue import (
    Catalogue,
    CatalogueError,
    check_ics,
    load_catalogue,
    load_data,
    load_ics,
    load_ixit,
    load_model,
    load_profiles,
    load_testpacks,
    sanitized_ixit,
)
from dppce.catalogue.loader import MAX_FILE_BYTES
from dppce.models import ICS, IXIT, Model, Profile, RequirementPack, SourceRecord, TestPack
from tests.core import builders as b

NORMATIVE_CLASSES = ["legal_obligation", "standard_method", "implementation_contract", "guidance"]
APPROVED: dict[str, Any] = {"review_status": "approved", "approval": b.TEST_ONLY_APPROVAL}


def rejected(**changes: Any) -> None:
    with pytest.raises(ValidationError, match="R-1"):
        b.requirement("R-1", **changes)


# --- Lifecycle rules of a requirement ------------------------------------------------------


def test_an_approved_requirement_needs_an_approval_record() -> None:
    rejected(review_status="approved")
    assert b.requirement("R-1", **APPROVED).approval is not None


@pytest.mark.parametrize("field", ["reviewer", "date", "rationale", "source_version", "artifact"])
def test_an_approval_record_needs_each_of_its_five_fields(field: str) -> None:
    missing = {k: v for k, v in b.TEST_ONLY_APPROVAL.items() if k != field}
    with pytest.raises(ValidationError, match=field):
        b.requirement("R-1", review_status="approved", approval=missing)
    with pytest.raises(ValidationError, match=field):
        b.requirement("R-1", review_status="approved", approval={**b.TEST_ONLY_APPROVAL, field: ""})


@pytest.mark.parametrize("date", ["yesterday", "01-01-2000", "2000-1-1", "2000-01-01T00:00:00Z"])
def test_an_approval_date_is_an_iso_date(date: str) -> None:
    with pytest.raises(ValidationError, match="date"):
        b.requirement("R-1", review_status="approved", approval={**b.TEST_ONLY_APPROVAL, "date": date})


@pytest.mark.parametrize("status", ["draft-needs-review", "placeholder"])
def test_an_approval_record_is_valid_only_on_an_approved_requirement(status: str) -> None:
    rejected(review_status=status, approval=b.TEST_ONLY_APPROVAL)
    assert b.requirement("R-1", review_status=status).approval is None


@pytest.mark.parametrize(
    "closed", [{"review_status": "withdrawn"}, {"review_status": "superseded", "superseded_by": "R-2"}]
)
def test_a_closed_requirement_may_keep_the_approval_record_that_it_had(closed: dict[str, str]) -> None:
    assert b.requirement("R-1", approval=b.TEST_ONLY_APPROVAL, **closed).approval is not None
    assert b.requirement("R-1", **closed).approval is None


def test_a_placeholder_has_an_empty_paraphrase() -> None:
    rejected(review_status="placeholder", paraphrase="Any text at all.")
    assert b.requirement("R-1", review_status="placeholder").paraphrase == ""
    assert b.requirement("R-1", paraphrase="A synthetic rule.").paraphrase == "A synthetic rule."


def test_a_superseded_requirement_names_its_successor() -> None:
    rejected(review_status="superseded")
    rejected(review_status="superseded", superseded_by="")
    assert b.requirement("R-1", review_status="superseded", superseded_by="R-2").superseded_by == "R-2"


@pytest.mark.parametrize("authority_class", NORMATIVE_CLASSES)
@pytest.mark.parametrize(
    "status", [{"review_status": "draft-needs-review"}, APPROVED], ids=["draft", "approved"]
)
def test_a_normative_interpretation_cites_a_provision_and_a_version(
    authority_class: str, status: dict[str, Any]
) -> None:
    for source in (
        {"source_id": "SRC-TEST"},
        {"source_id": "SRC-TEST", "citation": "synthetic provision A"},
        {"source_id": "SRC-TEST", "version": "TEST-ONLY"},
    ):
        rejected(authority_class=authority_class, source=source, **status)
    cited = b.requirement("R-1", authority_class=authority_class, source=b.CITED, **status)
    assert (cited.source.citation, cited.source.version) == ("synthetic provision A", "TEST-ONLY")


@pytest.mark.parametrize("authority_class", NORMATIVE_CLASSES)
def test_a_requirement_with_no_interpretation_needs_no_citation(authority_class: str) -> None:
    for status in (
        {"review_status": "placeholder"},
        {"review_status": "withdrawn"},
        {"review_status": "superseded", "superseded_by": "R-2"},
    ):
        assert b.requirement("R-1", authority_class=authority_class, **status).source.citation == ""


def test_an_illustrative_requirement_needs_no_citation() -> None:
    assert b.requirement("R-1", authority_class="illustrative").source.citation == ""
    assert b.requirement("R-1", authority_class="illustrative", **APPROVED).source.version == ""


def interpretation(status: str, author_kind: str = "human") -> dict[str, Any]:
    return {"id": "I-1", "text": "Synthetic reading.", "status": status, "author_kind": author_kind}


def test_an_approved_interpretation_needs_the_approval_record_of_the_requirement() -> None:
    rejected(interpretations=[interpretation("approved")])
    rejected(
        review_status="withdrawn",
        interpretations=[interpretation("draft-needs-review"), interpretation("approved")],
    )
    approved = b.requirement("R-1", interpretations=[interpretation("approved")], **APPROVED)
    assert approved.interpretations[0].status.value == "approved"
    draft = b.requirement("R-1", interpretations=[interpretation("draft-needs-review")])
    assert draft.approval is None


def test_the_assessment_paths_of_a_requirement_have_distinct_identifiers() -> None:
    rejected(assessment_paths=[b.path("p1", "T-1"), b.path("p1", "T-2")])
    distinct = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1"), b.path("p2", "T-1")])
    assert [p.id for p in distinct.assessment_paths] == ["p1", "p2"]


def test_a_pack_and_a_test_pack_reject_a_repeated_identifier() -> None:
    with pytest.raises(ValidationError, match="pack/a"):
        b.pack(b.requirement("R-1"), b.requirement("R-1"))
    with pytest.raises(ValidationError, match="tp/a"):
        b.purposes_pack(b.purpose("T-1"), b.purpose("T-1"))
    assert len(b.pack(b.requirement("R-1"), b.requirement("R-2")).requirements) == 2
    assert len(b.purposes_pack(b.purpose("T-1"), b.purpose("T-2")).test_purposes) == 2


# --- load_data: YAML is data ---------------------------------------------------------------


def write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return path


def as_text(model: Model) -> str:
    """JSON is also YAML, so this text can go in a ``.yaml`` file."""
    return json.dumps(model.model_dump(mode="json", by_alias=True))


def test_yaml_and_json_files_load_as_plain_data(tmp_path: Path) -> None:
    document = "name: widget\ncount: 3\nready: true\nnothing: null\ntags: [a, b]\nnested:\n  key: value\n"
    expected = {
        "name": "widget",
        "count": 3,
        "ready": True,
        "nothing": None,
        "tags": ["a", "b"],
        "nested": {"key": "value"},
    }
    assert load_data(write(tmp_path / "data.yaml", document)) == expected
    assert load_data(write(tmp_path / "data.json", json.dumps(expected))) == expected


@pytest.mark.parametrize(
    "document",
    ["a: 1\na: 2\n", "outer:\n  inner: 1\n  inner: 1\n", "items:\n  - {k: 1, k: 2}\n", '{"a": 1, "a": 1}\n'],
    ids=["top-level", "nested", "inside-a-list", "flow-style"],
)
def test_a_repeated_yaml_key_is_rejected(tmp_path: Path, document: str) -> None:
    with pytest.raises(CatalogueError, match="duplicate"):
        load_data(write(tmp_path / "repeated.yaml", document))


def test_the_same_key_in_two_different_mappings_is_not_a_repeated_key(tmp_path: Path) -> None:
    document = "first:\n  id: 1\nsecond:\n  id: 2\n"
    assert load_data(write(tmp_path / "ok.yaml", document)) == {"first": {"id": 1}, "second": {"id": 2}}


@pytest.mark.parametrize(
    "tag",
    [
        "!!python/object:pathlib.PurePosixPath {}",
        "!!python/object/apply:pathlib.Path.touch [{canary}]",
        "!!python/object/new:pathlib.Path [{canary}]",
        "!!python/name:pathlib.Path",
        "!!python/module:pathlib",
        "!custom {}",
    ],
)
def test_a_python_object_tag_is_rejected_and_nothing_runs(tmp_path: Path, tag: str) -> None:
    canary = tmp_path / "canary"
    document = "value: " + tag.replace("{canary}", json.dumps(str(canary))) + "\n"
    with pytest.raises(CatalogueError, match=r"tagged\.yaml"):
        load_data(write(tmp_path / "tagged.yaml", document))
    assert not canary.exists()


def test_no_yaml_value_is_evaluated_as_code_or_as_a_template(tmp_path: Path) -> None:
    document = {"a": "{{ 6 * 7 }}", "b": "${HOME}", "c": "__import__('os').getcwd()", "d": "%(name)s"}
    assert load_data(write(tmp_path / "plain.yaml", json.dumps(document))) == document


def test_a_file_above_the_size_limit_is_rejected(tmp_path: Path) -> None:
    filler = b"x" * (MAX_FILE_BYTES - 2)
    at_limit = write(tmp_path / "limit.json", b'"' + filler + b'"')
    assert at_limit.stat().st_size == MAX_FILE_BYTES
    assert len(load_data(at_limit)) == MAX_FILE_BYTES - 2
    for name in ("large.json", "large.yaml"):
        above = write(tmp_path / name, b'"' + filler + b'x"')
        assert above.stat().st_size == MAX_FILE_BYTES + 1
        with pytest.raises(CatalogueError, match=name):
            load_data(above)


@pytest.mark.parametrize(
    ("name", "document"),
    [
        ("broken.yaml", "key: [1, 2\n"),
        ("broken.yaml", "key: 'open\n"),
        ("broken.yaml", "a: b: c: d\n"),
        ("broken.json", '{"key": '),
        ("broken.json", "key: value\n"),
        ("broken.yaml", b"key: \xc3\x28\n"),
        ("broken.json", b"\xc3\x28"),
        ("broken.yaml", "key: \x01\n"),
    ],
)
def test_invalid_yaml_or_json_is_rejected(tmp_path: Path, name: str, document: str | bytes) -> None:
    with pytest.raises(CatalogueError, match=name):
        load_data(write(tmp_path / name, document))


def test_a_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError, match=r"absent\.yaml"):
        load_data(tmp_path / "absent.yaml")
    with pytest.raises(CatalogueError, match="cannot read"):
        load_data(tmp_path)  # a directory is not a file


# --- load_model and the declaration loaders ------------------------------------------------


def test_a_declaration_loads_into_its_contract(tmp_path: Path) -> None:
    declared = b.ics(characteristics={"capacity_wh": 2500}, features={"export": True})
    assert load_ics(write(tmp_path / "ics.yaml", as_text(declared))) == declared
    assert load_model(write(tmp_path / "ics.json", as_text(declared)), ICS) == declared
    ixit = IXIT(schema_version="dppce.ixit/1", endpoints={"api": "http://127.0.0.1:1/api"})
    assert load_ixit(write(tmp_path / "ixit.yaml", as_text(ixit))) == ixit


@pytest.mark.parametrize(
    ("change", "location"),
    [
        ({"surprise": 1}, "surprise"),
        ({"schema_version": "dppce.ics/2"}, "schema_version"),
        ({"sut": {"name": "No identifier"}}, "sut.identifier"),
        ({"characteristics": {"ratio": 0.5}}, "characteristics.ratio"),
    ],
)
def test_a_file_that_does_not_match_its_contract_is_rejected_with_the_location(
    tmp_path: Path, change: dict[str, Any], location: str
) -> None:
    document = b.ics().model_dump(mode="json") | change
    with pytest.raises(CatalogueError, match=location):
        load_ics(write(tmp_path / "ics.yaml", json.dumps(document)))


def test_a_file_that_is_not_a_mapping_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError, match=r"list\.yaml"):
        load_ics(write(tmp_path / "list.yaml", "- 1\n- 2\n"))


# --- load_catalogue ------------------------------------------------------------------------


def write_sources(root: Path, *sources: SourceRecord, **document: Any) -> None:
    body = {
        "schema_version": "dppce.sources/1",
        "legal_as_of": "2026-01-01",
        "sources": [s.model_dump(mode="json") for s in sources],
    }
    write(root / "catalogue" / "sources.yaml", json.dumps(body | document))


def write_pack(root: Path, name: str, pack: RequirementPack) -> Path:
    return write(root / "catalogue" / "packs" / name, as_text(pack))


def test_a_catalogue_loads_its_sources_and_its_packs(tmp_path: Path) -> None:
    first, second = b.source("SRC-A"), b.source("SRC-B")
    write_sources(tmp_path, first, second)
    pack_a = b.pack(b.requirement("R-1", applicability={"not": b.feature("legacy")}))
    pack_b = b.pack(b.requirement("R-2"), pack_id="pack/b")
    write_pack(tmp_path, "z-last.yaml", pack_a)
    write_pack(tmp_path, "a-first.yaml", pack_b)
    write(tmp_path / "catalogue" / "packs" / "notes.txt", "not a pack")
    loaded = load_catalogue(tmp_path)
    assert loaded.legal_as_of == "2026-01-01"
    assert loaded.sources == (first, second)
    assert loaded.packs == {"pack/a": pack_a, "pack/b": pack_b}


def test_an_imported_pack_is_added_and_the_shipped_files_stay_unchanged(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    write_sources(root, b.source())
    shipped = write_pack(root, "shipped.yaml", b.pack(b.requirement("R-1")))
    before = shipped.read_bytes()
    extra = b.pack(b.requirement("R-2", **APPROVED), pack_id="pack/imported")
    imported = write(outside / "imported.yaml", as_text(extra))
    loaded = load_catalogue(root, extra_packs=[imported])
    assert sorted(loaded.packs) == ["pack/a", "pack/imported"]
    assert loaded.packs["pack/imported"] == extra
    assert shipped.read_bytes() == before
    assert sorted(p.name for p in (root / "catalogue" / "packs").iterdir()) == ["shipped.yaml"]
    assert sorted(load_catalogue(root).packs) == ["pack/a"]


def test_a_duplicate_pack_id_is_rejected(tmp_path: Path) -> None:
    write_sources(tmp_path, b.source())
    write_pack(tmp_path, "one.yaml", b.pack(b.requirement("R-1")))
    write_pack(tmp_path, "two.yaml", b.pack(b.requirement("R-2")))
    with pytest.raises(CatalogueError, match="pack/a"):
        load_catalogue(tmp_path)


def test_an_imported_pack_cannot_replace_a_shipped_pack(tmp_path: Path) -> None:
    root = tmp_path / "root"
    write_sources(root, b.source())
    write_pack(root, "shipped.yaml", b.pack(b.requirement("R-1")))
    imported = write(tmp_path / "outside" / "same-id.yaml", as_text(b.pack(b.requirement("R-2"))))
    with pytest.raises(CatalogueError, match="pack/a"):
        load_catalogue(root, extra_packs=[imported])


def test_a_duplicate_source_id_is_rejected(tmp_path: Path) -> None:
    write_sources(tmp_path, b.source("SRC-A"), b.source("SRC-B"), b.source("SRC-A", title="Again"))
    with pytest.raises(CatalogueError, match="duplicate source id"):
        load_catalogue(tmp_path)


@pytest.mark.parametrize("version", ["dppce.sources/2", "dppce.pack/1", "", None, 1])
def test_a_wrong_schema_version_of_the_sources_file_is_rejected(tmp_path: Path, version: object) -> None:
    write_sources(tmp_path, b.source(), schema_version=version)
    with pytest.raises(CatalogueError, match="schema_version"):
        load_catalogue(tmp_path)


def test_a_sources_file_that_is_not_a_mapping_or_is_missing_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError, match=r"sources\.yaml"):
        load_catalogue(tmp_path)
    write(tmp_path / "catalogue" / "sources.yaml", "- schema_version: dppce.sources/1\n")
    with pytest.raises(CatalogueError, match="schema_version"):
        load_catalogue(tmp_path)


def test_an_invalid_source_record_is_rejected(tmp_path: Path) -> None:
    broken = b.source().model_dump(mode="json") | {"verification_level": "trust me"}
    write(
        tmp_path / "catalogue" / "sources.yaml",
        json.dumps({"schema_version": "dppce.sources/1", "sources": [broken]}),
    )
    with pytest.raises(CatalogueError, match="verification_level"):
        load_catalogue(tmp_path)


def test_a_sources_file_with_no_sources_and_no_date_loads_as_an_empty_catalogue(tmp_path: Path) -> None:
    write(tmp_path / "catalogue" / "sources.yaml", "schema_version: dppce.sources/1\n")
    loaded = load_catalogue(tmp_path)
    assert (loaded.sources, loaded.packs, loaded.legal_as_of) == ((), {}, "")


def test_the_loader_rejects_an_approved_requirement_that_has_no_approval_record(tmp_path: Path) -> None:
    write_sources(tmp_path, b.source())
    document = b.pack(b.requirement("R-1")).model_dump(mode="json", by_alias=True)
    document["requirements"][0]["review_status"] = "approved"
    path = write(tmp_path / "catalogue" / "packs" / "pack.yaml", json.dumps(document))
    with pytest.raises(CatalogueError, match="approv"):
        load_catalogue(tmp_path)
    document["requirements"][0]["approval"] = b.TEST_ONLY_APPROVAL
    write(path, json.dumps(document))
    (loaded,) = load_catalogue(tmp_path).packs["pack/a"].requirements
    assert loaded.approval is not None
    for field in b.TEST_ONLY_APPROVAL:
        document["requirements"][0]["approval"] = {
            k: v for k, v in b.TEST_ONLY_APPROVAL.items() if k != field
        }
        write(path, json.dumps(document))
        with pytest.raises(CatalogueError, match=field):
            load_catalogue(tmp_path)


def test_profiles_load_from_the_family_directories_only(tmp_path: Path) -> None:
    first, second = b.profile(), b.profile(id="test/beta")
    write(tmp_path / "profiles" / "test" / "alpha.yaml", as_text(first))
    write(tmp_path / "profiles" / "test" / "beta.yaml", as_text(second))
    write(tmp_path / "profiles" / "test" / "rules" / "rule-pack.yaml", "rules: []\n")
    write(tmp_path / "profiles" / "readme.yaml", "not: a profile\n")
    assert load_profiles(tmp_path) == {"test/alpha": first, "test/beta": second}
    write(tmp_path / "profiles" / "other" / "copy.yaml", as_text(first))
    with pytest.raises(CatalogueError, match="test/alpha"):
        load_profiles(tmp_path)


def test_test_packs_load_and_a_duplicate_id_is_rejected(tmp_path: Path) -> None:
    first = b.purposes_pack(b.purpose("T-1"))
    second = b.purposes_pack(b.purpose("T-2"), testpack_id="tp/b")
    write(tmp_path / "testpacks" / "a.yaml", as_text(first))
    write(tmp_path / "testpacks" / "b.yaml", as_text(second))
    assert load_testpacks(tmp_path) == {"tp/a": first, "tp/b": second}
    write(tmp_path / "testpacks" / "c.yaml", as_text(first))
    with pytest.raises(CatalogueError, match="tp/a"):
        load_testpacks(tmp_path)


def test_an_imported_test_pack_is_added_and_the_shipped_files_stay_unchanged(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    shipped = write(root / "testpacks" / "shipped.yaml", as_text(b.purposes_pack(b.purpose("T-1"))))
    before = shipped.read_bytes()
    extra = b.purposes_pack(b.purpose("T-2"), testpack_id="tp/imported")
    imported = write(outside / "imported.yaml", as_text(extra))
    loaded = load_testpacks(root, extra_testpacks=[imported])
    assert sorted(loaded) == ["tp/a", "tp/imported"]
    assert loaded["tp/imported"] == extra
    assert shipped.read_bytes() == before
    assert sorted(p.name for p in (root / "testpacks").iterdir()) == ["shipped.yaml"]
    assert sorted(load_testpacks(root)) == ["tp/a"]


def test_an_imported_test_pack_cannot_replace_a_shipped_test_pack(tmp_path: Path) -> None:
    root = tmp_path / "root"
    write(root / "testpacks" / "shipped.yaml", as_text(b.purposes_pack(b.purpose("T-1"))))
    imported = write(tmp_path / "outside" / "same-id.yaml", as_text(b.purposes_pack(b.purpose("T-2"))))
    with pytest.raises(CatalogueError, match="tp/a"):
        load_testpacks(root, extra_testpacks=[imported])


def test_empty_directories_load_as_empty_mappings(tmp_path: Path) -> None:
    assert load_profiles(tmp_path) == {}
    assert load_testpacks(tmp_path) == {}


def test_the_contracts_that_the_loaders_return_have_the_right_type(tmp_path: Path) -> None:
    write(tmp_path / "profiles" / "test" / "alpha.yaml", as_text(b.profile()))
    write(tmp_path / "testpacks" / "a.yaml", as_text(b.purposes_pack(b.purpose("T-1"))))
    assert isinstance(load_profiles(tmp_path)["test/alpha"], Profile)
    assert isinstance(load_testpacks(tmp_path)["tp/a"], TestPack)


# --- sanitized_ixit ------------------------------------------------------------------------

SECRETS = ("env:DPPCE_SECRET_AUDITOR", "file:owner.token")


def full_ixit() -> IXIT:
    return IXIT.model_validate(
        {
            "schema_version": "dppce.ixit/1",
            "endpoints": {"api": "http://127.0.0.1:8080/api", "resolver": "http://127.0.0.1:8080/r"},
            "samples": {"qr": "samples/qr.png"},
            "identities": [
                {"role": "anonymous"},
                {"role": "auditor", "secret_ref": SECRETS[0], "description": "Reads restricted fields."},
                {"role": "owner", "secret_ref": SECRETS[1]},
            ],
            "authorization_ref": "authorization.jws",
            "network": {
                "allowed_hosts": ["127.0.0.1"],
                "allow_private_hosts": ["127.0.0.1"],
                "timeout_ms": 900,
            },
            "trust": {"bundle": "trust.json", "policy_version": "test-1"},
            "observation": {"store_bodies": False, "retention_days": 7},
        }
    )


def test_the_sanitized_ixit_holds_no_secret_reference() -> None:
    clean = sanitized_ixit(full_ixit())
    text = json.dumps(clean)
    for secret in SECRETS:
        assert secret not in text
        assert secret.split(":", 1)[1] not in text
    assert [i["secret_ref"] for i in clean["identities"]].count(None) == 1, "the role with no secret"
    assert all(i["secret_ref"] not in SECRETS for i in clean["identities"])


def test_the_sanitized_ixit_changes_nothing_else() -> None:
    ixit = full_ixit()
    original = ixit.model_dump(mode="json")
    clean = sanitized_ixit(ixit)
    assert clean.keys() == original.keys()
    for key in original:
        if key != "identities":
            assert clean[key] == original[key], key
    without_secret = [{k: v for k, v in i.items() if k != "secret_ref"} for i in clean["identities"]]
    assert without_secret == [
        {k: v for k, v in i.items() if k != "secret_ref"} for i in original["identities"]
    ]
    assert clean["identities"][0] == original["identities"][0], "an identity with no secret is unchanged"
    assert [i.secret_ref for i in ixit.identities] == [None, *SECRETS], "the IXIT itself is not changed"
    plain = IXIT(schema_version="dppce.ixit/1")
    assert sanitized_ixit(plain) == plain.model_dump(mode="json")


# --- check_ics -----------------------------------------------------------------------------

FACTS = {
    "capacity_wh": {"type": "integer", "description": "Synthetic capacity."},
    "chemistry": {"type": "string", "description": "Synthetic chemistry."},
    "removable": {"type": "boolean", "description": "Synthetic flag."},
    "placed_on_market_date": {"type": "date", "description": "Synthetic date."},
}
GOOD = {
    "capacity_wh": 2500,
    "chemistry": "synthetic",
    "removable": True,
    "placed_on_market_date": "2027-03-01",
}


def problems(**changes: Any) -> list[str]:
    return check_ics(b.ics(**changes), b.profile(facts=FACTS))


def test_an_ics_that_fits_the_profile_has_no_problem() -> None:
    assert problems(product_category="widget", characteristics=GOOD) == []
    assert problems() == [], "an ICS may leave every fact undeclared"
    assert problems(product_category="unknown", characteristics=dict.fromkeys(GOOD, "unknown")) == []


def test_an_ics_for_a_different_profile_is_a_problem() -> None:
    found = problems(profile="test/other")
    assert len(found) == 1
    assert "test/other" in found[0]
    assert b.PROFILE_ID in found[0]


def test_an_ics_with_a_different_product_category_is_a_problem() -> None:
    found = problems(product_category="gadget")
    assert len(found) == 1
    assert "gadget" in found[0]


def test_a_characteristic_that_the_profile_does_not_declare_is_a_problem() -> None:
    found = problems(characteristics={**GOOD, "colour": "red"})
    assert len(found) == 1
    assert "colour" in found[0]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("capacity_wh", "2500"),
        ("capacity_wh", True),
        ("chemistry", 5),
        ("chemistry", False),
        ("removable", 1),
        ("removable", "yes"),
        ("placed_on_market_date", 20270301),
        ("placed_on_market_date", True),
    ],
)
def test_a_characteristic_of_the_wrong_type_is_a_problem(name: str, value: str | int | bool) -> None:
    found = problems(characteristics={**GOOD, name: value})
    assert len(found) == 1
    assert name in found[0]


FULL_WIDTH_YEAR = "".join(chr(0xFF10 + int(d)) for d in "2027")


@pytest.mark.parametrize(
    "date",
    ["2027-3-1", "20270301", "2027-W09-1", "2027-02-30", "2027-13-01", f"{FULL_WIDTH_YEAR}-03-01"],
)
def test_a_date_fact_must_be_a_calendar_date(date: str) -> None:
    assert problems(characteristics={**GOOD, "placed_on_market_date": "2027-03-01"}) == []
    assert problems(characteristics={**GOOD, "placed_on_market_date": "unknown"}) == []
    found = problems(characteristics={**GOOD, "placed_on_market_date": date})
    assert len(found) == 1
    assert "placed_on_market_date" in found[0]
    assert date not in found[0], "the supplier value is not echoed"
    other = problems(profile="test/other", characteristics={**GOOD, "placed_on_market_date": date})
    assert len(other) == 2


def test_every_problem_of_an_ics_is_reported() -> None:
    found = problems(
        profile="test/other",
        product_category="gadget",
        characteristics={"colour": "red", "capacity_wh": "big"},
    )
    assert len(found) == 4
    for needle in ("test/other", "gadget", "colour", "capacity_wh"):
        assert any(needle in problem for problem in found), needle


# --- Hashes --------------------------------------------------------------------------------


def two_pack_catalogue(
    *, title: str = "Synthetic requirement R-1", source_title: str = "Synthetic"
) -> Catalogue:
    pack_a = b.pack(b.requirement("R-1", title=title), b.requirement("R-2"))
    pack_b = b.pack(b.requirement("R-3"), pack_id="pack/b")
    return b.catalogue(pack_b, pack_a, sources=(b.source("SRC-A", title=source_title), b.source("SRC-B")))


def hashes(catalogue: Catalogue) -> tuple[str, str, dict[str, str]]:
    return catalogue.hash(), catalogue.sources_hash(), catalogue.pack_hashes()


def test_equal_content_gives_equal_hashes() -> None:
    first, second = two_pack_catalogue(), two_pack_catalogue()
    assert hashes(first) == hashes(second)
    reordered = Catalogue(
        legal_as_of=first.legal_as_of, sources=first.sources, packs=dict(reversed(list(first.packs.items())))
    )
    assert list(reordered.packs) != list(first.packs)
    assert hashes(reordered) == hashes(first), "the order in which the packs were loaded is not content"
    assert list(first.pack_hashes()) == ["pack/a", "pack/b"]
    assert len({first.hash(), first.sources_hash(), *first.pack_hashes().values()}) == 4


def test_a_change_in_one_requirement_changes_the_hash_of_its_pack_and_of_the_catalogue_only() -> None:
    before, after = two_pack_catalogue(), two_pack_catalogue(title="Synthetic requirement R-1, edited")
    assert after.pack_hashes()["pack/a"] != before.pack_hashes()["pack/a"]
    assert after.pack_hashes()["pack/b"] == before.pack_hashes()["pack/b"]
    assert after.sources_hash() == before.sources_hash()
    assert after.hash() != before.hash()


def test_a_change_in_one_source_changes_the_hash_of_the_sources_and_of_the_catalogue_only() -> None:
    before, after = two_pack_catalogue(), two_pack_catalogue(source_title="Synthetic, edited")
    assert after.sources_hash() != before.sources_hash()
    assert after.pack_hashes() == before.pack_hashes()
    assert after.hash() != before.hash()


def test_adding_or_removing_a_pack_or_a_source_changes_the_catalogue_hash() -> None:
    full = two_pack_catalogue()
    fewer_packs = Catalogue(
        legal_as_of=full.legal_as_of, sources=full.sources, packs={"pack/a": full.packs["pack/a"]}
    )
    fewer_sources = Catalogue(legal_as_of=full.legal_as_of, sources=full.sources[:1], packs=full.packs)
    assert len({full.hash(), fewer_packs.hash(), fewer_sources.hash()}) == 3
    assert fewer_packs.sources_hash() == full.sources_hash()
    assert fewer_sources.pack_hashes() == full.pack_hashes()


def test_the_layout_of_a_file_is_not_content(tmp_path: Path) -> None:
    pack = b.pack(b.requirement("R-1", applicability=b.feature("x")), b.requirement("R-2"))
    document = pack.model_dump(mode="json", by_alias=True)
    for name, text in (
        ("compact", json.dumps(document)),
        ("sorted", json.dumps(document, sort_keys=True, indent=4)),
        ("reversed", json.dumps(dict(reversed(list(document.items()))), indent=1)),
    ):
        write_sources(tmp_path / name, b.source())
        write(tmp_path / name / "catalogue" / "packs" / f"{name}.yaml", text)
    compact, by_key, backwards = (
        load_catalogue(tmp_path / name) for name in ("compact", "sorted", "reversed")
    )
    assert hashes(compact) == hashes(by_key) == hashes(backwards)
    assert compact.packs["pack/a"] == pack
