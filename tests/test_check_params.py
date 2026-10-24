"""Check parameters fit a closed model (gap D3-07), and an ICS date fact is a calendar date (D1-10).

A typo in a parameter must not change silently what a test purpose checks. The lint reports it,
and plan, run, and replay refuse the test pack. Every file is written to a temporary directory.
The requirement is a TEST-ONLY fixture with a synthetic approval record. No review took place.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import dppce.adapters  # noqa: F401 - the import registers every check
from dppce import cli
from dppce.catalogue import load_data, load_testpacks
from dppce.catalogue.lint import lint, params_problem
from dppce.infrastructure.resources import data_root
from dppce.models import Model
from dppce.testdefs import registry
from dppce.testdefs.registry import NoParams
from tests.core import builders as b

FIXTURES = Path("fixtures/reference")
RID, TID = "TEST-ONLY-R-101", "TEST-ONLY-TP-101"
PACK, TESTPACK = "test-only/params", "test-only/params-tests"
CITED = {**b.CITED, "source_id": "dppce-illustrative"}
IXIT = {
    "schema_version": "dppce.ixit/1",
    "endpoints": {"api": "https://id.example.test"},
    "samples": {"identifier": "https://id.example.test/01/09506000134352/21/EV0001"},
}
# The initial registry of the architecture contract, section 8.
CONTRACT_CHECKS = (
    "aas.validate",
    "access.restricted_fields",
    "api.contract",
    "carrier.qr_decode",
    "data.context",
    "data.jsonschema",
    "data.rules",
    "identifier.consistency",
    "identifier.parse",
    "identifier.resolve",
    "integrity.jws",
    "manual.review",
    "persistence.versions",
    "registry.consistency",
)
NO_PARAMETERS = (
    "integrity.jws",
    "manual.review",
    "persistence.versions",
    "registry.consistency",
)
ALLOWLIST: dict[str, Any] = {"allowed_contexts": ["https://example.test/c"]}

# Each check with a misspelled key, and the key that the problem must name.
MISSPELLED: dict[str, tuple[dict[str, Any], str]] = {
    "carrier.qr_decode": ({"artefact": "qr_image"}, "artefact"),
    "identifier.parse": ({"schema": "gs1-digital-link"}, "schema"),
    "identifier.resolve": ({"acept": "text/html"}, "acept"),
    "identifier.consistency": ({"compre_item": True}, "compre_item"),
    "api.contract": ({"resorce": "item"}, "resorce"),
    "data.jsonschema": ({"documnet": "item"}, "documnet"),
    "data.context": ({"document": "item", "allowed_context": ["https://example.test/c"]}, "allowed_context"),
    "data.rules": ({"documnet": "item"}, "documnet"),
    "access.restricted_fields": ({"rol": "anonymous"}, "rol"),
    "aas.validate": ({"artefact": "aas_file"}, "artefact"),
    **{name: ({"documnet": "item"}, "documnet") for name in NO_PARAMETERS},
}
UNKNOWN_VALUES: list[tuple[str, dict[str, Any]]] = [
    *((name, {"document": "nothing"}) for name in CONTRACT_CHECKS if name != "data.context"),
    ("data.context", {"document": "nothing", **ALLOWLIST}),
    ("api.contract", {"resource": "nothing"}),
    ("api.contract", {"method": "post"}),
    ("identifier.resolve", {"accepted_media_types": ["Text/HTML"]}),
    ("aas.validate", {"format": "yaml"}),
]
WRONG_TYPES: list[tuple[str, dict[str, Any]]] = [
    ("carrier.qr_decode", {"artifact": 7}),
    ("aas.validate", {"artifact": 7}),
    ("aas.validate", {"format": 7}),
    ("aas.validate", {"metamodel_version": "3"}),
    ("aas.validate", {"metamodel_version": 3.0}),
    ("identifier.parse", {"scheme": 7}),
    ("identifier.parse", {"require_https": "yes"}),
    ("identifier.parse", {"require_https": 1}),
    ("identifier.parse", {"scheme": None}),
    ("identifier.resolve", {"accept": 7}),
    ("identifier.resolve", {"accept": "text/html\n"}),
    ("identifier.resolve", {"require_https": "yes"}),
    ("identifier.resolve", {"require_https": 1}),
    ("identifier.consistency", {"compare_item": "yes"}),
    ("identifier.consistency", {"compare_item": 1}),
    ("api.contract", {"resource": 7}),
    ("data.jsonschema", {"document": 7}),
    ("data.rules", {"document": 7}),
    ("data.context", {"document": 7, **ALLOWLIST}),
    ("data.context", {"document": "item", "allowed_contexts": "https://example.test/c"}),
    ("access.restricted_fields", {"role": True}),
    *((name, {"document": 7}) for name in NO_PARAMETERS),
]


def _models() -> dict[str, type[Model]]:
    return registry.param_models()


def _problem(check: str, params: dict[str, Any]) -> str | None:
    return params_problem(_models()[check], params)


def test_the_adapter_checks_are_those_of_the_contract() -> None:
    adapters = {
        name: spec.params
        for name in registry.names()
        if (spec := registry.get(name)) is not None and spec.fn.__module__.startswith("dppce.adapters")
    }
    assert tuple(sorted(adapters)) == CONTRACT_CHECKS
    for name, model in adapters.items():
        assert model.model_config.get("extra") == "forbid", name
    # Section 8 lists manual.review in the registry, and CAT019 applies to a manual step too.
    assert registry.param_models()["manual.review"] is NoParams


def test_a_manual_step_with_a_parameter_is_refused_by_the_lint() -> None:
    manual = b.purpose("T-MANUAL", manual=True, stimulus={"check": "manual.review", "params": {"role": "x"}})
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-MANUAL")])
    findings = lint(
        b.catalogue(b.pack(requirement)),
        {b.PROFILE_ID: b.profile()},
        {"tp/a": b.purposes_pack(manual)},
        registry.param_models(),
    )
    assert [(f.code, f.location) for f in findings if f.code == "CAT019"] == [("CAT019", "T-MANUAL")]


@pytest.mark.parametrize("check", sorted(MISSPELLED))
def test_a_misspelled_key_is_refused(check: str) -> None:
    params, key = MISSPELLED[check]
    problem = _problem(check, params)
    assert problem is not None
    assert key in problem


def test_a_key_with_a_line_break_gives_one_line() -> None:
    problem = params_problem(NoParams, {"a\nb": 1, "c\rd": 2})
    assert problem is not None
    assert "\n" not in problem
    assert "\r" not in problem
    assert "a\\nb" in problem
    assert "c\\rd" in problem


@pytest.mark.parametrize(("check", "params"), UNKNOWN_VALUES, ids=[f"{c}-{p}" for c, p in UNKNOWN_VALUES])
def test_an_unknown_enumerated_value_is_refused(check: str, params: dict[str, Any]) -> None:
    assert _problem(check, params) is not None


@pytest.mark.parametrize(("check", "params"), WRONG_TYPES, ids=[f"{c}-{p}" for c, p in WRONG_TYPES])
def test_a_wrong_type_is_refused(check: str, params: dict[str, Any]) -> None:
    problem = _problem(check, params)
    assert problem is not None
    assert any(key in problem for key in params), problem


def test_the_shipped_parameters_and_the_empty_parameters_fit() -> None:
    models = _models()
    checked = 0
    for testpack in load_testpacks(data_root()).values():
        for purpose in testpack.test_purposes:
            model = models.get(purpose.stimulus.check)
            if model is not None:
                assert params_problem(model, purpose.stimulus.params) is None, purpose.id
                checked += 1
    assert checked, "the shipped test packs name registered checks"
    for name in CONTRACT_CHECKS:
        empty = params_problem(models[name], {})
        assert (empty is None) is (name != "data.context"), name
    assert _problem("data.context", {"document": "item", **ALLOWLIST}) is None
    assert (
        _problem("identifier.resolve", {"accept": "text/html", "accepted_media_types": ["text/html"]}) is None
    )


# --- The command line ----------------------------------------------------------------------


def _fixture_pair(tmp_path: Path, stimulus: dict[str, Any]) -> tuple[Path, Path]:
    requirement = b.requirement(
        RID,
        source=CITED,
        authority_class="guidance",
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
        assessment_paths=[b.path("default", TID)],
    )
    purpose = b.purpose(
        TID, requirements=[RID], permitted_modes=["reviewed"], stimulus=stimulus, requires_scope="none"
    )
    pack, testpack = tmp_path / "imports" / "pack.yaml", tmp_path / "imports" / "testpack.yaml"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text(b.pack(requirement, pack_id=PACK).model_dump_json(by_alias=True), encoding="utf-8")
    testpack.write_text(
        b.purposes_pack(purpose, testpack_id=TESTPACK).model_dump_json(by_alias=True), encoding="utf-8"
    )
    return pack, testpack


def _imports(pack: Path, testpack: Path) -> list[str]:
    return ["--import-pack", str(pack), "--import-testpack", str(testpack)]


def _plan_arguments(tmp_path: Path, pack: Path, testpack: Path, ics: Path | None = None) -> list[str]:
    ixit = tmp_path / "ixit.json"
    ixit.write_text(json.dumps(IXIT), encoding="utf-8")
    return [
        "--mode", "reviewed", "--profile", "battery/ev",
        "--ics", str(ics or FIXTURES / "ev.ics.yaml"), "--ixit", str(ixit), "--at", "2026-10-13T12:00:00Z",
        *_imports(pack, testpack), "--pack", PACK, "--testpack", TESTPACK,
    ]  # fmt: skip


def _snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        str(p.relative_to(root)): p.read_bytes() if p.is_file() else None
        for name in ("catalogue", "profiles", "testpacks")
        for p in sorted((root / name).rglob("*"))
    }


BAD = {"check": "data.jsonschema", "params": {"document": "nothing"}}


def test_lint_reports_CAT019_for_an_imported_test_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(data_root())
    code = cli.main(["catalogue", "lint", "--json", *_imports(*_fixture_pair(tmp_path, BAD))])
    findings = json.loads(capsys.readouterr().out)
    errors = [(f["code"], f["location"]) for f in findings if f["severity"] == "error"]
    assert errors == [("CAT019", TID)]
    (message,) = [f["message"] for f in findings if f["code"] == "CAT019"]
    assert "data.jsonschema" in message
    assert "'document'" in message
    assert code == 2
    assert _snapshot(data_root()) == before, "the shipped files stay unchanged"


def test_plan_and_run_refuse_a_test_pack_with_invalid_parameters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = _plan_arguments(tmp_path, *_fixture_pair(tmp_path, BAD))
    run, keys = tmp_path / "run", tmp_path / "keys"
    for command in (["plan"], ["run", "--out", str(run), "--keys", str(keys), "--create-data-key"]):
        assert cli.main([*command, *arguments]) == 2
        err = capsys.readouterr().err
        assert err.count("\n") == 1, err
        for needle in (TID, "data.jsonschema", "'document'"):
            assert needle in err, needle
    assert not run.exists(), "a refused run writes no output"


def test_an_unregistered_check_keeps_CAT006(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pack, testpack = _fixture_pair(tmp_path, {"check": "carrier.nfc_read", "params": {"x": 1}})
    assert cli.main(["catalogue", "lint", "--json", *_imports(pack, testpack)]) == 0
    findings = json.loads(capsys.readouterr().out)
    mine = [(f["code"], f["severity"]) for f in findings if f["location"] == TID]
    assert mine == [("CAT006", "warning")]
    assert cli.main(["plan", "--json", *_plan_arguments(tmp_path, pack, testpack)]) == 0
    plan = json.loads(capsys.readouterr().out)
    step = next(s for s in plan["steps"] if s["test_purpose_id"] == TID)
    assert step["planned_status"] == "unsupported"


# --- D1-10: an ICS date fact is a calendar date --------------------------------------------


@pytest.mark.parametrize("date", ["2027-3-1", "2027-02-30"])
def test_plan_names_a_malformed_date_fact_and_the_other_problems(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], date: str
) -> None:
    document = load_data(FIXTURES / "ev.ics.yaml")
    document["characteristics"]["placed_on_market_date"] = date
    document["product_category"] = "lmt"
    ics = tmp_path / "ics.json"
    ics.write_text(json.dumps(document), encoding="utf-8")
    pack, testpack = _fixture_pair(tmp_path, {"check": "identifier.parse"})
    assert cli.main(["plan", *_plan_arguments(tmp_path, pack, testpack, ics)]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1, err
    for needle in ("does not fit the profile", "placed_on_market_date", "lmt"):
        assert needle in err, needle
