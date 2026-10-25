"""The GS1 Digital Link form gs1-dl and the check identifier.granularity.

The grammar data comes from the vendored GS1 Barcode Syntax Dictionary. The vendored dl.c
cases in tests/test_external_vectors.py are the oracle for the whole grammar. The cases here
are engine inputs that name the rule of each failure.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from validation import cases

from dppce import cli
from dppce.adapters import gs1
from dppce.adapters.identifier import granularity, parse
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import ICS, IXIT, CheckOutcome, EvidenceEnvelope, ExecutionStatus
from dppce.testdefs.registry import CheckContext
from tests.test_adapters_security import _POLICY, _Canned, _context

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "reference"
EXAMPLES = ROOT / "profiles" / "family" / "examples"
GTIN = "09520123456788"
ORIGIN = "https://id.example"


# -- The dictionary ------------------------------------------------------------------------------


def test_the_primary_keys_and_qualifiers_come_from_the_vendored_dictionary() -> None:
    dictionary = gs1.dictionary()
    keys = {sequence[0] for sequence in dictionary.sequences}
    assert keys == {
        "00", "01", "253", "255", "401", "402", "414", "415", "417",
        "8003", "8004", "8006", "8010", "8013", "8017", "8018",
    }  # fmt: skip
    assert ("01", "22", "10", "21") in dictionary.sequences
    assert ("01", "235") in dictionary.sequences
    assert ("01", "22", "235") not in dictionary.sequences, "the two alternatives do not mix"
    assert ("01", "21", "10") not in dictionary.sequences
    # The range 3100-3105 expands to one entry per AI.
    assert {"3100", "3105"} <= set(dictionary.entries)
    assert "3106" not in dictionary.entries


def test_every_linter_of_a_primary_key_or_a_key_qualifier_is_implemented() -> None:
    dictionary = gs1.dictionary()
    path_ais = {ai for sequence in dictionary.sequences for ai in sequence}
    used = {
        linter
        for ai in path_ais
        for component in dictionary.entries[ai].components
        for linter in component.linters
    }
    assert used == {
        "csum",
        "csumalpha",
        "gcppos1",
        "gcppos2",
        "importeridx",
        "nozeroprefix",
        "pieceoftotal",
        "zero",
    }
    assert used <= set(gs1.LINTERS)


# -- The grammar ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "key", "qualifiers", "attributes"),
    [
        (f"{ORIGIN}/01/{GTIN}", "01", (), ()),
        (f"{ORIGIN}/01/{GTIN}/10/LOT-1", "01", ("10",), ()),
        (f"{ORIGIN}/01/{GTIN}/22/2A/10/ABC/21/X%2F1", "01", ("22", "10", "21"), ()),
        (f"{ORIGIN}/brand/prefix/01/{GTIN}/21/12345?17=201225&3103=000195", "01", ("21",), ("17", "3103")),
        (f"{ORIGIN}/01/{GTIN}?linkType=gs1:pip&99=A", "01", (), ("99",)),
        (f"{ORIGIN}/00/952012345678912345", "00", (), ()),
        (f"{ORIGIN}/414/9520123456788/254/32a%2Fb", "414", ("254",), ()),
        (f"{ORIGIN}/8013/1987654Ad4X4bL5ttr2310c2K", "8013", (), ()),
        (f"{ORIGIN}/01/{GTIN}#fragment", "01", (), ()),
    ],
)
def test_the_grammar_accepts_the_uncompressed_forms(
    uri: str, key: str, qualifiers: tuple[str, ...], attributes: tuple[str, ...]
) -> None:
    result = gs1.parse(uri)
    assert isinstance(result, gs1.DigitalLink), result
    assert (result.key, result.qualifiers, result.attributes) == (key, qualifiers, attributes)


@pytest.mark.parametrize(
    ("uri", "rule"),
    [
        ("ftp://a/01/09520123456788", "URI"),
        ("https://a$b/01/09520123456788", "URI"),
        ("https://a/01/09520123456788<", "URI"),
        ("https://a/products/09520123456788", "KEY"),
        ("https://a/01/09520123456788/", "KEY"),
        (f"{ORIGIN}/01/{GTIN}/21/S1/10/L1", "QUALIFIER_ORDER"),
        (f"{ORIGIN}/01/{GTIN}/99/ABC", "QUALIFIER_ORDER"),
        (f"{ORIGIN}/01/09520123456787", "CHECK_DIGIT"),
        (f"{ORIGIN}/8013/1987654Ad4X4bL5ttr2310c2X", "CHECK_DIGIT"),
        (f"{ORIGIN}/01/9520123456788", "AI_VALUE"),
        (f"{ORIGIN}/01/{GTIN}/10/{'L' * 21}", "AI_VALUE"),
        (f"{ORIGIN}/01/{GTIN}/10/", "AI_VALUE"),
        (f"{ORIGIN}/01/{GTIN}/10/A%20B", "AI_VALUE"),
        (f"{ORIGIN}/01/{GTIN}?99=A+B", "AI_VALUE"),
        (f"{ORIGIN}/01/{GTIN}/10/A%00B", "PERCENT"),
        (f"{ORIGIN}/01/{GTIN}?89=X", "ATTRIBUTE"),
        (f"{ORIGIN}/01/{GTIN}?10=ABC", "ATTRIBUTE"),
        (f"{ORIGIN}/01/{GTIN}?21=ABC", "ATTRIBUTE"),
        (f"{ORIGIN}/01/{GTIN}/10/A?10=A", "ATTRIBUTE"),
    ],
)
def test_the_grammar_names_the_rule_of_each_failure(uri: str, rule: str) -> None:
    result = gs1.parse(uri)
    assert isinstance(result, gs1.Problem), result
    assert result.rule == rule, result.reason
    assert result.rule in gs1.RULES


@pytest.mark.parametrize(
    "uri", ["https://id.gs1.org/AQnYUc1gmiAA", "https://brand.example/dl/ARHKVAdpQgtlYmVsLWV0aWtldA"]
)
def test_a_compressed_uri_is_recognized_and_not_judged(uri: str) -> None:
    result = gs1.parse(uri)
    assert isinstance(result, gs1.Problem)
    assert result.rule == "COMPRESSED"
    assert result.rule not in gs1.RULES, "COMPRESSED is an engine limit, not a syntax rule"


def test_an_unchecked_attribute_linter_is_named_and_a_key_linter_never_is() -> None:
    result = gs1.parse(f"{ORIGIN}/01/{GTIN}/10/ABC?17=201225")
    assert isinstance(result, gs1.DigitalLink)
    assert result.unchecked == ("yymmd0",)
    assert gs1.parse(f"{ORIGIN}/01/{GTIN}/10/ABC").unchecked == ()  # type: ignore[union-attr]  # a DigitalLink


# -- identifier.parse with form gs1-dl -----------------------------------------------------------


def _ctx(
    tmp_path: Path,
    identifier: str,
    params: dict[str, Any] | None = None,
    check: str = "identifier.parse",
    **ics: Any,
) -> CheckContext:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    stimulus = base.purpose.stimulus.model_copy(update={"check": check, "params": params or {}})
    changes = {"identifier_scheme": "gs1-digital-link", **ics}
    return replace(
        base,
        purpose=base.purpose.model_copy(update={"stimulus": stimulus}),
        ics=ICS.model_validate(base.ics.model_dump(mode="json") | changes),
        ixit=IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": {"identifier": identifier}}),
    )


def _status(outcome: CheckOutcome) -> tuple[ExecutionStatus, bool | None, str]:
    return outcome.status, outcome.passed, outcome.reason_code


def test_the_default_form_is_unchanged_for_a_gtin_only_uri(tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, f"{ORIGIN}/01/{GTIN}"))
    assert _status(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.SYNTAX.INVALID")
    assert set(outcome.observations[0].summary) == {"scheme", "valid", "reason"}, "no new summary key"


@pytest.mark.parametrize(
    "uri", [f"{ORIGIN}/01/{GTIN}", f"{ORIGIN}/01/{GTIN}/10/LOT1", f"{ORIGIN}/p/01/{GTIN}/21/S?17=201225"]
)
def test_form_gs1_dl_accepts_model_batch_and_prefixed_uris(uri: str, tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, uri, {"form": "gs1-dl"}))
    assert _status(outcome) == (ExecutionStatus.COMPLETED, True, "IDENTIFIER.SYNTAX.OK")
    summary = outcome.observations[0].summary
    assert (summary["form"], summary["valid"], summary["key"]) == ("gs1-dl", True, "01")


def test_form_gs1_dl_names_the_failed_rule(tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, f"{ORIGIN}/01/{GTIN}/21/S1/10/L1", {"form": "gs1-dl"}))
    assert _status(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.SYNTAX.INVALID")
    assert outcome.observations[0].summary["rule"] == "QUALIFIER_ORDER"


def test_form_gs1_dl_keeps_require_https(tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, f"http://id.example/01/{GTIN}", {"form": "gs1-dl", "require_https": True}))
    assert _status(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.SCHEME.NOT_HTTPS")


def test_form_gs1_dl_gives_unsupported_for_a_compressed_uri(tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, "https://id.gs1.org/AQnYUc1gmiAA", {"form": "gs1-dl"}))
    assert _status(outcome) == (ExecutionStatus.UNSUPPORTED, None, "IDENTIFIER.SYNTAX.COMPRESSED")


@pytest.mark.parametrize("form", ["gs1", 7, None])
def test_an_unknown_form_is_a_parameter_error(form: object, tmp_path: Path) -> None:
    outcome = parse(_ctx(tmp_path, f"{ORIGIN}/01/{GTIN}", {"form": form}))
    assert _status(outcome) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.PARAMS.INVALID")


# -- identifier.granularity ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "declared", "passed", "code"),
    [
        (f"{ORIGIN}/01/{GTIN}", "model", True, "IDENTIFIER.GRANULARITY.OK"),
        (f"{ORIGIN}/01/{GTIN}/22/V1", "model", True, "IDENTIFIER.GRANULARITY.OK"),
        (f"{ORIGIN}/01/{GTIN}/10/LOT1", "batch", True, "IDENTIFIER.GRANULARITY.OK"),
        (f"{ORIGIN}/01/{GTIN}/10/LOT1/21/S1", "item", True, "IDENTIFIER.GRANULARITY.OK"),
        (f"{ORIGIN}/01/{GTIN}/235/TPX1", "item", True, "IDENTIFIER.GRANULARITY.OK"),
        (f"{ORIGIN}/01/{GTIN}", "item", False, "IDENTIFIER.GRANULARITY.MISMATCH"),
        (f"{ORIGIN}/01/{GTIN}/21/S1", "batch", False, "IDENTIFIER.GRANULARITY.MISMATCH"),
    ],
)
def test_granularity_compares_the_key_set_with_the_ics(
    uri: str, declared: str, passed: bool, code: str, tmp_path: Path
) -> None:
    outcome = granularity(_ctx(tmp_path, uri, check="identifier.granularity", granularity=declared))
    assert _status(outcome) == (ExecutionStatus.COMPLETED, passed, code)
    assert outcome.observations[0].summary["declared"] == declared


_ITEM = {"granularity": "item"}
_BLOCKED, _UNSUPPORTED = ExecutionStatus.BLOCKED, ExecutionStatus.UNSUPPORTED


@pytest.mark.parametrize(
    ("uri", "ics", "status", "code"),
    [
        (f"{ORIGIN}/01/{GTIN}", {"granularity": "unknown"}, _BLOCKED, "IDENTIFIER.GRANULARITY.NOT_DECLARED"),
        (f"{ORIGIN}/00/952012345678912345", _ITEM, _UNSUPPORTED, "IDENTIFIER.GRANULARITY.KEY_UNSUPPORTED"),
        ("https://id.gs1.org/AQnYUc1gmiAA", _ITEM, _UNSUPPORTED, "IDENTIFIER.SYNTAX.COMPRESSED"),
        (f"{ORIGIN}/01/09520123456787", _ITEM, _BLOCKED, "IDENTIFIER.GRANULARITY.NOT_PARSED"),
        (
            f"{ORIGIN}/01/{GTIN}",
            {**_ITEM, "identifier_scheme": "unknown"},
            _BLOCKED,
            "IDENTIFIER.SCHEME.UNKNOWN",
        ),
        (
            f"{ORIGIN}/01/{GTIN}",
            {**_ITEM, "identifier_scheme": "urn-uuid"},
            _UNSUPPORTED,
            "IDENTIFIER.SCHEME.UNSUPPORTED",
        ),
    ],
)
def test_granularity_never_passes_without_a_classification(
    uri: str, ics: dict[str, str], status: ExecutionStatus, code: str, tmp_path: Path
) -> None:
    outcome = granularity(_ctx(tmp_path, uri, check="identifier.granularity", **ics))
    assert _status(outcome) == (status, None, code)


# -- The seeded faults under the family profile --------------------------------------------------


def _cli(arguments: list[str]) -> tuple[int, Any]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main([*arguments, "--json"])
    text = captured.getvalue().strip()
    return code, json.loads(text) if text else None


def _family_run(
    tmp_path: Path, qr: str | None = None, ics_changes: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run family/gs1-resolver against the reference system. Returns {test purpose: (verdict, code)}."""
    with ReferenceServer(FIXTURES) as server:
        ics = yaml.safe_load((EXAMPLES / "gs1-resolver.ics.yaml").read_text(encoding="utf-8"))
        ixit = yaml.safe_load((EXAMPLES / "gs1-resolver.ixit.yaml").read_text(encoding="utf-8"))
        ixit["endpoints"]["origin_override"] = server.origin
        if qr is not None:
            shutil.copyfile(ROOT / qr, tmp_path / "qr.png")
            ixit["samples"]["qr_image"] = "qr.png"
        ics |= ics_changes or {}
        (tmp_path / "ics.yaml").write_text(yaml.safe_dump(ics), encoding="utf-8")
        (tmp_path / "ixit.yaml").write_text(yaml.safe_dump(ixit), encoding="utf-8")
        out = tmp_path / "run"
        _cli(
            [
                "run",
                "--profile", "family/gs1-resolver",
                "--ics", str(tmp_path / "ics.yaml"),
                "--ixit", str(tmp_path / "ixit.yaml"),
                "--trust", str(FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"),
                "--at", "2026-10-13T12:00:00Z",
                "--out", str(out),
                "--keys", str(tmp_path / "keys"),
                "--create-data-key",
                "--allow-private-host", server.origin,
                "--issuer-name", "dppce test rig (synthetic)",
                "--issuer-id", "urn:example:test-lab",
            ]
        )  # fmt: skip
    envelope = EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())
    return {t.test_purpose_id: (t.verdict.value, t.reason_code) for t in envelope.decision.test_results}


def test_the_new_family_steps_pass_on_the_unmodified_reference_system(tmp_path: Path) -> None:
    steps = _family_run(tmp_path)
    assert steps["TP-GS1-SYNTAX-002"] == ("pass", "IDENTIFIER.SYNTAX.OK")
    assert steps["TP-GS1-GRANULARITY-001"] == ("pass", "IDENTIFIER.GRANULARITY.OK")


# How each family case of the catalogue is seeded here. validation/cases.py gives the rig the same.
_FAMILY_SEEDS: dict[str, dict[str, Any]] = {
    "F-40": {"qr": "fixtures/reference/qr/TEST-ONLY-qualifier-order.png"},
    "F-41": {"qr": "fixtures/reference/qr/TEST-ONLY-model-level.png"},
    "B-12": {"ics_changes": {"granularity": "unknown"}},
}


@pytest.mark.qr
@pytest.mark.parametrize("ident", sorted(_FAMILY_SEEDS))
def test_each_family_case_gives_its_catalogue_outcome(ident: str, tmp_path: Path) -> None:
    case = {c.id: c for c in [*cases.sut_faults(), *cases.boundary_cases()]}[ident]
    entry = {e["id"]: e for e in [*cases.load()["sut_faults"], *cases.load()["boundary_cases"]]}[ident]
    assert entry["profiles"] == ["family/gs1-resolver"]
    assert case.test_purpose is not None
    steps = _family_run(tmp_path, **_FAMILY_SEEDS[ident])
    assert steps[case.test_purpose] == (case.expected["verdict"], case.expected["reason_code"])
