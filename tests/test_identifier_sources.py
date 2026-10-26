"""Cross-family identity sources of identifier.consistency, and the check identifier.equivalence.

AAS, VC, and linked-data passports keep the subject identifier outside ``id``. ``sources`` names
where it is. ``identifier.equivalence`` compares GS1 Digital Link URIs in canonical form. Its
oracle for the GTIN padding is the vendored dl.c of gs1-syntax-engine. No test uses the network.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters import gs1
from dppce.adapters.identifier import consistency
from dppce.catalogue.lint import params_problem
from dppce.infrastructure.interfaces import Record
from dppce.models import IXIT, CheckOutcome, ExecutionStatus
from dppce.testdefs import registry
from dppce.testdefs.registry import CheckContext
from tests.support import make_artifact
from tests.test_adapters_security import _POLICY, _Canned, _context
from tests.test_external_vectors import _CALL, GS1_DL, _c_string, _strip_comments

CARRIER = "https://id.example.test/01/09506000134352/21/EV0001"
OTHER = "https://id.example.test/01/09506000134352/21/EV0002"
SUBJECT = {"label": "vc_json", "kind": "sample", "pointer": "/credentialSubject/id"}


class _Samples(_Canned):
    """The canned acquirer of the security tests, with JSON artifacts by sample name."""

    def __init__(self, samples: dict[str, Any], body: bytes = b"{}", **kwargs: Any) -> None:
        super().__init__(body, **kwargs)
        self._samples = samples

    def artifact(self, name: str) -> Record:
        if name not in self._samples:
            return make_artifact(name, error="artifact_unavailable")
        value = self._samples[name]
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        return make_artifact(name, body)


def _ctx(
    tmp_path: Path,
    check: str,
    params: dict[str, Any],
    samples: dict[str, Any] | None = None,
    *,
    carrier: str = CARRIER,
    body: bytes = b"{}",
    **kwargs: Any,
) -> tuple[CheckContext, _Samples]:
    acquirer = _Samples(samples or {}, body, **kwargs)
    base = _context(tmp_path, _POLICY, acquirer)
    files = {name: f"{name}.json" for name in samples or {}}
    ixit = IXIT.model_validate(
        base.ixit.model_dump(mode="json") | {"samples": {"identifier": carrier, "passport_id": "x", **files}}
    )
    stimulus = {"check": check, "params": params}
    purpose = base.purpose.model_copy(update={"stimulus": base.purpose.stimulus.model_copy(update=stimulus)})
    return replace(base, purpose=purpose, ixit=ixit), acquirer


def _state(outcome: CheckOutcome) -> tuple[ExecutionStatus, bool | None, str]:
    return outcome.status, outcome.passed, outcome.reason_code


FAIL = (ExecutionStatus.COMPLETED, False, "IDENTIFIER.CROSS.MISMATCH")
MISSING = (ExecutionStatus.BLOCKED, None, "IDENTIFIER.CROSS.SOURCE_MISSING")
CONSISTENT = (ExecutionStatus.COMPLETED, True, "IDENTIFIER.CONSISTENT")


# -- identifier.consistency with sources --------------------------------------------------------


def test_a_matching_sample_source_passes_without_a_request(tmp_path: Path) -> None:
    # A did or urn carrier has no resolver: a sample-only comparison sends no request.
    ctx, acquirer = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": [SUBJECT]},
        {"vc_json": {"credentialSubject": {"id": "urn:uuid:TEST-ONLY-1"}}},
        carrier="urn:uuid:TEST-ONLY-1",
    )
    outcome = consistency(ctx)
    assert _state(outcome) == CONSISTENT
    assert acquirer.records() == ()
    assert outcome.observations[0].summary == {
        "compared": ["carrier", "vc_json"],
        "different": [],
        "missing": [],
    }


def test_a_different_sample_source_fails(tmp_path: Path) -> None:
    ctx, _ = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": [SUBJECT]},
        {"vc_json": {"credentialSubject": {"id": OTHER}}},
    )
    outcome = consistency(ctx)
    assert _state(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.CROSS.MISMATCH")
    summary = outcome.observations[0].summary
    assert summary["different"] == ["vc_json"]
    assert OTHER not in json.dumps(summary), "no payload value in a summary"


@pytest.mark.parametrize(
    "document",
    [{"credentialSubject": {}}, {"credentialSubject": [CARRIER]}, {}],
    ids=["no-member", "array-at-the-parent", "no-parent"],
)
def test_a_pointer_that_does_not_resolve_is_blocked(tmp_path: Path, document: dict[str, Any]) -> None:
    ctx, _ = _ctx(tmp_path, "identifier.consistency", {"sources": [SUBJECT]}, {"vc_json": document})
    outcome = consistency(ctx)
    assert _state(outcome) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.CROSS.SOURCE_MISSING")
    assert outcome.observations[0].summary["missing"] == ["vc_json"]


@pytest.mark.parametrize("sample", [None, b"not json", b"[1]"], ids=["absent", "not-json", "not-an-object"])
def test_a_sample_without_a_json_object_is_blocked(tmp_path: Path, sample: bytes | None) -> None:
    samples = {} if sample is None else {"vc_json": sample}
    ctx, _ = _ctx(tmp_path, "identifier.consistency", {"sources": [SUBJECT]}, samples)
    assert _state(consistency(ctx)) == MISSING


@pytest.mark.parametrize("value", [7, None, True, {"id": CARRIER}, [CARRIER]])
def test_a_present_value_that_is_not_a_string_is_a_mismatch(tmp_path: Path, value: object) -> None:
    # A system that wraps the identifier must not turn the mismatch into blocked.
    ctx, _ = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": [SUBJECT]},
        {"vc_json": {"credentialSubject": {"id": value}}},
    )
    assert _state(consistency(ctx)) == FAIL


def test_a_difference_wins_over_a_missing_source(tmp_path: Path) -> None:
    # The order of the rules: any present value that differs gives fail, before a missing source.
    sources = [
        {"label": "aas_json", "kind": "sample", "pointer": "/assetAdministrationShells/0/id"},
        SUBJECT,
    ]
    samples = {"aas_json": {}, "vc_json": {"credentialSubject": {"id": OTHER}}}
    ctx, _ = _ctx(tmp_path, "identifier.consistency", {"sources": sources}, samples)
    outcome = consistency(ctx)
    assert _state(outcome) == FAIL
    assert outcome.observations[0].summary["missing"] == ["aas_json"]


def test_a_difference_wins_over_a_linkset_answer(tmp_path: Path) -> None:
    linkset = json.dumps({"linkset": [{"anchor": CARRIER}]}).encode()
    sources = [{"label": "passport", "kind": "resolved", "pointer": "/id"}, SUBJECT]
    ctx, _ = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": sources},
        {"vc_json": {"credentialSubject": {"id": OTHER}}},
        body=linkset,
    )
    assert _state(consistency(ctx)) == FAIL


EV_QR = Path(__file__).resolve().parent.parent / "fixtures" / "reference" / "qr" / "ev.png"


@pytest.mark.parametrize(
    ("extra", "vc", "body"),
    [
        ([], {"credentialSubject": {"id": CARRIER}}, b"{}"),
        (
            [{"label": "aas_json", "kind": "sample", "pointer": "/id"}],
            {"credentialSubject": {"id": CARRIER}},
            b"{}",
        ),
        (
            [{"label": "passport", "kind": "resolved", "pointer": "/id"}],
            {"credentialSubject": {"id": CARRIER}},
            json.dumps({"linkset": [{"anchor": CARRIER}]}).encode(),
        ),
    ],
    ids=["sources-match", "with-a-missing-source", "with-a-linkset"],
)
def test_a_different_declared_identifier_keeps_the_mismatch_of_today(
    tmp_path: Path, extra: list[dict[str, str]], vc: dict[str, Any], body: bytes
) -> None:
    # The QR image holds CARRIER. The IXIT declares OTHER, so the carrier side itself disagrees.
    pytest.importorskip("zxingcpp", reason="needs the optional 'qr' extra (zxing-cpp)")
    pytest.importorskip("PIL", reason="needs the optional 'qr' extra (Pillow)")
    samples: dict[str, Any] = {"qr_image": EV_QR.read_bytes(), "vc_json": vc, "aas_json": {}}
    ctx, _ = _ctx(
        tmp_path, "identifier.consistency", {"sources": [*extra, SUBJECT]}, samples, carrier=OTHER, body=body
    )
    outcome = consistency(ctx)
    assert _state(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.MISMATCH")
    assert outcome.observations[0].summary["different"][0] == "declared"


def test_a_linkset_without_a_difference_is_blocked(tmp_path: Path) -> None:
    linkset = json.dumps({"linkset": [{"anchor": CARRIER}]}).encode()
    sources = [{"label": "passport", "kind": "resolved", "pointer": "/id"}, SUBJECT]
    ctx, _ = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": sources},
        {"vc_json": {"credentialSubject": {"id": CARRIER}}},
        body=linkset,
    )
    assert _state(consistency(ctx)) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.NOT_RESOLVED")


def test_a_resolved_source_replaces_the_id_comparison(tmp_path: Path) -> None:
    # The passport id names the passport, and the subject names the product.
    passport = {"id": "https://id.example.test/passports/1", "credentialSubject": {"id": CARRIER}}
    source = {"label": "subject", "kind": "resolved", "pointer": "/credentialSubject/id"}
    ctx, acquirer = _ctx(
        tmp_path, "identifier.consistency", {"sources": [source]}, body=json.dumps(passport).encode()
    )
    outcome = consistency(ctx)
    assert _state(outcome) == CONSISTENT
    assert [r.url for r in acquirer.records()] == [CARRIER]
    # The same passport without sources keeps the comparison of today.
    plain, _ = _ctx(tmp_path, "identifier.consistency", {}, body=json.dumps(passport).encode())
    assert _state(consistency(plain)) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.MISMATCH")


def test_a_resolved_source_needs_a_url_carrier(tmp_path: Path) -> None:
    source = {"label": "passport", "kind": "resolved", "pointer": "/id"}
    ctx, acquirer = _ctx(
        tmp_path, "identifier.consistency", {"sources": [source]}, carrier="urn:uuid:TEST-ONLY-1"
    )
    assert _state(consistency(ctx)) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.NOT_RESOLVABLE")
    assert acquirer.records() == ()


def test_a_resource_source_reads_the_ixit_template(tmp_path: Path) -> None:
    source = {"label": "item", "kind": "resource", "pointer": "/subject"}
    item = "http://sut.example/dpp/x"
    ctx, acquirer = _ctx(
        tmp_path,
        "identifier.consistency",
        {"sources": [source]},
        by_url={item: (200, json.dumps({"subject": CARRIER}).encode())},
    )
    assert _state(consistency(ctx)) == CONSISTENT
    assert [r.url for r in acquirer.records()] == [item]
    missing, _ = _ctx(tmp_path, "identifier.consistency", {"sources": [source]}, by_url={item: (404, b"{}")})
    assert _state(consistency(missing)) == MISSING


def test_a_server_error_of_a_source_is_no_answer(tmp_path: Path) -> None:
    source = {"label": "passport", "kind": "resolved", "pointer": "/id"}
    ctx, _ = _ctx(tmp_path, "identifier.consistency", {"sources": [source]}, status=503)
    outcome = consistency(ctx)
    assert (outcome.reason_code, outcome.unreachable) == ("TRANSPORT.SERVER_ERROR", True)


SOURCE_MODEL_REFUSALS: list[Any] = [
    [],
    [SUBJECT] * 2,
    [{**SUBJECT, "label": f"s{i}"} for i in range(9)],
    [{**SUBJECT, "pointer": "credentialSubject/id"}],
    [{**SUBJECT, "pointer": "/a~2"}],
    [{**SUBJECT, "kind": "registry"}],
    [{**SUBJECT, "label": "Vc"}],
    [{**SUBJECT, "label": "../x"}],
    [{"label": "items", "kind": "resource", "pointer": "/id"}],
    [{"label": "vc_json", "kind": "sample"}],
    [{**SUBJECT, "extra": 1}],
    SUBJECT,
]


@pytest.mark.parametrize("sources", SOURCE_MODEL_REFUSALS)
def test_the_parameter_model_refuses_malformed_sources(sources: Any) -> None:
    model = registry.param_models()["identifier.consistency"]
    assert params_problem(model, {"sources": sources}) is not None


def test_the_parameter_model_refuses_sources_with_compare_item() -> None:
    # _cross ignores compare_item, so the item comparison that the pack asked for would not run.
    model = registry.param_models()["identifier.consistency"]
    assert params_problem(model, {"sources": [SUBJECT], "compare_item": True}) is not None


@pytest.mark.parametrize(
    "params",
    [*({"sources": s} for s in SOURCE_MODEL_REFUSALS[:3]), {"sources": [SUBJECT], "compare_item": True}],
)
def test_the_check_refuses_malformed_sources_without_the_planner(
    tmp_path: Path, params: dict[str, Any]
) -> None:
    ctx, acquirer = _ctx(tmp_path, "identifier.consistency", params)
    assert _state(consistency(ctx)) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.PARAMS.INVALID")
    assert acquirer.records() == ()


def test_the_model_accepts_the_three_kinds() -> None:
    sources = [
        {"label": "passport", "kind": "resolved", "pointer": "/id"},
        {"label": "registry_record", "kind": "resource", "pointer": "/product/~1id~0"},
        SUBJECT,
    ]
    model = registry.param_models()["identifier.consistency"]
    assert params_problem(model, {"sources": sources, "compare_item": False}) is None


# -- identifier.equivalence ---------------------------------------------------------------------

DECLARED = {"label": "gs1_declared", "kind": "sample", "pointer": "/id"}
OK = (ExecutionStatus.COMPLETED, True, "IDENTIFIER.EQUIVALENCE.OK")
DIFFERENT = (ExecutionStatus.COMPLETED, False, "IDENTIFIER.EQUIVALENCE.DIFFERENT")
NOT_PARSED = (ExecutionStatus.BLOCKED, None, "IDENTIFIER.EQUIVALENCE.NOT_PARSED")


def _equivalence(tmp_path: Path, declared: object, carrier: str = CARRIER) -> CheckOutcome:
    from dppce.adapters.gs1 import equivalence  # noqa: PLC0415 - the check is new in this package

    ctx, _ = _ctx(
        tmp_path,
        "identifier.equivalence",
        {"source": DECLARED},
        {"gs1_declared": {"id": declared}},
        carrier=carrier,
    )
    return equivalence(ctx)


@pytest.mark.parametrize(
    ("carrier", "declared"),
    [
        (CARRIER, CARRIER),
        (CARRIER, "https://id.example.test/01/9506000134352/21/EV0001"),
        ("https://id.example.test/01/00000002345673/21/A", "https://id.example.test/01/02345673/21/A"),
        ("https://id.example.test/01/00416000336108/21/A", "https://id.example.test/01/416000336108/21/A"),
        (CARRIER, "HTTPS://ID.Example.TEST/01/09506000134352/21/EV0001"),
        (CARRIER, "https://id.example.test/some/prefix/01/09506000134352/21/EV0001"),
        (
            "https://id.example.test/01/09506000134352/21/A%2fB",
            "https://id.example.test/01/09506000134352/21/A%2FB",
        ),
        (
            "https://id.example.test/01/09506000134352/21/A%2DB",
            "https://id.example.test/01/09506000134352/21/A-B",
        ),
        (CARRIER, CARRIER + "?17=261231"),
    ],
    ids=[
        "same",
        "gtin13",
        "gtin8",
        "gtin12",
        "scheme-host-case",
        "path-prefix",
        "percent-case",
        "percent",
        "attr",
    ],
)
def test_equivalent_gs1_identifiers_pass(tmp_path: Path, carrier: str, declared: str) -> None:
    outcome = _equivalence(tmp_path, declared, carrier)
    assert _state(outcome) == OK, outcome.message


@pytest.mark.parametrize(
    "declared",
    [
        "https://id.example.test/01/9506000134352/21/EV0002",
        "https://other.example.test/01/09506000134352/21/EV0001",
        "http://id.example.test/01/09506000134352/21/EV0001",
        "https://id.example.test/01/09506000134352",
        "https://id.example.test/01/09506000134352/10/EV0001",
        "https://id.example.test/01/09506000134352/21/ev0001",
        7,
        None,
        {"id": CARRIER},
    ],
    ids=["serial", "host", "scheme", "no-serial", "lot-not-serial", "serial-case", "int", "null", "object"],
)
def test_a_different_gs1_identifier_fails(tmp_path: Path, declared: object) -> None:
    outcome = _equivalence(tmp_path, declared)
    assert _state(outcome) == DIFFERENT
    assert "EV000" not in json.dumps(outcome.observations[0].summary), "no payload value in a summary"


@pytest.mark.parametrize(
    "declared",
    [
        "not a uri",
        "https://id.example.test/01/09506000134353/21/EV0001",
        "https://id.example.test/01/950600013435/21/EV0001",
        # The compressed form is a heuristic that any long last segment reaches, so no limit.
        "https://id.example.test/AQnYUc1gu4BCfNrP6M",
    ],
    ids=["declared-not-a-uri", "check-digit", "gtin12-check-digit", "declared-looks-compressed"],
)
def test_an_unparsable_declared_identifier_differs(tmp_path: Path, declared: str) -> None:
    # A system under test must not turn a difference into blocked by serving an unparsable value.
    outcome = _equivalence(tmp_path, declared)
    assert _state(outcome) == DIFFERENT
    assert outcome.observations[0].summary["different"] == ["syntax"]
    assert "EV000" not in json.dumps(outcome.observations[0].summary), "no payload value in a summary"


def test_an_unparsable_carrier_is_blocked(tmp_path: Path) -> None:
    assert _state(_equivalence(tmp_path, CARRIER, "urn:uuid:TEST-ONLY-1")) == NOT_PARSED


def test_a_compressed_carrier_is_unsupported(tmp_path: Path) -> None:
    outcome = _equivalence(tmp_path, CARRIER, "https://id.example.test/AQnYUc1gu4BCfNrP6M")
    assert _state(outcome) == (ExecutionStatus.UNSUPPORTED, None, "IDENTIFIER.SYNTAX.COMPRESSED")


def test_a_missing_declared_source_is_blocked(tmp_path: Path) -> None:
    from dppce.adapters.gs1 import equivalence  # noqa: PLC0415 - the check is new in this package

    ctx, _ = _ctx(tmp_path, "identifier.equivalence", {"source": DECLARED}, {"gs1_declared": {}})
    assert _state(equivalence(ctx)) == MISSING


def test_the_equivalence_model_needs_one_source() -> None:
    model = registry.param_models()["identifier.equivalence"]
    assert params_problem(model, {}) is not None
    assert params_problem(model, {"source": [DECLARED]}) is not None
    assert params_problem(model, {"source": DECLARED}) is None


def test_identifier_parse_keeps_refusing_a_short_gtin() -> None:
    # The padding is for the comparison only. identifier.parse keeps the default options of dl.c.
    short = "https://id.example.test/01/9506000134352/21/EV0001"
    assert isinstance(gs1.parse(short), gs1.Problem)
    assert isinstance(gs1.parse(short, zero_suppressed=True), gs1.DigitalLink)


# -- Oracle: the zero-suppressed GTIN cases of dl.c ---------------------------------------------


def _zero_suppressed_cases() -> list[tuple[str, str, str]]:
    """The dl.c cases that run with PermitZeroSuppressedGTINinDLuris as their only option."""
    text = GS1_DL.read_bytes().decode("utf-8")
    start, end = "void test_dl_parseDLuri(void)", "void test_dl_URIunescape(void)"
    body = _strip_comments(text[text.index(start) : text.index(end)])
    active: set[str] = set()
    out = []
    for match in _CALL.finditer(body):
        if match["setter"] is not None:
            on = match["args"].split(",")[-1].strip() == "true"
            (active.add if on else active.discard)(match["setter"])
        elif active == {"PermitZeroSuppressedGTINinDLuris"}:
            out.append((match["err"], _c_string(match["uri"]), _c_string(match["out"])))
    return out


def test_the_padding_follows_the_dl_c_cases() -> None:
    cases = _zero_suppressed_cases()
    assert len(cases) >= 5
    assert all(err == "OK" for err, _, _ in cases)
    for _, uri, out in cases:
        result = gs1.parse(uri, zero_suppressed=True)
        assert isinstance(result, gs1.DigitalLink), uri
        gtin = dict(result.elements)["01"]
        assert re.search(rf"\^?01{gtin}", out), (uri, out)
