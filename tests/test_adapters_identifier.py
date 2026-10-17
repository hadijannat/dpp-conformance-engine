"""The identifier adapter on a declared carrier identifier."""

from __future__ import annotations

import http.server
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.identifier import consistency, parse, resolve
from dppce.models import ICS, IXIT, ExecutionStatus
from dppce.testdefs.registry import CheckContext
from tests.support import reply
from tests.test_adapters_security import _POLICY, _Canned, _context
from tests.test_review_findings import transport


@pytest.mark.parametrize(
    ("gtin", "passed", "code"),
    [
        ("09506000134352", True, "IDENTIFIER.SYNTAX.OK"),
        ("09506000134353", False, "IDENTIFIER.SYNTAX.INVALID"),
    ],
)
def test_a_gtin_with_a_wrong_check_digit_is_invalid_syntax(
    gtin: str, passed: bool, code: str, tmp_path: Path
) -> None:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": "gs1-digital-link"})
    samples = {"identifier": f"https://id.example/01/{gtin}/21/EV0001"}
    ixit = IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": samples})
    outcome = parse(replace(base, ics=ics, ixit=ixit))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, passed, code)
    # The cause must be the check digit, not a path shape that a later regex change rejects.
    reason = None if passed else "the GTIN check digit is wrong"
    assert outcome.observations[0].summary.get("reason") == reason


def test_a_gtin_in_non_ascii_digits_is_invalid_syntax(tmp_path: Path) -> None:
    # Arabic-Indic digits are Unicode decimals: `\d` and int() accept them, GS1 does not.
    gtin = "09506000134352".translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": "gs1-digital-link"})
    samples = {"identifier": f"https://id.example/01/{gtin}/21/EV0001"}
    ixit = IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": samples})
    outcome = parse(replace(base, ics=ics, ixit=ixit))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.SYNTAX.INVALID",
    )
    reason = "the path does not have the form /01/<14 digits>/21/<serial>"
    assert outcome.observations[0].summary.get("reason") == reason


# -- identifier.resolve with test-purpose media types (gap D4-04) ------------------------------


class Resolver:
    """A loopback resolver that answers with one body. It keeps every Accept header line it gets."""

    def __init__(self, loopback: Any, body: bytes, media_type: str) -> None:
        self.accepts: list[list[str]] = []

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            self.accepts.append(request.headers.get_all("Accept") or [])
            reply(request, 200, body, {"Content-Type": media_type})

        self.server = loopback(handle)


def live(tmp_path: Path, resolver: Resolver, params: dict[str, Any], acquirer: Any = None) -> CheckContext:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    stimulus = base.purpose.stimulus.model_copy(update={"check": "identifier.resolve", "params": params})
    samples = {"identifier": f"{resolver.server.origin}/01/09506000134352/21/EV0001"}
    ixit = IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": samples})
    return replace(
        base,
        purpose=base.purpose.model_copy(update={"stimulus": stimulus}),
        ixit=ixit,
        acquirer=acquirer or transport(),
    )


HTML = b"<!doctype html><title>passport</title>"
HTML_PARAMS: dict[str, Any] = {"accept": "text/html", "accepted_media_types": ["text/html"]}


def test_resolve_by_default_still_needs_a_json_object_and_records_the_media_type(
    tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, HTML, "text/html; charset=utf-8")
    outcome = resolve(live(tmp_path, resolver, {}))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.RESPONSE.NOT_JSON")
    assert outcome.observations[0].summary["media_type"] == "text/html"
    assert resolver.accepts == [["*/*"]]


def test_resolve_with_accepted_media_types_accepts_an_html_resolver(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, HTML, "text/html")
    ctx = live(tmp_path, resolver, HTML_PARAMS)
    outcome = resolve(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED.MEDIA_TYPE")
    assert "does not show that the resource is the passport" in outcome.message
    assert outcome.observations[0].summary["media_type"] == "text/html"
    assert resolver.accepts == [["text/html"]]
    (record,) = ctx.acquirer.records()
    assert ("Accept", "text/html") in record.request_headers


def test_resolve_with_an_accepted_json_type_and_a_json_object_keeps_the_resolved_code(
    tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, b'{"id": "x"}', "application/json")
    outcome = resolve(live(tmp_path, resolver, {"accepted_media_types": ["application/json", "text/html"]}))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED")


def test_resolve_refuses_a_media_type_outside_the_accepted_list(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, HTML, "text/html")
    outcome = resolve(live(tmp_path, resolver, {"accepted_media_types": ["application/json"]}))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.RESPONSE.MEDIA_TYPE")


def test_resolve_with_a_json_media_type_still_needs_a_json_object(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, HTML, "application/ld+json")
    outcome = resolve(live(tmp_path, resolver, {"accepted_media_types": ["application/ld+json"]}))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.RESPONSE.NOT_JSON")


@pytest.mark.parametrize(
    "params",
    [
        {"accept": "text/html\r\nX-Injected: 1"},
        {"accept": "text/html\n"},
        {"accept": ""},
        {"accept": 7},
        {"accepted_media_types": ["Text/HTML"]},
        {"accepted_media_types": ["text/html\n"]},
        {"accepted_media_types": []},
        {"accepted_media_types": "text/html"},
        {"accepted_media_types": ["text/html"] * 17},
    ],
)
def test_resolve_refuses_malformed_parameters_before_any_request(
    params: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, HTML, "text/html")
    outcome = resolve(live(tmp_path, resolver, params))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.PARAMS.INVALID",
    )
    assert resolver.server.seen == []


def test_a_record_fetched_with_a_custom_accept_is_not_reused_by_a_default_fetch(
    tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, b'{"id": "x"}', "application/json")
    engine = transport()
    resolve(live(tmp_path, resolver, {"accept": "application/ld+json"}, engine))
    consistency(live(tmp_path, resolver, {}, engine))
    assert resolver.accepts == [["application/ld+json"], ["*/*"]]
    resolve(live(tmp_path, resolver, {}, engine))
    assert len(resolver.server.seen) == 2, "a default fetch reuses the earlier default record"


def test_a_custom_accept_replaces_the_default_header(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, HTML, "text/html")
    resolve(live(tmp_path, resolver, HTML_PARAMS))
    assert resolver.accepts == [["text/html"]], "exactly one Accept header line"
