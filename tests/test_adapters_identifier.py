"""The identifier adapter on a declared carrier identifier."""

from __future__ import annotations

import http.server
import json
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.carrier import qr_decode
from dppce.adapters.identifier import consistency, parse, resolve
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import ICS, IXIT, CheckOutcome, ExecutionStatus
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


def _parse(tmp_path: Path, samples: dict[str, str], scheme: str = "gs1-digital-link") -> CheckOutcome:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": scheme})
    ixit = IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": samples})
    return parse(replace(base, ics=ics, ixit=ixit))


GS1_PATH = "/01/09520123456788/21/12345"
HOST = "the host has a character that GS1 Digital Link does not permit"
CHARACTER = "the URL has a character that a URI does not permit"


@pytest.mark.parametrize(
    ("identifier", "reason"),
    [
        (f"HtTp://a{GS1_PATH}", "it is not an HTTP or HTTPS URL"),
        (f"https://$a{GS1_PATH}", HOST),
        (f"https://a_b{GS1_PATH}", HOST),
        (f"https://u@a{GS1_PATH}", HOST),
        (f"https://[fe80::1%25lo]{GS1_PATH}", HOST),
        (f"https://ü.example{GS1_PATH}", HOST),
        (f"https://a{GS1_PATH}?q=<bad", CHARACTER),
        (f"https://a{GS1_PATH}#f g", CHARACTER),
    ],
)
def test_parse_refuses_a_scheme_host_or_character_that_gs1_refuses(
    identifier: str, reason: str, tmp_path: Path
) -> None:
    # Engine inputs built from the categories of the GS1 unit tests, not vendored vectors.
    outcome = _parse(tmp_path, {"identifier": identifier})
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.SYNTAX.INVALID",
    )
    assert outcome.observations[0].summary.get("reason") == reason


@pytest.mark.parametrize(
    "origin", ["HTTPS://A", "https://a:65535", "https://[2001:db8::1]", "https://a.", "http://127.0.0.1:8443"]
)
def test_parse_accepts_the_scheme_and_host_forms_that_gs1_accepts(origin: str, tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"identifier": f"{origin}{GS1_PATH}"})
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.SYNTAX.OK")


def test_parse_without_a_declared_scheme_is_blocked(tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"identifier": f"https://a{GS1_PATH}"}, scheme="unknown")
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.SCHEME.UNKNOWN",
    )


def test_parse_of_a_scheme_without_a_parser_is_unsupported(tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"identifier": f"https://a{GS1_PATH}"}, scheme="epc-tds")
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "IDENTIFIER.SCHEME.UNSUPPORTED",
    )


def test_an_ixit_without_a_carrier_sample_is_blocked(tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"passport_id": "09506000134352-EV0001"})
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "CARRIER.SAMPLE.MISSING",
    )


def test_qr_decode_without_the_decoder_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "zxingcpp", None)  # the import now raises ImportError
    outcome = qr_decode(_context(tmp_path, _POLICY, _Canned(b"{}")))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "CARRIER.QR.DEPENDENCY_MISSING",
    )


# -- identifier.resolve with test-purpose media types (gap D4-04) ------------------------------


class Resolver:
    """A loopback resolver that answers with one body. It keeps every Accept header line it gets."""

    def __init__(self, loopback: Any, body: bytes, media_type: str, status: int = 200) -> None:
        self.accepts: list[list[str]] = []
        self.body = body

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            self.accepts.append(request.headers.get_all("Accept") or [])
            reply(request, status, self.body, {"Content-Type": media_type})

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


def _with_identifier(ctx: CheckContext, identifier: str) -> CheckContext:
    samples = {"identifier": identifier}
    return replace(ctx, ixit=IXIT.model_validate(ctx.ixit.model_dump(mode="json") | {"samples": samples}))


# -- require_https: the EU registry user guide names https identifiers only -------------------


class _Redirected(_Canned):
    """A canned acquirer whose answer records the given redirect chain."""

    def __init__(self, redirects: tuple[str, ...]) -> None:
        super().__init__(b'{"id": "x"}')
        self._redirects = redirects

    def fetch(self, request: Request) -> Record:
        record = replace(super().fetch(request), redirects=self._redirects)
        self._records[-1] = record
        return record


@pytest.mark.parametrize(
    ("origin", "passed", "code"),
    [
        ("https://a", True, "IDENTIFIER.SYNTAX.OK"),
        ("HTTPS://a", True, "IDENTIFIER.SYNTAX.OK"),
        ("http://a", False, "IDENTIFIER.SCHEME.NOT_HTTPS"),
    ],
)
def test_parse_with_require_https_fails_a_valid_http_identifier(
    origin: str, passed: bool, code: str, tmp_path: Path
) -> None:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    stimulus = base.purpose.stimulus.model_copy(
        update={"check": "identifier.parse", "params": {"require_https": True}}
    )
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": "gs1-digital-link"})
    ixit = IXIT.model_validate(
        base.ixit.model_dump(mode="json") | {"samples": {"identifier": f"{origin}{GS1_PATH}"}}
    )
    outcome = parse(
        replace(base, purpose=base.purpose.model_copy(update={"stimulus": stimulus}), ics=ics, ixit=ixit)
    )
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, passed, code)
    # Syntax is judged first and stays valid: only the scheme rule failed.
    assert outcome.observations[0].summary["valid"] is True


def test_parse_without_require_https_still_accepts_http(tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"identifier": f"http://a{GS1_PATH}"})
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.SYNTAX.OK")


def test_parse_with_a_non_boolean_require_https_is_blocked(tmp_path: Path) -> None:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    stimulus = base.purpose.stimulus.model_copy(
        update={"check": "identifier.parse", "params": {"require_https": "yes"}}
    )
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": "gs1-digital-link"})
    outcome = parse(replace(base, purpose=base.purpose.model_copy(update={"stimulus": stimulus}), ics=ics))
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "IDENTIFIER.PARAMS.INVALID")


def test_resolve_with_require_https_does_not_fetch_an_http_carrier(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b'{"id": "x"}', "application/json")  # a loopback origin is http
    outcome = resolve(live(tmp_path, resolver, {"require_https": True}))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.SCHEME.NOT_HTTPS",
    )
    assert outcome.observations[0].kind == "derived"
    assert resolver.server.seen == []


@pytest.mark.parametrize(
    ("hops", "passed", "code"),
    [
        (("https://id.example.test/go", "https://dpp.example.test/x"), True, "IDENTIFIER.RESOLVED"),
        (("https://id.example.test/go", "http://dpp.example.test/x"), False, "IDENTIFIER.SCHEME.NOT_HTTPS"),
    ],
)
def test_resolve_with_require_https_judges_each_redirect_target(
    hops: tuple[str, ...], passed: bool, code: str, tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, b"{}", "application/json")
    ctx = _with_identifier(
        live(tmp_path, resolver, {"require_https": True}, _Redirected(hops)), f"https://a{GS1_PATH}"
    )
    outcome = resolve(ctx)
    assert (outcome.passed, outcome.reason_code) == (passed, code)
    assert outcome.observations[0].summary["redirects"] == 2
    if not passed:
        assert "1 of 2 redirect targets do not use the https scheme" in outcome.message


def test_resolve_without_require_https_ignores_a_downgraded_hop(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json")
    hops = ("http://dpp.example.test/x",)
    outcome = resolve(
        _with_identifier(live(tmp_path, resolver, {}, _Redirected(hops)), f"https://a{GS1_PATH}")
    )
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED")


# -- one named producing test for each identifier and carrier reason code (gap D4-13) ----------


def test_resolve_of_a_text_that_is_not_a_url_is_unresolved(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json")
    outcome = resolve(_with_identifier(live(tmp_path, resolver, {}), "not a url"))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.UNRESOLVED",
    )
    assert resolver.server.seen == []


@pytest.mark.parametrize("status", [404, 410])
def test_resolve_of_a_404_or_410_answer_is_unresolved(status: int, tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json", status)
    outcome = resolve(live(tmp_path, resolver, {}))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.UNRESOLVED")


@pytest.mark.parametrize("status", [500, 503, 599])
def test_resolve_of_a_5xx_answer_is_unreachable(status: int, tmp_path: Path, loopback: Any) -> None:
    # Owner decision of 2026-10-18: a server error counts like a connectivity failure.
    resolver = Resolver(loopback, b"{}", "application/json", status)
    outcome = resolve(live(tmp_path, resolver, {}))
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )
    assert len(resolver.server.seen) == 1, "a 5xx answer is not retried"


@pytest.mark.parametrize("status", [403, 600])
def test_resolve_of_another_status_is_a_status_failure(status: int, tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json", status)
    outcome = resolve(live(tmp_path, resolver, {}))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        False,
        "IDENTIFIER.RESOLUTION.STATUS",
    )


def test_consistency_of_a_text_that_is_not_a_url_is_blocked(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json")
    outcome = consistency(_with_identifier(live(tmp_path, resolver, {}), "not a url"))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.NOT_RESOLVABLE",
    )
    assert resolver.server.seen == []


@pytest.mark.parametrize(
    ("status", "body", "media_type"), [(200, HTML, "text/html"), (404, b"{}", "application/json")]
)
def test_consistency_without_a_json_passport_is_blocked(
    status: int, body: bytes, media_type: str, tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, body, media_type, status)
    outcome = consistency(live(tmp_path, resolver, {}))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.NOT_RESOLVED",
    )


def test_consistency_of_a_5xx_resolver_answer_is_unreachable(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json", 503)
    outcome = consistency(live(tmp_path, resolver, {}))
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


def test_consistency_of_the_same_identifier_is_consistent(tmp_path: Path, loopback: Any) -> None:
    resolver = Resolver(loopback, b"{}", "application/json")
    ctx = live(tmp_path, resolver, {})
    resolver.body = json.dumps({"id": ctx.ixit.samples["identifier"]}).encode()
    outcome = consistency(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.CONSISTENT")


@pytest.mark.parametrize("passport_id", ["https://id.example.test/01/09506000134352/21/OTHER0001", 7])
def test_consistency_of_a_different_passport_id_is_a_mismatch(
    passport_id: object, tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, json.dumps({"id": passport_id}).encode(), "application/json")
    outcome = consistency(live(tmp_path, resolver, {}))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.MISMATCH")
    assert outcome.observations[0].summary["different"] == ["passport"]


# -- identifier.consistency with compare_item (gap D4-05) ---------------------------------------

SERIAL_PATH = "/01/09506000134352/21/EV0001"


class Site:
    """A loopback system. The resolver path answers one passport, every other path the item."""

    def __init__(self, loopback: Any, *, item_status: int = 200, item_type: str = "application/json") -> None:
        self.resolved: Any = None
        self.item: Any = None

        def body(value: Any) -> bytes:
            return value if isinstance(value, bytes) else json.dumps(value).encode()

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            if request.path == SERIAL_PATH:
                reply(request, 200, body(self.resolved))
            else:
                reply(request, item_status, body(self.item), {"Content-Type": item_type})

        self.server = loopback(handle)
        self.identifier = f"{self.server.origin}{SERIAL_PATH}"

    def item_requests(self) -> int:
        return sum(1 for seen in self.server.seen if seen["path"] != SERIAL_PATH)


def binding(
    tmp_path: Path, site: Site, params: dict[str, Any] | None = None, *, item_template: bool = True
) -> CheckContext:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    chosen = {"compare_item": True} if params is None else params
    stimulus = base.purpose.stimulus.model_copy(update={"check": "identifier.consistency", "params": chosen})
    fields = base.ixit.model_dump(mode="json") | {
        "endpoints": {"api": site.server.origin},
        "samples": {"identifier": site.identifier, "passport_id": "09506000134352-EV0001"},
        "resources": {"item": {"endpoint": "api", "path": "/dpp/{id}"}} if item_template else {},
    }
    return replace(
        base,
        purpose=base.purpose.model_copy(update={"stimulus": stimulus}),
        ixit=IXIT.model_validate(fields),
        acquirer=transport(),
    )


def _passport(site_id: str, **more: Any) -> dict[str, Any]:
    return {"id": site_id, "version": 3, **more}


def _site(loopback: Any, resolved: Any = None, item: Any = None, **options: Any) -> Site:
    site = Site(loopback, **options)
    site.resolved = _passport(site.identifier) if resolved is None else resolved
    site.item = _passport(site.identifier) if item is None else item
    return site


def test_consistency_compares_the_resolved_and_api_passports(tmp_path: Path, loopback: Any) -> None:
    site = _site(loopback)
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.CONSISTENT")
    summary = outcome.observations[0].summary
    assert summary["compared"] == ["carrier", "passport", "api_item"]
    assert summary["different"] == []
    assert site.item_requests() == 1
    assert len(outcome.observations[0].record_ids) == 2, "the resolver record and the item record"


def test_consistency_of_a_divergent_api_passport_is_a_binding_mismatch(tmp_path: Path, loopback: Any) -> None:
    site = _site(loopback)
    site.resolved = _passport(site.identifier, version=4)
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.BINDING.MISMATCH",
    )
    assert outcome.observations[0].summary["different"] == ["api_item"]
    assert "Digital consistency does not prove physical authenticity." in outcome.message


@pytest.mark.parametrize(
    ("resolved", "item", "same"),
    [
        (b'{"version": 3, "id": "ID"}', b'{"id":"ID","version":3}', True),
        (b'{"id": "ID", "n": 1.0}', b'{"id": "ID", "n": 1}', True),
        (b'{"id": "ID", "n": 1.10}', b'{"id": "ID", "n": 1.1}', True),
        (b'{"id": "ID", "n": true}', b'{"id": "ID", "n": 1}', False),
        (b'{"id": "ID", "n": null}', b'{"id": "ID"}', False),
    ],
)
def test_binding_compares_json_values(
    resolved: bytes, item: bytes, same: bool, tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback)
    site.resolved = resolved.replace(b"ID", site.identifier.encode())
    site.item = item.replace(b"ID", site.identifier.encode())
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.passed, outcome.reason_code) == (
        (True, "IDENTIFIER.CONSISTENT") if same else (False, "IDENTIFIER.BINDING.MISMATCH")
    )


def test_an_identifier_mismatch_wins_and_skips_the_item_fetch(tmp_path: Path, loopback: Any) -> None:
    site = _site(loopback, resolved={"id": "https://id.example.test/01/09506000134352/21/OTHER0001"})
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.MISMATCH")
    assert outcome.observations[0].summary["different"] == ["passport"]
    assert site.item_requests() == 0


def test_an_identifier_mismatch_without_an_item_template_is_still_a_mismatch(
    tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback, resolved={"id": "https://id.example.test/01/09506000134352/21/OTHER0001"})
    outcome = consistency(binding(tmp_path, site, item_template=False))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "IDENTIFIER.MISMATCH",
    )


def test_binding_without_an_item_template_is_blocked_and_fetches_no_item(
    tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback)
    outcome = consistency(binding(tmp_path, site, item_template=False))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.NO_TARGET",
    )
    assert [seen["path"] for seen in site.server.seen] == [SERIAL_PATH]


@pytest.mark.parametrize(
    ("status", "body", "media_type"), [(200, HTML, "text/html"), (404, b'{"error": "x"}', "application/json")]
)
def test_binding_with_a_non_json_or_404_item_is_not_comparable(
    status: int, body: bytes, media_type: str, tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback, item=body, item_status=status, item_type=media_type)
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.BINDING.NOT_COMPARABLE",
    )


def test_binding_with_a_5xx_item_is_unreachable(tmp_path: Path, loopback: Any) -> None:
    site = _site(loopback, item=b'{"error": "unavailable"}', item_status=503)
    outcome = consistency(binding(tmp_path, site))
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


@pytest.mark.parametrize("params", [{}, {"compare_item": False}])
def test_consistency_without_compare_item_never_fetches_the_item(
    params: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback)
    site.item = {"id": "something else entirely"}
    outcome = consistency(binding(tmp_path, site, params))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.CONSISTENT")
    assert outcome.observations[0].summary["compared"] == ["carrier", "passport"]
    assert site.item_requests() == 0


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_consistency_refuses_a_non_bool_compare_item_before_any_request(
    value: object, tmp_path: Path, loopback: Any
) -> None:
    site = _site(loopback)
    outcome = consistency(binding(tmp_path, site, {"compare_item": value}))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.PARAMS.INVALID",
    )
    assert site.server.seen == []


ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = ROOT / "src" / "dppce" / "adapters"
DEGRADED_EXPECTED = ROOT / "fixtures" / "reference" / "qr" / "degraded" / "expected.json"
DEGRADED_TEST = "tests/test_adapters_carrier.py::test_a_degraded_image_gives_the_expected_outcome"
_HERE = "tests/test_adapters_identifier.py::"
_GS1 = "tests/test_adapters_gs1.py::"
# Seeded faults F-20, F-30, F-31, F-33, F-34, and F-35 also produce identifier and carrier codes
# in tests/test_e2e_reference.py. Their codes come from the fault catalogue, so they are not listed.
# F-32 gives a transport code since the owner decision of 2026-10-18.
PRODUCERS: dict[str, list[str]] = {
    "IDENTIFIER.SCHEME.UNKNOWN": [_HERE + "test_parse_without_a_declared_scheme_is_blocked"],
    "IDENTIFIER.SCHEME.UNSUPPORTED": [_HERE + "test_parse_of_a_scheme_without_a_parser_is_unsupported"],
    "IDENTIFIER.SYNTAX.OK": [
        _HERE + "test_a_gtin_with_a_wrong_check_digit_is_invalid_syntax",
        _HERE + "test_parse_accepts_the_scheme_and_host_forms_that_gs1_accepts",
    ],
    "IDENTIFIER.SYNTAX.INVALID": [
        _HERE + "test_a_gtin_with_a_wrong_check_digit_is_invalid_syntax",
        _HERE + "test_a_gtin_in_non_ascii_digits_is_invalid_syntax",
        _HERE + "test_parse_refuses_a_scheme_host_or_character_that_gs1_refuses",
    ],
    "IDENTIFIER.PARAMS.INVALID": [
        _HERE + "test_resolve_refuses_malformed_parameters_before_any_request",
        _HERE + "test_parse_with_a_non_boolean_require_https_is_blocked",
    ],
    "IDENTIFIER.SCHEME.NOT_HTTPS": [
        _HERE + "test_parse_with_require_https_fails_a_valid_http_identifier",
        _HERE + "test_resolve_with_require_https_does_not_fetch_an_http_carrier",
        _HERE + "test_resolve_with_require_https_judges_each_redirect_target",
    ],
    "IDENTIFIER.UNRESOLVED": [
        _HERE + "test_resolve_of_a_text_that_is_not_a_url_is_unresolved",
        _HERE + "test_resolve_of_a_404_or_410_answer_is_unresolved",
    ],
    "IDENTIFIER.RESOLUTION.STATUS": [_HERE + "test_resolve_of_another_status_is_a_status_failure"],
    "IDENTIFIER.RESPONSE.MEDIA_TYPE": [_HERE + "test_resolve_refuses_a_media_type_outside_the_accepted_list"],
    "IDENTIFIER.RESOLVED.MEDIA_TYPE": [
        _HERE + "test_resolve_with_accepted_media_types_accepts_an_html_resolver"
    ],
    "IDENTIFIER.RESPONSE.LINKSET": [
        "tests/test_false_verdict_guards.py::test_resolve_does_not_call_a_linkset_a_passport"
    ],
    "IDENTIFIER.RESPONSE.NOT_JSON": [
        _HERE + "test_resolve_by_default_still_needs_a_json_object_and_records_the_media_type"
    ],
    "IDENTIFIER.RESOLVED": [
        _HERE + "test_resolve_with_an_accepted_json_type_and_a_json_object_keeps_the_resolved_code"
    ],
    "IDENTIFIER.NOT_RESOLVABLE": [_HERE + "test_consistency_of_a_text_that_is_not_a_url_is_blocked"],
    "IDENTIFIER.NOT_RESOLVED": [_HERE + "test_consistency_without_a_json_passport_is_blocked"],
    "IDENTIFIER.CONSISTENT": [_HERE + "test_consistency_of_the_same_identifier_is_consistent"],
    "IDENTIFIER.MISMATCH": [_HERE + "test_consistency_of_a_different_passport_id_is_a_mismatch"],
    "IDENTIFIER.BINDING.MISMATCH": [
        _HERE + "test_consistency_of_a_divergent_api_passport_is_a_binding_mismatch"
    ],
    "IDENTIFIER.BINDING.NOT_COMPARABLE": [
        _HERE + "test_binding_with_a_non_json_or_404_item_is_not_comparable"
    ],
    "IDENTIFIER.SYNTAX.COMPRESSED": [_GS1 + "test_form_gs1_dl_gives_unsupported_for_a_compressed_uri"],
    "IDENTIFIER.GRANULARITY.OK": [_GS1 + "test_granularity_compares_the_key_set_with_the_ics"],
    "IDENTIFIER.GRANULARITY.MISMATCH": [_GS1 + "test_granularity_compares_the_key_set_with_the_ics"],
    "IDENTIFIER.GRANULARITY.NOT_DECLARED": [_GS1 + "test_granularity_never_passes_without_a_classification"],
    "IDENTIFIER.GRANULARITY.NOT_PARSED": [_GS1 + "test_granularity_never_passes_without_a_classification"],
    "IDENTIFIER.GRANULARITY.KEY_UNSUPPORTED": [
        _GS1 + "test_granularity_never_passes_without_a_classification"
    ],
    "CARRIER.SAMPLE.MISSING": [_HERE + "test_an_ixit_without_a_carrier_sample_is_blocked"],
    "CARRIER.QR.DEPENDENCY_MISSING": [_HERE + "test_qr_decode_without_the_decoder_is_unsupported"],
    "CARRIER.SAMPLE.TOO_LARGE": [
        "tests/test_adapters_carrier.py::test_qr_decode_of_an_image_above_the_pixel_limit_is_blocked"
    ],
    "CARRIER.SAMPLE.UNREADABLE": [DEGRADED_TEST],
    "CARRIER.QR.NOT_DECODED": [DEGRADED_TEST],
    "CARRIER.QR.OK": [DEGRADED_TEST],
}


def _test_source(file: str, name: str) -> str:
    """The source of one top-level test: its decorators, its signature, and its body."""
    text = (ROOT / file).read_text(encoding="utf-8")
    start = text.find(f"\ndef {name}(")
    assert start >= 0, f"{file} does not define {name}"
    start = text.rfind("\n\n", 0, start) + 2  # the decorators directly above the def
    # The next column-0 line that is not blank, a comment, or a closing bracket of a multi-line
    # signature, so the module constants after the last test are excluded.
    end = re.compile(r"\n(?=[^\s#)\]}])").search(text, text.index(f"def {name}(", start) + 1)
    return text[start : end.start() if end else len(text)]


def test_every_identifier_and_carrier_reason_code_has_a_named_producing_test() -> None:
    sources = "".join(
        (ADAPTERS / name).read_text(encoding="utf-8") for name in ("identifier.py", "carrier.py", "common.py")
    )
    codes = set(re.findall(r"(?:IDENTIFIER|CARRIER)\.[A-Z_.]+", sources))
    assert len(codes) == 31
    assert codes == set(PRODUCERS)
    # The window of the last test must stop before the module constants, which name every code.
    assert '"CARRIER.QR.OK"' not in _test_source(
        "tests/test_adapters_identifier.py", "test_consistency_of_a_different_passport_id_is_a_mismatch"
    )
    degraded = {case["reason_code"] for case in json.loads(DEGRADED_EXPECTED.read_text())["cases"].values()}
    for code, tests in PRODUCERS.items():
        for test in tests:
            file, name = test.split("::")
            if test == DEGRADED_TEST:
                assert code in degraded, f"{code}: no degraded image expects it"
            else:
                assert f'"{code}"' in _test_source(file, name), f"{code}: {test} does not name it"
