"""The check identifier.negotiation (P2-14): content negotiation of the carrier URL.

The expected outcome of F-72 and F-73 comes from validation/fault-catalogue.yaml, which states
them before the check exists. Loopback servers and the local reference system only. The check
sends GET requests with five fixed Accept values and no other negotiation header.
"""

from __future__ import annotations

import http.server
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.infrastructure.reference.base import Request
from dppce.infrastructure.reference_server import ReferenceSystem
from dppce.models import CheckOutcome, EvidenceEnvelope, ExecutionStatus
from dppce.testdefs.registry import param_models
from tests.support import reply
from tests.test_family_profiles import _cli, _example
from tests.test_resolved_target import RESOLVER_PATH, resolved_context
from tests.test_url_templates import run

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "validation" / "fault-catalogue.yaml"
PURPOSE = "TP-WEB-NEGOTIATION-001"
PROFILE = "family/web"
PASSPORT = b'{"id": "x"}'
HTML = b"<!doctype html><html><body><p>Passport</p></body></html>"
ACCEPTS = [
    "application/json",
    "text/html",
    "application/ld+json",
    "text/html;q=0.2, application/json;q=0.9",
    "application/x-dppce-unsupported",
]

Answer = tuple[int, bytes, dict[str, str]]


def _wants(accept: str, media: str) -> float:
    for item in accept.split(","):
        name, _, quality = item.partition(";")
        if name.strip() == media:
            return float(quality.partition("=")[2] or 1) if quality else 1.0
    return 0.0


class Server:
    """A loopback carrier that negotiates by the Accept header. Options switch off one rule."""

    def __init__(self, loopback: Any, **options: Any) -> None:
        self.options = options

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            status, body, headers = self.answer(request.headers.get("Accept", ""))
            reply(request, status, body, headers)

        self.server = loopback(handle)
        self.origin: str = self.server.origin

    def answer(self, accept: str) -> Answer:
        o = self.options
        vary = {} if o.get("no_vary") else {"Vary": o.get("vary", "Accept")}
        if o.get("status"):
            return o["status"], PASSPORT, {}
        json_type = o.get("json_type", "application/json")
        if "x-dppce-unsupported" in accept:
            if o.get("unsupported") == "406":
                return 406, b"{}", vary
            return 200, PASSPORT, {"Content-Type": json_type, **vary}
        if o.get("ignore_accept"):
            return 200, PASSPORT, {"Content-Type": json_type}
        html_wins = _wants(accept, "text/html") > _wants(accept, "application/json")
        if html_wins or (o.get("ignore_q") and ";q=" in accept):
            body = o.get("html_body", HTML)
            return 200, body, {"Content-Type": "text/html; charset=utf-8", **vary}
        return 200, o.get("json_body", PASSPORT), {"Content-Type": json_type, **vary}

    def accepts(self) -> list[str]:
        return [seen.get("Accept", "") for seen in self.server.seen if seen["path"] == RESOLVER_PATH]


def _run(
    tmp_path: Path, loopback: Any, params: dict[str, Any] | None = None, **options: Any
) -> tuple[CheckOutcome, Server]:
    api = Server(loopback, **options)
    ctx = resolved_context(tmp_path, "identifier.negotiation", api.origin, params=params)
    return run(ctx), api


def _failed(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, False, code)


def _blocked(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def _passed(outcome: CheckOutcome) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        "NEGOTIATION.OK",
    )


# -- passes ---------------------------------------------------------------------------------------


def test_a_negotiating_carrier_with_vary_passes(tmp_path: Path, loopback: Any) -> None:
    outcome, api = _run(tmp_path, loopback)
    _passed(outcome)
    assert api.accepts() == ACCEPTS
    assert len(outcome.observations) == 5
    assert all("Accept-Language" not in seen for seen in api.server.seen)


def test_a_carrier_that_ignores_accept_needs_no_vary(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, ignore_accept=True)
    _passed(outcome)


def test_the_406_answer_passes_when_the_test_purpose_declares_it(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, {"unsupported_answer": "406"}, unsupported="406")
    _passed(outcome)


def test_the_observations_hold_no_payload_value(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback)
    text = json.dumps([o.summary for o in outcome.observations])
    assert "Passport" not in text
    assert "http" not in text


# -- Vary -----------------------------------------------------------------------------------------


def test_different_answers_without_vary_fail(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, no_vary=True)
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


def test_vary_without_accept_fails(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, vary="Accept-Language")
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


@pytest.mark.parametrize("vary", ["*", "Origin, accept", "ACCEPT"])
def test_vary_that_lists_accept_or_a_star_passes(tmp_path: Path, loopback: Any, vary: str) -> None:
    outcome, _ = _run(tmp_path, loopback, vary=vary)
    _passed(outcome)


# -- media type and body --------------------------------------------------------------------------


def test_a_json_request_answered_with_html_fails(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, json_type="text/html", json_body=HTML)
    _failed(outcome, "NEGOTIATION.MEDIA_TYPE")


def test_a_json_media_type_with_a_body_that_is_not_json_fails(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, json_body=b"<html><body>x</body></html>")
    _failed(outcome, "NEGOTIATION.BODY")


def test_an_html_media_type_with_a_json_body_fails(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, html_body=PASSPORT)
    _failed(outcome, "NEGOTIATION.BODY")


def test_a_weight_that_prefers_json_must_get_json(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, ignore_q=True)
    _failed(outcome, "NEGOTIATION.QUALITY")


# -- the unsupported type -------------------------------------------------------------------------


def test_406_is_a_fail_when_the_test_purpose_declares_the_default(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, unsupported="406")
    _failed(outcome, "NEGOTIATION.UNSUPPORTED")


def test_the_default_is_a_fail_when_the_test_purpose_declares_406(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, {"unsupported_answer": "406"})
    _failed(outcome, "NEGOTIATION.UNSUPPORTED")


def test_an_unknown_value_of_the_parameter_is_refused() -> None:
    model = param_models()["identifier.negotiation"]
    with pytest.raises(ValueError, match="unsupported_answer"):
        model.model_validate({"unsupported_answer": "500"})
    with pytest.raises(ValueError, match="extra"):
        model.model_validate({"accept_language": "de"})


# -- no answer, and no way to hide a fail ---------------------------------------------------------


def test_a_server_error_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    outcome, api = _run(tmp_path, loopback, status=503)
    assert (outcome.status, outcome.passed, outcome.unreachable) == (ExecutionStatus.COMPLETED, False, True)
    assert outcome.reason_code == "TRANSPORT.SERVER_ERROR"
    # Changed by the P2-14 review: the check now sends all five requests, so that a missing
    # answer cannot hide a fail that the other answers prove.
    assert len(api.accepts()) == 5


def test_an_unrelated_status_on_the_json_request_fails(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _run(tmp_path, loopback, status=404)
    _failed(outcome, "NEGOTIATION.STATUS")


def test_a_body_coding_does_not_hide_a_head_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback, no_vary=True)
    plain = api.answer

    def encoded(accept: str) -> Answer:
        status, body, headers = plain(accept)
        return status, body, {**headers, "Content-Encoding": "gzip"}

    api.answer = encoded  # type: ignore[method-assign] # test double: every answer carries a coding
    outcome = run(resolved_context(tmp_path, "identifier.negotiation", api.origin))
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


def test_a_body_coding_blocks_a_step_that_has_no_head_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    plain = api.answer

    def encoded(accept: str) -> Answer:
        status, body, headers = plain(accept)
        return status, body, {**headers, "Content-Encoding": "gzip"}

    api.answer = encoded  # type: ignore[method-assign] # test double: every answer carries a coding
    outcome = run(resolved_context(tmp_path, "identifier.negotiation", api.origin))
    _blocked(outcome, "TRANSPORT.BODY_ENCODED")


def _override(api: Server, rule: Any) -> None:
    """Let ``rule(accept)`` replace the answer when it returns one. Test double."""
    plain = api.answer

    def answer(accept: str) -> Answer:
        return rule(accept) or plain(accept)

    api.answer = answer  # type: ignore[method-assign] # test double


def _check(tmp_path: Path, api: Server, params: dict[str, Any] | None = None) -> CheckOutcome:
    return run(resolved_context(tmp_path, "identifier.negotiation", api.origin, params=params))


def test_a_later_server_error_does_not_hide_a_media_type_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    html = {"Content-Type": "text/html", "Vary": "Accept"}
    _override(
        api,
        lambda a: (503, b"", {}) if "x-dppce-unsupported" in a else (200, HTML, html),
    )
    _failed(_check(tmp_path, api), "NEGOTIATION.MEDIA_TYPE")


def test_an_encoded_answer_does_not_hide_a_body_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback, json_body=b"not json")
    plain = api.answer

    def answer(accept: str) -> Answer:
        status, body, headers = plain(accept)
        if accept == "text/html":
            headers = {**headers, "Content-Encoding": "gzip"}
        return status, body, headers

    api.answer = answer  # type: ignore[method-assign] # test double
    _failed(_check(tmp_path, api), "NEGOTIATION.BODY")


def test_a_406_for_other_types_needs_vary(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback, no_vary=True, unsupported="406")
    _failed(_check(tmp_path, api, {"unsupported_answer": "406"}), "NEGOTIATION.VARY.MISSING")
    api = Server(loopback, no_vary=True)
    _override(api, lambda a: (406, b"{}", {}) if a == "text/html" else None)
    _failed(_check(tmp_path, api), "NEGOTIATION.VARY.MISSING")


def test_a_body_that_changes_without_accept_is_not_a_vary_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback, no_vary=True, ignore_accept=True)
    count = iter(range(100))
    _override(api, lambda a: (200, b'{"n": %d}' % next(count), {"Content-Type": "application/json"}))
    _passed(_check(tmp_path, api))


def test_a_406_for_the_weighted_range_fails_when_json_is_served(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    _override(api, lambda a: (406, b"{}", {"Vary": "Accept"}) if ";q=" in a else None)
    _failed(_check(tmp_path, api), "NEGOTIATION.QUALITY")


def test_a_json_array_is_valid_json_ld(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    _override(
        api,
        lambda a: (
            (200, b'[{"@id": "x"}]', {"Content-Type": "application/ld+json", "Vary": "Accept"})
            if a == "application/ld+json"
            else None
        ),
    )
    _passed(_check(tmp_path, api))


def _redirecting(loopback: Any, negotiate_at_target: bool) -> Any:
    """A carrier that answers 307 with ``Vary: Accept``. The targets answer without Vary.

    With ``negotiate_at_target``, every request goes to one target that negotiates. Otherwise
    text/html goes to /p.html and every other Accept value goes to /p.json.
    """

    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        html = request.headers.get("Accept", "") == "text/html"
        if request.path == RESOLVER_PATH:
            target = "/p" if negotiate_at_target else ("/p.html" if html else "/p.json")
            reply(request, 307, b"", {"Location": target, "Vary": "Accept"})
        elif request.path == "/p.html" or (request.path == "/p" and html):
            reply(request, 200, HTML, {"Content-Type": "text/html"})
        else:
            reply(request, 200, PASSPORT)

    return loopback(handle)


def test_a_carrier_that_negotiates_with_a_redirect_needs_no_vary_on_the_targets(
    tmp_path: Path, loopback: Any
) -> None:
    # Each target is its own resource, so a cache keys it by URL. Vary is judged per final URL.
    server = _redirecting(loopback, negotiate_at_target=False)
    _passed(run(resolved_context(tmp_path, "identifier.negotiation", server.origin)))


def test_answers_that_end_at_one_url_and_differ_need_vary(tmp_path: Path, loopback: Any) -> None:
    server = _redirecting(loopback, negotiate_at_target=True)
    outcome = run(resolved_context(tmp_path, "identifier.negotiation", server.origin))
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


def test_answers_that_end_at_one_url_after_a_location_that_the_readers_read_apart_need_vary(
    tmp_path: Path, loopback: Any
) -> None:
    # urljoin reads both Locations as /p. The record marks the first, and the mark is not another URL.
    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        html = request.headers.get("Accept", "") == "text/html"
        if request.path == RESOLVER_PATH:
            reply(request, 307, b"", {"Location": "/a\\b/../p" if html else "/p", "Vary": "Accept"})
        elif html:
            reply(request, 200, HTML, {"Content-Type": "text/html"})
        else:
            reply(request, 200, PASSPORT)

    outcome = run(resolved_context(tmp_path, "identifier.negotiation", loopback(handle).origin))
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


def test_a_url_that_redirects_one_request_and_serves_another_needs_vary(
    tmp_path: Path, loopback: Any
) -> None:
    # The F-72 shape: a cache of the carrier URL would serve the HTML page to a JSON client.
    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        if request.path == RESOLVER_PATH and request.headers.get("Accept", "") == "text/html":
            reply(request, 200, HTML, {"Content-Type": "text/html"})
        elif request.path == RESOLVER_PATH:
            reply(request, 307, b"", {"Location": "/p.json", "Vary": "Accept"})
        else:
            reply(request, 200, PASSPORT)

    outcome = run(resolved_context(tmp_path, "identifier.negotiation", loopback(handle).origin))
    _failed(outcome, "NEGOTIATION.VARY.MISSING")


def test_a_carrier_that_is_not_a_url_is_not_probed(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    ctx = resolved_context(
        tmp_path, "identifier.negotiation", api.origin, samples={"identifier": "urn:uuid:" + "0" * 32}
    )
    _blocked(run(ctx), "NEGOTIATION.NO_TARGET")
    assert api.server.seen == []


# -- the reference system: F-72 and F-73 ----------------------------------------------------------


def _cases() -> list[dict[str, Any]]:
    document = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    return [e for e in document["sut_faults"] if e["test_purpose"] == PURPOSE]


def _family_step(tmp_path: Path, faults: frozenset[str]) -> tuple[str, str]:
    from dppce.infrastructure.reference_server import ReferenceServer  # noqa: PLC0415 - test only

    with ReferenceServer(FIXTURES, faults=faults) as server:
        ics, ixit = _example(tmp_path, "web", server.origin)
        out = tmp_path / "run"
        _cli(
            [
                "run",
                "--profile", PROFILE,
                "--ics", str(ics),
                "--ixit", str(ixit),
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
    result = next(t for t in envelope.decision.test_results if t.test_purpose_id == PURPOSE)
    return result.verdict.value, result.reason_code


def test_the_catalogue_names_f72_and_f73() -> None:
    assert sorted(e["id"] for e in _cases()) == ["F-72", "F-73"]


def test_the_unmodified_reference_system_passes(tmp_path: Path) -> None:
    assert _family_step(tmp_path, frozenset()) == ("pass", "NEGOTIATION.OK")


@pytest.mark.parametrize("case", _cases(), ids=lambda c: str(c["id"]))
def test_each_seeded_fault_gives_the_catalogue_outcome(case: dict[str, Any], tmp_path: Path) -> None:
    expected = case["expected"]
    assert _family_step(tmp_path, frozenset({case["fault"]})) == (
        expected["verdict"],
        expected["reason_code"],
    )


def test_the_flags_change_only_a_request_with_a_negotiation_accept() -> None:
    plain = ReferenceSystem(FIXTURES, frozenset())
    request = Request("GET", RESOLVER_PATH, {"accept": "*/*"})
    for flag in ("negotiation_no_vary", "negotiation_wrong_type"):
        flagged = ReferenceSystem(FIXTURES, frozenset({flag}))
        assert flagged.respond(request) == plain.respond(request), flag
