"""The resolved item target (gap D4-05, architecture section 9.2).

With ``IXIT.item_target: resolved``, api.contract, the data checks, and integrity.jws fetch the
item from the URL that the carrier resolves to. The transport policy still applies to that URL,
so the system under test cannot steer a request to an origin that the operator did not confirm.
Loopback servers only.
"""

from __future__ import annotations

import http.server
import io
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.common import item_url
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import CheckOutcome, ExecutionStatus
from dppce.testdefs.registry import CheckContext
from tests import test_review_findings
from tests.support import make_artifact, reply
from tests.test_review_findings import b64u, token, transport
from tests.test_url_templates import REFERENCE, Canned, context, ixit, run

pki = test_review_findings.pki  # the module fixture of the integrity tests

ID = "09506000134352-EV0001"
RESOLVER_PATH = "/01/09506000134352/21/EV0001"
ITEM_PATH = f"/dpp/{ID}"
PASSPORT = b'{"id": "x", "version": 3}'
NARROW = {"allowed_hosts": ("127.0.0.1",), "allow_private_hosts": ("127.0.0.1",)}
Route = tuple[int, bytes, dict[str, str]]


class Origin:
    """A loopback origin that answers from a table of paths. Every other path is not found."""

    def __init__(self, loopback: Any, routes: dict[str, Route] | None = None) -> None:
        self.routes = dict(routes or {})

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            status, body, headers = self.routes.get(request.path, (404, b'{"error": "not_found"}', {}))
            reply(request, status, body, headers)

        self.server = loopback(handle)
        self.origin: str = self.server.origin

    def hits(self, path: str) -> int:
        return sum(1 for seen in self.server.seen if seen["path"] == path)


def moved(target: str) -> Route:
    return 303, b"", {"Location": target, "Content-Type": "text/plain"}


def served(body: bytes = PASSPORT) -> Route:
    return 200, body, {}


def resolved_context(
    tmp_path: Path,
    check: str,
    origin: str,
    *,
    params: dict[str, Any] | None = None,
    samples: dict[str, str] | None = None,
    policy: dict[str, Any] | None = None,
    trust: Any = None,
    acquirer: Any = None,
) -> CheckContext:
    chosen = {"identifier": origin + RESOLVER_PATH} if samples is None else samples
    the_ixit = ixit(
        endpoints={"api": origin, "registry": origin},
        samples={"passport_id": ID, **chosen},
        resources=REFERENCE,
        item_target="resolved",
    )
    engine = transport(policy) if acquirer is None else acquirer
    return context(tmp_path, check, params=params, the_ixit=the_ixit, acquirer=engine, trust=trust)


def template_mode(ctx: CheckContext) -> CheckContext:
    return replace(ctx, ixit=ctx.ixit.model_copy(update={"item_target": "template"}))


def _blocked(outcome: CheckOutcome | str, code: str) -> None:
    assert isinstance(outcome, CheckOutcome)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def _no_answer(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        code,
    )


# -- the data checks ------------------------------------------------------------------------------


def test_the_data_check_fetches_the_url_that_the_carrier_resolves_to(tmp_path: Path, loopback: Any) -> None:
    published = Origin(loopback, {ITEM_PATH: served()})
    api = Origin(loopback, {RESOLVER_PATH: moved(published.origin + ITEM_PATH), ITEM_PATH: served()})
    outcome = run(resolved_context(tmp_path, "data.jsonschema", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "DATA.SCHEMA.OK")
    assert api.hits(ITEM_PATH) == 0, "the item template is not used"
    assert published.hits(ITEM_PATH) == 2, "once in the resolver exchange, once fetched again"


def test_the_template_mode_does_not_resolve(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {ITEM_PATH: served()})
    outcome = run(template_mode(resolved_context(tmp_path, "data.jsonschema", api.origin)))
    assert outcome.reason_code == "DATA.SCHEMA.OK"
    assert [seen["path"] for seen in api.server.seen] == [ITEM_PATH]


@pytest.mark.parametrize("check", ["data.jsonschema", "data.rules", "api.contract"])
def test_a_redirect_to_an_unconfirmed_origin_is_never_fetched(
    check: str, tmp_path: Path, loopback: Any
) -> None:
    elsewhere = Origin(loopback, {ITEM_PATH: served()})
    target = f"http://localhost:{elsewhere.server.port}{ITEM_PATH}"
    api = Origin(loopback, {RESOLVER_PATH: moved(target), ITEM_PATH: served()})
    _no_answer(
        run(resolved_context(tmp_path, check, api.origin, policy=NARROW)), "TRANSPORT.REDIRECT_OUT_OF_SCOPE"
    )
    assert elsewhere.server.seen == [], "the origin that the operator did not confirm gets no request"
    assert api.hits(ITEM_PATH) == 0


def test_a_resolver_404_gives_no_target_not_a_fail(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {ITEM_PATH: served()})
    _blocked(run(resolved_context(tmp_path, "data.jsonschema", api.origin)), "DATA.NO_TARGET")
    assert api.hits(ITEM_PATH) == 0


def test_a_resolver_5xx_gives_server_error(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {RESOLVER_PATH: (503, b'{"error": "unavailable"}', {}), ITEM_PATH: served()})
    _no_answer(run(resolved_context(tmp_path, "data.jsonschema", api.origin)), "TRANSPORT.SERVER_ERROR")
    assert api.hits(ITEM_PATH) == 0


@pytest.mark.parametrize("identifier", ["not a url", "urn:epc:id:sgtin:0614141.107346.2017", "http://[::1"])
def test_a_carrier_that_is_not_a_url_gives_no_target_and_sends_nothing(
    identifier: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback, {ITEM_PATH: served()})
    params = {"allowed_contexts": ["https://example.test/c"]}
    ctx = resolved_context(
        tmp_path, "data.context", api.origin, params=params, samples={"identifier": identifier}
    )
    _blocked(run(ctx), "DATA.NO_TARGET")
    assert api.server.seen == []


def test_a_missing_carrier_sample_keeps_its_outcome(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {ITEM_PATH: served()})
    _blocked(
        run(resolved_context(tmp_path, "data.jsonschema", api.origin, samples={})), "CARRIER.SAMPLE.MISSING"
    )
    assert api.server.seen == []


def test_a_redirect_with_a_redacted_query_is_not_fetched(tmp_path: Path, loopback: Any) -> None:
    query = "?token=TEST-ONLY-secret-value"
    published = Origin(loopback, {ITEM_PATH + query: served()})
    api = Origin(loopback, {RESOLVER_PATH: moved(published.origin + ITEM_PATH + query)})
    ctx = resolved_context(tmp_path, "data.jsonschema", api.origin)
    _blocked(run(ctx), "DATA.NO_TARGET")
    (resolver,) = ctx.acquirer.records()
    assert "%3Cremoved%3E" in resolver.redirects[-1]
    assert len(published.server.seen) == 1, "only the resolver exchange reached the redirect target"


class _Redirected(Canned):
    """A resolver record whose redirect target holds the plain redaction marker."""

    def fetch(self, request: Request) -> Record:
        record = replace(super().fetch(request), redirects=("http://127.0.0.1/dpp/<removed>",))
        self._records[-1] = record
        return record


def test_a_url_with_the_plain_removed_marker_is_not_fetched(tmp_path: Path) -> None:
    acquirer = _Redirected()
    ctx = resolved_context(tmp_path, "data.jsonschema", "http://127.0.0.1", acquirer=acquirer)
    _blocked(item_url(ctx, "DATA"), "DATA.NO_TARGET")
    assert len(acquirer.records()) == 1


def test_a_resolver_that_answers_200_directly_needs_one_request(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {RESOLVER_PATH: served(), ITEM_PATH: served(b'{"other": true}')})
    outcome = run(resolved_context(tmp_path, "data.jsonschema", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "DATA.SCHEMA.OK")
    assert [seen["path"] for seen in api.server.seen] == [RESOLVER_PATH]


# -- api.contract ---------------------------------------------------------------------------------


def test_api_contract_uses_the_resolved_url_and_says_so(tmp_path: Path, loopback: Any) -> None:
    routes = {RESOLVER_PATH: moved(ITEM_PATH), ITEM_PATH: served(), f"{ITEM_PATH}/model": served()}
    api = Origin(loopback, routes)
    outcome = run(resolved_context(tmp_path, "api.contract", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")
    summary = outcome.observations[0].summary
    assert (summary["path"], summary["item_target"], summary["fetched_path"]) == (
        "/dpp/{id}",
        "resolved",
        ITEM_PATH,
    )
    model = run(resolved_context(tmp_path, "api.contract", api.origin, params={"resource": "model"}))
    assert (model.passed, model.reason_code) == (True, "API.CONTRACT.OK")
    assert "item_target" not in model.observations[0].summary, "the model resource keeps its template"
    assert api.hits(f"{ITEM_PATH}/model") == 1


def test_api_contract_in_template_mode_keeps_its_summary(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {ITEM_PATH: served()})
    outcome = run(template_mode(resolved_context(tmp_path, "api.contract", api.origin)))
    assert sorted(outcome.observations[0].summary) == ["media_type", "path", "resource", "status"]


@pytest.mark.parametrize(
    "where",
    [
        "same origin, other path",
        "other origin, same path",
        "empty segment",
        "dot segment",
        "encoded dot segment",
    ],
)
def test_api_contract_refuses_a_resolved_url_off_the_marked_operation(
    where: str, tmp_path: Path, loopback: Any
) -> None:
    other = Origin(loopback, {ITEM_PATH: served()})
    off_paths = ["/static/passport.json", f"/static/dpp/{ID}", "/dpp/..", "/dpp/%2e%2e"]
    api = Origin(loopback, {ITEM_PATH: served(), **{path: served() for path in off_paths}})
    target = {
        "same origin, other path": f"{api.origin}/static/passport.json",
        "other origin, same path": other.origin + ITEM_PATH,
        # The remainder //static/dpp/{ID} must not parse as the host "static" with the path /dpp/{ID}.
        "empty segment": f"/.//static/dpp/{ID}",
        # A real server normalizes these paths to /, which is not the marked operation.
        "dot segment": f"{api.origin}/dpp/..",
        "encoded dot segment": f"{api.origin}/dpp/%2e%2e",
    }[where]
    api.routes[RESOLVER_PATH] = moved(target)
    _blocked(run(resolved_context(tmp_path, "api.contract", api.origin)), "API.CONTRACT.PATH_MISMATCH")
    requests = len(api.server.seen) + len(other.server.seen)
    assert requests == 2, "only the resolver exchange: the resolver and its redirect target"
    assert api.hits(ITEM_PATH) == 0


# -- integrity.jws --------------------------------------------------------------------------------


def _signed(pki: dict[str, Any], payload: bytes) -> Route:
    return 200, token(pki["header"], payload, pki["leaf"][0]).encode(), {"Content-Type": "application/jose"}


@pytest.mark.parametrize(
    ("published", "code"),
    [(PASSPORT, "INTEGRITY.OK"), (b'{"id": "x", "version": 4}', "INTEGRITY.PAYLOAD.MISMATCH")],
)
def test_integrity_compares_the_signed_payload_with_the_resolved_passport(
    published: bytes, code: str, pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    elsewhere = Origin(loopback, {ITEM_PATH: served(published)})
    routes = {
        f"{ITEM_PATH}/signed": _signed(pki, PASSPORT),
        RESOLVER_PATH: moved(elsewhere.origin + ITEM_PATH),
    }
    api = Origin(loopback, {**routes, ITEM_PATH: served(PASSPORT)})
    outcome = run(resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"]))
    assert outcome.reason_code == code
    assert api.hits(ITEM_PATH) == 0, "the item template is not used"


def test_a_resolver_failure_does_not_hide_an_invalid_signature(
    pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    header, _, signature = token(pki["header"], PASSPORT, pki["leaf"][0]).split(".")
    forged = f"{header}.{b64u(b'{"id": "y"}')}.{signature}".encode()
    routes = {
        f"{ITEM_PATH}/signed": (200, forged, {"Content-Type": "application/jose"}),
        RESOLVER_PATH: (503, b"{}", {}),
    }
    api = Origin(loopback, routes)
    outcome = run(resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"]))
    assert (outcome.passed, outcome.reason_code) == (False, "INTEGRITY.SIGNATURE.INVALID")
    assert api.hits(RESOLVER_PATH) == 0, "the signature is judged before the resolver is asked"


def test_a_resolver_failure_after_a_valid_signature_is_no_answer(
    pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback, {f"{ITEM_PATH}/signed": _signed(pki, PASSPORT), RESOLVER_PATH: (503, b"{}", {})})
    outcome = run(resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"]))
    _no_answer(outcome, "TRANSPORT.SERVER_ERROR")


# -- a QR carrier ---------------------------------------------------------------------------------


class _BlankImage(Canned):
    """A carrier image with no QR symbol. Nothing is fetched."""

    def fetch(self, request: Request) -> Record:
        raise AssertionError("a carrier that fails its own check gives no URL to fetch")

    def artifact(self, name: str) -> Record:
        from PIL import Image  # noqa: PLC0415 - optional dependency of the `qr` extra

        buffer = io.BytesIO()
        Image.new("L", (64, 64), 255).save(buffer, format="PNG")
        return make_artifact(name, buffer.getvalue())


@pytest.mark.qr
@pytest.mark.parametrize(("check", "area"), [("data.jsonschema", "DATA"), ("api.contract", "API.CONTRACT")])
def test_a_qr_carrier_that_fails_its_own_check_gives_no_target(check: str, area: str, tmp_path: Path) -> None:
    ctx = resolved_context(
        tmp_path, check, "http://127.0.0.1", samples={"qr_image": "qr.png"}, acquirer=_BlankImage()
    )
    _blocked(run(ctx), f"{area}.NO_TARGET")
