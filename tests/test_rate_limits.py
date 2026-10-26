"""A rate-limited answer (HTTP 429) is no answer (P2-31, fault B-20).

A 429 counts like a 5xx answer: the check reports ``unreachable`` with ``TRANSPORT.RATE_LIMITED``,
and the step verdict follows ``on_unreachable``, inconclusive by default. A missing answer is set
aside, so it cannot hide a fail that another answer proves. The transport honors ``Retry-After``
with at most one bounded retry of a read. Architecture contract, sections 7.1 and 9.
Loopback servers and canned acquirers only.
"""

from __future__ import annotations

import http.server
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.access import restricted_fields
from dppce.adapters.integrity import jws_check
from dppce.infrastructure import transport as transport_module
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.models import CheckOutcome, ExecutionStatus, NetworkPolicy, TrustBundle, Verdict, VerdictRules
from dppce.verdicts import step_verdict
from tests.support import reply
from tests.test_adapters_aas_api import BASE, SHELL, UNKNOWN_SHELL, _ctx, _failed, _server, b64
from tests.test_adapters_did import _live
from tests.test_adapters_negotiation import HTML, Server, _check, _override
from tests.test_adapters_resolver import INVALID, RELATION, _conformance, _resolver
from tests.test_adapters_security import _POLICY, _Canned, _context
from tests.test_jose_profiles import Served, jose
from tests.test_resolved_target import RESOLVER_PATH, Origin, resolved_context
from tests.test_review_findings import Passport, integrity_context, pki, token  # noqa: F401 - pki is a fixture
from tests.test_server_errors import CANARY_BODY, FETCHING, _fetching
from tests.test_status_list_w3c import LIST_URL, Routes, check, credential, key, trust  # noqa: F401 - fixtures
from tests.test_transport import LOCAL, authorization
from tests.test_url_templates import Canned, context, run

NOW_CLOCK = FrozenClock(datetime(2026, 10, 13, 12, tzinfo=UTC))


def _rate_limited(outcome: CheckOutcome) -> None:
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.RATE_LIMITED",
    ), outcome.message
    assert "A connectivity failure does not prove a breach." in outcome.message


# -- every check that fetches -------------------------------------------------------------------


@pytest.mark.parametrize(("check", "params"), FETCHING, ids=[f"{c}-{p}" for c, p in FETCHING])
def test_a_rate_limited_answer_is_no_answer_for_each_fetching_check(
    check: str, params: dict[str, Any], tmp_path: Path
) -> None:
    outcome = _fetching(tmp_path, check, params, 429)
    _rate_limited(outcome)
    assert outcome.observations[0].summary == {"status": 429}
    assert step_verdict(outcome.status, outcome.passed, outcome.unreachable, VerdictRules()) is (
        Verdict.INCONCLUSIVE
    )


def test_a_rate_limited_resolve_is_not_a_resolution_fail(tmp_path: Path) -> None:
    # Before P2-31 a 429 gave the false fail IDENTIFIER.RESOLUTION.STATUS.
    outcome = _fetching(tmp_path, "identifier.resolve", {}, 429)
    _rate_limited(outcome)


def test_a_server_error_keeps_its_own_code(tmp_path: Path) -> None:
    outcome = _fetching(tmp_path, "identifier.resolve", {}, 503)
    assert (outcome.reason_code, outcome.unreachable) == ("TRANSPORT.SERVER_ERROR", True)


def test_a_rate_limited_signed_passport_is_no_answer(pki: dict[str, Any]) -> None:  # noqa: F811 - fixture
    item, signed = b'{"a":1}', token(pki["header"], b'{"a":1}', pki["leaf"][0])
    _rate_limited(jws_check(integrity_context(Passport(signed, item, status=429), pki["trust"])))


def test_a_rate_limited_signed_resource_is_no_answer_for_jose(
    tmp_path: Path,
    trust: TrustBundle,  # noqa: F811 - fixture
) -> None:
    _rate_limited(jose(tmp_path, Served(b"{}", status=429), trust))


def test_a_rate_limited_did_document_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    _rate_limited(_live(tmp_path, loopback, (429, b"{}", {})))


def test_a_rate_limited_linkset_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {RESOLVER_PATH: (429, b"{}", {})})
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    _rate_limited(run(ctx))


def test_a_rate_limited_conformance_probe_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes.update(_resolver(api.origin) | {INVALID: (429, b"{}", {})})
    _rate_limited(_conformance(tmp_path, api))


# -- negotiation: one probe is rate limited, the others are still judged -------------------------


def test_a_rate_limited_negotiation_probe_does_not_hide_a_fail(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    html = {"Content-Type": "text/html", "Vary": "Accept"}
    _override(api, lambda a: (429, b"", {}) if "x-dppce-unsupported" in a else (200, HTML, html))
    outcome = _check(tmp_path, api)
    expected = (False, False, "NEGOTIATION.MEDIA_TYPE")
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == expected


def test_a_rate_limited_negotiation_probe_alone_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    api = Server(loopback)
    _override(api, lambda a: (429, b"", {}) if "x-dppce-unsupported" in a else None)
    _rate_limited(_check(tmp_path, api))


# -- persistence: a rate-limited history does not hide a status fail of the item ------------------


class _Statuses(Canned):
    """An acquirer that answers the requests with the given statuses, in order."""

    def __init__(self, *statuses: int) -> None:
        super().__init__(b"{}")
        self._statuses = list(statuses)

    def fetch(self, request: Request) -> Record:
        record = replace(super().fetch(request), status=self._statuses.pop(0))
        self._records[-1] = record
        return record


@pytest.mark.parametrize("statuses", [(429, 418), (418, 429), (503, 418)])
def test_a_missing_version_answer_does_not_hide_a_status_fail(
    statuses: tuple[int, int], tmp_path: Path
) -> None:
    outcome = run(context(tmp_path, "persistence.versions", acquirer=_Statuses(*statuses)))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        False,
        "PERSISTENCE.RESPONSE.STATUS",
    )


def test_a_rate_limited_version_history_alone_is_no_answer(tmp_path: Path) -> None:
    _rate_limited(run(context(tmp_path, "persistence.versions", acquirer=_Statuses(429, 200))))


# -- status list and AAS ---------------------------------------------------------------------------


def test_a_rate_limited_status_list_is_no_answer(
    tmp_path: Path,
    key: Any,  # noqa: F811 - fixture
    trust: TrustBundle,  # noqa: F811 - fixture
) -> None:
    _rate_limited(check(tmp_path, Routes(credential(key), {LIST_URL: (429, b"")}), trust))


def test_a_rate_limited_aas_probe_does_not_hide_a_fail(tmp_path: Path, loopback: Any) -> None:
    limit = {f"{BASE}/description": (429, b"{}")}
    unknown = {f"{BASE}/shells/{b64(UNKNOWN_SHELL)}": (200, b"{}")}
    _failed(run(_ctx(tmp_path, _server(loopback, limit | unknown).origin)), "unknown_id_status")


def test_a_rate_limited_aas_probe_alone_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback, {f"{BASE}/shells/{b64(SHELL)}": (429, b"{}")})
    _rate_limited(run(_ctx(tmp_path, server.origin)))


# -- access probes: a 429 body is still searched for a leak --------------------------------------


def test_a_rate_limited_entitled_fetch_is_no_answer(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(b"{}", status=429), role="authority"))
    _rate_limited(outcome)


def test_a_leak_in_a_rate_limited_body_still_fails(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(CANARY_BODY, status=429)))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (False, False, "ACCESS.LEAK.FETCH")


# -- transport: Retry-After --------------------------------------------------------------------


def _answers(*replies: tuple[int, dict[str, str]]) -> Callable[[http.server.BaseHTTPRequestHandler], None]:
    """A handler that gives the replies in order and repeats the last one."""
    left = list(replies)

    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        status, headers = left.pop(0) if len(left) > 1 else left[0]
        reply(request, status, b"{}", headers)

    return handle


def _engine(waits: list[float], **policy: Any) -> PolicyTransport:
    config = TransportConfig(policy=NetworkPolicy(**(LOCAL | policy)), engine_version="1")
    return PolicyTransport(config, NOW_CLOCK, sleep=waits.append, monotonic=lambda: 0.0)


def test_the_cap_is_five_seconds() -> None:
    assert transport_module.RETRY_AFTER_CAP_SECONDS == 5


def test_a_retry_after_within_the_cap_gives_one_retry(loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": "2"}), (200, {})))
    waits: list[float] = []
    record = _engine(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts, record.error) == (200, 2, None)
    assert waits == [2.0]
    assert len(server.seen) == 2


def test_a_second_429_is_not_retried_again(loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": "1"})))
    waits: list[float] = []
    record = _engine(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts) == (429, 2)
    assert waits == [1.0]


# The 5000-digit values exceed the integer conversion limit of Python: no exception, no wait.
@pytest.mark.parametrize(
    "value", ["6", "3600", "Wed, 21 Oct 2026 07:28:00 GMT", "-1", "", "9" * 5000, "0" * 4999 + "9"]
)
def test_a_retry_after_beyond_the_cap_or_not_a_number_is_not_waited_for(value: str, loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": value}), (200, {})))
    waits: list[float] = []
    record = _engine(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts) == (429, 1)
    assert waits == []
    assert len(server.seen) == 1


def test_a_retry_after_beyond_the_total_time_is_not_waited_for(loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": "2"}), (200, {})))
    waits: list[float] = []
    record = _engine(waits, total_timeout_ms=1000).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts, waits) == (429, 1, [])


def test_a_retry_after_beyond_the_request_budget_is_not_waited_for(loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": "1"}), (200, {})))
    waits: list[float] = []
    record = _engine(waits, max_requests=1).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts, record.error, waits) == (429, 1, None, [])


def test_a_write_is_never_retried(loopback: Any) -> None:
    server = loopback(_answers((429, {"Retry-After": "1"}), (200, {})))
    waits: list[float] = []
    config = TransportConfig(
        policy=NetworkPolicy(**LOCAL),
        engine_version="1",
        authorization=authorization(endpoints=(server.origin,)),
    )
    engine = PolicyTransport(config, NOW_CLOCK, sleep=waits.append, monotonic=lambda: 0.0)
    record = engine.fetch(Request("POST", f"{server.origin}/x", body=b"1"))
    assert (record.status, record.attempts, waits) == (429, 1, [])
    assert len(server.seen) == 1


def test_a_server_error_with_retry_after_is_not_retried(loopback: Any) -> None:
    server = loopback(_answers((503, {"Retry-After": "1"}), (200, {})))
    waits: list[float] = []
    record = _engine(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts, waits) == (503, 1, [])


# -- fault B-20: the reference resolver answers 429 ---------------------------------------------


def test_flag_resolver_rate_limited_answers_the_default_request_with_429(tmp_path: Path) -> None:
    with ReferenceServer(FIXTURES, faults=frozenset({"resolver_rate_limited"})) as server:
        ctx = resolved_context(tmp_path, "identifier.resolve", server.origin)
        outcome = run(ctx)
        records: tuple[Record, ...] = ctx.acquirer.records()
    _rate_limited(outcome)
    assert records[0].status == 429
    # The transport waits once for Retry-After 1, and the resolver answers 429 again.
    assert records[0].attempts == 2


def test_flag_resolver_rate_limited_keeps_the_linkset_request() -> None:
    with ReferenceServer(FIXTURES, faults=frozenset({"resolver_rate_limited"})) as server:
        engine = PolicyTransport(
            TransportConfig(policy=NetworkPolicy(**LOCAL), engine_version="1"),
            NOW_CLOCK,
            sleep=lambda _: None,
        )
        default = engine.fetch(Request("GET", server.origin + RESOLVER_PATH))
        linkset = engine.fetch(Request("GET", server.origin + RESOLVER_PATH + "?linkType=linkset"))
    assert (default.status, default.header("retry-after") is not None) == (429, True)
    assert linkset.status == 200
