"""A server error is no answer (owner decision of 2026-10-18).

An answer with a status from 500 to 599 counts like a connectivity failure. The check reports
``unreachable`` with ``TRANSPORT.SERVER_ERROR``, and the step verdict follows ``on_unreachable``:
inconclusive by default. Architecture contract, sections 7.1 and 9.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.access import restricted_fields
from dppce.adapters.common import fetch_once
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import CheckOutcome, ExecutionStatus, Verdict, VerdictRules
from dppce.verdicts import step_verdict
from tests.test_adapters_security import _POLICY, _Canned, _context
from tests.test_url_templates import Canned, context, ixit, run

IDENTIFIER = "https://id.example.test/01/09506000134352/21/EV0001"


class Status(Canned):
    """An acquirer that answers every request with one status and one body."""

    def __init__(self, status: int, body: bytes = b"{}") -> None:
        super().__init__(body)
        self._status = status

    def fetch(self, request: Request) -> Record:
        record = replace(super().fetch(request), status=self._status)
        self._records[-1] = record
        return record


# Each fetching check, with the parameters that it needs to reach its fetch.
FETCHING: list[tuple[str, dict[str, Any]]] = [
    ("data.jsonschema", {"document": "item"}),
    ("data.jsonschema", {"document": "model"}),
    ("data.context", {"allowed_contexts": ["https://example.test/c"]}),
    ("data.rules", {}),
    ("api.contract", {}),
    ("persistence.versions", {}),
    ("registry.consistency", {}),
    ("identifier.resolve", {}),
    ("identifier.consistency", {}),
]


def _fetching(tmp_path: Path, check: str, params: dict[str, Any], status: int) -> CheckOutcome:
    the_ixit = ixit(samples={"passport_id": "09506000134352-EV0001", "identifier": IDENTIFIER})
    ctx = context(tmp_path, check, params=params, the_ixit=the_ixit, acquirer=Status(status))
    return run(ctx)


@pytest.mark.parametrize(("check", "params"), FETCHING, ids=[f"{c}-{p}" for c, p in FETCHING])
def test_a_server_error_is_no_answer_for_each_fetching_check(
    check: str, params: dict[str, Any], tmp_path: Path
) -> None:
    outcome = _fetching(tmp_path, check, params, 503)
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )
    assert outcome.observations[0].summary == {"status": 503}
    assert "A connectivity failure does not prove a breach." in outcome.message
    verdict = step_verdict(outcome.status, outcome.passed, outcome.unreachable, VerdictRules())
    assert verdict is Verdict.INCONCLUSIVE
    approved = VerdictRules(on_unreachable="fail")
    assert step_verdict(outcome.status, outcome.passed, outcome.unreachable, approved) is Verdict.FAIL


@pytest.mark.parametrize(("status", "server_error"), [(499, False), (500, True), (599, True), (600, False)])
def test_the_server_error_range_is_500_to_599(status: int, server_error: bool, tmp_path: Path) -> None:
    outcome = _fetching(tmp_path, "data.jsonschema", {"document": "item"}, status)
    expected = ("TRANSPORT.SERVER_ERROR", True) if server_error else ("DATA.RESPONSE.STATUS", False)
    assert (outcome.reason_code, outcome.unreachable) == expected
    assert outcome.passed is False


def test_a_server_error_record_is_reused_and_not_fetched_again(tmp_path: Path) -> None:
    acquirer = Status(503)
    ctx = context(tmp_path, "data.jsonschema", acquirer=acquirer)
    first = fetch_once(ctx, "https://id.example.test/dpp/x")
    second = fetch_once(ctx, "https://id.example.test/dpp/x")
    assert second is first
    assert len(acquirer.records()) == 1, "a replay serves the same sequence of requests"


# -- access.restricted_fields: a 5xx answer is never evidence of enforcement (finding 2) ----------

CANARY_BODY = b'{"restricted": {"secret": "CANARY-test"}}'
FETCH_URL = "http://sut.example/dpp/09506000134352-EV0001"
SEARCH_URL = "http://sut.example/search?q=EV0001"
TWO_CHANNELS: dict[str, Any] = _POLICY | {"channels": {"fetch": "/dpp/{id}", "search": "/search?q={serial}"}}


def _server_error(outcome: CheckOutcome) -> None:
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


def test_an_entitled_fetch_with_a_server_error_is_no_answer(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(b"{}", status=503), role="authority"))
    _server_error(outcome)


def test_a_leak_in_a_server_error_body_still_fails(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(CANARY_BODY, status=503)))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (False, False, "ACCESS.LEAK.FETCH")


def test_a_server_error_on_a_withheld_only_channel_is_no_answer_not_pass(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, TWO_CHANNELS, _Canned(b"{}", status=503)))
    _server_error(outcome)
    assert outcome.reason_code != "ACCESS.POLICY.ENFORCED"
    assert outcome.observations[0].summary["role"] == "anonymous"


def test_a_server_error_does_not_stop_the_reading(tmp_path: Path) -> None:
    acquirer = _Canned(by_url={FETCH_URL: (503, b"{}"), SEARCH_URL: (200, CANARY_BODY)})
    outcome = restricted_fields(_context(tmp_path, TWO_CHANNELS, acquirer))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.SEARCH")
    assert len(acquirer.records()) == 2


def test_a_server_error_with_a_non_json_body_is_no_answer_not_not_json(tmp_path: Path) -> None:
    acquirer = _Canned(b"<html>maintenance</html>", "application/json", status=503)
    outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer))
    _server_error(outcome)
