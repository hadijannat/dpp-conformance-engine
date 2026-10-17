"""data.rules reads a third-party passport with exact decimals (gap D3-05, criterion 1).

A binary float makes 0.1 and 0.10000000000000001 the same number, so data.rules parses the
passport with exact decimals. No decimal may reach an observation summary or the decision body:
canonical bodies hold strings, integers, booleans, and null only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.common import json_object
from dppce.adapters.data import Rule, rule_holds
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.envelope import decision_digest
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import IXIT, ExecutionMode, ExecutionStatus, Verdict
from dppce.orchestrator.run import RunInputs, evaluate  # noqa: TID251 - a run shows the decision body
from tests.core import builders as b
from tests.support import AT, make_record

NOW = datetime(2026, 10, 14, tzinfo=UTC)
URL = "http://127.0.0.1/dpp/P-1"
BASIS = {"class": "illustrative"}
SOH_RANGE = Rule.model_validate(
    {
        "id": "R-RANGE",
        "kind": "range",
        "document": "item",
        "field": "state_of_health_percent",
        "min": 0,
        "max": 100,
        "basis": BASIS,
    }
)


def relationship(op: str) -> Rule:
    fields = {"id": "R-REL", "kind": "relationship", "document": "item", "left": "a", "right": "b"}
    return Rule.model_validate(fields | {"op": op, "basis": BASIS})


def parsed(raw: str) -> dict[str, Any]:
    """Parse the body the way data.rules does, so no float is on the path."""
    document = json_object(make_record(1, raw.encode()), decimals=True)
    assert document is not None
    return document


@pytest.mark.parametrize(
    ("raw", "holds"),
    [
        ('{"state_of_health_percent": 97.5}', True),
        ('{"state_of_health_percent": 100.5}', False),
        ('{"state_of_health_percent": 100.0}', True),
        ('{"state_of_health_percent": 100.00000000000000001}', False),
        ('{"state_of_health_percent": 0.0}', True),
        ('{"state_of_health_percent": -0.5}', False),
        ('{"state_of_health_percent": 1E+2}', True),
        ('{"state_of_health_percent": 99}', True),
        ('{"state_of_health_percent": 101}', False),
        ('{"state_of_health_percent": "97.5"}', False),
        ('{"state_of_health_percent": true}', False),
    ],
)
def test_a_range_rule_with_integer_bounds_compares_a_decimal_exactly(raw: str, holds: bool) -> None:
    assert rule_holds(SOH_RANGE, parsed(raw), NOW) is holds


def test_the_parsed_decimal_is_exact_and_never_a_float() -> None:
    value = parsed('{"state_of_health_percent": 97.5}')["state_of_health_percent"]
    assert type(value) is Decimal
    assert value == Decimal("97.5")


@pytest.mark.parametrize(
    ("op", "holds"),
    [("eq", False), ("lt", True), ("le", True), ("ge", False), ("gt", False)],
)
def test_a_relationship_rule_tells_close_decimals_apart(op: str, holds: bool) -> None:
    # As binary floats the two numbers are equal; as exact decimals the left one is smaller.
    document = parsed('{"a": 0.1, "b": 0.10000000000000001}')
    assert rule_holds(relationship(op), document, NOW) is holds


def test_a_relationship_rule_compares_a_decimal_with_an_integer() -> None:
    assert rule_holds(relationship("le"), parsed('{"a": 74999.5, "b": 75000}'), NOW)
    assert not rule_holds(relationship("le"), parsed('{"a": 75000.5, "b": 75000}'), NOW)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"state_of_health_percent": NaN}',
        b'{"state_of_health_percent": Infinity}',
        b'{"state_of_health_percent": -Infinity}',
        b'{"state_of_health_percent": 1e999999999999999999999}',
        b'{"state_of_health_percent": 1.2.3}',
        b'{"state_of_health_percent": .5}',
        b'{"state_of_health_percent": 97.5, "state_of_health_percent": 1}',
    ],
)
def test_a_non_finite_or_malformed_number_is_refused(raw: bytes) -> None:
    assert json_object(make_record(1, raw), decimals=True) is None


def test_a_non_finite_decimal_never_satisfies_a_rule() -> None:
    """Defense in depth: a quiet NaN from a changed decimal context must not pass a range."""
    assert not rule_holds(SOH_RANGE, {"state_of_health_percent": Decimal("NaN")}, NOW)
    assert not rule_holds(SOH_RANGE, {"state_of_health_percent": Decimal("Infinity")}, NOW)
    nan = {"a": Decimal("NaN"), "b": Decimal("1")}
    assert not rule_holds(relationship("le"), nan, NOW)


def test_the_default_parser_of_other_checks_is_unchanged() -> None:
    """data.jsonschema and the other checks keep the float parser; only data.rules opts in."""
    document = json_object(make_record(1, b'{"state_of_health_percent": 97.5}'))
    assert document is not None
    assert type(document["state_of_health_percent"]) is float


# --- A whole run --------------------------------------------------------------------------


class OneRecordAcquirer:
    """Answers every request with the same passport body. It has no transport."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self._served: list[Record] = []

    def fetch(self, request: Request) -> Record:
        record = make_record(len(self._served) + 1, self._body, url=request.url)
        self._served.append(record)
        return record

    def artifact(self, name: str) -> Record:
        raise AssertionError(f"data.rules reads no artifact ({name})")

    def records(self) -> tuple[Record, ...]:
        return tuple(self._served)


def run_rules(tmp_path: Path, body: bytes) -> Any:
    rules = [SOH_RANGE, relationship("lt")]
    pack: dict[str, Any] = {
        "schema_version": "dppce.rulepack/1",
        "rulepack_id": "test/rules",
        "version": "1",
        "rules": [r.model_dump(mode="json", by_alias=True, exclude_none=True) for r in rules],
    }
    (tmp_path / "rules.json").write_text(json.dumps(pack), encoding="utf-8")
    purpose = b.purpose("T-1", stimulus={"check": "data.rules", "params": {"document": "item"}})
    inputs = RunInputs(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(rule_packs=["rules.json"]),
        catalogue=b.catalogue(b.pack(b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")]))),
        testpacks={"tp/a": b.purposes_pack(purpose)},
        ics=b.ics(),
        ixit=IXIT(
            schema_version="dppce.ixit/1",
            endpoints={"api": "http://127.0.0.1"},
            samples={"passport_id": "P-1"},
        ),
        data_root=tmp_path,
        evaluation_time=AT,
    )
    return evaluate(inputs, OneRecordAcquirer(body))


def _no_decimal_or_float(value: Any) -> bool:
    if isinstance(value, dict):
        return all(_no_decimal_or_float(v) for v in value.values())
    if isinstance(value, list | tuple):
        return all(_no_decimal_or_float(v) for v in value)
    return not isinstance(value, Decimal | float)


@pytest.mark.parametrize(
    ("body", "verdict", "reason_code"),
    [
        (
            b'{"state_of_health_percent": 97.5, "a": 0.1, "b": 0.10000000000000001}',
            Verdict.PASS,
            "DATA.RULES.OK",
        ),
        (b'{"state_of_health_percent": 100.5, "a": 0.1, "b": 0.1}', Verdict.FAIL, "DATA.RANGE.VIOLATED"),
    ],
)
def test_a_run_on_a_decimal_passport_gives_a_canonical_decision_body(
    tmp_path: Path, body: bytes, verdict: Verdict, reason_code: str
) -> None:
    decision = run_rules(tmp_path, body)
    (result,) = decision.test_results
    assert result.execution_status is ExecutionStatus.COMPLETED
    assert (result.verdict, result.reason_code) == (verdict, reason_code)
    (observation,) = result.observations
    assert _no_decimal_or_float(observation.summary)
    assert canonical_bytes(decision)
    assert decision_digest(decision).startswith("sha256:")
