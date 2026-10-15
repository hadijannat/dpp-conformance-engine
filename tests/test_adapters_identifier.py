"""The identifier adapter on a declared carrier identifier."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from dppce.adapters.identifier import parse
from dppce.models import ICS, IXIT, ExecutionStatus
from tests.test_adapters_security import _POLICY, _Canned, _context


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
