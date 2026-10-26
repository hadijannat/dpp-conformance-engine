"""identifier.parse for the schemes https-url, did-web, and urn-uuid."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from validation import cases
from validation.rig import ReferenceRig

from dppce.adapters.identifier import parse
from dppce.models import ICS, IXIT, CheckOutcome, ExecutionStatus
from tests.test_adapters_identifier import _parse
from tests.test_adapters_security import _POLICY, _Canned, _context

_UUID = "123e4567-e89b-12d3-a456-426614174000"


def _status(outcome: CheckOutcome) -> tuple[ExecutionStatus, bool | None, str]:
    return outcome.status, outcome.passed, outcome.reason_code


_OK = (ExecutionStatus.COMPLETED, True, "IDENTIFIER.SYNTAX.OK")
_BAD = (ExecutionStatus.COMPLETED, False, "IDENTIFIER.SYNTAX.INVALID")


@pytest.mark.parametrize(
    ("scheme", "identifier", "expected"),
    [
        ("https-url", "https://id.example.test/p/1?x=1", _OK),
        ("https-url", "HTTPS://id.example.test:8443/a%20b", _OK),
        ("https-url", "https://user@id.example.test/p/1", _BAD),
        ("https-url", "https://user:pw@id.example.test/p/1", _BAD),
        ("https-url", "https://id.example.test/p/1#frag", _BAD),
        ("https-url", "http://id.example.test/p/1", _BAD),
        ("https-url", "https://127.0.0.1/p/1", _BAD),
        ("https-url", "https://127.1/p/1", _BAD),
        ("https-url", "https://[2001:db8::1]/p/1", _BAD),
        ("https-url", "https://id.example.test:99999/p", _BAD),
        ("https-url", "https://id.example.test%3A8080/p", _BAD),
        ("https-url", "https://id.example.test%3a1:443/p", _BAD),
        ("https-url", "https://id.example.test./p", _OK),
        ("https-url", "https://id.example.test../p", _BAD),
        ("https-url", "https://id.example.test/a b", _BAD),
        ("https-url", "urn:uuid:" + _UUID, _BAD),
        ("did-web", "did:web:id.example.test", _OK),
        ("did-web", "did:web:id.example.test:issuers:1", _OK),
        ("did-web", "did:web:127.0.0.1", _BAD),
        ("did-web", "did:web:127.1", _BAD),
        ("did-web", "did:key:z6Mk", _BAD),
        ("did-web", "https://id.example.test", _BAD),
        ("urn-uuid", "urn:uuid:" + _UUID, _OK),
        ("urn-uuid", "urn:uuid:" + _UUID.upper(), _OK),
        ("urn-uuid", _UUID, _BAD),
        ("urn-uuid", "urn:uuid:" + _UUID[:-1], _BAD),
        ("urn-uuid", "urn:uuid:{" + _UUID + "}", _BAD),
        ("urn-uuid", "urn:uuid:" + _UUID.replace("e", "g", 1), _BAD),
        ("urn-uuid", "urn:uuid:" + _UUID.replace("1", chr(0x661)), _BAD),
        ("urn-uuid", "urn:uuid:" + _UUID + "\n", _BAD),
    ],
)
def test_each_declared_scheme_has_a_parser(
    scheme: str, identifier: str, expected: tuple[ExecutionStatus, bool, str], tmp_path: Path
) -> None:
    outcome = _parse(tmp_path, {"identifier": identifier}, scheme=scheme)
    assert _status(outcome) == expected
    assert identifier not in str(outcome.observations[0].summary)


def test_a_payload_that_does_not_match_the_scheme_is_a_fail_never_blocked(tmp_path: Path) -> None:
    outcome = _parse(tmp_path, {"identifier": "not a url"}, scheme="https-url")
    assert _status(outcome) == _BAD
    assert outcome.observations[0].summary.get("reason")


def test_require_https_fails_a_valid_urn_uuid(tmp_path: Path) -> None:
    base = _parse(tmp_path, {"identifier": "urn:uuid:" + _UUID}, scheme="urn-uuid")
    assert _status(base) == _OK
    outcome = _with_params(tmp_path, "urn:uuid:" + _UUID, "urn-uuid", {"require_https": True})
    assert _status(outcome) == (ExecutionStatus.COMPLETED, False, "IDENTIFIER.SCHEME.NOT_HTTPS")


def test_the_gs1_form_does_not_apply_to_another_scheme(tmp_path: Path) -> None:
    outcome = _with_params(tmp_path, "https://id.example.test/p", "https-url", {"form": "gs1-dl"})
    assert _status(outcome) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.PARAMS.INVALID")


def test_gs1_unknown_and_other_schemes_keep_their_behavior(tmp_path: Path) -> None:
    gs1 = "https://id.example.test/01/09506000134352/21/EV0001"
    assert _status(_parse(tmp_path, {"identifier": gs1})) == _OK
    unknown = _parse(tmp_path, {"identifier": gs1}, scheme="unknown")
    assert _status(unknown) == (ExecutionStatus.BLOCKED, None, "IDENTIFIER.SCHEME.UNKNOWN")
    other = _parse(tmp_path, {"identifier": gs1}, scheme="epc-tds")
    assert _status(other) == (ExecutionStatus.UNSUPPORTED, None, "IDENTIFIER.SCHEME.UNSUPPORTED")


def _with_params(tmp_path: Path, identifier: str, scheme: str, params: dict[str, object]) -> CheckOutcome:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    ics = ICS.model_validate(base.ics.model_dump(mode="json") | {"identifier_scheme": scheme})
    ixit = IXIT.model_validate(base.ixit.model_dump(mode="json") | {"samples": {"identifier": identifier}})
    stimulus = base.purpose.stimulus.model_copy(update={"params": params})
    purpose = base.purpose.model_copy(update={"stimulus": stimulus})
    return parse(replace(base, ics=ics, ixit=ixit, purpose=purpose))


# -- the reference system: control C-FAMILY-WEB and F-71 ------------------------------------------

_PURPOSE = "TP-WEB-IDENTIFIER-001"


def test_the_web_control_passes_the_identifier_syntax_step(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, "family/web") as rig:
        run = rig.run()
    assert (run.step(_PURPOSE)["verdict"], run.step(_PURPOSE)["reason_code"]) == (
        "pass",
        "IDENTIFIER.SYNTAX.OK",
    )


def test_f71_gives_the_catalogue_outcome(tmp_path: Path) -> None:
    case = next(c for c in cases.sut_faults() if c.id == "F-71")
    assert case.test_purpose == _PURPOSE
    with ReferenceRig(tmp_path, "family/web", faults=case.faults, **case.rig) as rig:
        run = rig.run()
    step = run.step(_PURPOSE)
    assert (step["verdict"], step["reason_code"]) == ("fail", "IDENTIFIER.SYNTAX.INVALID")
