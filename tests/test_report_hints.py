"""Report explanations: what would make a step conclusive, and a remediation for a fail.

The hints are render-only. They never enter the canonical decision body, so a report renders
with or without them and keeps the same decision digest. Every envelope here is synthetic.
"""

from __future__ import annotations

import importlib
import os
from typing import Any
from unittest import mock

import pytest

from dppce.evidence.envelope import decision_digest
from dppce.models import (
    EvidenceEnvelope,
    Exclusion,
    ExecutionMode,
    ExecutionStatus,
    RequirementResult,
    TestResult,
)
from dppce.report import render
from dppce.report.hints import (
    BY_STATUS,
    HINTS,
    NO_INTERPRETATION,
    NOT_APPROVED,
    hint_for_code,
    hint_for_step,
    requirement_hint,
)
from tests.support import make_envelope, make_requirement_result

# The generator sets COLUMNS at import time; keep the test process environment unchanged.
with mock.patch.dict(os.environ):
    gen = importlib.import_module("scripts.gen_reference_docs")

# P2-31 adds this code in the same wave. Remove the entry after the merge.
PENDING = frozenset({"TRANSPORT.RATE_LIMITED"})
SENTINEL = "SENTINEL-PAYLOAD-VALUE-7731"


def _codes() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for site in gen.extract_reason_codes(gen.source_modules(), gen.code_families()):
        found.setdefault(site.code, set()).add(site.effect or "not fixed here")
    return found


def _step(status: str, verdict: str, code: str, summary: dict[str, Any] | None = None) -> TestResult:
    observations = []
    if summary is not None:
        observations = [
            {
                "id": "o1",
                "test_purpose_id": "TP-009",
                "kind": "exchange",
                "acquired_at": "2026-10-13T12:00:00Z",
                "summary": summary,
            }
        ]
    return TestResult.model_validate(
        {
            "test_purpose_id": "TP-009",
            "requirement_ids": ["ILL-009"],
            "check": "data.rules",
            "applicability": "true",
            "applicability_reason": "always",
            "execution_status": status,
            "verdict": verdict,
            "severity": "major",
            "reason_code": code,
            "message": "test",
            "observations": observations,
        }
    )


def _envelope(*steps: TestResult, exclusions: tuple[Exclusion, ...] = ()) -> EvidenceEnvelope:
    envelope = make_envelope(("pass",))
    decision = envelope.decision.model_copy(
        update={"test_results": (*envelope.decision.test_results, *steps), "exclusions": exclusions}
    )
    return envelope.model_copy(update={"decision": decision})


def test_every_reason_code_that_the_generator_finds_has_a_hint() -> None:
    # A new code without an entry fails here. Add it to HINTS in dppce.report.hints.
    missing = sorted(code for code in _codes() if hint_for_code(code) is None)
    assert missing == []


def test_every_hint_names_a_known_reason_code() -> None:
    # A typo or a removed code leaves a dead entry. A dead entry hides a missing hint.
    assert sorted(set(HINTS) - set(_codes()) - PENDING) == []


def test_every_hint_is_one_short_plain_line() -> None:
    for code, text in HINTS.items():
        assert text.strip() == text, code
        assert text.endswith("."), code
        assert "\n" not in text, code
        assert len(text) <= 200, code
        assert not gen.CODE.search(text), f"{code}: a hint must not name a reason code"


def test_a_step_with_an_unknown_code_falls_back_to_its_execution_status() -> None:
    for status in ExecutionStatus:
        if status is ExecutionStatus.COMPLETED:
            continue
        verdict = "error" if status is ExecutionStatus.ERROR else "inconclusive"
        hint = hint_for_step(_step(status.value, verdict, "UNKNOWN.NEW.CODE"))
        assert hint is not None
        assert hint.text == BY_STATUS[status], status


def test_a_completed_inconclusive_step_with_an_unknown_code_has_a_fallback() -> None:
    hint = hint_for_step(_step("completed", "inconclusive", "UNKNOWN.NEW.CODE"))
    assert hint is not None
    assert hint.text == BY_STATUS[ExecutionStatus.COMPLETED]


def test_a_pass_code_on_a_step_that_did_not_pass_gets_its_status_text() -> None:
    # A passed check with an unreachable flag is inconclusive. "None: the step passed" is false then.
    hint = hint_for_step(_step("completed", "inconclusive", "DATA.RULES.OK"))
    assert hint is not None
    assert hint.text == BY_STATUS[ExecutionStatus.COMPLETED]


def test_a_passing_step_has_no_hint() -> None:
    assert hint_for_step(_step("completed", "pass", "DATA.RULES.OK")) is None


def test_a_fail_gives_a_remediation_and_an_inconclusive_gives_a_next_step() -> None:
    failed = hint_for_step(_step("completed", "fail", "DATA.SCHEMA.INVALID"))
    assert failed is not None
    assert failed.kind == "remediation"
    assert failed.text == HINTS["DATA.SCHEMA.INVALID"]
    blocked = hint_for_step(_step("blocked", "inconclusive", "PLAN.BLOCKED"))
    assert blocked is not None
    assert blocked.kind == "next_step"


def test_the_named_examples_have_their_own_hints() -> None:
    # The owner's usability review names these cases (brief P2-34).
    for code, words in (
        ("MODE.NOT_APPROVED", "reviewer"),
        ("PLAN.MANUAL_UNAVAILABLE", "signed manual result"),
        ("MANUAL.RESULT.MISSING", "signed manual result"),
        ("TRANSPORT.REDIRECT_OUT_OF_SCOPE", "origin"),
        ("CARRIER.SAMPLE.MISSING", "sample"),
        ("INTEGRITY.JOSE.UNSUPPORTED", "engine"),
        ("TRANSPORT.SERVER_ERROR", "answer"),
        ("TRANSPORT.UNREACHABLE", "answer"),
    ):
        text = hint_for_code(code)
        assert text is not None, code
        assert words in text.lower(), code


def test_the_html_shows_the_next_step_and_the_remediation() -> None:
    envelope = _envelope(
        _step("completed", "fail", "DATA.SCHEMA.INVALID"),
        _step("blocked", "inconclusive", "PLAN.BLOCKED"),
    )
    page = render(envelope)
    assert "Next step or remediation" in page
    assert f"Remediation: {HINTS['DATA.SCHEMA.INVALID']}" in page
    assert f"Next step: {HINTS['PLAN.BLOCKED']}" in page


def test_a_failed_step_shows_redacted_observed_fields_and_never_a_payload_value() -> None:
    summary = {
        "status": 404,
        "media_type": "application/json",
        "different": ["batteryChemistry"],
        "schema_errors": [{"path": "/capacity", "keyword": "type"}],
        "key": SENTINEL,
        "reason": SENTINEL,
        "value": {"nested": SENTINEL},
        # status_list.py stores a list of JSON objects here. The depth limit hides them.
        "findings": {"signature": "invalid", "lists": [{"id": SENTINEL}]},
    }
    page = render(_envelope(_step("completed", "fail", "DATA.SCHEMA.INVALID", summary)))
    assert SENTINEL not in page
    section = page.split('id="failed"', 1)[1]
    assert "(nested, not shown)" in section
    for shown in ("404", "application/json", "batteryChemistry", "/capacity", "type", "signature invalid"):
        assert shown in section, shown
    # A field outside the allowlist is named, never shown with its value.
    assert "Other recorded fields, values not shown: key, reason, value" in section
    # The access checks record field paths, channel names, and a status code only.
    access = {
        "policy": SENTINEL,
        "role": SENTINEL,
        "leaks": {"fetch": ["/serial"]},
        "entitlement_missing": ["/repairManual"],
        "channels_probed": ["fetch"],
        "fetch_status": 200,
    }
    page = render(_envelope(_step("completed", "fail", "ACCESS.LEAK.FETCH", access)))
    assert SENTINEL not in page
    section = page.split('id="failed"', 1)[1]
    for shown in ("fetch /serial", "/repairManual", "fetch status: 200"):
        assert shown in section, shown
    assert "Other recorded fields, values not shown: policy, role" in section


def test_an_engine_limit_of_the_timestamp_verifier_reads_as_an_engine_limit() -> None:
    for code in (
        "TIMESTAMP.CMS.UNSUPPORTED",
        "TIMESTAMP.TSA.UNSUPPORTED_CONSTRAINT",
        "TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION",
    ):
        assert HINTS[code].startswith("Engine limit: "), code


def test_every_hint_and_observed_value_is_escaped() -> None:
    summary = {"different": ["<script>alert(1)</script>"], "media_type": '"><img src=x>'}
    page = render(_envelope(_step("completed", "fail", "DATA.SCHEMA.INVALID", summary)))
    assert "<script>" not in page
    assert "<img" not in page
    assert "&lt;script&gt;" in page


def test_an_exclusion_shows_the_reviewer_approval_that_is_missing() -> None:
    exclusion = Exclusion(
        kind="requirement", id="EU-001", reason_code="MODE.NOT_APPROVED", reason="Reviewed mode needs it."
    )
    page = render(_envelope(exclusions=(exclusion,)))
    exclusions = page.split("<caption>Exclusions</caption>", 1)[1].split("</table>", 1)[0]
    assert "Next step" in exclusions
    assert HINTS["MODE.NOT_APPROVED"] in exclusions


def test_an_inconclusive_requirement_names_the_missing_interpretation_or_approval() -> None:
    def result(status: str) -> RequirementResult:
        return make_requirement_result(1, "inconclusive", review_status=status)

    assert requirement_hint(result("placeholder"), ExecutionMode.EXPLORATORY) == NO_INTERPRETATION
    assert requirement_hint(result("draft-needs-review"), ExecutionMode.REVIEWED) == NOT_APPROVED
    # In exploratory mode a draft can be conclusive without approval. The step hints apply then.
    assert requirement_hint(result("draft-needs-review"), ExecutionMode.EXPLORATORY) is None
    assert requirement_hint(make_requirement_result(1, "pass"), ExecutionMode.REVIEWED) is None
    envelope = make_envelope(("inconclusive",))
    placeholder = result("placeholder")
    decision = envelope.decision.model_copy(update={"requirement_results": (placeholder,)})
    page = render(envelope.model_copy(update={"decision": decision}))
    assert f"Next step: {NO_INTERPRETATION}" in page


def test_hints_are_render_only_and_keep_the_decision_digest() -> None:
    envelope = _envelope(
        _step("completed", "fail", "DATA.SCHEMA.INVALID"), _step("blocked", "inconclusive", "PLAN.BLOCKED")
    )
    before = decision_digest(envelope.decision)
    with_hints, without = render(envelope), render(envelope, hints=False)
    assert decision_digest(envelope.decision) == before
    assert before in with_hints
    assert before in without
    assert HINTS["DATA.SCHEMA.INVALID"] in with_hints
    assert HINTS["DATA.SCHEMA.INVALID"] not in without
    assert "Next step or remediation" not in without


def test_the_hint_markup_keeps_the_accessibility_structure() -> None:
    page = render(_envelope(_step("completed", "fail", "DATA.SCHEMA.INVALID", {"status": 500})))
    assert page.startswith('<!doctype html><html lang="en">')
    assert "<script" not in page
    failed = page.split('id="failed"', 1)[1].split("</section>", 1)[0]
    assert "<caption>Failed steps</caption>" in failed
    assert 'scope="col"' in failed
    assert page.count("<h1>") == 1


@pytest.mark.parametrize("code", ["MODE.NOT_APPROVED", "DATA.SCHEMA.INVALID", "TRANSPORT.UNREACHABLE"])
def test_the_reason_code_page_has_the_hint_column(code: str) -> None:
    page = gen.reason_codes_page()
    assert "| Code | Area | Check | Produced in | Step verdict | Next step or remediation |" in page
    row = next(line for line in page.splitlines() if line.startswith(f"| `{code}` |"))
    assert row.endswith(f"| {hint_for_code(code)} |")


def test_the_hint_table_is_not_scanned_as_a_producer_of_codes() -> None:
    places = {s.module for s in gen.extract_reason_codes(gen.source_modules(), gen.code_families())}
    assert "dppce.report.hints" not in places
