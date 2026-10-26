"""dppce compare: two envelopes of repeated runs, compared step by step.

Replay re-evaluates one recording. A laboratory also shows that repeated live runs against the
same system give the same verdicts. The live runs here use the loopback reference system only.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
from validation.rig import TRUST, ReferenceRig

from dppce import cli
from dppce.evidence.envelope import build_decision
from dppce.models import DecisionBody, EvidenceEnvelope, Observation, TestResult
from tests.support import make_envelope, make_manifest

RC1_ENVELOPE = Path(__file__).parent / "fixtures" / "rc1-envelope-decision-v1.json"
VERIFY_AT = "2026-10-14T00:00:00Z"
SENTINEL = "SENTINEL-PAYLOAD-VALUE-4402"


def _compare(*arguments: str) -> tuple[int, str]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main(["compare", *arguments])
    return code, captured.getvalue()


def _compare_json(*arguments: str) -> tuple[int, dict[str, Any]]:
    code, text = _compare(*arguments, "--format", "json")
    return code, json.loads(text) if text.strip() else {}


def _write(path: Path, envelope: EvidenceEnvelope) -> str:
    path.write_text(envelope.model_dump_json(by_alias=True), encoding="utf-8")
    return str(path)


def _rebuilt(decision: DecisionBody, **changes: Any) -> EvidenceEnvelope:
    """The same decision with changed fields, and roots and counts computed again."""
    fields: dict[str, Any] = {
        "manifest": decision.manifest,
        "overall": decision.overall,
        "overall_reason": decision.overall_reason,
        "requirement_results": decision.requirement_results,
        "test_results": decision.test_results,
        "exclusions": decision.exclusions,
        "conflicts": decision.conflicts,
        "coverage": decision.coverage,
        "record_commitments": decision.record_commitments,
    } | changes
    return EvidenceEnvelope(schema_version="dppce.envelope/1", decision=build_decision(**fields))


def _with_summary(result: TestResult, summary: dict[str, Any]) -> TestResult:
    observation = Observation(
        id=f"{result.test_purpose_id}#1",
        test_purpose_id=result.test_purpose_id,
        kind="exchange",
        acquired_at="2026-10-13T12:00:00Z",
        summary=summary,
    )
    return result.model_copy(update={"observations": (observation,)})


@pytest.mark.qr
def test_two_runs_of_the_same_plan_on_loopback_compare_equal(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        first, second = rig.run(), rig.run()
        a, b = rig.sign(first), rig.sign(second)
    code, document = _compare_json(str(a), str(b), "--trust", str(TRUST), "--at", VERIFY_AT)
    assert code == 0, document
    assert document["verified"] is True
    assert document["same_plan_inputs"] is True
    assert document["plan_inputs"] == []
    assert document["verdicts_equal"] is True
    assert document["steps"] == []
    assert document["steps_compared"] == len(first.envelope.decision.test_results)
    assert document["a"]["decision_digest"] != document["b"]["decision_digest"], "fresh salts differ"
    code, text = _compare(str(a), str(b))
    assert code == 0
    assert "every step verdict is equal" in text
    assert "verification: not run" in text, "without --trust the envelopes are not verified"


@pytest.mark.qr
def test_a_seeded_fault_in_the_second_run_names_the_step_and_the_codes(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path / "control") as rig:
        control = rig.run()
    with ReferenceRig(tmp_path / "fault", faults=frozenset({"api_wrong_content_type"})) as rig:
        faulty = rig.run()
    a, b = str(control.run_dir / "envelope.json"), str(faulty.run_dir / "envelope.json")
    code, document = _compare_json(a, b)
    assert code == 1, "exit code 1 means that a step verdict differs"
    assert document["verdicts_equal"] is False
    steps = {s["test_purpose_id"]: s for s in document["steps"]}
    differences = {d["field"]: (d["a"], d["b"]) for d in steps["TP-API-001"]["differences"]}
    assert differences["verdict"] == ("pass", "fail")
    assert differences["reason_code"] == ("API.CONTRACT.OK", "API.CONTRACT.CONTENT_TYPE")
    assert "execution_status" not in differences, "both checks completed"
    code, text = _compare(a, b)
    assert code == 1
    assert "TP-API-001" in text
    assert "API.CONTRACT.OK" in text
    assert "API.CONTRACT.CONTENT_TYPE" in text
    for canary in ("CANARY-7f3a-supplier", "CANARY-4d1e-usage", "CANARY-2b9c-dismantling"):
        assert canary not in text, "a comparison prints no payload value"


@pytest.mark.qr
def test_a_tampered_envelope_with_trust_gives_the_verifier_failure_code(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        first, second = rig.run(), rig.run()
        a, b = rig.sign(first), rig.sign(second)
    b.write_text(b.read_text(encoding="utf-8").replace('"overall":"pass"', '"overall":"fail"'))
    code, _ = _compare(str(a), str(b), "--trust", str(TRUST), "--at", VERIFY_AT)
    assert code == 4, "exit code 4 means that evidence verification failed"


def test_different_plan_inputs_are_reported(tmp_path: Path) -> None:
    base = make_envelope()
    manifest = make_manifest().model_copy(
        update={
            "ics_hash": "sha256:" + "1" * 64,
            "engine_version": "0.0.1-test",
            "testpack_hashes": {"battery/reference": "sha256:" + "2" * 64},
        }
    )
    other = _rebuilt(base.decision, manifest=manifest)
    code, document = _compare_json(_write(tmp_path / "a.json", base), _write(tmp_path / "b.json", other))
    assert code == 0, "equal verdicts with different inputs still exit 0"
    assert document["same_plan_inputs"] is False
    fields = {d["field"]: (d["a"], d["b"]) for d in document["plan_inputs"]}
    assert fields == {
        "engine_version": ("0.0.0-test", "0.0.1-test"),
        "ics_hash": ("h", "sha256:" + "1" * 64),
        "testpack_hashes[battery/reference]": (None, "sha256:" + "2" * 64),
    }
    assert document["verified"] is False
    code, text = _compare(str(tmp_path / "a.json"), str(tmp_path / "b.json"))
    assert "plan inputs differ" in text
    assert "ics_hash" in text


def test_a_changed_observation_names_the_field_and_never_the_value(tmp_path: Path) -> None:
    base = make_envelope()
    tests = base.decision.test_results
    a = _rebuilt(
        base.decision, test_results=(_with_summary(tests[0], {"status": 200, "kept": "x"}), *tests[1:])
    )
    b = _rebuilt(
        base.decision, test_results=(_with_summary(tests[0], {"status": SENTINEL, "kept": "x"}), *tests[1:])
    )
    pa, pb = _write(tmp_path / "a.json", a), _write(tmp_path / "b.json", b)
    code, document = _compare_json(pa, pb)
    assert code == 0, "a summary difference alone is not a verdict difference"
    step = document["steps"][0]
    assert step["test_purpose_id"] == "TP-001"
    assert step["differences"] == []
    assert step["observation_fields"] == [{"observation": "TP-001#1", "field": "status"}]
    code, text = _compare(pa, pb)
    assert SENTINEL not in text
    assert SENTINEL not in json.dumps(document)
    assert "observation TP-001#1: summary field 'status' differs" in text


def test_a_step_on_one_side_only_is_a_verdict_difference(tmp_path: Path) -> None:
    base = make_envelope()
    fewer = make_envelope(("pass", "fail"))
    code, document = _compare_json(_write(tmp_path / "a.json", base), _write(tmp_path / "b.json", fewer))
    assert code == 1
    step = next(s for s in document["steps"] if s["test_purpose_id"] == "TP-003")
    assert {"field": "verdict", "a": "pass", "b": None} in step["differences"]


def test_a_decision_version_1_envelope_compares_with_itself_and_with_version_2(tmp_path: Path) -> None:
    rc1 = str(RC1_ENVELOPE)
    code, document = _compare_json(rc1, rc1)
    assert (code, document["same_plan_inputs"], document["steps"]) == (0, True, [])
    assert document["a"]["schema_version"] == "dppce.decision/1"
    code, document = _compare_json(rc1, _write(tmp_path / "v2.json", make_envelope()))
    assert code == 0
    fields = {d["field"]: (d["a"], d["b"]) for d in document["plan_inputs"]}
    # A version 1 body records no bound files, so they are not compared, as in a replay.
    assert fields == {"schema_version": ("dppce.decision/1", "dppce.decision/2")}


def test_an_unreadable_envelope_is_an_input_error(tmp_path: Path) -> None:
    good = _write(tmp_path / "a.json", make_envelope())
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert _compare(good, str(tmp_path / "bad.json"))[0] == 2
    assert _compare(good, str(tmp_path / "missing.json"))[0] == 2


def test_trust_without_an_explicit_time_is_a_usage_error(tmp_path: Path) -> None:
    good = _write(tmp_path / "a.json", make_envelope())
    assert _compare(good, good, "--trust", str(TRUST))[0] == 2, "now is never assumed"
