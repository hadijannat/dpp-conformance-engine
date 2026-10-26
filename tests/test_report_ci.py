"""CI report formats: JUnit XML and SARIF 2.1.0. Every envelope here is synthetic."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from dppce import __version__
from dppce.cli import main
from dppce.models import EvidenceEnvelope, TestResult
from dppce.report.junit import render_junit
from dppce.report.sarif import render_sarif
from tests.support import make_envelope

SENTINEL = "SENTINEL-PAYLOAD-VALUE-4417"


def _step(tp: str, status: str, verdict: str, code: str, applicability: str = "true") -> TestResult:
    return TestResult.model_validate(
        {
            "test_purpose_id": tp,
            "requirement_ids": ["ILL-009"],
            "check": "data.rules",
            "applicability": applicability,
            "applicability_reason": "always",
            "execution_status": status,
            "verdict": verdict,
            "severity": "major",
            "reason_code": code,
            "message": f'<b>&"msg"</b> {tp}',
            "observations": [
                {
                    "id": "o1",
                    "test_purpose_id": tp,
                    "kind": "exchange",
                    "acquired_at": "2026-10-13T12:00:00Z",
                    "summary": {"payload_body": SENTINEL},
                }
            ],
        }
    )


def _envelope() -> EvidenceEnvelope:
    base = make_envelope(("pass",))
    steps = (
        _step("TP-PASS", "completed", "pass", "DATA.RULES.OK"),
        _step("TP-FAIL", "completed", "fail", "DATA.RULES.VIOLATED"),
        _step("TP-INC", "blocked", "inconclusive", "DATA.RULES.BLOCKED"),
        _step("TP-NA", "skipped", "not_applicable", "APPLICABILITY.NOT_APPLICABLE", "false"),
        _step("TP-ERR", "error", "error", "EXECUTION.CHECK.ERROR"),
    )
    decision = base.decision.model_copy(update={"test_results": steps})
    return base.model_copy(update={"decision": decision})


def _parse(text: str) -> ET.Element:
    return ET.fromstring(text)  # noqa: S314 - parses the engine's own output, not untrusted input


def _suites(root: ET.Element) -> list[ET.Element]:
    return [root] if root.tag == "testsuite" else list(root.iter("testsuite"))


def test_junit_counts_and_no_false_pass() -> None:
    root = _parse(render_junit(_envelope()))
    cases = {c.get("classname"): c for c in root.iter("testcase")}
    assert set(cases) == {"TP-PASS", "TP-FAIL", "TP-INC", "TP-NA", "TP-ERR"}
    assert len(_suites(root)) == 1
    suite = _suites(root)[0]
    assert (suite.get("tests"), suite.get("failures"), suite.get("errors"), suite.get("skipped")) == (
        "5",
        "1",
        "1",
        "2",
    )
    assert cases["TP-FAIL"].find("failure") is not None
    assert cases["TP-ERR"].find("error") is not None
    for tp in ("TP-INC", "TP-NA"):
        skipped = cases[tp].find("skipped")
        assert skipped is not None, tp
        assert cases[tp].find("failure") is None
    inc = cases["TP-INC"].find("skipped")
    assert inc is not None
    assert "DATA.RULES.BLOCKED" in (inc.get("message") or "")
    props = {p.get("name"): p.get("value") for p in cases["TP-INC"].iter("property")}
    assert props["execution_status"] == "blocked"
    # Only the pass step has no failure, error, or skipped child.
    assert [c.tag for c in cases["TP-PASS"]] == ["properties"]


def test_junit_escapes_and_hides_payload() -> None:
    text = render_junit(_envelope())
    assert SENTINEL not in text
    assert "<b>" not in text  # the message markup arrives escaped, parse still works
    _parse(text)


def test_sarif_structure_and_levels() -> None:
    doc: dict[str, Any] = json.loads(render_sarif(_envelope()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].startswith("https://")
    (run,) = doc["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "dppce"
    assert driver["version"] == __version__
    results = run["results"]
    assert {(r["ruleId"], r["level"]) for r in results} == {
        ("DATA.RULES.VIOLATED", "error"),
        ("DATA.RULES.BLOCKED", "warning"),
    }
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"DATA.RULES.VIOLATED", "DATA.RULES.BLOCKED"}
    assert all(r["help"]["text"] for r in driver["rules"])
    names = {r["locations"][0]["logicalLocations"][0]["name"] for r in results}
    assert names == {"TP-FAIL", "TP-INC"}
    assert SENTINEL not in json.dumps(doc)


@pytest.mark.parametrize("fmt", ["junit", "sarif"])
def test_cli_report_format(tmp_path: Path, fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    env = tmp_path / "e.json"
    env.write_text(_envelope().model_dump_json(by_alias=True), encoding="utf-8")
    out = tmp_path / f"out.{fmt}"
    assert main(["report", "--envelope", str(env), "--format", fmt, "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    _parse(text) if fmt == "junit" else json.loads(text)
