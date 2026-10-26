"""Render an evidence envelope as JUnit XML for CI systems.

One testsuite per profile, one testcase per test step. Only a completed pass is a plain testcase.
A step that did not complete or is not applicable is ``skipped`` with its reason code and hint:
CI must never read a step that did not run as passed. No payload value is written, and the
decision body is not touched.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from dppce.models import EvidenceEnvelope, TestResult, Verdict
from dppce.report.hints import hint_for_step

# XML 1.0 forbids most control characters even as character references.
_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def clean(text: str) -> str:
    return _ILLEGAL.sub("�", text)


def step_message(step: TestResult) -> str:
    hint = hint_for_step(step)
    return clean(f"{step.reason_code}: {hint.text}" if hint else step.reason_code)


def _case(suite: ET.Element, step: TestResult) -> None:
    case = ET.SubElement(suite, "testcase", name=clean(step.check), classname=clean(step.test_purpose_id))
    props = ET.SubElement(case, "properties")
    for name, value in (
        ("execution_status", step.execution_status.value),
        ("verdict", step.verdict.value),
        ("reason_code", step.reason_code),
        ("severity", step.severity.value),
    ):
        ET.SubElement(props, "property", name=name, value=clean(value))
    message = step_message(step)
    if step.verdict is Verdict.FAIL:
        ET.SubElement(case, "failure", message=message, type=clean(step.reason_code)).text = clean(
            step.message
        )
    elif step.verdict is Verdict.ERROR:
        ET.SubElement(case, "error", message=message, type=clean(step.reason_code)).text = clean(step.message)
    elif step.verdict is not Verdict.PASS:
        ET.SubElement(case, "skipped", message=message)


def render_junit(envelope: EvidenceEnvelope) -> str:
    steps = envelope.decision.test_results
    suite = ET.Element(
        "testsuite",
        name=clean(envelope.decision.manifest.profile_id),
        tests=str(len(steps)),
        failures=str(sum(s.verdict is Verdict.FAIL for s in steps)),
        errors=str(sum(s.verdict is Verdict.ERROR for s in steps)),
        skipped=str(sum(s.verdict not in (Verdict.PASS, Verdict.FAIL, Verdict.ERROR) for s in steps)),
    )
    for step in steps:
        _case(suite, step)
    ET.indent(suite)
    return ET.tostring(suite, encoding="unicode", xml_declaration=False) + "\n"
