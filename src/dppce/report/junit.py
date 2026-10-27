"""Render an evidence envelope as JUnit XML for CI systems.

One testsuite per profile. One testcase per test step, per excluded test purpose, and one for the
overall decision. Only a completed pass is a plain testcase.
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
_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


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


def _outcome(case: ET.Element, verdict: Verdict, message: str, text: str = "") -> None:
    if verdict is Verdict.FAIL:
        ET.SubElement(case, "failure", message=message).text = text
    elif verdict is Verdict.ERROR:
        ET.SubElement(case, "error", message=message).text = text
    elif verdict is not Verdict.PASS:
        ET.SubElement(case, "skipped", message=message)


def render_junit(envelope: EvidenceEnvelope) -> str:
    d = envelope.decision
    profile = clean(d.manifest.profile_id)
    suite = ET.Element("testsuite", name=profile)
    for step in d.test_results:
        _case(suite, step)
    # An excluded test purpose did not run: it is skipped, never absent and never passed.
    for exc in d.exclusions:
        if exc.kind == "test_purpose":
            case = ET.SubElement(suite, "testcase", name="excluded", classname=clean(exc.id))
            ET.SubElement(case, "skipped", message=clean(f"{exc.reason_code}: {exc.reason}"))
    # The overall verdict can be worse than every step (unknown applicability, unapproved
    # interpretation, empty scope). Without this case CI would read such a run as green.
    overall = ET.SubElement(suite, "testcase", name="overall", classname=profile)
    _outcome(overall, d.overall, clean(f"{d.overall.value}: {d.overall_reason}"))
    cases = list(suite.iter("testcase"))
    suite.set("tests", str(len(cases)))
    suite.set("failures", str(len(suite.findall("testcase/failure"))))
    suite.set("errors", str(len(suite.findall("testcase/error"))))
    suite.set("skipped", str(len(suite.findall("testcase/skipped"))))
    ET.indent(suite)
    return ET.tostring(suite, encoding="unicode", xml_declaration=False) + "\n"
