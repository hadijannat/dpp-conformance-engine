"""Render an evidence envelope as SARIF 2.1.0.

One result per failed or errored step (level error) and per inconclusive step (level warning). A
non-pass overall verdict gives one more result with the rule DECISION.OVERALL.<VERDICT>, located at
the profile. The location is a logical location: the test purpose identifier. No payload value is
written.
"""

from __future__ import annotations

import json
from typing import Any

from dppce import __version__
from dppce.models import EvidenceEnvelope, Verdict
from dppce.report.hints import hint_for_step

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_OVERALL_RULE = {
    Verdict.FAIL: "DECISION.OVERALL.FAIL",
    Verdict.ERROR: "DECISION.OVERALL.ERROR",
    Verdict.INCONCLUSIVE: "DECISION.OVERALL.INCONCLUSIVE",
    Verdict.NOT_APPLICABLE: "DECISION.OVERALL.NOT_APPLICABLE",
}
_LEVEL = {Verdict.FAIL: "error", Verdict.ERROR: "error", Verdict.INCONCLUSIVE: "warning"}


def render_sarif(envelope: EvidenceEnvelope) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for step in envelope.decision.test_results:
        level = _LEVEL.get(step.verdict)
        if level is None:
            continue
        hint = hint_for_step(step)
        text = hint.text if hint else step.reason_code
        rules.setdefault(
            step.reason_code,
            {"id": step.reason_code, "shortDescription": {"text": step.reason_code}, "help": {"text": text}},
        )
        results.append(
            {
                "ruleId": step.reason_code,
                "level": level,
                "message": {"text": f"{step.reason_code}: {text}"},
                "locations": [{"logicalLocations": [{"name": step.test_purpose_id, "kind": "function"}]}],
                "properties": {"execution_status": step.execution_status.value},
            }
        )
    overall = envelope.decision.overall
    if overall in _OVERALL_RULE:
        # The overall verdict can be worse than every step. CI must still see it.
        rule = _OVERALL_RULE[overall]
        text = f"{overall.value}: {envelope.decision.overall_reason}"
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": rule}, "help": {"text": text}})
        results.append(
            {
                "ruleId": rule,
                "level": _LEVEL.get(overall, "note"),
                "message": {"text": text},
                "locations": [
                    {"logicalLocations": [{"name": envelope.decision.manifest.profile_id, "kind": "module"}]}
                ],
            }
        )
    failed = Verdict.ERROR in {s.verdict for s in envelope.decision.test_results} | {overall}
    doc = {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dppce",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": not failed}],
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
