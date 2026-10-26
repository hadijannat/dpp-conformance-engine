"""Render an evidence envelope as SARIF 2.1.0.

One result per failed step (level error) and per inconclusive step (level warning). The location
is a logical location: the test purpose identifier. No payload value is written.
"""

from __future__ import annotations

import json
from typing import Any

from dppce import __version__
from dppce.models import EvidenceEnvelope, Verdict
from dppce.report.hints import hint_for_step

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {Verdict.FAIL: "error", Verdict.INCONCLUSIVE: "warning"}


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
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
