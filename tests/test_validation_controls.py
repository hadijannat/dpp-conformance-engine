"""The valid controls of the method validation (finding server-clock-fixes-3 of the agent review).

A control passes only if its run passes and every planned step completes and passes. A step that
stops completing must not drop out of the metric. This is an agent review, not an audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from validation import cases
from validation import run as vrun

from dppce.adapters import data
from dppce.adapters.common import blocked
from dppce.models import ExecutionStatus, Verdict
from tests.support import make_envelope


def _decision(statuses: dict[str, tuple[ExecutionStatus, Verdict, str]]) -> Any:
    decision = make_envelope(("pass", "pass", "pass")).decision
    results = [
        t.model_copy(
            update=dict(
                zip(("execution_status", "verdict", "reason_code"), statuses[t.test_purpose_id], strict=True)
            )
        )
        if t.test_purpose_id in statuses
        else t
        for t in decision.test_results
    ]
    return decision.model_copy(update={"test_results": tuple(results)})


def test_a_control_with_every_step_completed_and_passed_is_as_expected() -> None:
    row = vrun._control_findings(_decision({}))
    assert (row["as_expected"], row["steps_not_completed"], row["executed_steps"]) == (True, [], 3)


def test_a_planned_skip_does_not_count_against_a_control() -> None:
    skipped = (ExecutionStatus.SKIPPED, Verdict.INCONCLUSIVE, "PLAN.SKIPPED")
    row = vrun._control_findings(_decision({"TP-002": skipped}))
    assert (row["as_expected"], row["steps_not_completed"]) == (True, [])


def test_a_control_step_that_stops_completing_is_not_as_expected() -> None:
    stopped = (ExecutionStatus.BLOCKED, Verdict.INCONCLUSIVE, "DATA.NO_TARGET")
    row = vrun._control_findings(_decision({"TP-002": stopped}))
    assert (row["as_expected"], row["steps_not_completed"], row["executed_steps"]) == (False, ["TP-002"], 2)


@pytest.mark.validation
def test_the_validation_fails_when_a_control_step_stops_completing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cases, "profiles", lambda: ["ev"])
    monkeypatch.setattr(cases, "sut_faults", lambda: [])
    monkeypatch.setattr(cases, "boundary_cases", lambda: [])
    monkeypatch.setattr(vrun, "RECORDS", tmp_path / "records")
    original = data._fetch_document

    def regressed(ctx: Any, kind: str, **options: Any) -> Any:
        if kind == "model":
            return None, None, blocked("DATA.NO_TARGET", "A simulated regression.")
        return original(ctx, kind, **options)

    monkeypatch.setattr(data, "_fetch_document", regressed)
    assert vrun.main() == 1
