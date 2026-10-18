"""The evidence faults of the fault catalogue as executable tamper functions.

Each function changes a parsed envelope in place, the way an attacker or a defect could.
The catalogue names the verification dimension that must then fail.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

Tamper = Callable[[dict[str, Any]], None]


def _decision(document: dict[str, Any]) -> dict[str, Any]:
    decision: dict[str, Any] = document["decision"]
    return decision


def _set_algorithm(document: dict[str, Any], algorithm: str, *, keep_signature: bool) -> None:
    header, payload, signature = document["signatures"][0].split(".")
    fields = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    fields["alg"] = algorithm
    forged = base64.urlsafe_b64encode(json.dumps(fields).encode()).rstrip(b"=").decode()
    document["signatures"][0] = f"{forged}.{payload}.{signature if keep_signature else ''}"


def _flip_verdict(document: dict[str, Any]) -> None:
    results = _decision(document)["requirement_results"]
    target = next(r for r in results if r["verdict"] in ("pass", "fail"))
    target["verdict"] = "fail" if target["verdict"] == "pass" else "pass"


def _duplicate_result(document: dict[str, Any]) -> None:
    results = _decision(document)["test_results"]
    results.append(results[-1])


def _drop_exclusion(document: dict[str, Any]) -> None:
    exclusions = _decision(document)["exclusions"]
    if not exclusions:
        raise LookupError("the envelope has no exclusion to drop")
    exclusions.pop()


def _change_counts(document: dict[str, Any]) -> None:
    counts = _decision(document)["verdict_counts"]
    counts["pass"], counts["fail"] = counts["pass"] + 1, max(counts["fail"] - 1, 0)


def _flip_manual_outcome(document: dict[str, Any]) -> None:
    """Change the outcome of a completed manual step. The signed result in the step still disagrees."""
    target = next(
        (
            t
            for t in _decision(document)["test_results"]
            if t["check"] == "manual.review" and t["verdict"] in ("pass", "fail")
        ),
        None,
    )
    if target is None:
        raise LookupError("the envelope has no completed manual step")
    flipped = "fail" if target["verdict"] == "pass" else "pass"
    target["verdict"] = flipped
    target["observations"][0]["summary"]["outcome"] = flipped


# Keyed by the `tamper` name in validation/fault-catalogue.yaml.
TAMPER: dict[str, Tamper] = {
    "flip_verdict": _flip_verdict,
    "omit_result": lambda d: _decision(d)["test_results"].pop(),
    "duplicate_result": _duplicate_result,
    "reorder_results": lambda d: _decision(d)["requirement_results"].reverse(),
    "substitute_result": lambda d: _decision(d)["test_results"][0].update(message="from a different run"),
    "change_scope": lambda d: _decision(d)["manifest"]["sut"].update(identifier="urn:example:other"),
    "drop_exclusion": _drop_exclusion,
    "change_counts": _change_counts,
    "substitute_commitment": lambda d: _decision(d)["record_commitments"][0].update(commitment="0" * 64),
    "alg_none": lambda d: _set_algorithm(d, "none", keep_signature=False),
    "flip_manual_outcome": _flip_manual_outcome,
}
# These two need a different key or a different evaluation time, not a changed document.
NEEDS_SETUP = ("untrusted_key", "expired_key")
