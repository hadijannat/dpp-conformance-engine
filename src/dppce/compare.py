"""Compare the decision bodies of two repeated runs.

A replay re-evaluates one recording. This compares two runs: it states whether they used the same
plan inputs, and lists each step whose verdict, execution status, reason code, or observation
summary differs. It names a differing summary field, never its value: a value can come from the
system under test. The caller reads and verifies the envelopes. This module does no I/O.
"""

from __future__ import annotations

import json
from typing import Any, Final

from dppce.models import PROVENANCE_FIELDS, DecisionBody, EvidenceEnvelope, RunManifest, TestResult

_V1_INPUTS: Final = (
    "engine_version",
    "mode",
    "profile_id",
    "profile_hash",
    "catalogue_hash",
    "sources_hash",
    "pack_hashes",
    "testpack_hashes",
    "ics_hash",
    "ixit_sanitized_hash",
    "trust_policy_version",
)
# The manifest fields that each decision version records as plan inputs. A new version needs one
# entry here. A version without an entry is refused, so that it is never compared only in part.
PLAN_INPUTS: Final[dict[str, tuple[str, ...]]] = {
    "dppce.decision/1": _V1_INPUTS,
    "dppce.decision/2": (*_V1_INPUTS, "bound_files"),
    # The provenance of the run: what was authorized, trusted, and tested. Never a verdict.
    "dppce.decision/3": (*_V1_INPUTS, "bound_files", *PROVENANCE_FIELDS),
}
_STEP_FIELDS: Final = ("verdict", "execution_status", "reason_code")


class CompareError(ValueError):
    """The two bodies cannot be compared."""


def _diff(field: str, a: Any, b: Any) -> dict[str, Any]:
    return {"field": field, "a": a, "b": b}


def _same(a: Any, b: Any) -> bool:
    # JSON text, so that true and 1 are not equal, as they are in Python.
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _plan_inputs(a: DecisionBody, b: DecisionBody) -> list[dict[str, Any]]:
    for decision in (a, b):
        if decision.schema_version not in PLAN_INPUTS:
            raise CompareError(f"compare does not support the decision version {decision.schema_version!r}")
    found = (
        []
        if a.schema_version == b.schema_version
        else [_diff("schema_version", a.schema_version, b.schema_version)]
    )
    # A field that only one version records is not compared, as in a replay (in_layout_of).
    shared = [f for f in PLAN_INPUTS[a.schema_version] if f in PLAN_INPUTS[b.schema_version]]
    # The dump leaves out an absent value. The field default stands for it, so false and () show.
    ma, mb = a.manifest.model_dump(mode="json"), b.manifest.model_dump(mode="json")
    for field in shared:
        absent = RunManifest.model_fields[field].default
        absent = list(absent) if isinstance(absent, tuple) else absent
        va, vb = ma.get(field, absent), mb.get(field, absent)
        if isinstance(va, dict) and isinstance(vb, dict):
            found += [
                _diff(f"{field}[{key}]", va.get(key), vb.get(key))
                for key in sorted(va.keys() | vb.keys())
                if not _same(va.get(key), vb.get(key))
            ]
        elif not _same(va, vb):
            found.append(_diff(field, va, vb))
    return found


def _observation_fields(a: TestResult, b: TestResult) -> list[dict[str, str | None]]:
    """The summary field names that differ. ``field`` is None for an observation on one side only."""
    sa = {o.id: o.summary for o in a.observations}
    sb = {o.id: o.summary for o in b.observations}
    found: list[dict[str, str | None]] = []
    for ident in sorted(sa.keys() | sb.keys()):
        if ident not in sa or ident not in sb:
            found.append({"observation": ident, "field": None})
            continue
        missing = object()
        found += [
            {"observation": ident, "field": key}
            for key in sorted(sa[ident].keys() | sb[ident].keys())
            if sa[ident].get(key, missing) is missing
            or sb[ident].get(key, missing) is missing
            or not _same(sa[ident][key], sb[ident][key])
        ]
    return found


def _steps(a: DecisionBody, b: DecisionBody) -> tuple[int, list[dict[str, Any]]]:
    ta = {t.test_purpose_id: t for t in a.test_results}
    tb = {t.test_purpose_id: t for t in b.test_results}
    idents = sorted(ta.keys() | tb.keys())
    steps = []
    for ident in idents:
        ra, rb = ta.get(ident), tb.get(ident)
        va = ra.model_dump(mode="json", include=set(_STEP_FIELDS)) if ra else {}
        vb = rb.model_dump(mode="json", include=set(_STEP_FIELDS)) if rb else {}
        differences = [_diff(f, va.get(f), vb.get(f)) for f in _STEP_FIELDS if va.get(f) != vb.get(f)]
        # A step on one side only differs in its verdict already. Its observations add nothing.
        fields = _observation_fields(ra, rb) if ra and rb else []
        if differences or fields:
            steps.append({"test_purpose_id": ident, "differences": differences, "observation_fields": fields})
    return len(idents), steps


def compare(a: EvidenceEnvelope, b: EvidenceEnvelope) -> dict[str, Any]:
    """The differences between two envelopes, as a JSON document. Only steps that differ are listed."""
    plan_inputs = _plan_inputs(a.decision, b.decision)
    compared, steps = _steps(a.decision, b.decision)
    return {
        "same_plan_inputs": not plan_inputs,
        "plan_inputs": plan_inputs,
        "overall": {"a": a.decision.overall.value, "b": b.decision.overall.value},
        "steps_compared": compared,
        "verdicts_equal": not any(d["field"] == "verdict" for s in steps for d in s["differences"]),
        "steps": steps,
    }


def _shown(value: Any) -> str:
    return (
        "absent" if value is None else value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    )


def as_text(document: dict[str, Any]) -> str:
    """Plain text for a person. It holds the same facts as the JSON document."""
    lines = [
        f"{side}: {run['path']} {run['schema_version']} {run['decision_digest']}"
        for side, run in (("a", document["a"]), ("b", document["b"]))
    ]
    verified = f"complete for both at {document['verified_at']}" if document["verified"] else "not run"
    lines.append(f"verification: {verified}")
    if document["same_plan_inputs"]:
        lines.append("plan inputs: the same")
    else:
        lines.append("plan inputs differ:")
        lines += [f"  {d['field']}: {_shown(d['a'])} -> {_shown(d['b'])}" for d in document["plan_inputs"]]
    overall = document["overall"]
    lines.append(f"overall: {overall['a']} -> {overall['b']}")
    lines.append(f"steps compared: {document['steps_compared']}")
    for step in document["steps"]:
        lines.append(step["test_purpose_id"])
        lines += [f"  {d['field']}: {_shown(d['a'])} -> {_shown(d['b'])}" for d in step["differences"]]
        for item in step["observation_fields"]:
            if item["field"] is None:
                lines.append(f"  observation {item['observation']}: in one envelope only")
            else:
                lines.append(f"  observation {item['observation']}: summary field {item['field']!r} differs")
    lines.append("every step verdict is equal" if document["verdicts_equal"] else "a step verdict differs")
    return "\n".join(lines)
