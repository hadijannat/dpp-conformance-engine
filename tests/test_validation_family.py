"""Family profiles in the method validation: the family controls and the per-case profiles field.

A wave-2 fault targets a test purpose of a family test pack. The rig must run that profile, and a
catalogue case that names a profile that does not plan its test purpose must stop the validation.
"""

from __future__ import annotations

import copy
import json
from importlib.util import find_spec
from pathlib import Path
from typing import Any

import pytest
from validation import cases
from validation import run as vrun

BATTERY = ("battery/ev", "battery/lmt", "battery/industrial")
FAMILY_CONTROLS = {
    "C-FAMILY-WEB": "family/web",
    "C-FAMILY-GS1": "family/gs1-resolver",
    "C-FAMILY-VC": "family/credentials",
    "C-FAMILY-AAS": "family/aas",
}
PREFIX = {
    "family/web": "TP-WEB-",
    "family/gs1-resolver": "TP-GS1-",
    "family/credentials": "TP-VC-",
    "family/aas": "TP-AAS-",
}
# Without the extra, aas.validate gives unsupported, so the AAS control cannot pass.
_AAS = [
    pytest.mark.aas,
    pytest.mark.skipif(find_spec("aas_test_engines") is None, reason="needs the optional 'aas' extra"),
]
_LOAD = cases.load  # the shipped catalogue, before any test patches it
_SYNTAX = {
    "id": "F-TEST-GS1",
    "class": "test_only",
    "fault": "none",
    "description": "A synthetic case of this test: the unmodified resolver path parses.",
    "test_purpose": "TP-GS1-SYNTAX-001",
    "expected": {"verdict": "pass", "reason_code": "IDENTIFIER.SYNTAX.OK"},
}


def _with_fault(monkeypatch: pytest.MonkeyPatch, section: str = "sut_faults", **changes: Any) -> cases.Case:
    """Add one synthetic case to a section of the shipped catalogue and return it."""
    document = _LOAD()
    entry = {**_SYNTAX, **changes}
    patched = copy.deepcopy(document)
    patched[section].append(entry)
    monkeypatch.setattr(cases, "load", lambda: patched)
    return next(c for c in cases._cases(section) if c.id == entry["id"])


def test_the_catalogue_names_one_control_per_family_profile() -> None:
    assert {c.id: c.profile for c in cases.controls()} == FAMILY_CONTROLS


@pytest.mark.parametrize(
    "control",
    [pytest.param(c, id=c.id, marks=_AAS if c.profile == "family/aas" else []) for c in cases.controls()],
)
def test_the_rig_runs_each_family_control_on_loopback(control: cases.Control, tmp_path: Path) -> None:
    row, run, _ = vrun._control(tmp_path, control.id, control.profile, control.rig)
    assert (row["id"], row["profile"]) == (control.id, control.profile)
    assert row["executed_steps"] > 0
    assert (row["as_expected"], row["executed_steps_not_passed"], row["steps_not_completed"]) == (
        True,
        [],
        [],
    )
    assert row["replay_digests_equal"] is True
    steps = [t.test_purpose_id for t in run.envelope.decision.test_results]
    assert steps
    assert all(s.startswith(PREFIX[control.profile]) for s in steps), steps


def test_a_case_without_profiles_runs_under_the_catalogue_profiles() -> None:
    document = cases.load()
    assert tuple(document["profiles"]) == BATTERY
    for case in [*cases.sut_faults(), *cases.boundary_cases()]:
        entry = next(e for e in [*document["sut_faults"], *document["boundary_cases"]] if e["id"] == case.id)
        if "profiles" not in entry:
            assert case.profiles == BATTERY, case.id
    # A boundary case keeps its single profile: the rig setup, else the first catalogue profile.
    assert {c.id: c.profile for c in cases.boundary_cases() if c.profile} == {
        "B-06": "battery/lmt",
        "B-12": "family/gs1-resolver",
        "B-14": "family/gs1-resolver",
        "B-16": "family/aas",
    }


@pytest.mark.qr
def test_a_case_without_profiles_runs_once_per_battery_profile(tmp_path: Path) -> None:
    case = next(c for c in cases.sut_faults() if c.id == "F-01")
    rows = vrun._sut_cases(tmp_path, [case], "fault", all_profiles=True)
    assert [r["profile"] for r in rows] == list(BATTERY)
    assert all(r["as_expected"] for r in rows), rows


def test_a_case_with_profiles_runs_only_under_those_profiles(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    case = _with_fault(monkeypatch, profiles=["family/gs1-resolver"])
    assert case.profiles == ("family/gs1-resolver",)
    # A consumer that runs a case once (tests/test_e2e_reference.py) takes this profile.
    assert case.profile == "family/gs1-resolver"
    rows = vrun._sut_cases(tmp_path, [case], "fault", all_profiles=True)
    assert [(r["id"], r["profile"], r["as_expected"]) for r in rows] == [
        ("F-TEST-GS1", "family/gs1-resolver", True)
    ]


def test_a_case_whose_test_purpose_no_profile_plans_fails_loudly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    case = _with_fault(monkeypatch, profiles=["family/web"])
    with pytest.raises(cases.CatalogueError, match=r"F-TEST-GS1.*TP-GS1-SYNTAX-001.*family/web"):
        vrun._sut_cases(tmp_path, [case], "fault", all_profiles=True)


@pytest.mark.parametrize("profiles", [[], ["gs1-resolver"], "family/web", [7]])
def test_a_malformed_profiles_field_is_a_catalogue_error(
    monkeypatch: pytest.MonkeyPatch, profiles: object
) -> None:
    with pytest.raises(cases.CatalogueError, match="F-TEST-GS1"):
        _with_fault(monkeypatch, profiles=profiles)


def test_a_boundary_case_with_more_than_one_profile_is_a_catalogue_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A boundary case runs once, so a second profile would never run.
    with pytest.raises(cases.CatalogueError, match=r"F-TEST-GS1.*one profile"):
        _with_fault(monkeypatch, "boundary_cases", profiles=["family/gs1-resolver", "battery/ev"])
    case = _with_fault(monkeypatch, "boundary_cases", profiles=["family/gs1-resolver"])
    assert case.profile == "family/gs1-resolver"


def test_a_setup_profile_on_a_sut_fault_is_a_catalogue_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # A sut fault picks its profiles with the catalogue field only, never with a setup row.
    monkeypatch.setitem(cases._SETUP, "F-TEST-GS1", {"profile": "family/gs1-resolver"})
    with pytest.raises(cases.CatalogueError, match=r"F-TEST-GS1.*'profiles'"):
        _with_fault(monkeypatch)
    assert _with_fault(monkeypatch, "boundary_cases").profile == "family/gs1-resolver"


@pytest.mark.validation
def test_the_record_keeps_its_figures_and_adds_the_family_controls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cases, "profiles", lambda: ["ev"])
    monkeypatch.setattr(cases, "sut_faults", lambda: [])
    monkeypatch.setattr(cases, "boundary_cases", lambda: [])
    monkeypatch.setattr(vrun, "RECORDS", tmp_path / "records")
    assert vrun.main() == 0
    record = json.loads(next((tmp_path / "records").glob("method-validation-*.json")).read_text("utf-8"))
    assert set(record["metrics"]) == {
        "fault_detection",
        "false_positives_on_controls",
        "controls",
        "boundary_cases",
        "evidence_faults",
        "evidence_faults_not_run",
        "replays",
        "control_verification_complete",
    }
    rows = record["controls"]
    assert [(r["id"], r["profile"]) for r in rows] == [
        ("C-BASELINE", "battery/ev"),
        *FAMILY_CONTROLS.items(),
    ]
    metrics = record["metrics"]
    assert metrics["controls"]["denominator"] == len(rows)
    assert metrics["false_positives_on_controls"]["denominator"] == sum(r["executed_steps"] for r in rows)
    assert metrics["replays"]["denominator"] == len(rows) * vrun.REPLAYS
