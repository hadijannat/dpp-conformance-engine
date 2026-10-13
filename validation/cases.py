"""The fault catalogue as executable cases.

``validation/fault-catalogue.yaml`` states what must happen. This module says how the rig
is set up for each case. The expected outcome always comes from the catalogue, never from here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CATALOGUE = Path(__file__).resolve().parent / "fault-catalogue.yaml"

# How the rig is set up for the cases that a fault flag alone does not describe.
_SETUP: dict[str, dict[str, Any]] = {
    "F-20": {"qr": "invalid"},
    "B-02": {"serve": False},
    "B-03": {"at": "2026-11-09T08:00:00Z"},  # exactly 30 days after the fixture update time
    "B-04": {"ics_changes": {"characteristics": {"capacity_wh": 2000}}},
    "B-05": {"ics_changes": {"characteristics": {"capacity_wh": "unknown"}}},
    "B-06": {"profile": "lmt"},
    "B-08": {"ics_changes": {"features": {"item_data": False}}},
}
_NOT_A_FLAG = ("none", "unreachable", "qr_payload_invalid")


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    expected: dict[str, str]
    test_purpose: str | None = None
    requirement: str | None = None
    faults: frozenset[str] = frozenset()
    profile: str | None = None
    at: str | None = None
    rig: dict[str, Any] = field(default_factory=dict)


def _case(entry: dict[str, Any]) -> Case:
    setup = dict(_SETUP.get(entry["id"], {}))
    flag = entry.get("fault", "none")
    return Case(
        id=entry["id"],
        description=entry["description"],
        expected=entry["expected"],
        test_purpose=entry.get("test_purpose"),
        requirement=entry.get("requirement"),
        faults=frozenset() if flag in _NOT_A_FLAG else frozenset({flag}),
        profile=setup.pop("profile", None),
        at=setup.pop("at", None),
        rig=setup,
    )


def load() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    return document


def sut_faults() -> list[Case]:
    return [_case(entry) for entry in load()["sut_faults"]]


def boundary_cases() -> list[Case]:
    return [_case(entry) for entry in load()["boundary_cases"]]


def profiles() -> list[str]:
    return [name.removeprefix("battery/") for name in load()["profiles"]]
