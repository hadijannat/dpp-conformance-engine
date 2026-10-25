"""The fault catalogue as executable cases.

``validation/fault-catalogue.yaml`` states what must happen. This module says how the rig
is set up for each case. The expected outcome always comes from the catalogue, never from here.

A row of ``_SETUP`` maps a catalogue id to keyword arguments of ``ReferenceRig``, plus the key
``at`` (an evaluation time) and, for a boundary case only, ``profile`` (a full profile id). Add a
row only when the fault flag alone does not describe the setup, for example
``"F-40": {"ixit_changes": {...}}``. A sut fault picks its profiles with the catalogue field
``profiles`` only; a ``profile`` key in its row is a catalogue error.
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
    "F-30": {"qr": "TEST-ONLY-wrong-shape"},
    "F-31": {"qr": "TEST-ONLY-non-ascii-digits"},
    "F-34": {"qr": "degraded/TEST-ONLY-two-symbols"},
    "B-02": {"serve": False},
    "B-03": {"at": "2026-11-09T08:00:00Z"},  # exactly 30 days after the fixture update time
    "B-04": {"ics_changes": {"characteristics": {"capacity_wh": 2000}}},
    "B-05": {"ics_changes": {"characteristics": {"capacity_wh": "unknown"}}},
    "B-06": {"profile": "battery/lmt"},
    "B-08": {"ics_changes": {"features": {"item_data": False}}},
    # The reference system serves no AAS file, so the control supplies a synthetic one.
    "C-FAMILY-AAS": {"samples": {"aas_json": "fixtures/aas/environment-valid.json"}},
}
_NOT_A_FLAG = (
    "none",
    "unreachable",
    "qr_payload_invalid",
    "qr_wrong_shape",
    "qr_non_ascii_digits",
    "qr_two_symbols",
)


class CatalogueError(ValueError):
    """The fault catalogue states a case that the rig cannot run as stated."""


@dataclass(frozen=True)
class Case:
    """``profiles`` are the full profile ids that a fault runs under.

    ``profile`` is the profile of a single run: the rig setup, else the first profile that the
    entry names. It is None when neither names one; a single run then takes ``profiles[0]``.
    """

    id: str
    description: str
    expected: dict[str, str]
    profiles: tuple[str, ...]
    test_purpose: str | None = None
    requirement: str | None = None
    faults: frozenset[str] = frozenset()
    profile: str | None = None
    at: str | None = None
    rig: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Control:
    """A valid control of one family profile. ``rig`` holds extra ``ReferenceRig`` arguments."""

    id: str
    profile: str
    rig: dict[str, Any] = field(default_factory=dict)


def _profiles(entry: dict[str, Any], default: tuple[str, ...]) -> tuple[str, ...]:
    if "profiles" not in entry:
        return default
    named = entry["profiles"]
    if not isinstance(named, list) or not named or not all(isinstance(p, str) and "/" in p for p in named):
        raise CatalogueError(f"{entry['id']}: 'profiles' must be a non-empty list of full profile ids")
    return tuple(named)


def _case(entry: dict[str, Any], default: tuple[str, ...], section: str) -> Case:
    setup = dict(_SETUP.get(entry["id"], {}))
    flag = entry.get("fault", "none")
    profiles = _profiles(entry, default)
    # validation.run runs a sut fault under each of `profiles` and a boundary case only once,
    # so either mismatch would leave a profile unrun without a message.
    if section == "sut_faults" and "profile" in setup:
        raise CatalogueError(f"{entry['id']}: a sut fault names its profiles in 'profiles', not in _SETUP")
    if section == "boundary_cases" and len(profiles) > 1 and "profiles" in entry:
        raise CatalogueError(f"{entry['id']}: a boundary case runs once, so it names at most one profile")
    return Case(
        id=entry["id"],
        description=entry["description"],
        expected=entry["expected"],
        profiles=profiles,
        test_purpose=entry.get("test_purpose"),
        requirement=entry.get("requirement"),
        faults=frozenset() if flag in _NOT_A_FLAG else frozenset({flag}),
        profile=setup.pop("profile", profiles[0] if "profiles" in entry else None),
        at=setup.pop("at", None),
        rig=setup,
    )


def load() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    return document


def _cases(section: str) -> list[Case]:
    document = load()
    default = tuple(document["profiles"])
    return [_case(entry, default, section) for entry in document[section]]


def sut_faults() -> list[Case]:
    return _cases("sut_faults")


def boundary_cases() -> list[Case]:
    return _cases("boundary_cases")


def controls() -> list[Control]:
    """The controls that name a family profile. C-BASELINE covers the catalogue profiles."""
    return [
        Control(entry["id"], entry["profile"], dict(_SETUP.get(entry["id"], {})))
        for entry in load()["controls"]
        if "profile" in entry
    ]


def profiles() -> list[str]:
    """The catalogue profiles as short battery names, for example ``ev``."""
    return [name.removeprefix("battery/") for name in load()["profiles"]]
