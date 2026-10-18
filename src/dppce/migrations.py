"""Upgrade a document from an older schema version to the current one.

Each contract carries a ``schema_version`` such as ``dppce.ics/1``. A breaking change adds a
new version and one step here. A document with an unknown version is rejected: the engine
never guesses how to read it.

A decision body has no step. It is signed, so it is never rewritten: the verifier reads
``dppce.decision/1`` and ``dppce.decision/2`` as written, and a new run writes version 2.

The record of run inputs (``inputs.json``) has one step, from ``dppce.runinputs/1`` to version 2.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from decimal import Decimal, InvalidOperation
from typing import Any

CURRENT: dict[str, str] = {"ics": "dppce.ics/1", "runinputs": "dppce.runinputs/2"}

Document = dict[str, Any]


class MigrationError(ValueError):
    """The document cannot be upgraded."""


def _ics_0_to_1(document: Document) -> Document:
    """Move product facts into ``characteristics`` and replace kilowatt-hours with integer watt-hours.

    No ``dppce.ics/0`` document was published. This step upgrades the draft layout that the
    project used before the first release, and it proves the migration mechanism.
    """
    out = deepcopy(document)
    characteristics: dict[str, Any] = dict(out.pop("characteristics", {}))
    if "capacity_kwh" in out:
        try:
            watt_hours = Decimal(str(out.pop("capacity_kwh"))) * 1000
        except InvalidOperation as exc:
            raise MigrationError("capacity_kwh is not a number") from exc
        if not watt_hours.is_finite():
            raise MigrationError("capacity_kwh is not a finite number")
        if watt_hours != watt_hours.to_integral_value():
            raise MigrationError("capacity_kwh is not a whole number of watt-hours")
        characteristics["capacity_wh"] = int(watt_hours)
    if "placed_on_market" in out:
        characteristics["placed_on_market_date"] = out.pop("placed_on_market")
    out["characteristics"] = characteristics
    out["schema_version"] = "dppce.ics/1"
    return out


def _runinputs_1_to_2(document: Document) -> Document:
    """Version 1 has no data root and no input hashes.

    0.1.0rc1 also wrote no test-pack and no manual-result fields, because it imported, selected,
    and supplied none. A replay of the result compares no input hashes (architecture section 10.1).
    """
    if "data_root" in document or "input_hashes" in document:
        raise MigrationError("a dppce.runinputs/1 record holds no data_root and no input_hashes")
    out = deepcopy(document)
    for name in ("import_testpacks", "extra_testpacks", "manual_results"):
        out.setdefault(name, [])
    out["data_root"] = None
    out["input_hashes"] = None
    out["schema_version"] = "dppce.runinputs/2"
    return out


_STEPS: dict[tuple[str, str], Callable[[Document], Document]] = {
    ("ics", "dppce.ics/0"): _ics_0_to_1,
    ("runinputs", "dppce.runinputs/1"): _runinputs_1_to_2,
}


def migrate(kind: str, document: Document) -> Document:
    """Return ``document`` at the current version of ``kind``. The input is not changed."""
    if kind not in CURRENT:
        raise MigrationError(f"unknown document kind '{kind}'")
    current = document
    for _ in range(len(_STEPS) + 1):
        version = current.get("schema_version")
        if version == CURRENT[kind]:
            return current
        step = _STEPS.get((kind, str(version)))
        if step is None:
            raise MigrationError(f"no migration from schema version {version!r} for '{kind}'")
        current = step(current)
    raise MigrationError(f"migration of '{kind}' does not reach {CURRENT[kind]}")
