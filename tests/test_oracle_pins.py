"""scripts/check_oracle_pins.py and catalogue/oracle-pins.yaml. No test here uses the network."""

from __future__ import annotations

import importlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from dppce.catalogue import load_catalogue
from dppce.infrastructure.resources import data_root

pins_mod = importlib.import_module("scripts.check_oracle_pins")
ROOT = data_root()
FIELDS = {
    "id",
    "path",
    "repo",
    "upstream_path",
    "commit",
    "url",
    "retrieval_date",
    "license",
    "sha256",
    "version",
}


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("a pin test started a subprocess")

    monkeypatch.setattr(subprocess, "run", refuse)


def test_the_manifest_matches_the_vendored_files() -> None:
    pins = pins_mod.load_pins(pins_mod.MANIFEST)
    assert len(pins) >= 4
    assert pins_mod.check(pins, ROOT) == []


def test_each_pin_has_every_field_and_a_url_at_its_commit() -> None:
    for pin in pins_mod.load_pins(pins_mod.MANIFEST):
        assert set(pin) == FIELDS, pin["id"]
        assert pin["commit"] in pin["url"], pin["id"]
        assert pin["repo"] in pin["url"], pin["id"]
        assert pin["license"].startswith("Apache-2.0"), pin["id"]
        assert len(pin["sha256"]) == 64, pin["id"]


def test_each_pin_agrees_with_the_source_record_of_the_file() -> None:
    records = {s.id: s for s in load_catalogue(ROOT).sources}
    for pin in pins_mod.load_pins(pins_mod.MANIFEST):
        record = records[pin["path"]]
        assert record.sha256 == pin["sha256"], pin["id"]
        assert record.official_url == pin["url"], pin["id"]
        assert record.retrieval_date == pin["retrieval_date"], pin["id"]


def _copy(tmp_path: Path, pin: dict[str, Any]) -> Path:
    target = tmp_path / pin["path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / pin["path"], target)
    return target


def test_a_changed_file_is_a_problem(tmp_path: Path) -> None:
    pins = pins_mod.load_pins(pins_mod.MANIFEST)
    for pin in pins:
        _copy(tmp_path, pin)
    assert pins_mod.check(pins, tmp_path) == []
    (tmp_path / pins[0]["path"]).write_bytes(b"changed")
    problems = pins_mod.check(pins, tmp_path)
    assert len(problems) == 1
    assert pins[0]["id"] in problems[0]


def test_a_missing_file_is_a_problem(tmp_path: Path) -> None:
    pins = pins_mod.load_pins(pins_mod.MANIFEST)
    assert len(pins_mod.check(pins, tmp_path)) == len(pins)


def test_the_check_command_is_offline_and_exits_0() -> None:
    assert pins_mod.main([]) == 0


def test_refresh_reports_drift_with_an_injected_fetcher() -> None:
    pins = pins_mod.load_pins(pins_mod.MANIFEST)

    def same(repo: str, path: str, ref: str | None) -> bytes:
        pin = next(p for p in pins if p["repo"] == repo and p["upstream_path"] == path)
        return (ROOT / pin["path"]).read_bytes()

    assert pins_mod.refresh(pins, same) == []

    def drifted(repo: str, path: str, ref: str | None) -> bytes:
        data = same(repo, path, ref)
        return data + b"x" if ref is None else data

    problems = pins_mod.refresh(pins, drifted)
    assert len(problems) == len(pins)
    assert all("drift" in p for p in problems)


def test_refresh_reports_a_pinned_object_that_changed_upstream() -> None:
    pins = pins_mod.load_pins(pins_mod.MANIFEST)
    problems = pins_mod.refresh(pins, lambda repo, path, ref: b"other")
    assert len(problems) == 2 * len(pins)
    assert any("pinned commit" in p for p in problems)
