"""Every body from the system under test is parsed with parse_strict (architecture section 2, rule 4).

A repeated key, NaN, or Infinity is refused, so that two parsers cannot read one body in two ways.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.lifecycle import aas_validate
from dppce.infrastructure.interfaces import Record, Request
from tests.support import make_artifact
from tests.test_url_templates import Canned, context

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "src" / "dppce"
# Files that read committed files only, with the reason.
ALLOWED = {"infrastructure/reference_server.py": "reads committed fixtures"}


def _json_load_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("loads", "load")
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
    ]
    # A bare import of loads or load would hide a call from the scan above.
    found += [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "json"
        and any(alias.name in ("loads", "load") for alias in node.names)
    ]
    return found


def test_no_adapter_or_infrastructure_module_calls_json_loads_on_a_body() -> None:
    found = {
        str(path.relative_to(SOURCES)): lines
        for folder in ("adapters", "infrastructure")
        for path in sorted((SOURCES / folder).glob("*.py"))
        if (lines := _json_load_calls(path))
    }
    assert set(found) == set(ALLOWED), found


class _Sample(Canned):
    """An acquirer that holds one AAS sample and sends nothing."""

    def fetch(self, request: Request) -> Record:
        raise AssertionError("aas.validate sends no request")

    def artifact(self, name: str) -> Record:
        record = make_artifact(name, self._body, index=len(self._records) + 1)
        self._records.append(record)
        return record


@pytest.fixture
def validator_calls(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """A stand-in for aas-test-engines that records each document that it gets."""
    calls: list[Any] = []

    class _Result:
        def ok(self) -> bool:
            return True

    def check_json_data(document: Any, version: str = "3.0") -> _Result:
        calls.append(document)
        return _Result()

    def supported_versions() -> dict[str, list[str]]:
        return {"3.0": []}

    package, module = types.ModuleType("aas_test_engines"), types.ModuleType("aas_test_engines.file")
    # A plain ModuleType declares no attributes; these two are the stand-in's whole interface.
    module.check_json_data = check_json_data  # type: ignore[attr-defined]
    module.supported_versions = supported_versions  # type: ignore[attr-defined]
    package.file = module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aas_test_engines", package)
    monkeypatch.setitem(sys.modules, "aas_test_engines.file", module)
    return calls


@pytest.mark.parametrize(
    "body",
    [
        b'{"a": 1, "a": 2}',
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": -Infinity}',
        b'{"a": 1e999}',
        b"[" * 200_000 + b"]" * 200_000,
        b"not json",
    ],
    ids=["repeated-key", "nan", "infinity", "minus-infinity", "overflow", "deep", "not-json"],
)
def test_aas_validate_refuses_a_repeated_key_nan_and_infinity(
    body: bytes, validator_calls: list[Any], tmp_path: Path
) -> None:
    outcome = aas_validate(context(tmp_path, "aas.validate", acquirer=_Sample(body)))
    assert (outcome.passed, outcome.reason_code) == (False, "AAS.INVALID")
    assert "repeated key, NaN, or Infinity" in outcome.message
    assert validator_calls == [], "the wrapped validator never sees an ambiguous sample"


def test_aas_validate_passes_a_plain_sample_to_the_validator(
    validator_calls: list[Any], tmp_path: Path
) -> None:
    outcome = aas_validate(context(tmp_path, "aas.validate", acquirer=_Sample(b'{"a": 1.5}')))
    assert (outcome.passed, outcome.reason_code) == (True, "AAS.VALID")
    assert validator_calls == [{"a": 1.5}]
    assert type(validator_calls[0]["a"]) is float, "the validator gets the same floats as before"
