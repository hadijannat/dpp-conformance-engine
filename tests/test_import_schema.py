"""scripts/import_schema.py: bundle a published schema set into one file with local references."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.common import validator

imp = importlib.import_module("scripts.import_schema")

DRAFT07 = "http://json-schema.org/draft-07/schema#"


def _write(directory: Path, name: str, document: dict[str, Any]) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _refs(node: Any) -> list[str]:
    if isinstance(node, dict):
        own = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
        return own + [r for v in node.values() for r in _refs(v)]
    if isinstance(node, list):
        return [r for v in node for r in _refs(v)]
    return []


def _set(tmp_path: Path) -> Path:
    _write(
        tmp_path,
        "common/units.json",
        {
            "$schema": DRAFT07,
            "$id": "https://example.test/schemas/units.json",
            "definitions": {"mass": {"type": "object", "properties": {"kg": {"type": "integer"}}}},
            "type": "string",
        },
    )
    _write(
        tmp_path,
        "common/item.json",
        {
            "$schema": DRAFT07,
            "properties": {
                "weight": {"$ref": "units.json#/definitions/mass"},
                "name": {"$ref": "#/definitions/n"},
            },
            "definitions": {"n": {"type": "string"}},
        },
    )
    return _write(
        tmp_path,
        "root.json",
        {
            "$schema": DRAFT07,
            "type": "object",
            "required": ["item"],
            "properties": {
                "item": {"$ref": "common/item.json"},
                "unit": {"$ref": "https://example.test/schemas/units.json"},
            },
        },
    )


def test_the_bundle_has_only_local_references_and_keeps_the_dialect(tmp_path: Path) -> None:
    out = imp.bundle(_set(tmp_path))
    assert out["$schema"] == DRAFT07
    assert all(ref.startswith("#/") for ref in _refs(out))
    assert "$id" not in json.dumps(out)
    assert validator(out) is not None


def test_the_bundle_validates_like_the_set(tmp_path: Path) -> None:
    check = validator(imp.bundle(_set(tmp_path)))
    assert check is not None
    good = {"item": {"name": "a", "weight": {"kg": 3}}, "unit": "kg"}
    assert list(check.iter_errors(good)) == []
    assert list(check.iter_errors({"item": {"name": 1, "weight": {"kg": "x"}}, "unit": 3}))


def test_a_reference_cycle_ends(tmp_path: Path) -> None:
    _write(tmp_path, "a.json", {"properties": {"b": {"$ref": "b.json"}}})
    _write(tmp_path, "b.json", {"properties": {"a": {"$ref": "a.json"}}})
    root = _write(tmp_path, "root.json", {"$schema": DRAFT07, "$ref": "a.json"})
    out = imp.bundle(root)
    assert all(ref.startswith("#/") for ref in _refs(out))
    assert validator(out) is not None


def test_a_reference_to_a_missing_document_is_an_error_and_nothing_is_fetched(tmp_path: Path) -> None:
    root = _write(tmp_path, "root.json", {"$ref": "https://example.test/not/in/the/set.json"})
    with pytest.raises(imp.BundleError, match="not in the set"):
        imp.bundle(root)


def test_a_reference_that_leaves_the_directory_is_an_error(tmp_path: Path) -> None:
    outside = _write(tmp_path, "outside.json", {"type": "string"})
    inner = tmp_path / "set"
    root = _write(inner, "root.json", {"$ref": "../outside.json"})
    assert outside.is_file()
    with pytest.raises(imp.BundleError, match="not in the set"):
        imp.bundle(root)


def test_the_command_writes_the_bundle(tmp_path: Path) -> None:
    out = tmp_path / "bundle.json"
    assert imp.main([str(_set(tmp_path)), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["$schema"] == DRAFT07
    assert imp.main([str(tmp_path / "missing.json"), "--out", str(out)]) == 1
