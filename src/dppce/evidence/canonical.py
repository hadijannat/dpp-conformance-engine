"""Canonical JSON for the engine's own bodies: RFC 8785 (JCS) with integer-only numbers.

This is the canonical form of dppce decision bodies and hashes. It does not replace the
processing rules of any credential securing specification. See ADR 0006.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from dppce.models import Model

# RFC 8785 serializes numbers as IEEE 754 doubles. Integers are exact only inside this range.
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value cannot be put in canonical form."""


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"{path}: integer {value} is outside the exact range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floats are not permitted; use an integer unit or a string")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object key {key!r} is not a string")
            _check(item, f"{path}.{key}")
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"{path}: type {type(value).__name__} is not JSON")


def canonical_bytes(value: Any) -> bytes:
    """Return the RFC 8785 bytes of a model or a JSON value."""
    data = value.model_dump(mode="json", by_alias=True) if isinstance(value, Model) else value
    _check(data, "$")
    try:
        return rfc8785.dumps(data)
    except (rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def digest(value: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
