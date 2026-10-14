"""Canonical JSON for the engine's own bodies: RFC 8785 (JCS) with integer-only numbers.

This is the canonical form of dppce decision bodies and hashes. It does not replace the
processing rules of any credential securing specification. See ADR 0006.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
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


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        repeated = sorted({k for k in keys if keys.count(k) > 1})
        raise CanonicalizationError(f"duplicate object key: {', '.join(repeated)}")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise CanonicalizationError(f"{name} is not JSON")


def _finite_float(text: str) -> float:
    """A JSON number like 1e999 overflows to infinity. JSON has no infinity, so it is refused."""
    value = float(text)
    if not math.isfinite(value):
        raise CanonicalizationError(f"number {text} is outside the range of a float")
    return value


def parse_strict(raw: bytes | str, *, decimals: bool = False) -> Any:
    """Parse JSON that two parsers cannot read differently.

    Rejects a repeated object key (parsers disagree on which value wins) and the non-JSON
    constants NaN and Infinity. Use this for every document whose content gets verified.
    With ``decimals`` a number that is not an integer stays exact: a binary float would make
    0.1 and 0.10000000000000001 the same number.
    """
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=Decimal if decimals else _finite_float,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CanonicalizationError):
            raise
        raise CanonicalizationError(f"not valid JSON: {exc}") from exc


def is_exact(document: Any, model: Model) -> bool:
    """True if ``document`` is exactly the canonical form of ``model``.

    Validation fills defaults and can coerce types. Without this check the verified model
    could differ from the document that a different consumer reads.
    """
    try:
        return canonical_bytes(document) == canonical_bytes(model)
    except CanonicalizationError:
        return False
