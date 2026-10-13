"""Three-valued evaluation of applicability expression trees.

Pure: no I/O and no clock. Missing information gives UNKNOWN, never FALSE.
The semantics are in docs/explanation/architecture.md, section 5.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from dppce.models import ICS, All, AnyOf, Compare, Const, Expr, Not, Op, Profile, Tri

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MISSING = object()
_NOT = {Tri.TRUE: Tri.FALSE, Tri.FALSE: Tri.TRUE, Tri.UNKNOWN: Tri.UNKNOWN}


class ApplicabilityError(ValueError):
    """The expression and the facts do not fit. This is a catalogue or ICS defect."""


@dataclass(frozen=True)
class Outcome:
    value: Tri
    reason: str


def facts_from(ics: ICS, profile: Profile) -> dict[str, Any]:
    """Build the fact tree that expressions address as ``ics.*`` and ``profile.*``."""
    profile_facts: dict[str, Any] = {"id": profile.id, "product_category": profile.product_category}
    profile_facts.update(profile.constants)
    return {"ics": ics.model_dump(mode="json"), "profile": profile_facts}


def fact_paths(expr: Expr) -> Iterator[str]:
    """Yield every fact path that the expression reads. Used by the catalogue lint."""
    match expr:
        case Compare():
            yield expr.fact
        case Not():
            yield from fact_paths(expr.operand)
        case All():
            for part in expr.all:
                yield from fact_paths(part)
        case AnyOf():
            for part in expr.any:
                yield from fact_paths(part)
        case Const():
            return


def evaluate(expr: Expr, facts: Mapping[str, Any]) -> Outcome:
    """Evaluate ``expr`` against ``facts`` with Kleene logic.

    Every branch is evaluated, so a defect raises the same error regardless of operand order.
    """
    match expr:
        case Const():
            return Outcome(expr.const, expr.reason or f"constant {expr.const.value}")
        case Compare():
            return _compare(expr, facts)
        case Not():
            inner = evaluate(expr.operand, facts)
            return Outcome(_NOT[inner.value], f"not ({inner.reason})")
        case All():
            return _combine([evaluate(e, facts) for e in expr.all], decisive=Tri.FALSE, neutral=Tri.TRUE)
        case AnyOf():
            return _combine([evaluate(e, facts) for e in expr.any], decisive=Tri.TRUE, neutral=Tri.FALSE)


def _combine(parts: Sequence[Outcome], *, decisive: Tri, neutral: Tri) -> Outcome:
    for value in (decisive, Tri.UNKNOWN):
        hits = [p.reason for p in parts if p.value is value]
        if hits:
            return Outcome(value, "; ".join(hits))
    return Outcome(neutral, "; ".join(p.reason for p in parts))


def _lookup(facts: Mapping[str, Any], path: str) -> Any:
    node: Any = facts
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _same(left: Any, right: Any, path: str) -> bool:
    # bool is a subclass of int in Python. Compare by exact type so that True never equals 1.
    if type(left) is not type(right):
        raise ApplicabilityError(f"{path}: cannot compare {left!r} with {right!r}: different types")
    return bool(left == right)


def _ordered(left: Any, right: Any, path: str) -> tuple[Any, Any]:
    if type(left) is int and type(right) is int:
        return left, right
    if isinstance(left, str) and isinstance(right, str) and _ISO_DATE.match(left) and _ISO_DATE.match(right):
        try:
            return date.fromisoformat(left), date.fromisoformat(right)
        except ValueError as exc:
            raise ApplicabilityError(f"{path}: not a calendar date: {exc}") from exc
    raise ApplicabilityError(f"{path}: ordering needs two integers or two ISO dates, got {left!r}, {right!r}")


def _result(node: Compare, actual: Any) -> bool:  # noqa: PLR0911 - one return per operator reads best
    op, expected, path = node.op, node.value, node.fact
    if op in (Op.IN, Op.NOT_IN):
        if not isinstance(expected, tuple):
            raise ApplicabilityError(f"{path}: operator '{op.value}' needs a list operand")
        hit = any(type(actual) is type(item) and actual == item for item in expected)
        return hit if op is Op.IN else not hit
    if isinstance(expected, tuple):
        raise ApplicabilityError(f"{path}: operator '{op.value}' needs a single operand")
    if op is Op.CONTAINS:
        if not isinstance(actual, list | tuple):
            raise ApplicabilityError(f"{path}: operator 'contains' needs a list-valued fact")
        return any(type(item) is type(expected) and item == expected for item in actual)
    if op is Op.EQ:
        return _same(actual, expected, path)
    if op is Op.NE:
        return not _same(actual, expected, path)
    left, right = _ordered(actual, expected, path)
    if op is Op.GT:
        return bool(left > right)
    if op is Op.GE:
        return bool(left >= right)
    if op is Op.LT:
        return bool(left < right)
    return bool(left <= right)


def _compare(node: Compare, facts: Mapping[str, Any]) -> Outcome:
    actual = _lookup(facts, node.fact)
    if actual is _MISSING or actual is None or actual == "unknown":
        return Outcome(Tri.UNKNOWN, f"{node.fact} is not known")
    result = _result(node, actual)
    shown = list(node.value) if isinstance(node.value, tuple) else node.value
    text = f"{node.fact} ({actual!r}) {node.op.value} {shown!r} is {str(result).lower()}"
    return Outcome(Tri.TRUE if result else Tri.FALSE, text)
