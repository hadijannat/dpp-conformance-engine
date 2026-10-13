"""Applicability expression tree.

This is data, not code. A YAML file can hold only these five node shapes.
Nothing here is evaluated as Python or as a template. See ADR 0004.
The evaluator is ``dppce.applicability.evaluate``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import ConfigDict, Field

from dppce.models.base import Model, Tri


class Op(StrEnum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"
    CONTAINS = "contains"


type Operand = str | int | bool
type Expr = Const | Compare | All | AnyOf | Not


class Const(Model):
    """A literal outcome. ``{const: unknown}`` marks an applicability that nobody has resolved."""

    const: Tri
    reason: str = ""


class Compare(Model):
    """Compare one declared fact, addressed by a dotted path such as ``ics.product_category``.

    Ordering operators accept two integers or two ISO 8601 dates (``YYYY-MM-DD``).
    """

    fact: str = Field(pattern=r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$")
    op: Op
    value: Operand | tuple[Operand, ...]


class All(Model):
    all: tuple[Expr, ...] = Field(min_length=1)


class AnyOf(Model):
    any: tuple[Expr, ...] = Field(min_length=1)


class Not(Model):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    operand: Expr = Field(alias="not")


ALWAYS = Const(const=Tri.TRUE, reason="applies to every system in the profile")
