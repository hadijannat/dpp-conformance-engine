"""Data adapter: JSON Schema, context allowlist, and versioned rule packs.

Rule pack format: docs/reference/reference-system.md, section 5.1. Every rule states its basis.
A normative threshold must cite its source. An engineering threshold is a project choice and is
reported as such. SHACL validation is an interface only in this version.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, ValidationError, model_validator

from dppce.adapters.common import (
    MISSING,
    blocked,
    completed,
    dig,
    fetch_once,
    json_object,
    resource_url,
    schema_errors,
    unusable,
    validator,
)
from dppce.applicability import ApplicabilityError, evaluate, facts_from
from dppce.catalogue import CatalogueError, load_data, load_model
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, Expr, Model, Tri
from dppce.testdefs.registry import CheckContext, register

DocumentKind = Literal["item", "model"]
# When more than one rule fails, the first kind in this order names the reason code.
_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("required_fields", "DATA.COMPLETENESS.MISSING"),
    ("unit", "DATA.UNIT.INVALID"),
    ("range", "DATA.RANGE.VIOLATED"),
    ("relationship", "DATA.RELATIONSHIP.VIOLATED"),
    ("freshness", "DATA.FRESHNESS.STALE"),
)


class Basis(Model):
    """Why a rule exists. A normative rule cites its source; an engineering rule is a project choice."""

    basis_class: Literal["normative", "engineering", "illustrative"] = Field(alias="class")
    source_id: str = ""
    citation: str = ""
    note: str = ""

    @model_validator(mode="after")
    def _normative_cites_a_source(self) -> Self:
        if self.basis_class == "normative" and not (self.source_id and self.citation):
            raise ValueError("a normative rule cites a source and a provision")
        return self


class Rule(Model):
    id: str
    kind: Literal["required_fields", "unit", "range", "relationship", "freshness"]
    document: DocumentKind
    basis: Basis
    when: Expr | None = None
    fields: tuple[str, ...] = ()
    field: str = ""
    allowed: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    left: str = ""
    op: Literal["lt", "le", "eq", "ge", "gt"] = "le"
    right: str = ""
    max_age_days: int | None = Field(default=None, ge=0)


class RulePack(Model):
    schema_version: Literal["dppce.rulepack/1"]
    rulepack_id: str
    version: str
    rules: tuple[Rule, ...]


def _fetch_document(
    ctx: CheckContext, kind: str, *, decimals: bool = False
) -> tuple[dict[str, Any] | None, Record | None, CheckOutcome | None]:
    """Fetch the item-level passport or the model-level data: (document, record, outcome if not usable)."""
    area = "DATA"
    url = resource_url(ctx, "model" if kind == "model" else "item", area)
    if isinstance(url, CheckOutcome):
        return None, None, url
    record = fetch_once(ctx, url)
    if (problem := unusable(ctx, record)) is not None:
        return None, record, problem
    document = json_object(record, decimals=decimals) if record.status == 200 else None
    if document is None:
        observation = ctx.observation(0, kind="exchange", records=[record], summary={"status": record.status})
        message = f"The {kind}-level document is not a JSON object (status {record.status})."
        return None, record, completed(False, f"{area}.RESPONSE.NOT_JSON", message, [observation])
    return document, record, None


@register("data.jsonschema", capability="data.jsonschema")
def jsonschema_check(ctx: CheckContext) -> CheckOutcome:
    kind = str(ctx.params.get("document", "item"))
    path = ctx.profile.model_schema if kind == "model" else ctx.profile.item_schema
    if path is None:
        return blocked("DATA.SCHEMA.MISSING", f"The profile names no {kind}-level schema.")
    try:
        check = validator(load_data(ctx.data_root / path))
    except CatalogueError:
        return blocked("DATA.SCHEMA.MISSING", f"The pinned {kind}-level schema cannot be read.")
    if check is None:
        return blocked(
            "DATA.SCHEMA.NOT_LOCAL", "The schema uses a reference that is not local. Nothing is fetched."
        )
    document, record, problem = _fetch_document(ctx, kind)
    if problem is not None or document is None or record is None:
        return problem or blocked("DATA.NO_TARGET", "No document is available.")
    errors = schema_errors(check, document)
    summary = {"document": kind, "schema": path, "schema_errors": errors}
    observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
    if errors:
        return completed(
            False,
            "DATA.SCHEMA.INVALID",
            f"The {kind}-level document has {len(errors)} schema errors.",
            [observation],
        )
    return completed(
        True, "DATA.SCHEMA.OK", f"The {kind}-level document matches the pinned schema.", [observation]
    )


@register("data.context", capability="data.context")
def context_check(ctx: CheckContext) -> CheckOutcome:
    kind = str(ctx.params.get("document", "item"))
    allowed = ctx.params.get("allowed_contexts")
    if not isinstance(allowed, list) or not allowed:
        return blocked("DATA.CONTEXT.NO_ALLOWLIST", "The test purpose gives no allowlist of contexts.")
    document, record, problem = _fetch_document(ctx, kind)
    if problem is not None or document is None or record is None:
        return problem or blocked("DATA.NO_TARGET", "No document is available.")
    declared = document.get("@context")
    entries = declared if isinstance(declared, list) else [declared] if declared is not None else []
    # An inline context object is not a pinned reference, so it is never in the allowlist.
    foreign = sorted(
        str(e) if isinstance(e, str) else "<inline context>" for e in entries if e not in allowed
    )
    summary = {"document": kind, "contexts": len(entries), "not_allowed": foreign}
    observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
    if not entries:
        return completed(False, "DATA.CONTEXT.MISSING", "The document names no context.", [observation])
    if foreign:
        message = f"{len(foreign)} context references are not in the pinned allowlist. No context is fetched."
        return completed(False, "DATA.CONTEXT.NOT_ALLOWED", message, [observation])
    return completed(
        True, "DATA.CONTEXT.OK", "Every context reference is in the pinned allowlist.", [observation]
    )


def _compare(left: int | Decimal, op: str, right: int | Decimal) -> bool:
    return {
        "lt": left < right,
        "le": left <= right,
        "eq": left == right,
        "ge": left >= right,
        "gt": left > right,
    }[op]


def _is_number(value: Any) -> bool:
    """An integer (not a boolean) or a finite exact decimal. A binary float is never accepted."""
    return type(value) is int or (type(value) is Decimal and value.is_finite())


def rule_holds(rule: Rule, document: dict[str, Any], now: datetime) -> bool:
    """True if the document obeys the rule. Only ``required_fields`` judges an absent field."""
    if rule.kind == "required_fields":
        return all(dig(document, name) not in (MISSING, None) for name in rule.fields)
    if rule.kind == "relationship":
        left, right = dig(document, rule.left), dig(document, rule.right)
        if left is MISSING or right is MISSING:
            return True
        return _is_number(left) and _is_number(right) and _compare(left, rule.op, right)
    value = dig(document, rule.field)
    if value is MISSING:
        return True
    if rule.kind == "unit":
        return value in rule.allowed
    if rule.kind == "range":
        if not _is_number(value):
            return False
        return (rule.min is None or value >= rule.min) and (rule.max is None or value <= rule.max)
    if rule.max_age_days is None:
        return True
    try:
        updated = parse_stamp(str(value))
    except ValueError:
        return False
    # The limit is inclusive: an age of exactly max_age_days passes.
    return now - updated <= timedelta(days=rule.max_age_days)


@register("data.rules", capability="data.rules")
def rules_check(ctx: CheckContext) -> CheckOutcome:
    kind = str(ctx.params.get("document", "item"))
    if not ctx.profile.rule_packs:
        return blocked("DATA.RULES.MISSING", "The profile names no rule pack.")
    try:
        packs = [load_model(ctx.data_root / path, RulePack) for path in ctx.profile.rule_packs]
    except (CatalogueError, ValidationError):
        return blocked("DATA.RULES.MISSING", "A pinned rule pack cannot be read or is not valid.")
    # Exact decimals: a third-party passport may hold 97.5, and a binary float would make close
    # values equal. The summary below holds rule ids only, so no Decimal reaches the decision body.
    document, record, problem = _fetch_document(ctx, kind, decimals=True)
    if problem is not None or document is None or record is None:
        return problem or blocked("DATA.NO_TARGET", "No document is available.")
    facts = facts_from(ctx.ics, ctx.profile)
    failed: list[Rule] = []
    applied = 0
    for rule in (r for pack in packs for r in pack.rules if r.document == kind):
        if rule.when is not None:
            try:
                applies = evaluate(rule.when, facts).value
            except ApplicabilityError:
                return blocked(
                    "DATA.RULES.MISSING", f"The condition of rule {rule.id} does not fit the declared facts."
                )
            if applies is Tri.UNKNOWN:
                message = f"The applicability of rule {rule.id} is unknown. Unknown is not treated as false."
                return blocked("DATA.RULES.APPLICABILITY_UNKNOWN", message)
            if applies is Tri.FALSE:
                continue
        applied += 1
        if not rule_holds(rule, document, ctx.evaluation_time):
            failed.append(rule)
    summary = {
        "document": kind,
        "rule_packs": [f"{p.rulepack_id} {p.version}" for p in packs],
        "rules_applied": applied,
        "failed_rules": [r.id for r in failed],
        "failed_engineering_rules": [r.id for r in failed if r.basis.basis_class == "engineering"],
    }
    observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
    if not failed:
        return completed(
            True, "DATA.RULES.OK", f"The document obeys the {applied} rules that apply.", [observation]
        )
    kinds = {r.kind for r in failed}
    code = next(code for name, code in _PRECEDENCE if name in kinds)
    return completed(
        False,
        code,
        f"{len(failed)} of {applied} rules failed: {', '.join(r.id for r in failed)}.",
        [observation],
    )
