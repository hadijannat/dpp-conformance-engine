"""Identifier adapter: scheme-aware parsing, bounded resolution, and consistency.

Digital consistency does not prove physical authenticity. These checks compare identifiers in
digital records. They cannot show that a carrier sits on the product that it names.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from dppce.adapters.common import (
    blocked,
    carrier_identifier,
    completed,
    fetch_once,
    json_object,
    not_done,
    unusable,
)
from dppce.models import CheckOutcome, ExecutionStatus
from dppce.testdefs.registry import CheckContext, register

_GS1_PATH = re.compile(r"^/01/(?P<gtin>[0-9]{14})/21/(?P<serial>[A-Za-z0-9._-]{1,20})$")
_LIMIT = "Digital consistency does not prove physical authenticity."


def gtin_check_digit_ok(gtin: str) -> bool:
    """GS1 modulo-10 check: weights 3 and 1 alternate, starting with 3 at the leftmost of 13 digits."""
    total = sum(int(digit) * (3 if index % 2 == 0 else 1) for index, digit in enumerate(gtin[:-1]))
    return (10 - total % 10) % 10 == int(gtin[-1])


def parse_gs1_digital_link(text: str) -> str | None:
    """Return why ``text`` is not a ``/01/<gtin>/21/<serial>`` identifier, or None if it is one."""
    try:
        parts = urlsplit(text)
    except ValueError:
        return "it is not a URL"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "it is not an HTTP or HTTPS URL"
    match = _GS1_PATH.match(parts.path)
    if match is None:
        return "the path does not have the form /01/<14 digits>/21/<serial>"
    if not gtin_check_digit_ok(match["gtin"]):
        return "the GTIN check digit is wrong"
    return None


@register("identifier.parse", capability="identifier.parse")
def parse(ctx: CheckContext) -> CheckOutcome:
    scheme = str(ctx.params.get("scheme", ctx.ics.identifier_scheme))
    if scheme == "unknown":
        return blocked("IDENTIFIER.SCHEME.UNKNOWN", "The ICS does not declare the identifier scheme.")
    if scheme != "gs1-digital-link":
        message = f"This version has no parser for the scheme '{scheme}'."
        return not_done(ExecutionStatus.UNSUPPORTED, "IDENTIFIER.SCHEME.UNSUPPORTED", message)
    text, records, transformations, problem = carrier_identifier(ctx)
    if problem is not None or text is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    reason = parse_gs1_digital_link(text)
    kind: Literal["artifact", "declaration"] = "artifact" if records else "declaration"
    summary = {"scheme": scheme, "valid": reason is None, **({"reason": reason} if reason else {})}
    observation = ctx.observation(
        0, kind=kind, records=records, summary=summary, transformations=transformations
    )
    if reason is not None:
        return completed(
            False,
            "IDENTIFIER.SYNTAX.INVALID",
            f"The carrier identifier is not valid: {reason}.",
            [observation],
        )
    return completed(
        True, "IDENTIFIER.SYNTAX.OK", f"The carrier identifier has valid {scheme} syntax.", [observation]
    )


@register("identifier.resolve", capability="identifier.resolve")
def resolve(ctx: CheckContext) -> CheckOutcome:
    text, _, transformations, problem = carrier_identifier(ctx)
    if problem is not None or text is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    if urlsplit(text).scheme not in ("http", "https"):
        observation = ctx.observation(
            0, kind="derived", summary={"resolvable": False}, transformations=transformations
        )
        return completed(
            False,
            "IDENTIFIER.UNRESOLVED",
            "The carrier identifier is not a URL, so it cannot resolve.",
            [observation],
        )
    record = fetch_once(ctx, text)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    summary = {"status": record.status, "redirects": len(record.redirects)}
    observation = ctx.observation(
        0, kind="exchange", records=[record], summary=summary, transformations=transformations
    )
    if record.status in (404, 410):
        return completed(
            False,
            "IDENTIFIER.UNRESOLVED",
            f"The resolver answers {record.status} for the identifier.",
            [observation],
        )
    if record.status != 200:
        return completed(
            False, "IDENTIFIER.RESOLUTION.STATUS", f"The resolver answers {record.status}.", [observation]
        )
    if json_object(record) is None:
        return completed(
            False,
            "IDENTIFIER.RESPONSE.NOT_JSON",
            "The resolved resource is not a JSON object.",
            [observation],
        )
    return completed(
        True, "IDENTIFIER.RESOLVED", "The identifier resolves to a passport document.", [observation]
    )


@register("identifier.consistency", capability="identifier.consistency")
def consistency(ctx: CheckContext) -> CheckOutcome:
    carrier, records, transformations, problem = carrier_identifier(ctx)
    if problem is not None or carrier is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    if urlsplit(carrier).scheme not in ("http", "https"):
        return blocked(
            "IDENTIFIER.NOT_RESOLVABLE",
            "The carrier identifier is not a URL. There is no passport to compare.",
        )
    record = fetch_once(ctx, carrier)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    document = json_object(record) if record.status == 200 else None
    if document is None:
        return blocked(
            "IDENTIFIER.NOT_RESOLVED",
            "The identifier did not resolve to a passport. There is nothing to compare.",
        )
    passport = document.get("id")
    declared = ctx.ixit.samples.get("identifier") if "qr_image" in ctx.ixit.samples else None
    differences = [
        name
        for name, value in (("passport", passport), ("declared", declared))
        if value is not None and value != carrier
    ]
    if not isinstance(passport, str):
        differences = sorted({*differences, "passport"})
    summary = {
        "compared": ["carrier", "passport", *(["declared"] if declared else [])],
        "different": differences,
    }
    observation = ctx.observation(
        0, kind="exchange", records=[*records, record], summary=summary, transformations=transformations
    )
    if differences:
        message = f"The carrier identifier differs from: {', '.join(differences)}. {_LIMIT}"
        return completed(False, "IDENTIFIER.MISMATCH", message, [observation])
    return completed(
        True,
        "IDENTIFIER.CONSISTENT",
        f"The compared sources give the same identifier. {_LIMIT}",
        [observation],
    )
