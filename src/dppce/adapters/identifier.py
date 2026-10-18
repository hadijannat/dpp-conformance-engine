"""Identifier adapter: scheme-aware parsing, bounded resolution, and consistency.

Digital consistency does not prove physical authenticity. These checks compare identifiers in
digital records. They cannot show that a carrier sits on the product that it names.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from dppce.adapters.common import (
    blocked,
    carrier_identifier,
    completed,
    fetch_once,
    json_object,
    media_type,
    not_done,
    unusable,
)
from dppce.models import CheckOutcome, ExecutionStatus, Model
from dppce.testdefs.registry import CheckContext, register

_GS1_PATH = re.compile(r"^/01/(?P<gtin>[0-9]{14})/21/(?P<serial>[A-Za-z0-9._-]{1,20})$")
# The scheme spellings, the host characters, and the URI characters that GS1 Digital Link permits.
_SCHEMES = ("http://", "https://", "HTTP://", "HTTPS://")
_HOST = re.compile(r"[A-Za-z0-9.:\[\]-]+")
_URI_CHARACTERS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
# Test-purpose parameters of identifier.resolve. Printable ASCII only: no CR, no LF.
_ACCEPT = re.compile(r"[\x20-\x7e]{1,256}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")
_MAX_MEDIA_TYPES = 16
_LIMIT = "Digital consistency does not prove physical authenticity."


class ParseParams(Model):
    scheme: str | None = Field(
        default=None,
        min_length=1,
        description="Identifier scheme to parse. Omit the key to use identifier_scheme of the ICS.",
    )

    @field_validator("scheme", mode="before")
    @classmethod
    def _not_null(cls, value: object) -> object:
        # A validator does not run on the default, so only an explicit null comes here. The
        # check would turn it into the scheme 'None'.
        if value is None:
            raise ValueError("must be a scheme name; omit the key to use the ICS scheme")
        return value


class ResolveParams(Model):
    accept: str | None = Field(
        default=None, description="Accept request header. Printable ASCII, 1 to 256 characters."
    )
    accepted_media_types: tuple[str, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=_MAX_MEDIA_TYPES,
        description="Final media types that count as resolved. Default: a final JSON object only.",
    )

    @field_validator("accept")
    @classmethod
    def _accept(cls, value: str | None) -> str | None:
        if value is not None and not _ACCEPT.fullmatch(value):
            raise ValueError("must be printable ASCII of 1 to 256 characters")
        return value

    @field_validator("accepted_media_types")
    @classmethod
    def _media_types(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is not None and not all(_MEDIA_TYPE.fullmatch(t) for t in value):
            raise ValueError("each entry must be a lower-case media type such as text/html")
        return value


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
    # The raw prefix, because urlsplit lower-cases the scheme and GS1 refuses a mixed case.
    if not text.startswith(_SCHEMES) or not parts.hostname:
        return "it is not an HTTP or HTTPS URL"
    # netloc, not hostname, so that user information is refused too.
    if not _HOST.fullmatch(parts.netloc):
        return "the host has a character that GS1 Digital Link does not permit"
    match = _GS1_PATH.match(parts.path)
    if match is None:
        return "the path does not have the form /01/<14 digits>/21/<serial>"
    if not gtin_check_digit_ok(match["gtin"]):
        return "the GTIN check digit is wrong"
    # Last, so that a path in non-ASCII digits keeps the path reason.
    if not _URI_CHARACTERS.fullmatch(text):
        return "the URL has a character that a URI does not permit"
    return None


@register("identifier.parse", capability="identifier.parse", params=ParseParams)
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


def _resolve_params(ctx: CheckContext) -> tuple[str | None, list[str] | None] | None:
    """The validated ``accept`` and ``accepted_media_types`` parameters, or None if malformed.

    fullmatch, not ``$``: a trailing newline must not pass. CR and LF are outside the classes.
    """
    accept = ctx.params.get("accept")
    accepted = ctx.params.get("accepted_media_types")
    if accept is not None and not (isinstance(accept, str) and _ACCEPT.fullmatch(accept)):
        return None
    if accepted is not None and not (
        isinstance(accepted, list)
        and 1 <= len(accepted) <= _MAX_MEDIA_TYPES
        and all(isinstance(t, str) and _MEDIA_TYPE.fullmatch(t) for t in accepted)
    ):
        return None
    return accept, [str(t) for t in accepted] if accepted is not None else None


@register("identifier.resolve", capability="identifier.resolve", params=ResolveParams)
def resolve(ctx: CheckContext) -> CheckOutcome:
    params = _resolve_params(ctx)
    if params is None:
        message = "The parameters 'accept' or 'accepted_media_types' are not valid. Nothing is fetched."
        return blocked("IDENTIFIER.PARAMS.INVALID", message)
    accept, accepted = params
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
    record = fetch_once(ctx, text, accept=accept)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    final = media_type(record)
    summary = {"status": record.status, "redirects": len(record.redirects), "media_type": final}
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
    if accepted is not None and final not in accepted:
        message = (
            f"The resolved resource has the media type '{final}', which the test purpose does not accept."
        )
        return completed(False, "IDENTIFIER.RESPONSE.MEDIA_TYPE", message, [observation])
    if accepted is not None and not (final == "application/json" or final.endswith("+json")):
        message = (
            f"The identifier resolves to a resource of the accepted media type '{final}'. "
            "This does not show that the resource is the passport of the product."
        )
        return completed(True, "IDENTIFIER.RESOLVED.MEDIA_TYPE", message, [observation])
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
