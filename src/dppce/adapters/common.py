"""Helpers that every adapter shares.

Contract: docs/reference/reference-system.md, section 8.
"""

from __future__ import annotations

import io
import re
import warnings
from collections.abc import Callable, Iterator, Mapping, Sequence
from decimal import Decimal
from typing import Any, Final
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import jsonschema
import referencing.jsonschema
from jsonschema.exceptions import SchemaError, ValidationError
from jsonschema.protocols import Validator
from referencing import Registry
from referencing.exceptions import Unresolvable

from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import REMOVED, redact_url
from dppce.infrastructure.transport import origin_of
from dppce.models import (
    PATH_TEMPLATE_PATTERN,
    PLACEHOLDER_PATTERN,
    CheckOutcome,
    ExecutionStatus,
    JsonValue,
    Observation,
    ResourceName,
)
from dppce.testdefs.registry import CheckContext

MISSING: Final = object()
_DENIED: Final = ("policy_denied", "authorization_denied", "budget_exhausted")
SERVER_ERRORS: Final = range(500, 600)
_MAX_QR_PIXELS: Final = 4096 * 4096


def completed(
    passed: bool,
    code: str,
    message: str,
    observations: Sequence[Observation] = (),
    *,
    no_answer: bool = False,
) -> CheckOutcome:
    return CheckOutcome(
        status=ExecutionStatus.COMPLETED,
        passed=passed,
        unreachable=no_answer,
        reason_code=code,
        message=message,
        observations=tuple(observations),
    )


def not_done(status: ExecutionStatus, code: str, message: str) -> CheckOutcome:
    """An outcome for a step that could not be assessed. It maps to inconclusive, never to pass."""
    return CheckOutcome(status=status, reason_code=code, message=message)


def blocked(code: str, message: str) -> CheckOutcome:
    return not_done(ExecutionStatus.BLOCKED, code, message)


def effective_url(ctx: CheckContext, url: str) -> tuple[str, tuple[str, ...]]:
    """Apply the origin override of the test rig. Returns the URL and the transformations used.

    The origin selects the override, not the spelling: HTTPS://ID.EXAMPLE:443 is https://id.example.
    """
    public = ctx.ixit.endpoints.get("public_origin")
    override = ctx.ixit.endpoints.get("origin_override")
    if not (public and override):
        return url, ()
    try:
        parts = urlsplit(url)
        same = origin_of(url) == origin_of(public) and not (parts.username or parts.password)
    except ValueError:
        return url, ()
    if not same:
        return url, ()
    return override.rstrip("/") + urlunsplit(("", "", parts.path, parts.query, parts.fragment)), (
        "origin_override",
    )


def _accept_of(record: Record) -> str:
    # The request headers, not Record.header(): that one searches the response headers.
    return next((v for k, v in record.request_headers if k.lower() == "accept"), "*/*")


def fetch_once(ctx: CheckContext, url: str, role: str = "anonymous", accept: str | None = None) -> Record:
    """Fetch a URL, or reuse an earlier good record of the same request. Keeps the request count low.

    A record is reused only if it asked for the same ``Accept`` value. ``*/*`` is the default of
    the transport, and a record without an ``Accept`` header counts as that default.
    """
    target, _ = effective_url(ctx, url)
    recorded = redact_url(target)
    wanted = accept or "*/*"
    for record in ctx.acquirer.records():
        same = (record.kind, record.method, record.url, record.role) == ("http", "GET", recorded, role)
        if same and record.error is None and _accept_of(record) == wanted:
            return record
    # The key is spelled as the transport spells its default, so it replaces that entry.
    headers = {"Accept": accept} if accept else {}
    return ctx.acquirer.fetch(Request("GET", target, role=role, headers=headers))


def no_answer(ctx: CheckContext, record: Record) -> CheckOutcome:
    """The outcome for a transport error or a server error. A missing answer is not a failure."""
    summary: dict[str, JsonValue] = {"transport_error": record.error}
    if record.error is None:
        # No transport error here means a 5xx answer (owner decision of 2026-10-18).
        code, text = "TRANSPORT.SERVER_ERROR", f"The system answers {record.status}, a server error."
        summary = {"status": record.status}
    elif record.error == "redirect_out_of_scope":
        code, text = (
            "TRANSPORT.REDIRECT_OUT_OF_SCOPE",
            "The engine did not follow a redirect to a host outside the scope.",
        )
    elif record.error in _DENIED:
        code, text = "TRANSPORT.DENIED", f"The transport policy refused the request ({record.error})."
    else:
        code, text = "TRANSPORT.UNREACHABLE", f"The system gave no answer ({record.error})."
    observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
    return completed(
        False, code, text + " A connectivity failure does not prove a breach.", [observation], no_answer=True
    )


def unusable(
    ctx: CheckContext, record: Record, *, server_error_is_no_answer: bool = True
) -> CheckOutcome | None:
    """Return an outcome if the record cannot be judged, or None if its body can be used.

    A status from 500 to 599 is no answer, like a transport error. A check that judges such an
    answer itself passes ``server_error_is_no_answer=False``.
    """
    if record.error is not None or (server_error_is_no_answer and record.status in SERVER_ERRORS):
        return no_answer(ctx, record)
    if record.truncated:
        return blocked(
            "TRANSPORT.BODY_TRUNCATED", "The body is larger than the limit. A partial body proves nothing."
        )
    # Every header line counts: a second Content-Encoding line adds a coding. A transfer coding
    # other than chunked (which the HTTP library removes) also leaves the body encoded.
    codings = [
        token.strip().lower()
        for name, value in record.headers
        if name.lower() in ("content-encoding", "transfer-encoding")
        for token in value.split(",")
    ]
    encoded = sorted({c for c in codings if c not in ("", "identity", "chunked")})
    if encoded:
        # The transport asks for no encoding and no check decompresses. An encoded body is
        # neither clean nor wrong: it is not assessed.
        message = f"The body has the coding {', '.join(encoded)}. This engine does not decode it."
        return blocked("TRANSPORT.BODY_ENCODED", message)
    return None


def not_200(ctx: CheckContext, area: str, record: Record, records: Sequence[Record]) -> CheckOutcome | None:
    """Return an outcome if ``record`` did not answer 200, or None. Call it after ``unusable``.

    401, 403, and 404 on an anonymous fetch prove nothing about the data, so the step is
    ``blocked``. Any other status is a fail with ``<AREA>.RESPONSE.STATUS``. The body is not read.
    """
    if record.status == 200:
        return None
    observation = ctx.observation(0, kind="exchange", records=records, summary={"status": record.status})
    if record.status in (401, 403, 404):
        return CheckOutcome(
            status=ExecutionStatus.BLOCKED,
            reason_code=f"{area}.RESPONSE.NOT_CONCLUSIVE",
            message=f"A document answers {record.status} to an anonymous request. That proves nothing.",
            observations=(observation,),
        )
    message = f"A document answers {record.status}, not 200."
    return completed(False, f"{area}.RESPONSE.STATUS", message, [observation])


def json_object(record: Record, *, decimals: bool = False) -> dict[str, Any] | None:
    """Parse the body as one JSON object. A repeated key is ambiguous, so it is not accepted.

    With ``decimals`` a non-integer number is an exact ``Decimal``. Such a document is for
    comparison only: a Decimal must never reach an observation or a decision body.
    """
    try:
        value = parse_strict(record.body, decimals=decimals)
    except CanonicalizationError:
        return None
    return value if isinstance(value, dict) else None


def media_type(record: Record) -> str:
    """The response media type without parameters, in lower case. Empty if absent."""
    return (record.header("content-type") or "").split(";")[0].strip().lower()


def template_url(ctx: CheckContext, endpoint: str, template: str, area: str) -> str | CheckOutcome:
    """Build the public URL of a path template under an IXIT endpoint, or a blocked outcome.

    The template is not evaluated. Each named placeholder is replaced with its percent-encoded
    value, and the path is appended to the endpoint. The template starts with one '/' and the
    endpoint has no query or fragment, so the scheme, the host, and the port cannot change.
    """
    if re.fullmatch(PATH_TEMPLATE_PATTERN, template) is None:
        # The IXIT and the access policy validate every template first. This is an engine defect.
        raise ValueError("not a path template")
    base = ctx.ixit.endpoints.get(endpoint, "")
    try:
        parts = urlsplit(base)
        plain = parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:
        plain = False
    if not plain or parts.query or parts.fragment or "#" in base or "?" in base:
        return blocked(
            f"{area}.NO_TARGET",
            f"The IXIT gives no http or https endpoint '{endpoint}' without a query or a fragment.",
        )
    passport_id = ctx.ixit.samples.get("passport_id", "")
    values = {"id": passport_id} if passport_id else {}
    split = ctx.ixit.id_parts
    if split is not None and passport_id:
        pieces = passport_id.split(split.separator, len(split.names) - 1)
        if len(pieces) == len(split.names) and all(pieces):
            values |= dict(zip(split.names, pieces, strict=True))
    for name in re.findall(PLACEHOLDER_PATTERN, template):
        if name in values:
            continue
        if name == "id" or not passport_id:
            message = "The IXIT gives no passport identifier."
        elif split is None or name not in split.names:
            message = f"The IXIT declares no identifier split for '{name}'."
        else:
            message = "The passport identifier does not split into the declared parts."
        return blocked(f"{area}.NO_TARGET", message)
    # quote() keeps '.', and a server resolves a dot segment to another resource (ADR 0011).
    if any(values[name] in (".", "..") for name in re.findall(PLACEHOLDER_PATTERN, template)):
        return blocked(f"{area}.NO_TARGET", "A placeholder value of the IXIT is a dot segment.")
    path = re.sub(PLACEHOLDER_PATTERN, lambda m: quote(values[m[1]], safe=""), template)
    return base.rstrip("/") + path


def resource_url(ctx: CheckContext, resource: ResourceName, area: str) -> str | CheckOutcome:
    """The public URL of a passport resource from its IXIT template, or a blocked outcome."""
    template = ctx.ixit.resources.get(resource)
    if template is None:
        message = f"The IXIT declares no URL template for the resource '{resource}'."
        return blocked(f"{area}.NO_TARGET", message + " The engine has no default path.")
    return template_url(ctx, template.endpoint, template.path, area)


def is_http_url(text: str) -> bool:
    """True for an http or https URL with a host and a valid port that the transport sends as written.

    urlsplit drops tab, CR, and LF, and strips leading and trailing controls and spaces. The
    record would then name a request that was never sent, so such a text is not a URL here.
    """
    if any(c <= " " or c == "\x7f" for c in text):
        return False
    try:
        parts = urlsplit(text)
        _ = parts.port  # ValueError for a port that is not a number from 0 to 65535
        return parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:
        return False


def item_url(ctx: CheckContext, area: str) -> str | CheckOutcome:
    """The URL of the item-level passport: from its template, or where the carrier resolves to.

    With ``IXIT.item_target: resolved`` the URL is the last redirect target of the resolver
    exchange. The transport checks it again when a check fetches it, so the system under test
    cannot add an origin that the operator did not confirm.
    """
    if ctx.ixit.item_target == "template":
        return resource_url(ctx, "item", area)
    text, _, _, problem = carrier_identifier(ctx)
    if problem is not None and problem.status is not ExecutionStatus.COMPLETED:
        return problem
    if problem is not None or text is None or not is_http_url(text):
        # A carrier that fails its own check is a finding of that check, not of this one.
        message = "The IXIT asks for the resolved item target, and the carrier gives no URL to resolve."
        return blocked(f"{area}.NO_TARGET", message)
    record = fetch_once(ctx, text)
    if record.error is not None or record.status in SERVER_ERRORS:
        return no_answer(ctx, record)
    if record.status != 200:
        message = f"The IXIT asks for the resolved item target, and the resolver answers {record.status}."
        return blocked(f"{area}.NO_TARGET", message)
    final = record.redirects[-1] if record.redirects else record.url
    # Redaction writes the marker percent-encoded in a query and plain elsewhere.
    if REMOVED in unquote(final):
        message = "Redaction changed the resolved URL. The engine does not fetch a changed URL."
        return blocked(f"{area}.NO_TARGET", message)
    return final


def same_json(a: Any, b: Any) -> bool:
    """Equality of two JSON values that were parsed with exact numbers.

    Python calls ``True`` and ``1`` equal. JSON does not: a passport that signs ``true`` and
    publishes ``1`` shows two different documents. The numbers 1 and 1.0 are one JSON number.
    """
    # A work list, not recursion: a deeply nested passport must not stop the check.
    pending = [(a, b)]
    while pending:
        x, y = pending.pop()
        if isinstance(x, bool) or isinstance(y, bool):
            same = x is y
        elif isinstance(x, dict) and isinstance(y, dict):
            same = x.keys() == y.keys()
            if same:
                pending.extend((value, y[key]) for key, value in x.items())
        elif isinstance(x, list) and isinstance(y, list):
            same = len(x) == len(y)
            if same:
                pending.extend(zip(x, y, strict=True))
        elif isinstance(x, int | Decimal) and isinstance(y, int | Decimal):
            same = x == y
        else:
            same = type(x) is type(y) and bool(x == y)
        if not same:
            return False
    return True


def dig(document: Any, dotted: str) -> Any:
    """Return the value at a dotted path, or ``MISSING``."""
    node = document
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return MISSING
        node = node[part]
    return node


# A fixed set, so that an installed optional package cannot change what a run asserts. These
# checkers of jsonschema need only the standard library. The other formats are the engine's own:
# jsonschema's checkers for them need packages that are not installed.
_FORMATS: Final = jsonschema.FormatChecker(formats=("email", "idn-email", "ipv4", "ipv6", "uuid"))

# RFC 3339 section 5.6. [0-9] and fullmatch: a non-ASCII digit or a trailing newline is refused.
_FULL_DATE: Final = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_FULL_TIME: Final = re.compile(
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)
# RFC 3339 Appendix A. ABNF literals are case-insensitive (RFC 5234 section 2.3); ASCII only,
# because Unicode case folding matches the long s to "S".
_DUR_TIME: Final = r"T(?:[0-9]+H(?:[0-9]+M(?:[0-9]+S)?)?|[0-9]+M(?:[0-9]+S)?|[0-9]+S)"
_DUR_DATE: Final = r"(?:[0-9]+D|[0-9]+M(?:[0-9]+D)?|[0-9]+Y(?:[0-9]+M(?:[0-9]+D)?)?)"
_DURATION: Final = re.compile(
    f"P(?:{_DUR_DATE}(?:{_DUR_TIME})?|{_DUR_TIME}|[0-9]+W)", re.ASCII | re.IGNORECASE
)


def _days_in(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _full_date(text: str) -> tuple[int, int, int] | None:
    # Not datetime.date: RFC 3339 permits the year 0000, and Python dates start at 0001.
    match = _FULL_DATE.fullmatch(text)
    if match is None:
        return None
    year, month, day = map(int, match.groups())
    return (year, month, day) if 1 <= month <= 12 and 1 <= day <= _days_in(year, month) else None


def _full_time(text: str) -> tuple[bool, int] | None:
    """(leap second, day shift to UTC) of an RFC 3339 full-time, or None.

    A leap second is valid only at 23:59 UTC (RFC 3339 section 5.7).
    """
    match = _FULL_TIME.fullmatch(text)
    if match is None:
        return None
    hour, minute, second, sign = int(match[1]), int(match[2]), int(match[3]), match[4]
    hours, minutes = int(match[5] or 0), int(match[6] or 0)
    if hour > 23 or minute > 59 or second > 60 or hours > 23 or minutes > 59:
        return None
    offset = (hours * 60 + minutes) * (-1 if sign == "-" else 1)
    shift, utc = divmod(hour * 60 + minute - offset, 1440)
    if second == 60 and utc != 23 * 60 + 59:
        return None
    return second == 60, shift


@_FORMATS.checks("date")
def _is_date(value: object) -> bool:
    return not isinstance(value, str) or _full_date(value) is not None


@_FORMATS.checks("time")
def _is_time(value: object) -> bool:
    return not isinstance(value, str) or _full_time(value) is not None


@_FORMATS.checks("date-time")
def _is_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    day, separator, time = value[:10], value[10:11], value[11:]
    date, clock = _full_date(day), _full_time(time)
    if date is None or separator not in ("T", "t") or clock is None:
        return False
    leap, shift = clock
    if not leap:
        return True
    # A leap second ends a month in UTC. The UTC date is the local date moved by the shift.
    year, month, mday = date
    last = _days_in(year, month)
    return {0: mday == last, 1: mday + 1 == last, -1: mday == 1}[shift]


@_FORMATS.checks("duration")
def _is_duration(value: object) -> bool:
    return not isinstance(value, str) or _DURATION.fullmatch(value) is not None


def _uri_grammar(ucschar: str, iprivate: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """RFC 3986 Appendix A, or RFC 3987 section 2.2 with the extra characters: (absolute, reference)."""
    hexdig, sub = "[0-9A-Fa-f]", "!$&'()*+,;="
    unreserved = "A-Za-z0-9._~" + ucschar + r"\-"
    pct = f"%{hexdig}{hexdig}"
    pchar = f"(?:[{unreserved}{sub}:@]|{pct})"
    octet = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    h16, ipv4 = hexdig + "{1,4}", rf"{octet}(?:\.{octet}){{3}}"
    ls32 = f"(?:{h16}:{h16}|{ipv4})"
    ipv6 = "|".join(
        (
            f"(?:{h16}:){{6}}{ls32}",
            f"::(?:{h16}:){{5}}{ls32}",
            f"(?:{h16})?::(?:{h16}:){{4}}{ls32}",
            f"(?:(?:{h16}:){{0,1}}{h16})?::(?:{h16}:){{3}}{ls32}",
            f"(?:(?:{h16}:){{0,2}}{h16})?::(?:{h16}:){{2}}{ls32}",
            f"(?:(?:{h16}:){{0,3}}{h16})?::{h16}:{ls32}",
            f"(?:(?:{h16}:){{0,4}}{h16})?::{ls32}",
            f"(?:(?:{h16}:){{0,5}}{h16})?::{h16}",
            f"(?:(?:{h16}:){{0,6}}{h16})?::",
        )
    )
    # An IP literal stays ASCII in an IRI too. RFC 3986 has no zone identifier.
    literal = rf"\[(?:{ipv6}|v{hexdig}+\.[A-Za-z0-9._~\-{sub}:]+)\]"
    userinfo = f"(?:[{unreserved}{sub}:]|{pct})*"
    authority = f"(?:{userinfo}@)?(?:{literal}|(?:[{unreserved}{sub}]|{pct})*)(?::[0-9]*)?"
    abempty = f"(?:/{pchar}*)*"
    absolute_path = f"/(?:{pchar}+{abempty})?"
    hier = f"(?://{authority}{abempty}|{absolute_path}|{pchar}+{abempty}|)"
    noscheme = f"(?:[{unreserved}{sub}@]|{pct})+{abempty}"
    relative = f"(?://{authority}{abempty}|{absolute_path}|{noscheme}|)"
    tail = f"(?:\\?(?:{pchar}|[/?{iprivate}])*)?(?:#(?:{pchar}|[/?])*)?"
    scheme = r"[A-Za-z][A-Za-z0-9+.\-]*"
    return re.compile(f"{scheme}:{hier}{tail}"), re.compile(f"(?:{scheme}:{hier}|{relative}){tail}")


_URI, _URI_REFERENCE = _uri_grammar("", "")


def _ranges(*bounds: tuple[int, int]) -> str:
    return "".join(f"{chr(low)}-{chr(high)}" for low, high in bounds)


# RFC 3987: ucschar extends unreserved, and iprivate is permitted in the query only.
_UCSCHAR: Final = _ranges(
    (0xA0, 0xD7FF),
    (0xF900, 0xFDCF),
    (0xFDF0, 0xFFEF),
    *((plane << 16, (plane << 16) + 0xFFFD) for plane in range(1, 14)),
    (0xE1000, 0xEFFFD),
)
_IPRIVATE: Final = _ranges((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))
_IRI, _IRI_REFERENCE = _uri_grammar(_UCSCHAR, _IPRIVATE)


def _grammar_check(grammar: re.Pattern[str]) -> Callable[[object], bool]:
    def check(value: object) -> bool:
        return not isinstance(value, str) or grammar.fullmatch(value) is not None

    return check


for _format, _grammar in (
    ("uri", _URI),
    ("uri-reference", _URI_REFERENCE),
    ("iri", _IRI),
    ("iri-reference", _IRI_REFERENCE),
):
    _FORMATS.checks(_format)(_grammar_check(_grammar))


def _is_number(_: object, value: object) -> bool:
    return isinstance(value, int | float | Decimal) and not isinstance(value, bool)


def _is_integer(_: object, value: object) -> bool:
    # JSON Schema 2020-12: a number with a zero fractional part is an integer, also 1.0.
    if isinstance(value, bool):
        return False
    if isinstance(value, Decimal):
        return value.is_finite() and value == value.to_integral_value()
    return isinstance(value, int) or (isinstance(value, float) and value.is_integer())


def _scaled(number: int | float | Decimal) -> tuple[int, int]:
    """(coefficient, exponent) with abs(number) == coefficient * 10**exponent, exactly."""
    if isinstance(number, int):
        return abs(number), 0
    _, digits, exponent = Decimal(repr(number) if isinstance(number, float) else number).as_tuple()
    # A Decimal with exponent 0 converts to int without the digit limit of int(str).
    return int(Decimal((0, digits, 0))), int(exponent)


def _multiple_of(validator: Validator, divisor: Any, instance: Any, schema: Any) -> Iterator[ValidationError]:
    """multipleOf in integer arithmetic. The jsonschema default divides a Decimal under a
    28-digit context and raises for 1e30, and a Fraction of 1e999999999 takes seconds."""
    if not validator.is_type(instance, "number"):
        return
    value, shift = _scaled(instance)
    step, divisor_shift = _scaled(divisor)
    shift -= divisor_shift
    if value == 0:
        return
    if shift >= 0:
        # value * 10**shift / step is an integer: the power stays modulo step.
        multiple = value * pow(10, shift, step) % step == 0
    else:
        # value / (step * 10**-shift): a denominator above the value leaves a fraction.
        multiple = -shift < value.bit_length() and value % (step * 10**-shift) == 0
    if not multiple:
        yield ValidationError(f"The value is not a multiple of {divisor}.")


def _extended(base: Any, integer: Callable[[object, object], bool] = _is_integer) -> type[Validator]:
    # Documents are parsed with exact decimals, so a value just above a bound cannot round onto it.
    extended: type[Validator] = jsonschema.validators.extend(  # type: ignore[no-untyped-call]  # jsonschema ships extend() without annotations
        base,
        validators={"multipleOf": _multiple_of},
        type_checker=base.TYPE_CHECKER.redefine_many({"number": _is_number, "integer": integer}),
    )
    return extended


_DRAFT_2020: Final = "https://json-schema.org/draft/2020-12/schema"
_DRAFT_07: Final = "http://json-schema.org/draft-07/schema"
_VALIDATORS: Final = {
    _DRAFT_2020: _extended(jsonschema.Draft202012Validator),
    _DRAFT_07: _extended(jsonschema.Draft7Validator),
}
_SPECIFICATIONS: Final = {
    _DRAFT_2020: referencing.jsonschema.DRAFT202012,
    _DRAFT_07: referencing.jsonschema.DRAFT7,
}
# Keywords of another dialect that this dialect does not implement. The validator would skip one
# silently, and a document that breaks it would pass.
_IGNORED: Final = {
    _DRAFT_2020: frozenset({"additionalItems", "dependencies", "$recursiveAnchor", "$recursiveRef"}),
    _DRAFT_07: frozenset(
        {
            "$dynamicRef",
            "$recursiveRef",
            "dependentRequired",
            "dependentSchemas",
            "maxContains",
            "minContains",
            "prefixItems",
            "unevaluatedItems",
            "unevaluatedProperties",
        }
    ),
}
# OpenAPI 3.0 takes its integer from JSON Schema Wright draft 00: no fraction and no exponent part.
# With exact parsing, only such a number is a Python int.
_OPENAPI_30: Final = _extended(jsonschema.Draft202012Validator, lambda _, value: type(value) is int)


class DialectError(SchemaError):
    """The schema names a JSON Schema dialect that the engine does not implement."""


def _dialect(value: object) -> str:
    """The dialect that a ``$schema`` value names, or DialectError. An empty fragment is the same URI."""
    name = value.removesuffix("#") if isinstance(value, str) else None
    if name not in _VALIDATORS:
        raise DialectError(f"the dialect {value!r} is not implemented")
    return name


def _check_keywords(part: Mapping[str, Any], dialect: str) -> None:
    """Raise if a subschema names another dialect, or uses a keyword that its dialect ignores.

    The walk follows the keywords of the dialect, so a property named "dependencies" is no keyword.
    ponytail: a subschema that only a ``$ref`` into an unknown keyword reaches is not walked.
    """
    pending: list[Any] = [part]
    while pending:
        node = pending.pop()
        if not isinstance(node, Mapping):
            continue
        if "$schema" in node and _dialect(node["$schema"]) != dialect:
            raise DialectError("a subschema names another dialect")
        if ignored := sorted(_IGNORED[dialect] & node.keys()):
            raise SchemaError(f"the dialect ignores the keywords {', '.join(ignored)}")
        pending.extend(_SPECIFICATIONS[dialect].subresources_of(node))
        # 2020-12 keeps "definitions" in its metaschema but does not walk it as a keyword.
        definitions = node.get("definitions")
        if isinstance(definitions, Mapping):
            pending.extend(definitions.values())


def _exact(node: Any) -> Any:
    """The schema with each float as a Decimal: a float bound and a Decimal value do not mix."""
    if isinstance(node, float):
        return Decimal(repr(node))
    if isinstance(node, Mapping):
        return {key: _exact(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_exact(value) for value in node]
    return node


def unassertable_formats(schema: Any) -> list[str]:
    """The ``format`` values in a schema that the engine cannot assert. A pass must not hide them."""
    found: set[str] = set()
    pending = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, Mapping):
            value = node.get("format")
            if isinstance(value, str) and value not in _FORMATS.checkers:
                found.add(value)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return sorted(found)


def validator(schema: Mapping[str, Any], *, openapi_30: bool = False) -> Validator | None:
    """Build a validator that never fetches anything. Returns None if the schema has a non-local ``$ref``.

    The top-level ``$schema`` selects the dialect: absent or 2020-12, or draft-07. Another value
    raises DialectError. Raises SchemaError for a schema that is not valid in its dialect, also in
    ``components.schemas``: such a schema would raise or blame the document for its own defect.
    A keyword that the dialect ignores also raises SchemaError. ``openapi_30`` takes a schema
    that api.contract translated from OpenAPI 3.0 and keeps the 3.0 integer. The validator
    asserts ``format``. Give it documents parsed with exact decimals.
    """

    def local(node: Any) -> bool:
        if isinstance(node, Mapping):
            reference = node.get("$ref")
            if isinstance(reference, str) and not reference.startswith("#"):
                return False
            return all(local(v) for v in node.values())
        if isinstance(node, list):
            return all(local(v) for v in node)
        return True

    if not local(schema):
        return None
    # check_schema does not read the OpenAPI "components" keyword, so each component is checked.
    components = schema.get("components")
    parts = components.get("schemas") if isinstance(components, Mapping) else None
    dialect = _dialect(schema.get("$schema", _DRAFT_2020))
    cls = _OPENAPI_30 if openapi_30 else _VALIDATORS[dialect]
    for part in [schema, *(parts.values() if isinstance(parts, Mapping) else ())]:
        cls.check_schema(part)
        if isinstance(part, Mapping):
            _check_keywords(part, dialect)
    # An empty registry has no retrieval function, so no reference can leave the document.
    return cls(_exact(dict(schema)), registry=Registry(), format_checker=_FORMATS)


def schema_errors(check: Validator, document: Any) -> list[JsonValue] | None:
    """Error locations and keywords. Values are left out on purpose.

    None if the validator cannot judge the document: a recursive schema follows a deep body
    with Python recursion. A body that the engine cannot judge never passes. A local reference
    that does not resolve is a defect of the schema: SchemaError.
    """
    try:
        errors = sorted(
            check.iter_errors(document), key=lambda e: (list(map(str, e.absolute_path)), str(e.validator))
        )
    except RecursionError:
        return None
    except Unresolvable as exc:
        raise SchemaError(f"a local reference does not resolve: {exc}") from exc
    return [
        {"path": "/" + "/".join(map(str, e.absolute_path)), "keyword": str(e.validator)} for e in errors[:50]
    ]


def decode_qr(
    ctx: CheckContext, artifact: str = "qr_image"
) -> tuple[str | None, Record | None, CheckOutcome | None]:
    """Decode one QR symbol from an image artifact. Returns (text, record, outcome if not decodable).

    The engine does not grade print quality. A clean synthetic image and a worn label are not
    the same thing, and this check says nothing about the second.
    """
    try:
        import zxingcpp  # noqa: PLC0415 - optional dependency of the `qr` extra
        from PIL import Image, UnidentifiedImageError  # noqa: PLC0415
    except ImportError:
        message = "The QR decoder is not installed. Install the 'qr' extra."
        return None, None, not_done(ExecutionStatus.UNSUPPORTED, "CARRIER.QR.DEPENDENCY_MISSING", message)
    record = ctx.acquirer.artifact(artifact)
    if record.error is not None:
        return None, record, blocked("CARRIER.SAMPLE.MISSING", f"The sample '{artifact}' is not available.")
    try:
        # Pillow warns about a large image and raises above twice that size. Both are too large.
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(record.body)) as image:
                if image.width * image.height > _MAX_QR_PIXELS:
                    return (
                        None,
                        record,
                        blocked("CARRIER.SAMPLE.TOO_LARGE", "The image is larger than the limit."),
                    )
                # With errors returned, a damaged second symbol is still counted. Without them, an
                # image with one clean and one damaged symbol looked like one symbol and passed.
                found = zxingcpp.read_barcodes(image.convert("L"), return_errors=True)
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        return None, record, blocked("CARRIER.SAMPLE.TOO_LARGE", "The image is larger than the limit.")
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError):
        # Pillow's PNG reader raises SyntaxError for a broken chunk.
        return None, record, blocked("CARRIER.SAMPLE.UNREADABLE", "The sample is not a readable image.")
    symbols = [s for s in found if s.valid and s.format == zxingcpp.BarcodeFormat.QRCode]
    # Every other detection counts, readable or not, in any format. zxing-cpp can report a damaged
    # QR symbol as an unreadable Micro QR candidate, and a readable symbol of another format next
    # to the QR also means the image is not one QR symbol.
    others = len(found) - len(symbols)
    if len(symbols) != 1 or others or not symbols[0].text:
        summary = {"qr_symbols": len(symbols), "other_symbols": others}
        observation = ctx.observation(0, kind="artifact", records=[record], summary=summary)
        message = (
            f"The image holds {len(symbols)} readable QR symbols and {others} other detected "
            "symbols; exactly one readable QR symbol and no other symbol is needed."
        )
        return None, record, completed(False, "CARRIER.QR.NOT_DECODED", message, [observation])
    return str(symbols[0].text), record, None


def carrier_identifier(
    ctx: CheckContext,
) -> tuple[str | None, list[Record], tuple[str, ...], CheckOutcome | None]:
    """The identifier that the carrier holds: (text, records, transformations, outcome if unavailable)."""
    if "qr_image" in ctx.ixit.samples:
        text, record, problem = decode_qr(ctx)
        return text, [record] if record else [], ("qr_decode",), problem
    declared = ctx.ixit.samples.get("identifier")
    if declared:
        return declared, [], ("declared_identifier",), None
    return None, [], (), blocked("CARRIER.SAMPLE.MISSING", "The IXIT gives no QR image and no identifier.")


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
