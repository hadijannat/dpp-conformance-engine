"""Helpers that every adapter shares.

Contract: docs/reference/reference-system.md, section 8.
"""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Final
from urllib.parse import quote, unquote, urlsplit

import jsonschema
from referencing import Registry

from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import REMOVED, redact_url
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
    """Apply the origin override of the test rig. Returns the URL and the transformations used."""
    public = ctx.ixit.endpoints.get("public_origin")
    override = ctx.ixit.endpoints.get("origin_override")
    if public and override and (url == public or url.startswith(public + "/")):
        return override + url[len(public) :], ("origin_override",)
    return url, ()


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
    path = re.sub(PLACEHOLDER_PATTERN, lambda m: quote(values[m[1]], safe=""), template)
    return base.rstrip("/") + path


def resource_url(ctx: CheckContext, resource: ResourceName, area: str) -> str | CheckOutcome:
    """The public URL of a passport resource from its IXIT template, or a blocked outcome."""
    template = ctx.ixit.resources.get(resource)
    if template is None:
        message = f"The IXIT declares no URL template for the resource '{resource}'."
        return blocked(f"{area}.NO_TARGET", message + " The engine has no default path.")
    return template_url(ctx, template.endpoint, template.path, area)


def _is_http_url(text: str) -> bool:
    try:
        return urlsplit(text).scheme in ("http", "https")
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
    if problem is not None or text is None or not _is_http_url(text):
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


def validator(schema: Mapping[str, Any]) -> jsonschema.Draft202012Validator | None:
    """Build a validator that never fetches anything. Returns None if the schema has a non-local ``$ref``."""

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
    # An empty registry has no retrieval function, so no reference can leave the document.
    return jsonschema.Draft202012Validator(dict(schema), registry=Registry())


def schema_errors(check: jsonschema.Draft202012Validator, document: Any) -> list[JsonValue]:
    """Error locations and keywords. Values are left out on purpose."""
    errors = sorted(
        check.iter_errors(document), key=lambda e: (list(map(str, e.absolute_path)), str(e.validator))
    )
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
    except (UnidentifiedImageError, OSError, ValueError):
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
