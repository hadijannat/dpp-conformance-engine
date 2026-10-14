"""Helpers that every adapter shares.

Contract: docs/reference/reference-system.md, section 8.
"""

from __future__ import annotations

import io
from collections.abc import Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlsplit

import jsonschema
from referencing import Registry

from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import redact_url
from dppce.models import CheckOutcome, ExecutionStatus, JsonValue, Observation
from dppce.testdefs.registry import CheckContext

MISSING: Final = object()
_DENIED: Final = ("policy_denied", "authorization_denied", "budget_exhausted")
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


def fetch_once(ctx: CheckContext, url: str, role: str = "anonymous") -> Record:
    """Fetch a URL, or reuse an earlier good record of the same request. Keeps the request count low."""
    target, _ = effective_url(ctx, url)
    recorded = redact_url(target)
    for record in ctx.acquirer.records():
        same = (record.kind, record.method, record.url, record.role) == ("http", "GET", recorded, role)
        if same and record.error is None:
            return record
    return ctx.acquirer.fetch(Request("GET", target, role=role))


def no_answer(ctx: CheckContext, record: Record) -> CheckOutcome:
    """The outcome for a record with a transport error. A missing answer is not a failure."""
    if record.error == "redirect_out_of_scope":
        code, text = (
            "TRANSPORT.REDIRECT_OUT_OF_SCOPE",
            "The engine did not follow a redirect to a host outside the scope.",
        )
    elif record.error in _DENIED:
        code, text = "TRANSPORT.DENIED", f"The transport policy refused the request ({record.error})."
    else:
        code, text = "TRANSPORT.UNREACHABLE", f"The system gave no answer ({record.error})."
    observation = ctx.observation(
        0, kind="exchange", records=[record], summary={"transport_error": record.error}
    )
    return completed(
        False, code, text + " A connectivity failure does not prove a breach.", [observation], no_answer=True
    )


def unusable(ctx: CheckContext, record: Record) -> CheckOutcome | None:
    """Return an outcome if the record cannot be judged, or None if its body can be used."""
    if record.error is not None:
        return no_answer(ctx, record)
    if record.truncated:
        return blocked(
            "TRANSPORT.BODY_TRUNCATED", "The body is larger than the limit. A partial body proves nothing."
        )
    encoding = (record.header("content-encoding") or "identity").strip().lower()
    if encoding not in ("", "identity"):
        # The transport asks for no encoding and no check decompresses. An encoded body is
        # neither clean nor wrong: it is not assessed.
        message = f"The body has the content encoding '{encoding}'. This engine does not decode it."
        return blocked("TRANSPORT.BODY_ENCODED", message)
    return None


def json_object(record: Record) -> dict[str, Any] | None:
    """Parse the body as one JSON object. A repeated key is ambiguous, so it is not accepted."""
    try:
        value = parse_strict(record.body)
    except CanonicalizationError:
        return None
    return value if isinstance(value, dict) else None


def api_url(ctx: CheckContext, suffix: str = "", base: str = "api") -> str | None:
    """Build ``{base}/dpp/{id}{suffix}`` in public form, or None if the IXIT lacks the parts."""
    origin = ctx.ixit.endpoints.get(base)
    passport_id = ctx.ixit.samples.get("passport_id")
    if not origin or not passport_id:
        return None
    return f"{origin.rstrip('/')}/dpp/{passport_id}{suffix}"


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
            symbols = [
                s
                for s in zxingcpp.read_barcodes(image.convert("L"))
                if s.format == zxingcpp.BarcodeFormat.QRCode
            ]
    except (UnidentifiedImageError, OSError, ValueError):
        return None, record, blocked("CARRIER.SAMPLE.UNREADABLE", "The sample is not a readable image.")
    if len(symbols) != 1 or not symbols[0].text:
        observation = ctx.observation(
            0, kind="artifact", records=[record], summary={"qr_symbols": len(symbols)}
        )
        message = f"The image holds {len(symbols)} QR symbols with text; exactly one is needed."
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
