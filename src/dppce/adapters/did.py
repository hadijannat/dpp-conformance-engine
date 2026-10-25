"""Identity adapter: resolve a did:web DID and check its DID document.

The URL mapping follows the did:web Method Specification, a W3C CCG report
(github.com/w3c-ccg/did-method-web at commit ea423c1, read on 2026-10-25). The document rules
follow W3C DID Core 1.0. The engine does no JSON-LD processing.

Resolution is not trust. DNS and TLS name the host, not the issuer. A key of the document is
trusted only through a pinned ``TrustedKey`` whose issuer equals the DID. The DID host is often a
third party: a live fetch goes through the engine transport and its policy only, and an offline
copy of the document can come from an IXIT sample instead.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Final, Literal

from pydantic import Field, field_validator

from dppce.adapters.common import (
    SERVER_ERRORS,
    blocked,
    completed,
    effective_url,
    fetch_once,
    json_object,
    media_type,
    no_answer,
    unusable,
)
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, ExecutionStatus, Model, Observation
from dppce.testdefs.registry import CheckContext, register

_MAX_DID: Final = 2048
_DID_WEB: Final = re.compile(r"did:web:(?P<authority>[^:]+)(?P<path>(?::[^:]*)*)")
# The colon before a port is percent-encoded. Hex digits are case-insensitive (RFC 3986, 2.1).
_AUTHORITY: Final = re.compile(r"(?P<host>[^%]+)(?:%3[Aa](?P<port>[0-9]{1,5}))?")
_LABEL: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
# ponytail: no percent-encoding in a path segment, so no segment can decode to '/', '?', or '#'.
_SEGMENT: Final = re.compile(r"[A-Za-z0-9._-]+")
# RFC 7517 and RFC 7518: the private members of an EC, OKP, RSA, or symmetric JWK.
PRIVATE_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
# A DID document has a few keys. The bound keeps the strict parse cheap, also for an offline copy.
MAX_DOCUMENT_BYTES: Final = 1024 * 1024
_INVALID: Final = "The parameter 'did' or 'source' is not valid. Nothing is fetched."
Source = Literal["live", "sample"]


def did_web_url(did: str) -> str | None:
    """The https URL of the DID document of a did:web DID, or None if ``did`` is not one.

    The host is a domain name, never an IP address. A port is 1 to 65535.
    A path segment holds only letters, digits, '.', '_', and '-', and is not a dot segment.
    """
    match = _DID_WEB.fullmatch(did) if len(did) <= _MAX_DID else None
    authority = _AUTHORITY.fullmatch(match["authority"]) if match else None
    if match is None or authority is None:
        return None
    host, port = authority["host"], authority["port"]
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    segments = match["path"].split(":")[1:]
    if not all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments):
        return None
    netloc = host if port is None else f"{host}:{int(port)}"
    path = "/" + "/".join(segments) if segments else "/.well-known"
    return f"https://{netloc}{path}/did.json"


class DidParams(Model):
    did: str = Field(
        max_length=_MAX_DID,
        description=(
            "The did:web DID to resolve, for example did:web:id.example.test. The host is a domain "
            "name. A port is percent-encoded as %3A. A path holds letters, digits, '.', '_', and '-'."
        ),
    )
    source: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description=(
            "Name of the IXIT sample that holds an offline copy of the DID document. Without it, "
            "the check fetches the document through the transport policy."
        ),
    )

    @field_validator("did")
    @classmethod
    def _did(cls, value: str) -> str:
        if did_web_url(value) is None:
            raise ValueError("not a did:web DID that the engine can map to an https URL")
        return value


@dataclass(frozen=True)
class DidDocument:
    """A resolved DID document that broke no rule. Resolution is not trust."""

    did: str
    source: Source
    document: dict[str, Any]
    # Absolute verification method id -> publicKeyJwk, for each method that has one.
    keys: dict[str, dict[str, Any]]
    # The absolute ids of the assertion methods, in document order.
    assertion_methods: tuple[str, ...]
    # Methods without publicKeyJwk, for example with publicKeyMultibase. The engine reads JWK only.
    unread_methods: int
    record: Record
    observation: Observation


def _absolute(did: str, ident: str) -> str:
    # DID Core 1.0, relative DID URLs: one that starts with '#' resolves against the DID.
    return did + ident if ident.startswith("#") else ident


def _is_method(value: object) -> bool:
    """DID Core 1.0, verification methods: id, type, and controller are strings. A JWK has a kty."""
    if not isinstance(value, dict):
        return False
    if not all(isinstance(value.get(name), str) and value[name] for name in ("id", "type", "controller")):
        return False
    jwk = value.get("publicKeyJwk")
    return "publicKeyJwk" not in value or (isinstance(jwk, dict) and isinstance(jwk.get("kty"), str))


def _failure(document: dict[str, Any], did: str) -> tuple[str, str] | None:
    """The reason code and message of the first document rule that breaks, or None.

    Each rule reads the whole document, so that no shape can hide an earlier rule.
    """
    if document.get("id") != did:
        return "IDENTITY.DID.ID_MISMATCH", "The id of the DID document is not the resolved DID."
    methods = document.get("verificationMethod", [])
    assertions = document.get("assertionMethod", [])
    listed = methods if isinstance(methods, list) else []
    embedded = [a for a in assertions if isinstance(a, dict)] if isinstance(assertions, list) else []
    candidates = [*listed, *embedded]
    for method in candidates:
        jwk = method.get("publicKeyJwk") if isinstance(method, dict) else None
        if isinstance(jwk, dict) and PRIVATE_MEMBERS & jwk.keys():
            return "IDENTITY.DID.PRIVATE_KEY", "A verification method publishes a private key member."
    if not isinstance(methods, list) or not all(_is_method(m) for m in candidates):
        message = (
            "A verification method lacks a string id, type, or controller, or has a malformed publicKeyJwk."
        )
        return "IDENTITY.DID.VERIFICATION_METHOD", message
    ids = [_absolute(did, m["id"]) for m in candidates]
    if len(set(ids)) != len(ids):
        return "IDENTITY.DID.VERIFICATION_METHOD", "Two verification methods have the same id."
    if not isinstance(assertions, list) or not all(
        isinstance(a, dict) or (isinstance(a, str) and _absolute(did, a) in ids) for a in assertions
    ):
        message = "An assertionMethod entry is not a verification method of this document."
        return "IDENTITY.DID.ASSERTION_UNRESOLVED", message
    return None


def _not_done(status: ExecutionStatus, code: str, message: str, observation: Observation) -> CheckOutcome:
    return CheckOutcome(status=status, reason_code=code, message=message, observations=(observation,))


def resolve_did_web(ctx: CheckContext, did: str, source: str | None = None) -> DidDocument | CheckOutcome:
    """Resolve ``did`` and apply the document rules. Give the document, or the outcome of the step.

    Without ``source`` the document is fetched through ``fetch_once``, so the transport policy and
    the origin override apply. A DID host that the operator did not confirm gives a transport
    denial, which is no answer. With ``source`` the document is the IXIT sample of that name.
    """
    url = did_web_url(did)
    if url is None or (source is not None and not 1 <= len(source) <= 128):
        return blocked("IDENTITY.DID.PARAMS_INVALID", _INVALID)
    mode: Source = "live" if source is None else "sample"
    record = fetch_once(ctx, url) if source is None else ctx.acquirer.artifact(source)
    summary: dict[str, Any] = {"source": mode}

    def seen() -> Observation:
        if mode == "sample":
            return ctx.observation(0, kind="artifact", records=[record], summary=summary)
        return ctx.observation(
            0, kind="exchange", records=[record], summary=summary, transformations=effective_url(ctx, url)[1]
        )

    if mode == "sample":
        if record.error is not None:
            return blocked(
                "IDENTITY.DID.SAMPLE_MISSING", "The IXIT sample of the DID document is not available."
            )
    else:
        # Only a missing answer is tested before the status rule: a body coding or a long body
        # must not turn a status fail into blocked.
        if record.error is not None or record.status in SERVER_ERRORS:
            return no_answer(ctx, record)
        summary |= {
            "status": record.status,
            "media_type": media_type(record),
            "redirects": len(record.redirects),
        }
        if record.status != 200:
            message = f"The DID document URL answers {record.status}, not 200."
            return completed(False, "IDENTITY.DID.STATUS", message, [seen()])
        if (problem := unusable(ctx, record)) is not None:
            return problem
    if len(record.body) > MAX_DOCUMENT_BYTES:
        message = (
            f"The DID document is larger than {MAX_DOCUMENT_BYTES} bytes. This engine does not judge it."
        )
        return _not_done(ExecutionStatus.BLOCKED, "IDENTITY.DID.TOO_LARGE", message, seen())
    document = json_object(record)
    if document is None:
        return completed(False, "IDENTITY.DID.NOT_JSON", "The DID document is not one JSON object.", [seen()])
    if (failure := _failure(document, did)) is not None:
        return completed(False, *failure, [seen()])
    methods = [
        *document.get("verificationMethod", []),
        *(a for a in document.get("assertionMethod", []) if isinstance(a, dict)),
    ]
    keys = {_absolute(did, m["id"]): m["publicKeyJwk"] for m in methods if "publicKeyJwk" in m}
    summary |= {"verification_methods": len(methods), "jwk_methods": len(keys)}
    if record.redirects:
        message = "The DID document URL redirects. This check does not pass a redirected DID document."
        return _not_done(ExecutionStatus.BLOCKED, "IDENTITY.DID.REDIRECTED", message, seen())
    assertions = tuple(
        _absolute(did, a if isinstance(a, str) else a["id"]) for a in document.get("assertionMethod", [])
    )
    return DidDocument(did, mode, document, keys, assertions, len(methods) - len(keys), record, seen())


@register("identity.did", capability="identity.did", params=DidParams)
def did_document(ctx: CheckContext) -> CheckOutcome:
    did, source = ctx.params.get("did"), ctx.params.get("source")
    if not isinstance(did, str) or not (source is None or isinstance(source, str)):
        return blocked("IDENTITY.DID.PARAMS_INVALID", _INVALID)
    resolved = resolve_did_web(ctx, did, source)
    if isinstance(resolved, CheckOutcome):
        return resolved
    if resolved.unread_methods:
        message = "A verification method has no publicKeyJwk. This engine reads JWK keys only."
        return _not_done(
            ExecutionStatus.UNSUPPORTED, "IDENTITY.DID.KEY_FORMAT", message, resolved.observation
        )
    message = (
        "The DID document has the DID as its id, publishes public keys only, and resolves its "
        "assertion methods. Resolution is not trust: a key is trusted only through a pinned key of the "
        "trust bundle. No JSON-LD processing was done."
    )
    return completed(True, "IDENTITY.DID.OK", message, [resolved.observation])
