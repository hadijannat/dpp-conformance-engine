"""Integrity adapter: verify a JWS-signed passport.

Signature validity, issuer trust, certificate validity, revocation, and payload match are
separate findings. A signature that verifies shows that the holder of a key signed these
bytes. It does not show that the signed attributes are true.

COSE and Bitstring Status List are interfaces only in this version.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timedelta
from typing import Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from dppce.adapters.common import (
    blocked,
    completed,
    fetch_once,
    is_linkset,
    item_url,
    json_object,
    resource_url,
    same_json,
    unusable,
)
from dppce.evidence import x509path
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.jws import SignatureError, header_of, public_jwk_of, verify_compact
from dppce.evidence.x509path import MAX_CHAIN, extension_value, path_gap
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, ExecutionStatus, JsonValue, Observation, TrustBundle
from dppce.testdefs.registry import CheckContext, register

PASSPORT_TYP = "dpp+jws"
_LIMIT = "A valid signature does not prove that the signed attributes are true."
# Non-empty base64url with no padding (RFC 7515, section 2).
_B64URL: Final = re.compile(r"[A-Za-z0-9_-]+")

# Extended key usages that permit signing a document, and usages that name a different purpose.
_SIGNING_PURPOSES: Final = frozenset(
    {
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36"),  # id-kp-documentSigning, RFC 9336
    }
)
_OTHER_PURPOSES: Final = frozenset(
    {
        ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.CODE_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.OCSP_SIGNING,
    }
)  # fmt: skip


class _TooLongError(Exception):
    """The chain in ``x5c`` is longer than this engine follows."""


def _is_b64url(value: object) -> bool:
    return isinstance(value, str) and _B64URL.fullmatch(value) is not None


def _is_signature(member: dict[str, object]) -> bool:
    """One signature of RFC 7515, section 7.2.1: a signature, and a protected header, a header, or both."""
    if not _is_b64url(member.get("signature")) or not {"protected", "header"} & member.keys():
        return False
    if "header" in member and not isinstance(member["header"], dict):
        return False
    if "protected" not in member:
        return True
    protected = member["protected"]
    if not _is_b64url(protected):
        return False
    try:
        header_of(f"{protected}..")  # the decoder, the strict parser, and the object test of the compact path
    except SignatureError:
        return False
    return True


def _is_jws_json(document: dict[str, object] | None) -> bool:
    """A JWS JSON Serialization (RFC 7515, section 7.2), by the exact shape of its members.

    A non-empty base64url payload. The flattened form has the members of one signature at the top
    level. The general form has a non-empty list of signatures and no signature member at the top.
    Any other shape is a malformed token, so that a system under test cannot turn a fail into a
    blocked step.
    """
    if document is None or not _is_b64url(document.get("payload")):
        return False
    if "signatures" not in document:
        return _is_signature(document)
    signatures = document["signatures"]
    return (
        not {"signature", "protected", "header"} & document.keys()
        and isinstance(signatures, list)
        and bool(signatures)
        and all(isinstance(s, dict) and _is_signature(s) for s in signatures)
    )


def _certificates(header: dict[str, object]) -> list[x509.Certificate] | None:
    """The certificates of ``x5c``, or None if it does not hold certificates. Raises ``_TooLongError``."""
    chain = header.get("x5c")
    if not isinstance(chain, list) or not chain:
        return None
    if len(chain) > MAX_CHAIN:
        raise _TooLongError
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(str(item), validate=True)) for item in chain]
    except (binascii.Error, ValueError, x509.InvalidVersion):  # InvalidVersion is no ValueError
        return None


def trust_path(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], trust: TrustBundle
) -> list[x509.Certificate] | None:
    """Return the path from the leaf to a passport anchor of the trust bundle, or None."""
    return x509path.trust_path(leaf, intermediates, trust.anchors)


def _status_gap(trust: TrustBundle, now: datetime) -> str | None:
    """Return why the mandatory status snapshot cannot be used, or None if it can."""
    if not trust.require_status:
        return None
    if trust.status_as_of is None:
        return "The trust policy needs status evidence, and the trust bundle has no status snapshot."
    age = now - parse_stamp(trust.status_as_of)
    if age < timedelta(0) or age > timedelta(days=trust.status_max_age_days):
        return "The trust policy needs status evidence, and the status snapshot is stale."
    return None


# What a SignatureError code means for the tested system. Only a token that is not a JWS, or a
# signature that does not verify, is a defect of the system. Every other code is a limit of this
# engine: it supports one profile (ES256, a P-256 leaf in ``x5c``, four header parameters).
_ENGINE_LIMITS = ("ALGORITHM", "TYPE", "HEADER", "KEY", "TOO_LARGE", "NOT_PROCESSABLE")
_SERVER_ERROR = 500


def _purpose(leaf: x509.Certificate) -> tuple[bool | None, str]:
    """May the leaf sign a document? True, False (it states a different purpose), or None (unknown)."""
    usage = extension_value(leaf, x509.KeyUsage)
    if usage is not None and not (usage.digital_signature or usage.content_commitment):
        return False, "The key usage of the signing certificate does not permit a digital signature."
    purposes = extension_value(leaf, x509.ExtendedKeyUsage)
    if purposes is None or set(purposes) & _SIGNING_PURPOSES:
        return True, ""
    if set(purposes) <= _OTHER_PURPOSES:
        return False, "The extended key usage of the signing certificate names other purposes only."
    return (
        None,
        "The extended key usage of the signing certificate names a purpose that this engine does not know.",
    )


@register("integrity.jws", capability="integrity.jws")
def jws_check(ctx: CheckContext) -> CheckOutcome:  # noqa: PLR0912, PLR0915 - the ordered findings of the contract
    if ctx.trust is None:
        return blocked(
            "INTEGRITY.TRUST.MISSING", "No trust bundle is configured. Nothing is trusted by default."
        )
    signed_url = resource_url(ctx, "signed", "INTEGRITY")
    if isinstance(signed_url, CheckOutcome):
        return signed_url
    # A request-free guard. The resolved target is asked for after every signature finding, so a
    # resolver fault cannot hide one.
    if ctx.ixit.item_target == "template" and isinstance(
        guard := resource_url(ctx, "item", "INTEGRITY"), CheckOutcome
    ):
        return guard
    record = fetch_once(ctx, signed_url)
    # The signed passport keeps its own code for a status of 500 or higher (INTEGRITY.TOKEN.NO_ANSWER).
    if (problem := unusable(ctx, record, server_error_is_no_answer=False)) is not None:
        return problem
    findings: dict[str, JsonValue] = {"status": record.status}
    more: list[Record] = []

    def observed() -> Observation:
        return ctx.observation(0, kind="exchange", records=[record, *more], summary={"findings": findings})

    def result(passed: bool, code: str, message: str, *, no_answer: bool = False) -> CheckOutcome:
        return completed(passed, code, f"{message} {_LIMIT}", [observed()], no_answer=no_answer)

    if record.status is None or record.status >= _SERVER_ERROR:
        # A server error is no answer about the signature. It is not a failed signature.
        message = f"The endpoint of the signed passport answers {record.status}."
        return result(False, "INTEGRITY.TOKEN.NO_ANSWER", message, no_answer=True)
    if record.status != 200:
        message = f"The system declares a signed passport, and its endpoint answers {record.status}."
        return result(False, "INTEGRITY.TOKEN.NOT_AVAILABLE", message)

    token = record.body.decode("ascii", errors="replace").strip()
    try:
        header = header_of(token)
    except SignatureError:
        if _is_jws_json(json_object(record)):
            # OD-05: the JWS JSON serialization (RFC 7515, section 7.2) is valid JWS. A limit of this engine.
            findings["structure"] = "a JWS JSON serialization"
            message = (
                "The body is a JWS JSON serialization. This engine verifies the compact serialization only."
            )
            return CheckOutcome(
                status=ExecutionStatus.BLOCKED,
                reason_code="INTEGRITY.FORMAT.UNSUPPORTED",
                message=message,
                observations=(observed(),),
            )
        findings["structure"] = "not a compact JWS"
        return result(False, "INTEGRITY.TOKEN.MALFORMED", "The body is not a compact JWS.")
    if "x5c" not in header:
        return blocked(
            "INTEGRITY.KEY.UNSUPPORTED", "The token has no x5c header. This engine finds the key there only."
        )
    try:
        certificates = _certificates(header)
    except _TooLongError:
        return blocked("INTEGRITY.TOKEN.TOO_LARGE", f"The x5c chain is longer than {MAX_CHAIN} certificates.")
    if certificates is None:
        findings["structure"] = "x5c is not a list of certificates"
        return result(False, "INTEGRITY.TOKEN.MALFORMED", "The x5c header does not hold certificates.")
    try:
        try:
            leaf_key = certificates[0].public_key()
        except (UnsupportedAlgorithm, ValueError) as exc:
            raise SignatureError(
                "the certificate key is of a type that this engine does not support", "KEY"
            ) from exc
        if not isinstance(leaf_key, ec.EllipticCurvePublicKey):
            raise SignatureError("the certificate key is not an elliptic-curve key", "KEY")
        payload = verify_compact(token, public_jwk_of(leaf_key), typ=PASSPORT_TYP)
    except SignatureError as exc:
        if exc.code in _ENGINE_LIMITS:
            # A limit of this engine. It says nothing about the system under test.
            code = (
                "INTEGRITY.TOKEN.TOO_LARGE" if exc.code == "TOO_LARGE" else "INTEGRITY.TOKEN.NOT_PROCESSABLE"
            )
            # The code only: the text of the error can quote values that the tested system chose.
            return blocked(code, f"This engine cannot process the signed passport ({exc.code}).")
        if exc.code == "MALFORMED":
            findings["structure"] = "a part cannot be decoded"
            return result(False, "INTEGRITY.TOKEN.MALFORMED", "A part of the token cannot be decoded.")
        findings["signature"] = "invalid"
        message = "The signature does not verify with the key of its certificate."
        return result(False, "INTEGRITY.SIGNATURE.INVALID", message)
    findings["signature"] = "valid"

    path = trust_path(certificates[0], certificates[1:], ctx.trust)
    if path is None:
        findings["issuer_trust"] = "no path to a trust anchor"
        message = (
            "The signature is valid, but its certificate does not chain to an anchor of the trust bundle."
        )
        return result(False, "INTEGRITY.ISSUER.UNTRUSTED", message)
    if (gap := path_gap(path)) is not None:
        return blocked("INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT", gap)
    findings["issuer_trust"] = "chains to a trust anchor"
    may_sign, message = _purpose(certificates[0])
    if may_sign is None:
        return blocked("INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT", message)
    if not may_sign:
        findings["key_usage"] = "the certificate does not permit signing a document"
        return result(False, "INTEGRITY.CERT.KEY_USAGE", message)

    now = ctx.evaluation_time
    # The anchor is configuration of the operator. A problem with it is not a fault of the system.
    anchor, below = path[-1], path[:-1]
    revocations = ctx.trust.revoked_certificates
    if not anchor.not_valid_before_utc <= now <= anchor.not_valid_after_utc or x509path.revoked(
        [anchor], revocations, now
    ):
        message = "The trust anchor of this chain is expired or revoked in the operator's trust bundle."
        return blocked("INTEGRITY.TRUST.ANCHOR_INVALID", message)
    if not all(c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in below):
        findings["certificate_validity"] = "outside the validity period"
        message = "A certificate of the chain is outside its validity period at the evaluation time."
        return result(False, "INTEGRITY.CERT.EXPIRED", message)
    findings["certificate_validity"] = "valid at the evaluation time"

    if (gap := _status_gap(ctx.trust, now)) is not None:
        return blocked("INTEGRITY.STATUS.MISSING", gap)
    if x509path.revoked(below, revocations, now):
        findings["revocation"] = "revoked"
        message = "A certificate of the chain is in the revocation snapshot."
        return result(False, "INTEGRITY.CERT.REVOKED", message)
    findings["revocation"] = (
        "not revoked in the snapshot" if ctx.trust.status_as_of else "no snapshot; not required"
    )

    published_url = item_url(ctx, "INTEGRITY")
    if isinstance(published_url, CheckOutcome):
        return published_url
    item = fetch_once(ctx, published_url)
    if (problem := unusable(ctx, item)) is not None:
        return problem
    more.append(item)
    document = json_object(item) if item.status == 200 else None
    if document is None:
        message = (
            "The published passport is not a JSON object, so the signed payload has nothing to compare with."
        )
        return blocked("INTEGRITY.PAYLOAD.NOT_COMPARABLE", message)
    if is_linkset(document):
        message = (
            "The published passport is a linkset, so the signed payload has no passport to compare with."
        )
        return blocked("INTEGRITY.PAYLOAD.NOT_COMPARABLE", message)
    # Compare the two documents as JSON values. The canonical form with integers only is a rule
    # for the bodies of this engine (ADR 0006). It is not a rule for a passport of a third party:
    # a different key order, white space, or a decimal number is not a mismatch.
    try:
        same = same_json(parse_strict(payload, decimals=True), parse_strict(item.body, decimals=True))
    except CanonicalizationError:
        same = False
    if not same:
        findings["payload"] = "differs from the published passport"
        return result(
            False, "INTEGRITY.PAYLOAD.MISMATCH", "The signed payload is not the published passport."
        )
    findings["payload"] = "equals the published passport"
    return result(
        True, "INTEGRITY.OK", "The signature, the issuer, the certificates, and the payload are in order."
    )
