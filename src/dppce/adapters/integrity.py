"""Integrity adapter: verify a JWS-signed passport.

Signature validity, issuer trust, certificate validity, revocation, and payload match are
separate findings. A signature that verifies shows that the holder of a key signed these
bytes. It does not show that the signed attributes are true.

COSE, RFC 3161 timestamps, and Bitstring Status List are interfaces only in this version.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from dppce.adapters.common import api_url, blocked, completed, fetch_once, json_object, unusable
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.jws import SignatureError, header_of, public_jwk_of, verify_compact
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, JsonValue, TrustBundle
from dppce.testdefs.registry import CheckContext, register

PASSPORT_TYP = "dpp+jws"
_MAX_CHAIN = 5
_LIMIT = "A valid signature does not prove that the signed attributes are true."


# Extensions that this engine evaluates. Any other extension marked critical is a constraint
# that a conforming validator must understand (RFC 5280, section 4.2), so the path is not passed.
_EVALUATED: Final = frozenset(
    {
        x509.BasicConstraints.oid, x509.KeyUsage.oid, x509.ExtendedKeyUsage.oid,
        x509.SubjectKeyIdentifier.oid, x509.AuthorityKeyIdentifier.oid,
    }
)  # fmt: skip
_NOT_EVALUATED: Final = (x509.NameConstraints, x509.PolicyConstraints, x509.InhibitAnyPolicy)
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


def _certificates(header: dict[str, object]) -> list[x509.Certificate] | None:
    """The certificates of ``x5c``, or None if it does not hold certificates. Raises ``_TooLongError``."""
    chain = header.get("x5c")
    if not isinstance(chain, list) or not chain:
        return None
    if len(chain) > _MAX_CHAIN:
        raise _TooLongError
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(str(item), validate=True)) for item in chain]
    except (binascii.Error, ValueError):
        return None


def _extensions(certificate: x509.Certificate) -> x509.Extensions | None:
    """The extensions, or None if they cannot be parsed (malformed or repeated)."""
    try:
        return certificate.extensions
    except ValueError:
        return None


def _value[E: x509.ExtensionType](certificate: x509.Certificate, kind: type[E]) -> E | None:
    extensions = _extensions(certificate)
    if extensions is None:
        return None
    try:
        return extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _may_issue(issuer: x509.Certificate, authorities_below: int) -> bool:
    """True if ``issuer`` is a certificate authority that may sign the next certificate of the path.

    A signature and a matching name are not enough. Without this test, the holder of any end
    certificate from a trusted root could sign certificates of its own.
    """
    constraints = _value(issuer, x509.BasicConstraints)
    if constraints is None or not constraints.ca:
        # No basic constraints, or extensions that cannot be read: not a certificate authority.
        return False
    if constraints.path_length is not None and authorities_below > constraints.path_length:
        return False
    usage = _value(issuer, x509.KeyUsage)
    return usage is None or bool(usage.key_cert_sign)


def trust_path(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], trust: TrustBundle
) -> list[x509.Certificate] | None:
    """Return the path from the leaf to an anchor of the trust bundle, or None if there is none.

    Each issuer must have signed the certificate below it, must be a certificate authority,
    must permit signing certificates, and must respect its path length constraint.
    """
    anchors = [x509.load_pem_x509_certificate(a.certificate_pem.encode("ascii")) for a in trust.anchors]
    candidates = [*((a, True) for a in anchors), *((i, False) for i in intermediates)]

    def extend(path: list[x509.Certificate]) -> list[x509.Certificate] | None:
        # Depth first, with backtracking: a cross-signed authority can appear twice in ``x5c``,
        # once under an anchor and once under a root that the bundle does not hold.
        depth = len(path) - 1  # the number of certificate authorities already below the next issuer
        if depth >= _MAX_CHAIN:
            return None
        for candidate, is_anchor in candidates:
            if candidate in path or not _may_issue(candidate, authorities_below=depth):
                continue
            try:
                path[-1].verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            found = [*path, candidate] if is_anchor else extend([*path, candidate])
            if found is not None:
                return found
        return None

    return extend([leaf])


def revoked(path: list[x509.Certificate], trust: TrustBundle) -> bool:
    """True if any certificate of the path is in the revocation snapshot. Serials compare as integers."""
    snapshot = {int(serial.replace(":", ""), 16) for serial in trust.revoked_serials}
    return any(certificate.serial_number in snapshot for certificate in path)


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


def _path_gap(path: list[x509.Certificate]) -> str | None:
    """Return a constraint of the path that this engine cannot evaluate, or None.

    The engine implements a subset of RFC 5280 path validation: signature, issuer name,
    certificate authority, path length, certificate signing usage, validity, and revocation by
    snapshot. It does not evaluate name constraints or policy constraints. A path that carries
    one is not passed: the result is inconclusive.
    """
    for certificate in path:
        extensions = _extensions(certificate)
        if extensions is None:
            return "A certificate of the chain has extensions that this engine cannot read."
        for extension in extensions:
            if isinstance(extension.value, _NOT_EVALUATED):
                return (
                    f"A certificate of the chain has {type(extension.value).__name__}, "
                    "which this engine does not evaluate."
                )
            if extension.critical and extension.oid not in _EVALUATED:
                return (
                    "A certificate of the chain has a critical extension that this engine does not evaluate."
                )
    return None


def _purpose(leaf: x509.Certificate) -> tuple[bool | None, str]:
    """May the leaf sign a document? True, False (it states a different purpose), or None (unknown)."""
    usage = _value(leaf, x509.KeyUsage)
    if usage is not None and not (usage.digital_signature or usage.content_commitment):
        return False, "The key usage of the signing certificate does not permit a digital signature."
    purposes = _value(leaf, x509.ExtendedKeyUsage)
    if purposes is None or set(purposes) & _SIGNING_PURPOSES:
        return True, ""
    if set(purposes) <= _OTHER_PURPOSES:
        return False, "The extended key usage of the signing certificate names other purposes only."
    return (
        None,
        "The extended key usage of the signing certificate names a purpose that this engine does not know.",
    )


def _same_json(a: Any, b: Any) -> bool:
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


@register("integrity.jws", capability="integrity.jws")
def jws_check(ctx: CheckContext) -> CheckOutcome:  # noqa: PLR0912, PLR0915 - the ordered findings of the contract
    if ctx.trust is None:
        return blocked(
            "INTEGRITY.TRUST.MISSING", "No trust bundle is configured. Nothing is trusted by default."
        )
    signed_url, item_url = api_url(ctx, "/signed"), api_url(ctx)
    if signed_url is None or item_url is None:
        return blocked("INTEGRITY.NO_TARGET", "The IXIT gives no API endpoint or no passport identifier.")
    record = fetch_once(ctx, signed_url)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    findings: dict[str, JsonValue] = {"status": record.status}
    more: list[Record] = []

    def result(passed: bool, code: str, message: str, *, no_answer: bool = False) -> CheckOutcome:
        summary = {"findings": findings}
        observation = ctx.observation(0, kind="exchange", records=[record, *more], summary=summary)
        return completed(passed, code, f"{message} {_LIMIT}", [observation], no_answer=no_answer)

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
        findings["structure"] = "not a compact JWS"
        return result(False, "INTEGRITY.TOKEN.MALFORMED", "The body is not a compact JWS.")
    if "x5c" not in header:
        return blocked(
            "INTEGRITY.KEY.UNSUPPORTED", "The token has no x5c header. This engine finds the key there only."
        )
    try:
        certificates = _certificates(header)
    except _TooLongError:
        return blocked(
            "INTEGRITY.TOKEN.TOO_LARGE", f"The x5c chain is longer than {_MAX_CHAIN} certificates."
        )
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
    if (gap := _path_gap(path)) is not None:
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
    if not anchor.not_valid_before_utc <= now <= anchor.not_valid_after_utc or revoked([anchor], ctx.trust):
        message = "The trust anchor of this chain is expired or revoked in the operator's trust bundle."
        return blocked("INTEGRITY.TRUST.ANCHOR_INVALID", message)
    if not all(c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in below):
        findings["certificate_validity"] = "outside the validity period"
        message = "A certificate of the chain is outside its validity period at the evaluation time."
        return result(False, "INTEGRITY.CERT.EXPIRED", message)
    findings["certificate_validity"] = "valid at the evaluation time"

    if (gap := _status_gap(ctx.trust, now)) is not None:
        return blocked("INTEGRITY.STATUS.MISSING", gap)
    if revoked(below, ctx.trust):
        findings["revocation"] = "revoked"
        message = "A certificate of the chain is in the revocation snapshot."
        return result(False, "INTEGRITY.CERT.REVOKED", message)
    findings["revocation"] = (
        "not revoked in the snapshot" if ctx.trust.status_as_of else "no snapshot; not required"
    )

    item = fetch_once(ctx, item_url)
    if (problem := unusable(ctx, item)) is not None:
        return problem
    more.append(item)
    document = json_object(item) if item.status == 200 else None
    if document is None:
        message = (
            "The published passport is not a JSON object, so the signed payload has nothing to compare with."
        )
        return blocked("INTEGRITY.PAYLOAD.NOT_COMPARABLE", message)
    # Compare the two documents as JSON values. The canonical form with integers only is a rule
    # for the bodies of this engine (ADR 0006). It is not a rule for a passport of a third party:
    # a different key order, white space, or a decimal number is not a mismatch.
    try:
        same = _same_json(parse_strict(payload, decimals=True), parse_strict(item.body, decimals=True))
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
