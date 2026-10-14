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
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

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


def _certificates(header: dict[str, object]) -> list[x509.Certificate] | None:
    chain = header.get("x5c")
    if not isinstance(chain, list) or not chain or len(chain) > _MAX_CHAIN:
        return None
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(str(item), validate=True)) for item in chain]
    except (binascii.Error, ValueError):
        return None


def _may_issue(issuer: x509.Certificate, authorities_below: int) -> bool:
    """True if ``issuer`` is a certificate authority that may sign the next certificate of the path.

    A signature and a matching name are not enough. Without this test, the holder of any end
    certificate from a trusted root could sign certificates of its own.
    """
    try:
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    if not constraints.ca:
        return False
    if constraints.path_length is not None and authorities_below > constraints.path_length:
        return False
    try:
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return bool(usage.key_cert_sign)


def trust_path(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], trust: TrustBundle
) -> list[x509.Certificate] | None:
    """Return the path from the leaf to an anchor of the trust bundle, or None if there is none.

    Each issuer must have signed the certificate below it, must be a certificate authority,
    must permit signing certificates, and must respect its path length constraint.
    """
    anchors = [x509.load_pem_x509_certificate(a.certificate_pem.encode("ascii")) for a in trust.anchors]
    path, current = [leaf], leaf
    for depth in range(_MAX_CHAIN):
        # ``depth`` is the number of certificate authorities already below the next issuer.
        for candidate, is_anchor in [*((a, True) for a in anchors), *((i, False) for i in intermediates)]:
            if not _may_issue(candidate, authorities_below=depth):
                continue
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                continue
            path.append(candidate)
            if is_anchor:
                return path
            current = candidate
            break
        else:
            return None
    return None


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
        for extension in (x509.NameConstraints, x509.PolicyConstraints):
            try:
                certificate.extensions.get_extension_for_class(extension)
            except x509.ExtensionNotFound:
                continue
            return (
                f"A certificate of the chain has {extension.__name__}, which this engine does not evaluate."
            )
    return None


def _may_sign_documents(leaf: x509.Certificate) -> bool:
    """False if the leaf states its key usage and that usage does not include a digital signature."""
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return bool(usage.digital_signature or usage.content_commitment)


def _same_json(a: Any, b: Any) -> bool:
    """Equality of two JSON values that were parsed with exact numbers.

    Python calls ``True`` and ``1`` equal. JSON does not: a passport that signs ``true`` and
    publishes ``1`` shows two different documents. The numbers 1 and 1.0 are one JSON number.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same_json(value, b[key]) for key, value in a.items())
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(map(_same_json, a, b))
    if isinstance(a, int | Decimal) and isinstance(b, int | Decimal):
        return a == b
    return type(a) is type(b) and bool(a == b)


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
    certificates = _certificates(header)
    if certificates is None:
        findings["structure"] = "x5c is not a list of certificates"
        return result(False, "INTEGRITY.TOKEN.MALFORMED", "The x5c header does not hold certificates.")
    leaf_key = certificates[0].public_key()
    try:
        if not isinstance(leaf_key, ec.EllipticCurvePublicKey):
            raise SignatureError("the certificate key is not an elliptic-curve key", "KEY")
        payload = verify_compact(token, public_jwk_of(leaf_key), typ=PASSPORT_TYP)
    except SignatureError as exc:
        if exc.code in _ENGINE_LIMITS:
            # A limit of this engine. It says nothing about the system under test.
            code = (
                "INTEGRITY.TOKEN.TOO_LARGE" if exc.code == "TOO_LARGE" else "INTEGRITY.TOKEN.NOT_PROCESSABLE"
            )
            return blocked(code, f"This engine cannot process the signed passport: {exc}.")
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
    if not _may_sign_documents(certificates[0]):
        findings["key_usage"] = "the certificate does not permit a digital signature"
        message = "The key usage of the signing certificate does not permit a digital signature."
        return result(False, "INTEGRITY.CERT.KEY_USAGE", message)

    now = ctx.evaluation_time
    if not all(c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in path):
        findings["certificate_validity"] = "outside the validity period"
        message = "A certificate of the chain is outside its validity period at the evaluation time."
        return result(False, "INTEGRITY.CERT.EXPIRED", message)
    findings["certificate_validity"] = "valid at the evaluation time"

    if (gap := _status_gap(ctx.trust, now)) is not None:
        return blocked("INTEGRITY.STATUS.MISSING", gap)
    if revoked(path, ctx.trust):
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
