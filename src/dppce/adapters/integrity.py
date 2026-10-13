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

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from dppce.adapters.common import api_url, blocked, completed, fetch_once, json_object, unusable
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes
from dppce.evidence.jws import SignatureError, header_of, public_jwk_of, verify_compact
from dppce.infrastructure.clock import parse_stamp
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


def trust_path(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], trust: TrustBundle
) -> list[x509.Certificate] | None:
    """Return the path from the leaf to an anchor of the trust bundle, or None if there is none."""
    anchors = [x509.load_pem_x509_certificate(a.certificate_pem.encode("ascii")) for a in trust.anchors]
    path, current = [leaf], leaf
    for _ in range(_MAX_CHAIN):
        for candidate, is_anchor in [*((a, True) for a in anchors), *((i, False) for i in intermediates)]:
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


@register("integrity.jws", capability="integrity.jws")
def jws_check(ctx: CheckContext) -> CheckOutcome:  # noqa: PLR0912 - the ordered findings of the contract
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
    findings: dict[str, JsonValue] = {}

    def result(passed: bool, code: str, message: str, *more: object) -> CheckOutcome:
        records = [record, *(r for r in more if r is not None)]
        observation = ctx.observation(0, kind="exchange", records=records, summary={"findings": findings})  # type: ignore[arg-type]
        return completed(passed, code, f"{message} {_LIMIT}", [observation])

    token = record.body.decode("ascii", errors="replace").strip()
    try:
        certificates = _certificates(header_of(token)) if record.status == 200 else None
        leaf_key = certificates[0].public_key() if certificates else None
        if not isinstance(leaf_key, ec.EllipticCurvePublicKey):
            raise SignatureError("the token carries no usable P-256 certificate")
        payload = verify_compact(token, public_jwk_of(leaf_key), typ=PASSPORT_TYP)
    except SignatureError as exc:
        if exc.code == "TOO_LARGE":
            # A limit of this engine. It says nothing about the system under test.
            return blocked(
                "INTEGRITY.TOKEN.TOO_LARGE", "The signed passport is larger than this engine accepts."
            )
        findings["signature"] = "invalid"
        return result(
            False,
            "INTEGRITY.SIGNATURE.INVALID",
            "The signature does not verify with the key of its certificate.",
        )
    assert certificates is not None  # noqa: S101 - set when the signature verified
    findings["signature"] = "valid"

    path = trust_path(certificates[0], certificates[1:], ctx.trust)
    if path is None:
        findings["issuer_trust"] = "no path to a trust anchor"
        message = (
            "The signature is valid, but its certificate does not chain to an anchor of the trust bundle."
        )
        return result(False, "INTEGRITY.ISSUER.UNTRUSTED", message)
    findings["issuer_trust"] = "chains to a trust anchor"

    now = ctx.evaluation_time
    if not all(c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in path):
        findings["certificate_validity"] = "outside the validity period"
        message = "A certificate of the chain is outside its validity period at the evaluation time."
        return result(False, "INTEGRITY.CERT.EXPIRED", message)
    findings["certificate_validity"] = "valid at the evaluation time"

    if (gap := _status_gap(ctx.trust, now)) is not None:
        return blocked("INTEGRITY.STATUS.MISSING", gap)
    if f"{certificates[0].serial_number:x}" in {s.lower() for s in ctx.trust.revoked_serials}:
        findings["revocation"] = "revoked"
        return result(
            False, "INTEGRITY.CERT.REVOKED", "The signing certificate is in the revocation snapshot."
        )
    findings["revocation"] = (
        "not revoked in the snapshot" if ctx.trust.status_as_of else "no snapshot; not required"
    )

    item = fetch_once(ctx, item_url)
    if (problem := unusable(ctx, item)) is not None:
        return problem
    document = json_object(item)
    try:
        same = document is not None and canonical_bytes(document) == payload
    except CanonicalizationError:
        same = False
    if not same:
        findings["payload"] = "differs from the published passport"
        return result(
            False, "INTEGRITY.PAYLOAD.MISMATCH", "The signed payload is not the published passport.", item
        )
    findings["payload"] = "equals the published passport"
    return result(
        True,
        "INTEGRITY.OK",
        "The signature, the issuer, the certificates, and the payload are in order.",
        item,
    )
