"""Signed manual-step results. See docs/explanation/architecture.md, section 8.1, and ADR 0013.

The person who performed a manual step signs its result as a compact JWS with ES256. The
engine and the standalone verifier verify it with the same function. Neither performs the
review: a valid signature shows who signed the result, not that the review was correct.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from typing import Final

from dppce.evidence.canonical import canonical_bytes, parse_strict
from dppce.evidence.jws import ALLOWED_ALGORITHMS, SignatureError, header_of, sign_compact, verify_compact
from dppce.infrastructure.interfaces import Signer
from dppce.models import ManualResult, SutIdentity, TrustBundle, TrustedKey

MANUAL_RESULT_TYP: Final = "dppce-manual-result+jws"
MANUAL_CHECK: Final = "manual.review"
SAMPLE_PREFIX: Final = "manual/"
TRUST_PURPOSE: Final = "manual"
_HEADER: Final = frozenset({"alg", "kid", "typ"})
_STAMP: Final = "%Y-%m-%dT%H:%M:%SZ"
_COMPACT: Final = re.compile(r"[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
# SignatureError code from verify_compact -> MANUAL.* reason code.
_SIGNATURE_CODES: Final = {
    "TOO_LARGE": "MANUAL.RESULT.TOO_LARGE",
    "BAD_SIGNATURE": "MANUAL.SIGNATURE.INVALID",
    "ALGORITHM": "MANUAL.SIGNATURE.INVALID",
    "KEY": "MANUAL.KEY.UNTRUSTED",
}


class ManualResultError(ValueError):
    """A manual result cannot be used. ``code`` is a stable MANUAL.* reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _time(value: str) -> datetime:
    return datetime.strptime(value, _STAMP).replace(tzinfo=UTC)


def declared_sut_version(sut: SutIdentity) -> str | None:
    """The SUT version that a manual result must name: the declared one, or None. Never invented."""
    return None if sut.version == "unknown" else sut.version


def issue_manual_result(result: ManualResult, signer: Signer) -> str:
    """Sign a manual result. For tests and the rig: a person signs with their own ``Signer``."""
    # sign_compact writes exactly {alg, kid, typ}, so its output passes the header rule.
    return sign_compact(canonical_bytes(result), signer, typ=MANUAL_RESULT_TYP)


def claimed_test_purpose(token: str) -> str:
    """UNVERIFIED. Return the test purpose that the payload names, to route the file only."""
    try:
        if not _COMPACT.fullmatch(token):
            raise ValueError("not three base64url parts")
        part = token.split(".")[1]
        payload = parse_strict(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, RecursionError) as exc:
        raise ManualResultError("MANUAL.RESULT.MALFORMED", "The text is not a compact JWS.") from exc
    named = payload.get("test_purpose_id") if isinstance(payload, dict) else None
    if not isinstance(named, str):
        raise ManualResultError("MANUAL.RESULT.MALFORMED", "The payload names no test purpose.")
    return named


def _trusted_key(header: dict[str, object], trust: TrustBundle, key_valid_at: datetime) -> TrustedKey:
    kid = header.get("kid")
    key = next((k for k in trust.keys if k.kid == kid and TRUST_PURPOSE in k.purposes), None)
    if key is None:
        raise ManualResultError("MANUAL.KEY.UNTRUSTED", "No key of the trust bundle signs manual results.")
    try:
        valid = _time(key.not_before) <= key_valid_at <= _time(key.not_after)
    except ValueError:
        valid = False
    if key.kid in trust.revoked_kids or not valid:
        raise ManualResultError(
            "MANUAL.KEY.NOT_VALID", "The key is revoked or not valid at the evaluation time."
        )
    return key


def verify_manual_result(
    token: str,
    trust: TrustBundle,
    *,
    test_purpose_id: str,
    test_purpose_digest: str,
    sut: SutIdentity,
    evaluation_time: datetime,
    key_valid_at: datetime,
) -> tuple[ManualResult, TrustedKey]:
    """Verify a manual result in the order of section 8.1, tests 2 to 14. The first failure raises.

    The function reads no clock. The evidence list is not compared here: the verifier does not
    hold the test pack, so the check compares it (test 15). No maximum age applies (ADR 0013).
    """
    try:
        header = header_of(token)
    except SignatureError as exc:
        raise ManualResultError("MANUAL.RESULT.MALFORMED", "The text is not a compact JWS.") from exc
    if set(header) != _HEADER or header["typ"] != MANUAL_RESULT_TYP:
        # Refuses x5c (which usually names a person), any other parameter, and other token types.
        raise ManualResultError("MANUAL.RESULT.MALFORMED", "The header is not that of a manual result.")
    if header["alg"] not in ALLOWED_ALGORITHMS:
        raise ManualResultError("MANUAL.SIGNATURE.INVALID", "The algorithm is not on the allowlist.")
    key = _trusted_key(header, trust, key_valid_at)
    try:
        payload = verify_compact(token, key.public_jwk, typ=MANUAL_RESULT_TYP)
    except SignatureError as exc:
        code = _SIGNATURE_CODES.get(exc.code, "MANUAL.RESULT.MALFORMED")
        raise ManualResultError(code, "The signature does not verify with the trusted key.") from exc
    try:
        result = ManualResult.model_validate(parse_strict(payload))
        if canonical_bytes(result) != payload:
            raise ValueError("the payload is not canonical")
        performed = _time(result.performed_at)
    except (ValueError, RecursionError) as exc:
        raise ManualResultError(
            "MANUAL.RESULT.MALFORMED", "The payload is not a canonical manual result."
        ) from exc
    if result.test_purpose_id != test_purpose_id:
        raise ManualResultError("MANUAL.PURPOSE.MISMATCH", "The result names a different test purpose.")
    if result.test_purpose_digest != test_purpose_digest:
        raise ManualResultError(
            "MANUAL.PURPOSE.DIGEST_MISMATCH", "The result answers a different version of the test purpose."
        )
    if result.sut_identifier != sut.identifier:
        raise ManualResultError("MANUAL.SUT.MISMATCH", "The result names a different system under test.")
    if result.sut_version != declared_sut_version(sut):
        raise ManualResultError(
            "MANUAL.SUT.VERSION_MISMATCH", "The result does not name the SUT version that the ICS declares."
        )
    if performed > evaluation_time:
        raise ManualResultError(
            "MANUAL.TIME.AFTER_EVALUATION", "The review is later than the evaluation time."
        )
    # _trusted_key parsed both stamps already. A result signed outside the window is a replay risk.
    if not _time(key.not_before) <= performed <= _time(key.not_after):
        raise ManualResultError(
            "MANUAL.TIME.OUTSIDE_KEY_VALIDITY", "The review is outside the validity period of the key."
        )
    return result, key
