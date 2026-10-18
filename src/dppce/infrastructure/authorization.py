"""Validate a signed test authorization from the system owner or an authorized delegate.

The transport enforces the endpoints, methods, roles, validity period, and request limit of a
validated authorization on every request. This module decides whether the document can be
trusted at all.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from pydantic import ValidationError

from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.jws import SignatureError, header_of, sign_compact, verify_compact
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Signer
from dppce.models import Authorization, TrustBundle

AUTHORIZATION_TYP: Final = "dppce-authorization+jws"


class AuthorizationError(ValueError):
    """The authorization cannot be used. ``code`` is a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def issue_authorization(authorization: Authorization, signer: Signer) -> str:
    """Sign an authorization. The system owner runs this, not the tester."""
    return sign_compact(canonical_bytes(authorization), signer, typ=AUTHORIZATION_TYP)


def validate_authorization(
    token: str, trust: TrustBundle, at: datetime, sut_identifier: str
) -> Authorization:
    """Return the authorization if a trusted issuer signed it for this system and time."""
    try:
        kid = str(header_of(token).get("kid"))
    except SignatureError as exc:
        raise AuthorizationError("AUTHZ.MALFORMED", str(exc)) from exc
    key = next((k for k in trust.keys if k.kid == kid and "authorization" in k.purposes), None)
    if key is None:
        raise AuthorizationError("AUTHZ.ISSUER.UNTRUSTED", f"Key '{kid}' is not trusted to authorize tests.")
    if trust.key_revoked(kid, at) or not parse_stamp(key.not_before) <= at <= parse_stamp(key.not_after):
        raise AuthorizationError(
            "AUTHZ.ISSUER.KEY_NOT_VALID", f"Key '{kid}' is revoked or outside its validity."
        )
    try:
        payload = verify_compact(token, key.public_jwk, typ=AUTHORIZATION_TYP)
        authorization = Authorization.model_validate(parse_strict(payload))
        if canonical_bytes(authorization) != payload:
            raise AuthorizationError(
                "AUTHZ.MALFORMED", "The signed payload is not a canonical authorization."
            )
    except SignatureError as exc:
        raise AuthorizationError("AUTHZ.SIGNATURE.INVALID", str(exc)) from exc
    except (ValidationError, CanonicalizationError) as exc:
        raise AuthorizationError("AUTHZ.MALFORMED", str(exc).splitlines()[0]) from exc
    if authorization.issuer != key.issuer:
        raise AuthorizationError(
            "AUTHZ.ISSUER.MISMATCH", "The authorization names a different issuer than the key."
        )
    if authorization.sut_identifier != sut_identifier:
        raise AuthorizationError(
            "AUTHZ.SUT.MISMATCH", "The authorization is for a different system under test."
        )
    if not parse_stamp(authorization.not_before) <= at <= parse_stamp(authorization.not_after):
        raise AuthorizationError("AUTHZ.EXPIRED", "The authorization is not valid at the evaluation time.")
    return authorization
