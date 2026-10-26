"""JOSE profiles for credentials and tokens of a system under test (the check ``integrity.jose``).

These profiles are separate from the report signing profile in ``dppce.evidence.jws``. That
profile and its allowlist do not change. Sources, by name only: RFC 7515 (JWS), RFC 7517 (JWK),
RFC 7518 (JWA), RFC 8037 (EdDSA in JOSE), RFC 8725 (JWT best current practice), and the W3C
Recommendation "Securing Verifiable Credentials using JOSE and COSE" of 13 October 2026.

The key decides the algorithm: P-256 gives ES256, P-384 gives ES384, and Ed25519 gives EdDSA.
The header ``alg`` must name that algorithm. It never selects one. Verification uses the
``cryptography`` package directly, so no library default can widen the allowlist.

Every function here judges untrusted bytes. A ``JoseError`` says why a token is refused. Only
the codes in ``ENGINE_LIMITS`` are limits of this engine. They apply to a well-formed token only,
so that a system under test cannot reshape a defect into a step that is not judged.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.jws import SignatureError, header_of

Profile = Literal["vc-jose", "jws"]
Algorithm = Literal["ES256", "ES384", "EdDSA"]
PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

ALGORITHMS: Final[tuple[Algorithm, ...]] = ("ES256", "ES384", "EdDSA")
VC_TYP: Final = "vc+jwt"
# RFC 8725, sections 2.1 and 3.1: an unsecured token, and a MAC that a public key could make.
REFUSED_ALGORITHMS: Final = frozenset({"none", "HS256", "HS384", "HS512"})
# Engine limits. The transport limits a body to 1 MiB by default, so the body limit rarely applies.
MAX_BODY_BYTES: Final = 2 * 1024 * 1024
MAX_SIGNATURES: Final = 8
ENGINE_LIMITS: Final = frozenset({"INTEGRITY.JOSE.TOO_LARGE", "INTEGRITY.JOSE.UNSUPPORTED"})

_B64URL: Final = re.compile(r"[A-Za-z0-9_-]+")
_COMPACT: Final = re.compile(r"[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
# RFC 3339, section 5.6, with ASCII digits. The offset is required.
_DATE_TIME: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:([0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})"
)
# (curve, coordinate bytes, hash) of each ECDSA algorithm (RFC 7518, section 3.4).
_ECDSA: Final = {"ES256": ("secp256r1", 32, hashes.SHA256), "ES384": ("secp384r1", 48, hashes.SHA384)}
_CURVES: Final = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48)}


class JoseError(ValueError):
    """A token is refused. ``code`` is the reason code of the step.

    The message never quotes a value of the token: the system under test chose those values.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Signature:
    """One signature: its joined header (protected and unprotected), its signing input, and its value."""

    header: dict[str, Any]
    protected: frozenset[str]
    signing_input: bytes
    value: bytes


@dataclass(frozen=True)
class Token:
    serialization: Literal["compact", "flattened", "general"]
    payload: bytes
    signatures: tuple[Signature, ...]


# -- shape --------------------------------------------------------------------------------------


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


def is_jws_json(document: dict[str, object] | None) -> bool:
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


def _decode(part: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError) as exc:
        raise JoseError("INTEGRITY.JOSE.MALFORMED", "A part of the token is not base64url.") from exc


def _signature(protected: str, unprotected: object, payload: str, signature: str) -> Signature:
    try:
        header = header_of(f"{protected}..") if protected else {}
    except SignatureError as exc:
        raise JoseError("INTEGRITY.JOSE.MALFORMED", "The protected header is not a JSON object.") from exc
    extra = unprotected if isinstance(unprotected, dict) else {}
    if header.keys() & extra.keys():
        raise JoseError(
            "INTEGRITY.JOSE.MALFORMED", "The protected and the unprotected header share a member name."
        )
    if "crit" in extra:
        raise JoseError("INTEGRITY.JOSE.MALFORMED", "The member crit is in the unprotected header.")
    return Signature(
        header={**header, **extra},
        protected=frozenset(header),
        signing_input=f"{protected}.{payload}".encode("ascii"),
        value=_decode(signature),
    )


def parse(body: bytes) -> Token:
    """Read a compact, a flattened JSON, or a general JSON serialization. Verifies nothing."""
    if len(body) > MAX_BODY_BYTES:
        raise JoseError("INTEGRITY.JOSE.TOO_LARGE", f"The token is larger than {MAX_BODY_BYTES} bytes.")
    text = body.strip()
    if _COMPACT.fullmatch(text.decode("ascii", errors="replace")):
        protected, payload, signature = text.decode("ascii").split(".")
        return Token("compact", _decode(payload), (_signature(protected, None, payload, signature),))
    try:
        document = parse_strict(body)
    except (CanonicalizationError, RecursionError) as exc:
        raise JoseError(
            "INTEGRITY.JOSE.MALFORMED", "The body is neither a compact JWS nor a JWS JSON serialization."
        ) from exc
    if not isinstance(document, dict) or not is_jws_json(document):
        raise JoseError(
            "INTEGRITY.JOSE.MALFORMED", "The body is neither a compact JWS nor a JWS JSON serialization."
        )
    members = document.get("signatures", [document])
    if len(members) > MAX_SIGNATURES:
        raise JoseError("INTEGRITY.JOSE.TOO_LARGE", f"The token has more than {MAX_SIGNATURES} signatures.")
    payload = document["payload"]
    signatures = tuple(
        _signature(m.get("protected", ""), m.get("header"), payload, m["signature"]) for m in members
    )
    return Token("general" if "signatures" in document else "flattened", _decode(payload), signatures)


# -- header rules -------------------------------------------------------------------------------


def _media_type(value: str) -> str:
    # RFC 7515, section 4.1.9: compared without case, and "application/" may be left out.
    lowered = value.lower()
    return lowered.removeprefix("application/") if "/" in lowered else lowered


def check_header(signature: Signature, profile: Profile) -> None:
    """Apply the header rules of the profile. They do not need a key."""
    header = signature.header
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise JoseError("INTEGRITY.JOSE.MALFORMED", "The header names no algorithm.")
    if alg in REFUSED_ALGORITHMS:
        raise JoseError(
            "INTEGRITY.JOSE.ALGORITHM", "The header names an algorithm that every profile refuses (RFC 8725)."
        )
    crit = header.get("crit")
    if "crit" in header and not (
        isinstance(crit, list)
        and crit
        and all(isinstance(name, str) and name in signature.protected for name in crit)
    ):
        raise JoseError(
            "INTEGRITY.JOSE.MALFORMED", "The member crit is not a list of protected header member names."
        )
    if isinstance(crit, list) and set(crit) - {"b64"}:
        raise JoseError(
            "INTEGRITY.JOSE.HEADER", "The token needs a header extension that the profile does not define."
        )
    if "b64" in header:
        # RFC 7797, section 6: a protected b64 that crit names. Any other b64 is no such form, so
        # one more header member cannot turn a fail into a blocked step.
        if "b64" not in signature.protected or not isinstance(crit, list) or "b64" not in crit:
            raise JoseError("INTEGRITY.JOSE.MALFORMED", "The member b64 is not protected and named in crit.")
        if not isinstance(header["b64"], bool):
            raise JoseError("INTEGRITY.JOSE.MALFORMED", "The member b64 is not a boolean.")
        if header["b64"] is False:
            if profile == "vc-jose":
                raise JoseError(
                    "INTEGRITY.JOSE.HEADER", "A credential of the vc-jose profile has a base64url payload."
                )
            raise JoseError(
                "INTEGRITY.JOSE.UNSUPPORTED", "This engine does not verify an unencoded payload (RFC 7797)."
            )
    if profile == "vc-jose" and "typ" in header:
        typ = header["typ"]
        if not isinstance(typ, str) or _media_type(typ) != VC_TYP:
            raise JoseError("INTEGRITY.JOSE.TYPE", f"The header typ of a vc-jose credential is not {VC_TYP}.")


# -- keys and signatures ------------------------------------------------------------------------


def key_algorithm(key: object) -> Algorithm:
    """The one algorithm of a key type. Any other key type is a limit of this engine."""
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "EdDSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        for algorithm, (curve, _, _) in _ECDSA.items():
            if key.curve.name == curve:
                return algorithm  # type: ignore[return-value]  # a key of _ECDSA
    raise JoseError("INTEGRITY.JOSE.UNSUPPORTED", "The key is of a type that this engine does not verify.")


def public_key_from_jwk(jwk: dict[str, str]) -> PublicKey:
    """The public key of a trusted JWK. A JWK of another type, or with a private member, is not used."""
    try:
        if "d" in jwk or jwk.get("use", "sig") != "sig":
            raise ValueError("not a public signing key")
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            key: PublicKey = ed25519.Ed25519PublicKey.from_public_bytes(_decode(jwk["x"]))
        elif jwk.get("kty") == "EC" and jwk.get("crv") in _CURVES:
            curve, size = _CURVES[jwk["crv"]]
            x, y = _decode(jwk["x"]), _decode(jwk["y"])
            if len(x) != size or len(y) != size:
                raise ValueError("a coordinate has the wrong length")
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve()
            )
            key = numbers.public_key()
        else:
            raise ValueError("a key type outside the profiles")
    except (KeyError, ValueError, JoseError) as exc:
        raise JoseError(
            "INTEGRITY.JOSE.UNSUPPORTED", "The trusted key is not a public key that this engine verifies."
        ) from exc
    if jwk.get("alg", key_algorithm(key)) != key_algorithm(key):
        raise JoseError(
            "INTEGRITY.JOSE.UNSUPPORTED", "The trusted key names an algorithm that does not fit its type."
        )
    return key


def verify(signature: Signature, key: object, allowed: tuple[Algorithm, ...]) -> None:
    """Verify one signature with ``key``. The key type, not the header, gives the algorithm."""
    algorithm = key_algorithm(key)
    if algorithm not in allowed:
        raise JoseError(
            "INTEGRITY.JOSE.ALGORITHM", "The key type needs an algorithm outside the allowlist of the test."
        )
    if signature.header["alg"] != algorithm:
        raise JoseError(
            "INTEGRITY.JOSE.ALGORITHM", "The header names an algorithm that the key type does not give."
        )
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature.value, signature.signing_input)
            return
        assert isinstance(key, ec.EllipticCurvePublicKey)  # noqa: S101 - key_algorithm gave an ECDSA algorithm
        _, size, digest = _ECDSA[algorithm]
        if len(signature.value) != 2 * size:
            raise InvalidSignature
        r, s = (int.from_bytes(signature.value[i : i + size], "big") for i in (0, size))
        key.verify(encode_dss_signature(r, s), signature.signing_input, ec.ECDSA(digest()))
    except InvalidSignature as exc:
        raise JoseError("INTEGRITY.JOSE.SIGNATURE", "The signature does not verify with the key.") from exc


# -- credential claims (vc-jose) ----------------------------------------------------------------


def _moment(value: object) -> datetime:
    message = "A validity member is not an RFC 3339 date-time with an offset."
    text = value.upper() if isinstance(value, str) else ""
    match = _DATE_TIME.fullmatch(text)
    if match is None:
        raise JoseError("INTEGRITY.JOSE.CLAIMS", message)
    if match[1] == "60":  # a leap second counts as the second before it
        text = text[: match.start(1)] + "59" + text[match.end(1) :]
    try:
        # Aware moments compare across offsets. A conversion to UTC can leave the date range.
        return datetime.fromisoformat(text)
    except (ValueError, OverflowError) as exc:
        raise JoseError("INTEGRITY.JOSE.CLAIMS", message) from exc


def _seconds(value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, int | Decimal):
        raise JoseError("INTEGRITY.JOSE.CLAIMS", "A NumericDate claim is not a number.")
    return Decimal(value)


def credential_issuer(payload: bytes, now: datetime) -> str:
    """Judge the claims of a vc-jose credential at ``now`` and return its issuer identifier."""
    try:
        document = parse_strict(payload, decimals=True)
    except (CanonicalizationError, RecursionError) as exc:
        raise JoseError("INTEGRITY.JOSE.CLAIMS", "The payload is not one JSON object.") from exc
    if not isinstance(document, dict):
        raise JoseError("INTEGRITY.JOSE.CLAIMS", "The payload is not one JSON object.")
    issuer = document.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
    if not isinstance(issuer_id, str) or not issuer_id:
        raise JoseError("INTEGRITY.JOSE.CLAIMS", "The credential names no issuer identifier.")
    if "iss" in document and document["iss"] != issuer_id:
        raise JoseError(
            "INTEGRITY.JOSE.ISSUER_MISMATCH", "The claim iss differs from the issuer of the credential."
        )
    starts = [_moment(document[k]) for k in ("validFrom",) if k in document]
    ends = [_moment(document[k]) for k in ("validUntil",) if k in document]
    instant = Decimal(str(now.timestamp()))
    if any(start > now for start in starts) or ("nbf" in document and _seconds(document["nbf"]) > instant):
        raise JoseError(
            "INTEGRITY.JOSE.NOT_YET_VALID", "The credential is not yet valid at the evaluation time."
        )
    # RFC 7519, section 4.1.4: the token expires at exp. validUntil is the last valid moment.
    if any(end < now for end in ends) or ("exp" in document and _seconds(document["exp"]) <= instant):
        raise JoseError("INTEGRITY.JOSE.EXPIRED", "The credential is expired at the evaluation time.")
    return issuer_id
