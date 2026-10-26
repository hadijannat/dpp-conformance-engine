"""The one signing profile: JWS Compact Serialization (RFC 7515) with ES256.

Verification goes through joserfc with a fixed algorithm allowlist. The header ``alg`` value
never selects the algorithm. See ADR 0008.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from joserfc import jws
from joserfc.errors import BadSignatureError, DecodeError, ExceededSizeError, JoseError
from joserfc.jwk import ECKey
from joserfc.jws import JWSRegistry

from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.infrastructure.interfaces import Signer

ALLOWED_ALGORITHMS: Final = ("ES256",)
_PUBLIC_JWK_FIELDS: Final = frozenset({"kty", "crv", "x", "y"})
_SUPPORTED_HEADERS: Final = frozenset({"alg", "kid", "typ", "x5c"})
# A compact JWS is three base64url parts with no padding (RFC 7515, section 7.1).
_COMPACT: Final = re.compile(r"[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")


# Explicit size limits. The library default for a header is 512 bytes, which is smaller than
# one certificate in ``x5c``. A token above a limit is "too large for this engine". It is never
# reported as an invalid signature.
MAX_HEADER_BYTES: Final = 16 * 1024
MAX_PAYLOAD_BYTES: Final = 1024 * 1024
MAX_SIGNATURE_BYTES: Final = 1024


class _Registry(JWSRegistry):
    max_header_length = MAX_HEADER_BYTES
    max_payload_length = MAX_PAYLOAD_BYTES
    max_signature_length = MAX_SIGNATURE_BYTES


class SignatureError(ValueError):
    """A token is malformed, uses a disallowed algorithm, is too large, or does not verify.

    ``code`` says which:

    - ``MALFORMED``: the text is not a compact JWS.
    - ``ALGORITHM``, ``TYPE``, ``HEADER``, ``KEY``: the token is outside the one profile that
      this engine supports. That is a limit of the engine, not a defect of the token.
    - ``TOO_LARGE``: above a size limit of this engine.
    - ``NOT_PROCESSABLE``: the JOSE library refused the token for a different reason.
    - ``BAD_SIGNATURE``: the cryptographic check ran and failed. Only this code means that.
    """

    def __init__(self, message: str, code: str = "MALFORMED") -> None:
        super().__init__(message)
        self.code = code


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("a token part is not base64url") from exc


def sign_compact(payload: bytes, signer: Signer, *, typ: str) -> str:
    """Return a compact JWS over ``payload``. The header is canonical JSON."""
    if signer.algorithm not in ALLOWED_ALGORITHMS:
        raise SignatureError(f"algorithm {signer.algorithm!r} is not in the allowlist", "ALGORITHM")
    header = canonical_bytes({"alg": signer.algorithm, "kid": signer.key_id, "typ": typ})
    signing_input = f"{_b64(header)}.{_b64(payload)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64(signer.sign(signing_input))}"


def header_of(token: str) -> dict[str, Any]:
    """Return the protected header WITHOUT verifying anything. Use it only to find the key."""
    if not _COMPACT.fullmatch(token):
        # Checked before the library sees the token: a broken part is a malformed token, not
        # a signature that does not verify.
        raise SignatureError("a compact JWS is three base64url parts")
    parts = token.split(".")
    try:
        header = parse_strict(_unb64(parts[0]))
    except (CanonicalizationError, RecursionError) as exc:
        # A repeated member (two "alg") or a nesting deeper than the parser handles is not a header.
        raise SignatureError("the protected header is not JSON") from exc
    if not isinstance(header, dict):
        raise SignatureError("the protected header is not a JSON object")
    return header


def payload_of(token: str) -> bytes:
    """Return the decoded payload WITHOUT verifying anything. Use it only to show what a token declares."""
    if not _COMPACT.fullmatch(token):
        raise SignatureError("a compact JWS is three base64url parts")
    return _unb64(token.split(".")[1])


def signature_value(token: str) -> bytes:
    """Return the base64url-decoded third part WITHOUT verifying anything. A timestamp covers it."""
    if not _COMPACT.fullmatch(token):
        raise SignatureError("a compact JWS is three base64url parts")
    return _unb64(token.split(".")[2])


def verify_compact(token: str, public_jwk: Mapping[str, str], *, typ: str) -> bytes:
    """Verify ``token`` with ``public_jwk`` and return the payload.

    Rejects a disallowed algorithm, a wrong ``typ``, an unknown header parameter, a key
    that is not a public P-256 key, and a key whose use or alg does not permit ES256 signatures.
    """
    if len(token) > MAX_HEADER_BYTES + MAX_PAYLOAD_BYTES * 2 + MAX_SIGNATURE_BYTES:
        raise SignatureError("the token is larger than this engine accepts", "TOO_LARGE")
    header = header_of(token)
    if header.get("alg") not in ALLOWED_ALGORITHMS:
        raise SignatureError(f"algorithm {header.get('alg')!r} is not in the allowlist", "ALGORITHM")
    if header.get("typ") != typ:
        raise SignatureError(f"type {header.get('typ')!r} is not {typ!r}", "TYPE")
    unknown = set(header) - _SUPPORTED_HEADERS
    if unknown:
        raise SignatureError(f"unsupported header parameters: {sorted(unknown)}", "HEADER")
    is_public_ec = set(public_jwk) - {"kid", "use", "alg"} == _PUBLIC_JWK_FIELDS
    if not is_public_ec or public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        raise SignatureError("the verification key is not a public P-256 key", "KEY")
    if public_jwk.get("use", "sig") != "sig" or public_jwk.get("alg", "ES256") not in ALLOWED_ALGORITHMS:
        raise SignatureError("the verification key is not a public P-256 signing key for ES256", "KEY")
    try:
        key = ECKey.import_key({k: public_jwk[k] for k in _PUBLIC_JWK_FIELDS})
        verified = jws.deserialize_compact(
            token,
            key,
            algorithms=list(ALLOWED_ALGORITHMS),
            registry=_Registry(algorithms=list(ALLOWED_ALGORITHMS)),
        )
        return bytes(verified.payload)
    except ExceededSizeError as exc:
        raise SignatureError("the token is larger than this engine accepts", "TOO_LARGE") from exc
    except BadSignatureError as exc:
        raise SignatureError("the signature does not verify", "BAD_SIGNATURE") from exc
    except DecodeError as exc:
        raise SignatureError("a token part cannot be decoded", "MALFORMED") from exc
    except (JoseError, ValueError) as exc:
        raise SignatureError(
            f"the token cannot be processed: {type(exc).__name__}", "NOT_PROCESSABLE"
        ) from exc


def public_jwk_of(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Return the public JWK of a P-256 key. A key on a different curve is outside the profile."""
    if not isinstance(key.curve, ec.SECP256R1):
        raise SignatureError(f"the key is on curve {key.curve.name}, not on P-256", "KEY")
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def public_jwk_from(document: object) -> dict[str, str]:
    """Return the public JWK of a P-256 signing key: ``kty``, ``crv``, ``x``, and ``y`` only.

    ``document`` is untrusted JSON. A private member gives the code ``PRIVATE``. Anything else
    outside the one profile, a point that is not on the curve included, gives ``KEY``.
    """
    # "d" first: a private JWK from WebCrypto or jose also holds members that are not strings.
    if not isinstance(document, dict):
        raise SignatureError("a public key is a JSON object of strings", "KEY")
    if "d" in document:
        raise SignatureError("the JWK holds the private member 'd'; give the public key only", "PRIVATE")
    if not all(isinstance(v, str) for v in document.values()):
        raise SignatureError("a public key is a JSON object of strings", "KEY")
    if set(document) - {"kid", "use", "alg"} != _PUBLIC_JWK_FIELDS:
        raise SignatureError("the JWK is not an EC public key with kty, crv, x, and y", "KEY")
    if document["kty"] != "EC" or document["crv"] != "P-256":
        raise SignatureError("the JWK is not a P-256 key", "KEY")
    if document.get("use", "sig") != "sig" or document.get("alg", "ES256") not in ALLOWED_ALGORITHMS:
        raise SignatureError("the JWK is not a signing key for ES256", "KEY")
    try:
        x, y = (_unb64(document[name]) for name in ("x", "y"))
        if len(x) != 32 or len(y) != 32:  # a P-256 coordinate has 32 bytes
            raise ValueError("a coordinate is not 32 bytes")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        key = numbers.public_key()
    except ValueError as exc:  # SignatureError is a ValueError too
        raise SignatureError("the JWK is not a point on P-256", "KEY") from exc
    canonical = public_jwk_of(key)
    # One spelling per point: no padding, no standard alphabet, no unused bits, no x + p.
    if (canonical["x"], canonical["y"]) != (document["x"], document["y"]):
        raise SignatureError("a coordinate of the JWK is not the unpadded base64url of 32 bytes", "KEY")
    return canonical


class LocalSigner:
    """A signer that holds a private key in memory. For tests and development only.

    A production deployment implements ``Signer`` for a KMS or a PKCS#11 device instead.
    """

    algorithm: Final = "ES256"

    def __init__(self, key_id: str, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise SignatureError("ES256 needs a P-256 key", "KEY")
        self.key_id = key_id
        self._key = private_key

    @classmethod
    def generate(cls, key_id: str) -> LocalSigner:
        return cls(key_id, ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, path: Path, key_id: str) -> LocalSigner:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SignatureError(f"{path}: not an elliptic-curve private key")
        return cls(key_id, key)

    def to_pem(self) -> bytes:
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def public_jwk(self) -> dict[str, str]:
        return public_jwk_of(self._key.public_key())

    def sign(self, signing_input: bytes) -> bytes:
        # JWS wants the raw R || S form. The library returns DER.
        r, s = decode_dss_signature(self._key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


_: type[Signer] = LocalSigner  # LocalSigner satisfies the Signer protocol
