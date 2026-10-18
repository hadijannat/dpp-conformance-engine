"""RFC 3161 timestamp tokens over report signatures (ADR 0015; architecture sections 11.3, 11.4).

A token is untrusted data. ``verify_token`` checks one token in the order of section 11.4 and
raises only ``TimestampError``, whose ``code`` is a full reason code. Each step names the
exceptions that it can raise. asn1crypto parses the DER, and cryptography verifies the
signature. The module does no network I/O: it reads no CRL, no OCSP response, and no URL.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Collection
from dataclasses import dataclass
from datetime import UTC, datetime
from math import ceil
from typing import Any, Final

from asn1crypto import cms, core, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from dppce.evidence import x509path
from dppce.evidence.jws import signature_value
from dppce.models import TrustBundle

MAX_TOKEN_BYTES: Final = 64 * 1024
MAX_TOKEN_TEXT: Final = 4 * ceil(MAX_TOKEN_BYTES / 3)  # 87384 base64 characters
MAX_TOKENS: Final = 16
MAX_TOKEN_CERTS: Final = 5

_SIGNED_DATA: Final = "1.2.840.113549.1.7.2"
_TST_INFO: Final = "1.2.840.113549.1.9.16.1.4"
_CONTENT_TYPE: Final = "1.2.840.113549.1.9.3"
_MESSAGE_DIGEST: Final = "1.2.840.113549.1.9.4"
_ESS_V1: Final = "1.2.840.113549.1.9.16.2.12"
_ESS_V2: Final = "1.2.840.113549.1.9.16.2.47"
SHA256: Final = "2.16.840.1.101.3.4.2.1"
_DIGESTS: Final = {SHA256: "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
_HASHES: Final[dict[str, type[hashes.HashAlgorithm]]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
# Signature OID -> (key type, hash). None: the hash of the digest algorithm (rsaEncryption).
_SIGNATURES: Final[dict[str, tuple[str, str | None]]] = {
    "1.2.840.113549.1.1.1": ("rsa", None),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.4.3.2": ("ec", "sha256"),
    "1.2.840.10045.4.3.3": ("ec", "sha384"),
    "1.2.840.10045.4.3.4": ("ec", "sha512"),
}
_MIN_RSA_BITS: Final = 2048
_CURVES: Final = (ec.SECP256R1, ec.SECP384R1)
# The exceptions that asn1crypto raises on a malformed or unexpected structure, and the one that
# cryptography raises on a certificate of an unknown version, which is no ValueError.
_PARSE_ERRORS: Final = (
    x509.InvalidVersion,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    OverflowError,
    AttributeError,
    RecursionError,
)


class TimestampError(ValueError):
    """A token cannot be used. ``code`` is a full reason code, such as ``TIMESTAMP.TSA.EKU``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Stamp:
    """A good token: the TSA states that a signature with this imprint existed at ``gen_time``."""

    gen_time: datetime  # aware UTC, with its fraction of a second
    imprint: bytes
    tsa_subject: str


@dataclass(frozen=True)
class _Signer:
    digest_oid: str
    signature_oid: str
    signature: bytes
    signed_attrs: bytes  # the original bytes, retagged from [0] to SET OF
    content_types: tuple[str, ...]
    message_digests: tuple[bytes, ...]
    ess: tuple[str, str, bytes] | None  # (attribute OID, hash OID, hash of the first certificate)
    sid: tuple[bytes, int] | bytes  # (issuer DER, serial number), or a subject key identifier


@dataclass(frozen=True)
class _Token:
    gen_time: datetime
    imprint_oid: str
    imprint: bytes
    critical_extensions: tuple[str, ...]
    content: bytes
    signer: _Signer | None  # None: not exactly one signer, or no signed attributes
    certificates: tuple[tuple[bytes, x509.Certificate], ...]


def format_time(value: datetime) -> str:
    """``%Y-%m-%dT%H:%M:%SZ``, with ``.%f`` before the Z when the fraction is not zero."""
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ" if utc.microsecond else "%Y-%m-%dT%H:%M:%SZ")


def imprint_of(jws_token: str) -> bytes:
    """SHA-256 over the signature value of a compact JWS. Raises ``SignatureError`` if malformed."""
    return hashlib.sha256(signature_value(jws_token)).digest()


def imprint_hex(jws_token: str) -> str:
    return imprint_of(jws_token).hex()


def _malformed(message: str) -> TimestampError:
    return TimestampError("TIMESTAMP.TOKEN.MALFORMED", message)


def _bytes(value: Any) -> bytes:
    if not isinstance(value, bytes):
        raise _malformed("a field is not an octet string")
    return value


def _signer(signed: Any) -> _Signer | None:
    signers = signed["signer_infos"]
    if len(signers) != 1:
        return None
    info = signers[0]
    attributes = info["signed_attrs"]
    if isinstance(attributes, core.Void):
        return None
    raw = attributes.dump()
    content_types: list[str] = []
    digests: list[bytes] = []
    ess: tuple[str, str, bytes] | None = None
    for attribute in attributes:
        kind = str(attribute["type"].dotted)
        if kind == _CONTENT_TYPE:
            content_types += [str(v.dotted) for v in attribute["values"]]
        elif kind == _MESSAGE_DIGEST:
            digests += [_bytes(v.native) for v in attribute["values"]]
        elif kind in (_ESS_V1, _ESS_V2) and ess is None:
            first = attribute["values"][0]["certs"][0]
            # ESSCertIDv2.hashAlgorithm DEFAULT sha256: asn1crypto returns the default if absent.
            algorithm = (
                "1.3.14.3.2.26" if kind == _ESS_V1 else str(first["hash_algorithm"]["algorithm"].dotted)
            )
            ess = (kind, algorithm, _bytes(first["cert_hash"].native))
    sid = info["sid"]
    identifier: tuple[bytes, int] | bytes
    if sid.name == "issuer_and_serial_number":
        identifier = (sid.chosen["issuer"].dump(), int(sid.chosen["serial_number"].native))
    else:
        identifier = _bytes(sid.chosen.native)
    return _Signer(
        digest_oid=str(info["digest_algorithm"]["algorithm"].dotted),
        signature_oid=str(info["signature_algorithm"]["algorithm"].dotted),
        signature=_bytes(info["signature"].native),
        signed_attrs=b"\x31" + raw[1:],
        content_types=tuple(content_types),
        message_digests=tuple(digests),
        ess=ess,
        sid=identifier,
    )


def parse_token(der: bytes) -> _Token:
    """Parse a DER TimeStampToken. The only function that touches asn1crypto for a token.

    Each field is read explicitly inside one block, so a malformed structure gives
    ``TIMESTAMP.TOKEN.MALFORMED`` and never another exception.
    """
    try:
        info = cms.ContentInfo.load(der, strict=True)
        if info["content_type"].dotted != _SIGNED_DATA:
            raise _malformed("the token is not CMS SignedData")
        signed = info["content"]
        encapsulated = signed["encap_content_info"]
        if encapsulated["content_type"].dotted != _TST_INFO or isinstance(encapsulated["content"], core.Void):
            raise _malformed("the token holds no TSTInfo")
        content = bytes(encapsulated["content"])
        tst = tsp.TSTInfo.load(content, strict=True)
        if tst["version"].native != "v1":
            raise _malformed("the TSTInfo version is not 1")
        gen_time = tst["gen_time"].native
        # extended_datetime (year 0) and a naive time are refused, so later comparisons cannot raise.
        if not isinstance(gen_time, datetime) or gen_time.utcoffset() is None or gen_time.utcoffset():
            raise _malformed("genTime is not a UTC time")
        imprint = tst["message_imprint"]
        extensions = tst["extensions"]
        critical = (
            ()
            if isinstance(extensions, core.Void)
            else tuple(str(e["extn_id"].dotted) for e in extensions if e["critical"].native)
        )
        signer = _signer(signed)
        choices = signed["certificates"]
        raw_certificates = (
            []
            if isinstance(choices, core.Void)
            else [c.chosen.dump() for c in choices if c.name == "certificate"]
        )
        if len(raw_certificates) > MAX_TOKEN_CERTS:
            raise TimestampError(
                "TIMESTAMP.TOKEN.TOO_LARGE", f"the token holds more than {MAX_TOKEN_CERTS} certificates"
            )
        certificates = tuple((raw, x509.load_der_x509_certificate(raw)) for raw in raw_certificates)
        return _Token(
            gen_time=gen_time.astimezone(UTC),
            imprint_oid=str(imprint["hash_algorithm"]["algorithm"].dotted),
            imprint=_bytes(imprint["hashed_message"].native),
            critical_extensions=critical,
            content=content,
            signer=signer,
            certificates=certificates,
        )
    except TimestampError:
        raise
    except _PARSE_ERRORS as exc:
        raise _malformed(f"the token is not a DER TimeStampToken ({type(exc).__name__})") from exc


class _TimeStampResp(core.Sequence):  # type: ignore[misc]  # asn1crypto has no type information
    """RFC 3161, section 2.4.2. asn1crypto 1.5.1 declares the token as required, not OPTIONAL."""

    _fields = [  # noqa: RUF012 - the asn1crypto declaration style
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


def token_from_response(der: bytes) -> tuple[str, bytes]:
    """Return the PKI status name and the original token DER (empty if the response has none)."""
    try:
        response = _TimeStampResp.load(der, strict=True)
        status = str(response["status"]["status"].native)
        token = response["time_stamp_token"]
        return status, b"" if isinstance(token, core.Void) else bytes(token.dump())
    except _PARSE_ERRORS as exc:
        raise _malformed(f"the file is not a DER TimeStampResp ({type(exc).__name__})") from exc


def _find_signer(
    sid: tuple[bytes, int] | bytes, candidates: list[tuple[bytes, x509.Certificate]]
) -> tuple[bytes, x509.Certificate] | None:
    for raw, certificate in candidates:
        if isinstance(sid, tuple):
            try:
                issuer = certificate.issuer.public_bytes()
            except ValueError:
                continue
            if (issuer, certificate.serial_number) == sid:
                return raw, certificate
        else:
            key_id = x509path.extension_value(certificate, x509.SubjectKeyIdentifier)
            if key_id is not None and key_id.digest == sid:
                return raw, certificate
    return None


def _check_cms(token: _Token, signer: _Signer, raw: bytes, certificate: x509.Certificate) -> None:
    """Steps 6 to 8: the key profile, the signing certificate attribute, and the signature."""
    kind, signature_hash = _SIGNATURES[signer.signature_oid]
    digest = _DIGESTS[signer.digest_oid]
    try:
        key = certificate.public_key()
    except (UnsupportedAlgorithm, ValueError) as exc:
        raise TimestampError("TIMESTAMP.CMS.UNSUPPORTED", "the TSA key cannot be read") from exc
    if not (
        (kind == "rsa" and isinstance(key, rsa.RSAPublicKey) and key.key_size >= _MIN_RSA_BITS)
        or (kind == "ec" and isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, _CURVES))
    ):
        raise TimestampError("TIMESTAMP.CMS.UNSUPPORTED", "the TSA key is outside the timestamp profile")
    ess_hashes = {"1.3.14.3.2.26": "sha1", **_DIGESTS}
    if (
        signer.ess is None
        or (signer.ess[0] == _ESS_V1) != (signer.ess[1] == "1.3.14.3.2.26")
        or signer.ess[1] not in ess_hashes
        or hashlib.new(ess_hashes[signer.ess[1]], raw).digest() != signer.ess[2]
    ):
        raise TimestampError(
            "TIMESTAMP.CMS.SIGNING_CERT",
            "the signing certificate attribute does not identify the TSA certificate",
        )
    if signer.content_types != (_TST_INFO,) or signer.message_digests != (
        hashlib.new(digest, token.content).digest(),
    ):
        raise TimestampError(
            "TIMESTAMP.CMS.SIGNATURE_INVALID", "the content type or the message digest does not verify"
        )
    algorithm = _HASHES[signature_hash or digest]()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signer.signature, signer.signed_attrs, padding.PKCS1v15(), algorithm)
        else:
            key.verify(signer.signature, signer.signed_attrs, ec.ECDSA(algorithm))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TimestampError(
            "TIMESTAMP.CMS.SIGNATURE_INVALID", "the signature of the token does not verify"
        ) from exc


def _check_tsa(certificate: x509.Certificate) -> None:
    """Steps 11 and 12: time stamping as the only purpose (RFC 3161, section 2.3), and the key usage."""
    extensions = x509path.extensions(certificate)
    try:
        usage = None if extensions is None else extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        usage = None
    if usage is None or not usage.critical or set(usage.value) != {ExtendedKeyUsageOID.TIME_STAMPING}:
        raise TimestampError(
            "TIMESTAMP.TSA.EKU",
            "the TSA certificate does not have time stamping as its only critical purpose",
        )
    key_usage = x509path.extension_value(certificate, x509.KeyUsage)
    if key_usage is not None and not (key_usage.digital_signature or key_usage.content_commitment):
        raise TimestampError(
            "TIMESTAMP.TSA.KEY_USAGE", "the key usage of the TSA certificate does not permit signing"
        )


def verify_token(text: str, imprints: Collection[bytes], trust: TrustBundle, at: datetime) -> Stamp:  # noqa: PLR0912 - the ordered steps of section 11.4
    """Check one token in the order of architecture section 11.4. Raises only ``TimestampError``.

    ``imprints`` are the imprints of the signatures that verify. Only ``trust.timestamp_anchors``
    end a TSA path. The TSA certificate path is checked at ``genTime``.
    """
    # Step 1: size and decoding.
    if len(text) > MAX_TOKEN_TEXT:
        raise TimestampError(
            "TIMESTAMP.TOKEN.TOO_LARGE", f"the token is longer than {MAX_TOKEN_TEXT} characters"
        )
    try:
        der = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _malformed("the token is not standard base64") from exc
    if len(der) > MAX_TOKEN_BYTES:
        raise TimestampError("TIMESTAMP.TOKEN.TOO_LARGE", f"the token is larger than {MAX_TOKEN_BYTES} bytes")
    # Step 2: the structure, and at most five certificates.
    token = parse_token(der)
    # Step 3.
    if token.critical_extensions:
        raise TimestampError("TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION", "the TSTInfo has a critical extension")
    # Step 4: one signer, signed attributes, and algorithms of the profile.
    signer = token.signer
    if (
        signer is None
        or signer.digest_oid not in _DIGESTS
        or signer.signature_oid not in _SIGNATURES
        or _SIGNATURES[signer.signature_oid][1] not in (None, _DIGESTS[signer.digest_oid])
    ):
        raise TimestampError("TIMESTAMP.CMS.UNSUPPORTED", "the CMS signer is outside the timestamp profile")
    # Step 5: the signer certificate, from the token or from the timestamp anchors.
    anchors = [
        x509.load_pem_x509_certificate(a.certificate_pem.encode("ascii")) for a in trust.timestamp_anchors
    ]
    anchor_der = [a.public_bytes(serialization.Encoding.DER) for a in anchors]
    found = _find_signer(signer.sid, [*token.certificates, *zip(anchor_der, anchors, strict=True)])
    if found is None:
        raise TimestampError("TIMESTAMP.TSA.UNKNOWN", "no certificate matches the signer of the token")
    raw, certificate = found
    # Steps 6 to 8.
    _check_cms(token, signer, raw, certificate)
    # Steps 9 and 10.
    if token.imprint_oid != SHA256:
        raise TimestampError("TIMESTAMP.IMPRINT.ALGORITHM", "the imprint does not use SHA-256")
    if token.imprint not in imprints:
        raise TimestampError(
            "TIMESTAMP.IMPRINT.MISMATCH", "the imprint is not that of a signature that verifies"
        )
    # Steps 11 and 12.
    _check_tsa(certificate)
    # Steps 13 and 14: a pinned TSA certificate, or a path to a timestamp anchor.
    if raw in anchor_der:
        path: list[x509.Certificate] | None = [certificate]
    else:
        others = [c for r, c in token.certificates if r != raw]
        path = x509path.trust_path(certificate, others, trust.timestamp_anchors)
    if path is None:
        raise TimestampError(
            "TIMESTAMP.TSA.UNTRUSTED", "the TSA certificate has no path to a timestamp anchor"
        )
    if (gap := x509path.path_gap(path)) is not None:
        raise TimestampError("TIMESTAMP.TSA.UNSUPPORTED_CONSTRAINT", gap)
    # Steps 15 to 17, with exact instants.
    gen_time = token.gen_time
    if gen_time > at:
        raise TimestampError(
            "TIMESTAMP.TIME.FUTURE", f"genTime {format_time(gen_time)} is after the evaluation time"
        )
    if not all(c.not_valid_before_utc <= gen_time <= c.not_valid_after_utc for c in path):
        raise TimestampError(
            "TIMESTAMP.TSA.EXPIRED", f"a certificate of the TSA path is not valid at {format_time(gen_time)}"
        )
    if x509path.revoked(path, trust.revoked_certificates, gen_time):
        raise TimestampError(
            "TIMESTAMP.TSA.REVOKED", f"a certificate of the TSA path is revoked at {format_time(gen_time)}"
        )
    try:
        subject = certificate.subject.rfc4514_string()
    except ValueError:
        subject = "(a subject name that cannot be printed)"
    return Stamp(gen_time=gen_time, imprint=token.imprint, tsa_subject=subject)
