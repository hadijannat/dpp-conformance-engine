"""TEST-ONLY timestamp authority builders. Every key is generated for the test run.

The tokens are built in-process with asn1crypto and signed with cryptography. Nothing here
contacts a timestamp authority or any other host.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from asn1crypto import cms, core, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey
Pair = tuple[PrivateKey, x509.Certificate]
TIME_STAMPING = ExtendedKeyUsageOID.TIME_STAMPING
START, END = datetime(2026, 1, 1, tzinfo=UTC), datetime(2036, 1, 1, tzinfo=UTC)
_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _usage(*, digital_signature: bool, cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign,
        encipher_only=False, decipher_only=False,
    )  # fmt: skip


def tsa_ca(name: str = "TEST-ONLY TSA root", not_before: datetime = START) -> Pair:
    """A self-signed P-256 certificate authority for timestamp certificates."""
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(_name(name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_usage(digital_signature=False, cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def tsa_cert(
    ca: Pair | None,
    *,
    eku: Sequence[x509.ObjectIdentifier] | None = (TIME_STAMPING,),
    eku_critical: bool = True,
    digital_signature: bool = True,
    not_before: datetime = START,
    not_after: datetime = END,
    key: Literal["p256", "rsa", "ed25519"] = "p256",
    name: str = "TEST-ONLY TSA",
) -> Pair:
    """A timestamp certificate under ``ca``, or self-signed if ``ca`` is None. ``eku`` None: no EKU."""
    private: PrivateKey
    if key == "rsa":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key == "ed25519":
        private = ed25519.Ed25519PrivateKey.generate()
    else:
        private = ec.generate_private_key(ec.SECP256R1())
    issuer_key, issuer_name = (ca[0], ca[1].subject) if ca else (private, _name(name))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(issuer_name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_usage(digital_signature=digital_signature, cert_sign=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False)
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[0].public_key()), critical=False
        )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=eku_critical)
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return private, builder.sign(issuer_key, algorithm)


def der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _sign(key: PrivateKey, data: bytes, digest: str) -> bytes:
    algorithm = _HASHES[digest]()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(algorithm))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), algorithm)
    return key.sign(data)


def _default_signature_algorithm(key: PrivateKey, digest: str) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"{digest}_ecdsa"
    if isinstance(key, rsa.RSAPrivateKey):
        return "rsassa_pkcs1v15"
    return "ed25519"


def make_token(
    imprint: bytes,
    gen_time: datetime,
    signer: Pair,
    *,
    certs: Sequence[x509.Certificate] | None = None,
    ess: Literal["v1", "v2"] | None = "v2",
    imprint_alg: str = "sha256",
    digest: str = "sha256",
    signature_algorithm: str | None = None,
    tamper: Literal["signature", "tstinfo"] | None = None,
    critical_ext: bool = False,
    pad_to: int | None = None,
    sid: Literal["issuer_serial", "key_id"] = "issuer_serial",
) -> bytes:
    """Return a DER TimeStampToken. ``certs`` defaults to the signer certificate."""
    key, certificate = signer
    certificate_der = der(certificate)
    info: dict[str, Any] = {
        "version": "v1",
        "policy": "1.3.6.1.4.1.99999.1",  # an arbitrary TEST-ONLY policy
        "message_imprint": {"hash_algorithm": {"algorithm": imprint_alg}, "hashed_message": imprint},
        "serial_number": 1,
        "gen_time": core.GeneralizedTime(gen_time),
    }
    if critical_ext:
        info["extensions"] = [{"extn_id": "1.3.6.1.4.1.99999.2", "critical": True, "extn_value": b"\x05\x00"}]
    tst_info = tsp.TSTInfo(info)
    content = tst_info.dump()
    attributes: list[dict[str, Any]] = [
        {"type": "content_type", "values": ["tst_info"]},
        {"type": "message_digest", "values": [hashlib.new(digest, content).digest()]},
    ]
    if ess == "v2":
        cert_id = {
            "hash_algorithm": {"algorithm": "sha256"},
            "cert_hash": hashlib.sha256(certificate_der).digest(),
        }
        attributes.append({"type": "signing_certificate_v2", "values": [{"certs": [cert_id]}]})
    elif ess == "v1":
        cert_id_v1 = {"cert_hash": hashlib.sha1(certificate_der).digest()}  # noqa: S324 - the ESS v1 hash
        attributes.append({"type": "signing_certificate", "values": [{"certs": [cert_id_v1]}]})
    loaded = asn1_x509.Certificate.load(certificate_der)
    identifier: dict[str, Any]
    if sid == "key_id":
        ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        identifier = {"subject_key_identifier": ski}
    else:
        identifier = {
            "issuer_and_serial_number": {"issuer": loaded.issuer, "serial_number": loaded.serial_number}
        }
    algorithm = signature_algorithm or _default_signature_algorithm(key, digest)
    signer_info = cms.SignerInfo(
        {
            "version": "v3" if sid == "key_id" else "v1",
            "sid": identifier,
            "digest_algorithm": {"algorithm": digest},
            "signed_attrs": attributes,
            "signature_algorithm": {"algorithm": algorithm},
            "signature": b"",
        }
    )
    # Sign exactly the bytes that the token will carry: the [0] tag retagged to SET OF.
    signature = _sign(key, b"\x31" + signer_info["signed_attrs"].dump()[1:], digest)
    if tamper == "signature":
        signature = bytes([signature[0], signature[1] ^ 0x01, *signature[2:]])
    signer_info["signature"] = signature
    if tamper == "tstinfo":
        content = tsp.TSTInfo({**info, "serial_number": 2}).dump()
    choices = [asn1_x509.Certificate.load(der(c)) for c in (certs if certs is not None else [certificate])]

    def build(padding_bytes: int | None) -> bytes:
        info_copy = cms.SignerInfo.load(signer_info.dump())
        if padding_bytes is not None:
            info_copy["unsigned_attrs"] = [
                {"type": "1.3.6.1.4.1.99999.3", "values": [core.OctetString(b"\x00" * padding_bytes)]}
            ]
        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": digest}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": core.ParsableOctetString(content),
                },
                "certificates": choices,
                "signer_infos": [info_copy],
            }
        )
        token: bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
        return token

    if pad_to is None:
        return build(None)
    # Two passes: the length prefixes grow with the padding.
    size = pad_to - len(build(0))
    for _ in range(8):
        token = build(max(size, 0))
        if len(token) == pad_to:
            return token
        size += pad_to - len(token)
    raise AssertionError(f"cannot pad the token to exactly {pad_to} bytes")


class _TimeStampResp(core.Sequence):
    """RFC 3161, section 2.4.2. asn1crypto 1.5.1 declares the token as required, not OPTIONAL."""

    _fields = [  # noqa: RUF012 - the asn1crypto declaration style
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


def make_response(token: bytes | None, status: int = 0) -> bytes:
    """A DER TimeStampResp. Status 0 is granted, 1 granted with modifications, 2 rejection."""
    response: dict[str, Any] = {"status": {"status": status}}
    if token is not None:
        response["time_stamp_token"] = cms.ContentInfo.load(token)
    raw: bytes = _TimeStampResp(response).dump()
    return raw


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def break_time(token: bytes, when: datetime) -> bytes:
    """Break the UTCTime ``when`` inside a token, at the same length.

    asn1crypto carries the certificate unparsed, and cryptography cannot load it. Use a time
    that only one certificate of the token holds, outside the signer certificate.
    """
    stamp = when.strftime("%y%m%d%H%M%SZ").encode("ascii")
    assert token.count(stamp) == 1
    return token.replace(stamp, stamp[:-2] + b"ZZ")
