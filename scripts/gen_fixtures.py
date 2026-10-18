"""Write the synthetic fixtures of the reference system into ``fixtures/reference``.

Specification: docs/reference/reference-system.md, section 7.

Keys and tokens are random, so the generated files are committed. Run this script again only
to rotate them. Every key, certificate, and token here is a test value: its file name starts
with ``TEST-ONLY-``. None of them protects anything.

Needs the ``qr`` extra (zxing-cpp and Pillow) for the QR images.

``--degraded-qr-only`` writes only the degraded QR images in ``qr/degraded``. They have no
randomness, so this option rotates no key.

``--fault-qr-only`` writes only the QR images of faults F-30 and F-31 in ``qr``. They have no
randomness, so this option rotates no key.

``--add-manual-key`` adds the key ``TEST-ONLY-manual-key-1`` (trust purpose ``manual``) to the
existing trust bundle and writes its private key. It rotates no other key.
"""

from __future__ import annotations

import io
import json
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
import zxingcpp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from PIL import Image, ImageDraw, ImageFilter

from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import issue_authorization
from dppce.models import Authorization, TrustAnchor, TrustBundle, TrustedKey

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "reference"
PUBLIC_ORIGIN = "https://id.example.test"
LOCAL_ORIGIN = "http://127.0.0.1:8765"
GTIN = "09506000134352"
SUT = "urn:example:sut:reference-dpp"
OPERATOR = "urn:example:operator:0001"
LAB = "urn:example:test-lab"
VALID_FROM, VALID_TO = "2026-01-01T00:00:00Z", "2036-01-01T00:00:00Z"
# The key identifier names no person. A laboratory maps it to the performer in its own records.
MANUAL_KID = "TEST-ONLY-manual-key-1"

# profile -> (serial, rated Wh, remaining Wh, nominal V, mass kg)
ITEMS = {
    "ev": ("EV0001", 75000, 74000, 400, 450),
    "lmt": ("LMT0001", 500, 495, 36, 3),
    "industrial": ("IND0001", 5000, 4900, 48, 60),
}
CONTEXT = ["https://dppce.example.test/contexts/battery/v1"]


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


def _json(path: Path, document: Any) -> None:
    _write(path, json.dumps(document, indent=2, sort_keys=True) + "\n")


def _yaml(path: Path, document: Any, comment: str) -> None:
    _write(path, f"# {comment}\n" + yaml.safe_dump(document, sort_keys=False))


def _documents() -> None:
    for name, (serial, rated, remaining, voltage, mass) in ITEMS.items():
        identifier = f"{PUBLIC_ORIGIN}/01/{GTIN}/21/{serial}"
        _json(
            OUT / "items" / f"{name}.json",
            {
                "@context": CONTEXT,
                "id": identifier,
                "type": "BatteryPassport",
                "granularity": "item",
                "model": f"{PUBLIC_ORIGIN}/01/{GTIN}",
                "category": name,
                "operator": {"name": "Example Battery Works (synthetic)", "identifier": OPERATOR},
                "manufactured": "2027-03-01",
                "rated_capacity": {"value": rated, "unit": "Wh"},
                "remaining_capacity": {"value": remaining, "unit": "Wh"},
                "state_of_health_percent": 99,
                "status": "original",
                "version": 3,
                "updated_at": "2026-10-10T08:00:00Z",
            },
        )
        _json(
            OUT / "models" / f"{name}.json",
            {
                "@context": CONTEXT,
                "id": f"{PUBLIC_ORIGIN}/01/{GTIN}",
                "type": "BatteryModel",
                "granularity": "model",
                "category": name,
                "chemistry": "synthetic-chemistry-a",
                "nominal_voltage": {"value": voltage, "unit": "V"},
                "mass": {"value": mass, "unit": "kg"},
            },
        )
        _yaml(
            OUT / f"{name}.ics.yaml",
            {
                "schema_version": "dppce.ics/1",
                "sut": {
                    "name": "dppce reference DPP system (synthetic)",
                    "version": "1",
                    "operator": "Example Battery Works (synthetic)",
                    "identifier": SUT,
                },
                "profile": f"battery/{name}",
                "product_category": name,
                "granularity": "item",
                "identifier_scheme": "gs1-digital-link",
                "carriers": ["qr"],
                "api": {"version": "1", "contract": "battery/reference-api"},
                "access": {
                    "tiers": ["anonymous", "legitimate_interest", "authority"],
                    "policy": "battery/reference-policy",
                },
                "signature_format": "jws",
                "characteristics": {
                    "capacity_wh": rated,
                    "placed_on_market_date": "2027-03-01",
                    "put_into_service_date": "unknown",
                    "mass_g": mass * 1000,
                    "external_storage_only": False,
                },
                "features": {"item_data": True, "aas": False},
            },
            "Synthetic declaration for the reference system. Generated by scripts/gen_fixtures.py.",
        )
        _yaml(
            OUT / f"{name}.ixit.yaml",
            {
                "schema_version": "dppce.ixit/1",
                "endpoints": {
                    "api": PUBLIC_ORIGIN,
                    "registry": PUBLIC_ORIGIN,
                    "public_origin": PUBLIC_ORIGIN,
                    "origin_override": LOCAL_ORIGIN,
                },
                "samples": {
                    "qr_image": f"qr/{name}.png",
                    "identifier": identifier,
                    "passport_id": f"{GTIN}-{serial}",
                },
                # The URL layout of the reference system. A real system declares its own.
                "resources": {
                    "item": {"endpoint": "api", "path": "/dpp/{id}"},
                    "model": {"endpoint": "api", "path": "/dpp/{id}/model"},
                    "signed": {"endpoint": "api", "path": "/dpp/{id}/signed"},
                    "versions": {"endpoint": "api", "path": "/dpp/{id}/versions"},
                    "registry_record": {"endpoint": "registry", "path": "/registry/{id}"},
                },
                "id_parts": {"separator": "-", "names": ["gtin", "serial"]},
                "identities": [
                    {"role": "anonymous"},
                    {"role": "legitimate_interest", "secret_ref": "file:TEST-ONLY-legitimate_interest.token"},
                    {"role": "authority", "secret_ref": "file:TEST-ONLY-authority.token"},
                ],
                "authorization_ref": "authorization/TEST-ONLY-authorization.jws",
                "network": {
                    "allowed_hosts": ["127.0.0.1"],
                    "allow_private_hosts": ["127.0.0.1"],
                    "max_requests": 100,
                    "contact": "reference-rig@example.test",
                },
                "trust": {"policy_version": "TEST-ONLY-reference-1"},
                "observation": {"retention_days": 30},
            },
            "Synthetic test information for the reference rig. Generated by scripts/gen_fixtures.py.",
        )
        _qr(OUT / "qr" / f"{name}.png", identifier)
    _qr(OUT / "qr" / "invalid.png", "this text is not a URL")


def _qr_image(
    text: str, scale: int = 6, fmt: zxingcpp.BarcodeFormat = zxingcpp.BarcodeFormat.QRCode
) -> Image.Image:
    return Image.fromarray(zxingcpp.write_barcode_to_image(zxingcpp.create_barcode(text, fmt), scale=scale))


def _qr(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _qr_image(text).save(path, format="PNG", optimize=True)


def _fault_qr() -> None:
    """Write the QR images of faults F-30 and F-31. No randomness, so no key rotates."""
    serial = ITEMS["ev"][0]
    _qr(OUT / "qr" / "TEST-ONLY-wrong-shape.png", f"{PUBLIC_ORIGIN}/01/9506000134352/21/{serial}")
    arabic_indic = GTIN.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
    _qr(OUT / "qr" / "TEST-ONLY-non-ascii-digits.png", f"{PUBLIC_ORIGIN}/01/{arabic_indic}/21/{serial}")


def _blot(image: Image.Image, box: tuple[int, int, int, int], fill: int) -> Image.Image:
    copy = image.copy()
    ImageDraw.Draw(copy).rectangle(box, fill=fill)
    return copy


def _degraded_qr() -> None:
    """Write TEST-ONLY degraded QR images. Their expected outcomes are in qr/degraded/expected.json.

    No randomness: the same library versions give the same images.
    """
    out = OUT / "qr" / "degraded"
    out.mkdir(parents=True, exist_ok=True)
    text = f"{PUBLIC_ORIGIN}/01/{GTIN}/21/{ITEMS['ev'][0]}"
    clean, tiny = _qr_image(text), _qr_image(text, scale=1)
    side, gap = clean.width, 24
    pair = Image.new("L", (2 * side + gap, side), 255)
    pair.paste(clean, (0, 0))
    pair.paste(_qr_image(f"{PUBLIC_ORIGIN}/01/{GTIN}/21/EV0002"), (side + gap, 0))
    right = side + gap  # left edge of the second symbol
    # A readable symbol of another format next to the QR also means the image is not one QR.
    qr_and_micro = Image.new("L", pair.size, 255)
    qr_and_micro.paste(clean, (0, 0))
    qr_and_micro.paste(_qr_image("EV0002", fmt=zxingcpp.BarcodeFormat.MicroQRCode), (right, 0))

    def part(percent: int) -> int:
        return side * percent // 100

    images = {
        "blur-mild": clean.filter(ImageFilter.GaussianBlur(1)),
        "blur-heavy": clean.filter(ImageFilter.GaussianBlur(6)),
        "rotated-30": clean.rotate(30, Image.Resampling.BICUBIC, expand=True, fillcolor=255),
        "contrast-reduced": clean.point(lambda v: 64 if v < 128 else 192),
        "contrast-very-low": clean.point(lambda v: 124 if v < 128 else 132),
        "occluded-small": _blot(clean, (part(40), part(40), part(50), part(50)), 0),
        "occluded-large": _blot(clean, (part(30), part(30), part(70), part(70)), 0),
        "module-1px": tiny,
        "module-half-px": tiny.resize((tiny.width // 2, tiny.height // 2), Image.Resampling.BOX),
        "two-symbols": pair,
        "two-symbols-one-finder-wiped": _blot(pair, (right, 0, right + part(35), part(35)), 255),
        "two-symbols-one-blotted": _blot(pair, (right + part(30), part(30), right + part(70), part(70)), 0),
        "two-symbols-qr-and-micro-qr": qr_and_micro,
    }
    for name, image in images.items():
        image.save(out / f"TEST-ONLY-{name}.png", format="PNG", optimize=True)
    whole = io.BytesIO()
    clean.save(whole, format="PNG", optimize=True)
    _write(out / "TEST-ONLY-truncated.png", whole.getvalue()[: len(whole.getvalue()) // 2])


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(  # noqa: PLR0917 - mirrors the fields of a certificate
    subject: str,
    public_key: ec.EllipticCurvePublicKey,
    issuer: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    not_before: datetime,
    not_after: datetime,
    *,
    ca: bool,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                key_cert_sign=ca,
                crl_sign=ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _pki() -> x509.Certificate:
    """Write the fixture PKI and return the trusted root certificate."""
    pki = OUT / "pki"
    start, end = datetime(2026, 1, 1, tzinfo=UTC), datetime(2036, 1, 1, tzinfo=UTC)
    roots: dict[str, tuple[ec.EllipticCurvePrivateKey, x509.Certificate]] = {}
    for label in ("root", "untrusted-root"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = f"TEST-ONLY dppce reference {label}"
        roots[label] = (key, _certificate(subject, key.public_key(), subject, key, start, end, ca=True))
        _write(pki / f"TEST-ONLY-{label}.cert.pem", roots[label][1].public_bytes(serialization.Encoding.PEM))
    leaves = {
        "leaf": ("root", start, end),
        "expired-leaf": ("root", datetime(2025, 1, 1, tzinfo=UTC), datetime(2025, 12, 31, tzinfo=UTC)),
        "untrusted-leaf": ("untrusted-root", start, end),
    }
    for label, (parent, not_before, not_after) in leaves.items():
        key = ec.generate_private_key(ec.SECP256R1())
        parent_key, parent_certificate = roots[parent]
        issuer = parent_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        certificate = _certificate(
            f"TEST-ONLY dppce reference {label}",
            key.public_key(),
            str(issuer),
            parent_key,
            not_before,
            not_after,
            ca=False,
        )
        _write(pki / f"TEST-ONLY-{label}.key.pem", _pem(key))
        _write(pki / f"TEST-ONLY-{label}.cert.pem", certificate.public_bytes(serialization.Encoding.PEM))
    return roots["root"][1]


def _trust_and_authorization(root: x509.Certificate) -> None:
    report = LocalSigner.generate("TEST-ONLY-report-key-1")
    owner = LocalSigner.generate("TEST-ONLY-owner-key-1")
    manual, manual_key = _manual_key()
    _write(OUT / "trust" / "TEST-ONLY-report-signing.key.pem", report.to_pem())
    _write(OUT / "authorization" / "TEST-ONLY-owner.key.pem", owner.to_pem())
    _write(OUT / "trust" / "TEST-ONLY-manual-signing.key.pem", manual.to_pem())
    bundle = TrustBundle(
        schema_version="dppce.trust/2",
        policy_version="TEST-ONLY-reference-1",
        keys=(
            TrustedKey(
                kid=report.key_id, issuer=LAB, purposes=("report",), public_jwk=report.public_jwk(),
                not_before=VALID_FROM, not_after=VALID_TO,
            ),
            TrustedKey(
                kid=owner.key_id, issuer=OPERATOR, purposes=("authorization",), public_jwk=owner.public_jwk(),
                not_before=VALID_FROM, not_after=VALID_TO,
            ),
            manual_key,
        ),
        anchors=(
            TrustAnchor(
                name="TEST-ONLY dppce reference root",
                certificate_pem=root.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            ),
        ),
    )  # fmt: skip
    _write(OUT / "trust" / "TEST-ONLY-trust-bundle.json", bundle.model_dump_json(indent=2) + "\n")
    authorization = Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-authorization-1",
        issuer=OPERATOR,
        subject=LAB,
        sut_identifier=SUT,
        endpoints=(LOCAL_ORIGIN,),
        methods=("GET",),
        roles=("anonymous", "legitimate_interest", "authority"),
        scopes=("read", "access_probe"),
        not_before=VALID_FROM,
        not_after=VALID_TO,
        max_requests=1000,
    )
    _write(
        OUT / "authorization" / "TEST-ONLY-authorization.jws",
        issue_authorization(authorization, owner) + "\n",
    )


def _manual_key() -> tuple[LocalSigner, TrustedKey]:
    """A TEST-ONLY key of a person who signs manual results for the synthetic reference system."""
    signer = LocalSigner.generate(MANUAL_KID)
    key = TrustedKey(
        kid=signer.key_id, issuer=LAB, purposes=("manual",), public_jwk=signer.public_jwk(),
        not_before=VALID_FROM, not_after=VALID_TO,
    )  # fmt: skip
    return signer, key


def _add_manual_key() -> None:
    """Append the manual key to the existing bundle. No other key rotates."""
    path = OUT / "trust" / "TEST-ONLY-trust-bundle.json"
    bundle = TrustBundle.model_validate_json(path.read_bytes())
    if any(k.kid == MANUAL_KID for k in bundle.keys):
        raise SystemExit(f"{path} already holds the key {MANUAL_KID}")
    signer, key = _manual_key()
    _write(OUT / "trust" / "TEST-ONLY-manual-signing.key.pem", signer.to_pem())
    bundle = bundle.model_copy(update={"keys": (*bundle.keys, key)})
    _write(path, bundle.model_dump_json(indent=2) + "\n")


def _roles() -> None:
    tokens = {role: f"TEST-ONLY-{secrets.token_urlsafe(18)}" for role in ("legitimate_interest", "authority")}
    _json(OUT / "roles.json", {"tokens": {token: role for role, token in tokens.items()}})
    for role, token in tokens.items():
        _write(OUT / "secrets" / f"TEST-ONLY-{role}.token", token + "\n")


def main() -> None:
    if sys.argv[1:] == ["--add-manual-key"]:
        _add_manual_key()
        print(f"added {MANUAL_KID} to {OUT / 'trust' / 'TEST-ONLY-trust-bundle.json'}")
        return
    if sys.argv[1:] == ["--fault-qr-only"]:
        _fault_qr()
        print(f"wrote fault QR images to {OUT / 'qr'}")
        return
    _degraded_qr()
    if sys.argv[1:] == ["--degraded-qr-only"]:
        print(f"wrote degraded QR images to {OUT / 'qr' / 'degraded'}")
        return
    _fault_qr()
    _documents()
    _roles()
    _trust_and_authorization(_pki())
    print(f"wrote fixtures to {OUT}")


if __name__ == "__main__":
    main()
