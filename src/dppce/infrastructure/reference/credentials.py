"""Credentials family: a VC-JOSE credential for the signed passport, and its status list.

Synthetic behavior, after the W3C Recommendations "Securing Verifiable Credentials using JOSE and
COSE" and "Bitstring Status List v1.0", and RFC 7515. A request for ``/dpp/{id}/signed`` with
exactly ``Accept: application/vc+jwt`` gets a compact JWS with ``typ: vc+jwt``. Its payload is a
credential of the operator about the item passport. Its ``BitstringStatusListEntry`` names the
status list credential at ``/credentials/status/1``, a path that version 1 did not serve. Every
other request passes to the core, so the answers of version 1 stay the same. Each flag of this
module changes this credential or its status list only.

The credential and the list are signed with the TEST-ONLY leaf key of ``fixtures/reference/pki``.
The TEST-ONLY trust bundle pins its public key under the kid ``TEST-ONLY-vc-issuer-key-1`` with the
purpose ``passport``. The key signs no other credential, and it protects nothing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import TYPE_CHECKING, Any, Final

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.status import encode_list
from dppce.infrastructure.reference.base import PUBLIC_ORIGIN, Reply, Request

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset(
    {
        # F-56: the payload changes after signing.
        "vc_tampered",
        # F-57: the header names HS256, and the MAC key is the DER public key of the issuer.
        "vc_hs256_confusion",
        # F-58: a validly signed credential whose validUntil is 2026-01-01T00:00:00Z.
        "vc_expired",
        # F-59: a validly signed credential whose kid names no key of the trust bundle.
        "vc_untrusted_kid",
        # F-60: an unsecured credential with alg none and an empty signature.
        "vc_alg_none",
    }
)
MEDIA_TYPE: Final = "application/vc+jwt"
KID: Final = "TEST-ONLY-vc-issuer-key-1"
UNKNOWN_KID: Final = "TEST-ONLY-unknown-issuer-key"
ISSUER: Final = "urn:example:operator:0001"
_SIGNED_PATH: Final = re.compile(r"^/dpp/(?P<id>[0-9]{14}-[A-Za-z0-9]+)/signed$")
STATUS_PATH: Final = "/credentials/status/1"
STATUS_URL: Final = PUBLIC_ORIGIN + STATUS_PATH
# One list holds the status of every credential of the reference system at this index.
STATUS_INDEX: Final = 41267
# Ten years of 365 days: the list stays fresh from its validFrom past the key validity.
STATUS_TTL_MS: Final = 3650 * 86_400_000


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def credential(subject: str) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": ISSUER,
        "validFrom": "2026-01-01T00:00:00Z",
        "validUntil": "2036-01-01T00:00:00Z",
        "credentialSubject": {"id": subject},
        "credentialStatus": {
            "id": subject + "#status",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(STATUS_INDEX),
            "statusListCredential": STATUS_URL,
        },
    }


def status_list(revoked: bool = False, ttl_ms: int = STATUS_TTL_MS) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": STATUS_URL,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": ISSUER,
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {
            "id": STATUS_URL + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encode_list((STATUS_INDEX,) if revoked else ()),
            "ttl": ttl_ms,
        },
    }


def status_token(system: ReferenceSystem) -> str:
    signer, _ = system.signer("leaf")
    header = _b64(canonical_bytes({"alg": "ES256", "kid": KID, "typ": "vc+jwt"}))
    signing_input = f"{header}.{_b64(canonical_bytes(status_list()))}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64(signer.sign(signing_input))}"


def token(system: ReferenceSystem, subject: str) -> str:
    faults = system.faults
    signer, certificate = system.signer("leaf")
    document = credential(subject)
    if "vc_expired" in faults:
        document |= {"validFrom": "2025-01-01T00:00:00Z", "validUntil": "2026-01-01T00:00:00Z"}
    alg = "none" if "vc_alg_none" in faults else "HS256" if "vc_hs256_confusion" in faults else "ES256"
    kid = UNKNOWN_KID if "vc_untrusted_kid" in faults else KID
    header = _b64(canonical_bytes({"alg": alg, "kid": kid, "typ": "vc+jwt"}))
    signing_input = f"{header}.{_b64(canonical_bytes(document))}".encode("ascii")
    if alg == "none":
        signature = b""
    elif alg == "HS256":
        public = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        signature = hmac.new(public, signing_input, hashlib.sha256).digest()
    else:
        signature = signer.sign(signing_input)
    if "vc_tampered" in faults:
        changed = {**document, "credentialSubject": {"id": subject.rsplit("/", 1)[0] + "/OTHER0001"}}
        signing_input = f"{header}.{_b64(canonical_bytes(changed))}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64(signature)}"


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if request.path == STATUS_PATH:
        return 200, MEDIA_TYPE, status_token(system).encode("ascii"), {}
    match = _SIGNED_PATH.match(request.path)
    if match is None or request.header("accept") != MEDIA_TYPE:
        return None
    reply = system.handle(request.path, request.header("authorization"))
    if reply[0] != 200:
        return reply
    subject = system.item(match["id"], "anonymous")["id"]
    return 200, MEDIA_TYPE, token(system, subject).encode("ascii"), {}
