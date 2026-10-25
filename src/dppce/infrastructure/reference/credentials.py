"""Credentials family: a VC-JOSE credential for the signed passport.

Synthetic behavior, after the W3C Recommendation "Securing Verifiable Credentials using JOSE and
COSE" and RFC 7515. A request for ``/dpp/{id}/signed`` with exactly ``Accept: application/vc+jwt``
gets a compact JWS with ``typ: vc+jwt``. Its payload is a credential of the operator about the
item passport. Every other request passes to the core, so the answers of version 1 stay the same.

The credential is signed with the TEST-ONLY leaf key of ``fixtures/reference/pki``. The TEST-ONLY
trust bundle pins its public key under the kid ``TEST-ONLY-vc-issuer-key-1`` with the purpose
``passport``. The key signs no other credential, and it protects nothing.
"""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING, Any, Final

from dppce.evidence.canonical import canonical_bytes
from dppce.infrastructure.reference.base import Reply, Request

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final[frozenset[str]] = frozenset()
MEDIA_TYPE: Final = "application/vc+jwt"
KID: Final = "TEST-ONLY-vc-issuer-key-1"
ISSUER: Final = "urn:example:operator:0001"
_SIGNED_PATH: Final = re.compile(r"^/dpp/(?P<id>[0-9]{14}-[A-Za-z0-9]+)/signed$")


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
    }


def token(system: ReferenceSystem, subject: str) -> str:
    # ponytail: the core holds the TEST-ONLY leaf key. ReferenceSystem keeps no fixtures path.
    signer = system._signers["leaf"][0]
    header = canonical_bytes({"alg": "ES256", "kid": KID, "typ": "vc+jwt"})
    signing_input = f"{_b64(header)}.{_b64(canonical_bytes(credential(subject)))}"
    return f"{signing_input}.{_b64(signer.sign(signing_input.encode('ascii')))}"


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    match = _SIGNED_PATH.match(request.path)
    if match is None or request.header("accept") != MEDIA_TYPE:
        return None
    reply = system.handle(request.path, request.header("authorization"))
    if reply[0] != 200:
        return reply
    subject = system.item(match["id"], "anonymous")["id"]
    return 200, MEDIA_TYPE, token(system, subject).encode("ascii"), {}
