"""DID family: the did:web document of the reference system.

Synthetic behavior, after W3C DID Core 1.0 and the did:web Method Specification (W3C CCG report).
The public origin of the reference system gives the DID ``did:web:id.example.test``. This module
serves its DID document at ``/.well-known/did.json`` and passes every other request on. The
document has no ``@context``, so a reader processes it as plain JSON.

The one verification method holds the public key of ``pki/TEST-ONLY-leaf.cert.pem``. The flags:

- ``did_id_mismatch`` (F-61): the id of the document is another DID.
- ``did_private_key`` (F-62): the JWK of the method also holds a synthetic private member ``d``.
- ``did_redirect_off_host`` (B-15): the path redirects to a host outside the scope of the rig.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from dppce.infrastructure.reference.base import Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset({"did_id_mismatch", "did_private_key", "did_redirect_off_host"})
DID: Final = "did:web:id.example.test"
PATH: Final = "/.well-known/did.json"
MEDIA_TYPE: Final = "application/did+json"
# The public key of fixtures/reference/pki/TEST-ONLY-leaf.cert.pem. A test pins the equality.
PUBLIC_JWK: Final = {
    "kty": "EC",
    "crv": "P-256",
    "x": "74KUCPh8WbId2ZqDOx0azhmfPgSZAI2pRYmJmy2DEeY",
    "y": "X_6VWdqoqUSDFZQ0uIbnxAfKJLpkLVYIsuPjE288zmE",
}


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if request.path != PATH:
        return None
    faults = system.faults
    if "did_redirect_off_host" in faults:
        return 302, "text/plain", b"", {"Location": "https://other.example.test" + PATH}
    jwk = dict(PUBLIC_JWK)
    if "did_private_key" in faults:
        jwk["d"] = "TEST-ONLY-synthetic-private-member"
    key = DID + "#key-1"
    document = {
        "id": "did:web:other.example.test" if "did_id_mismatch" in faults else DID,
        "verificationMethod": [{"id": key, "type": "JsonWebKey", "controller": DID, "publicKeyJwk": jwk}],
        "assertionMethod": [key],
    }
    return json_reply(200, document, MEDIA_TYPE)
