"""JOSE family: other serializations of the signed passport.

Synthetic behavior, after RFC 7515, section 7.2.2. With the flag ``signed_jws_json`` (B-11), the
signed route serves the flattened JWS JSON serialization of the compact token of the core. The
three members are the three parts of that token, so the token stays valid.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from dppce.infrastructure.reference.base import Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset({"signed_jws_json"})
_SIGNED_PATH: Final = re.compile(r"^/dpp/(?P<id>[0-9]{14}-[A-Za-z0-9]+)/signed$")


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if "signed_jws_json" not in system.faults or _SIGNED_PATH.match(request.path) is None:
        return None
    reply = system.handle(request.path, request.header("authorization"))
    if reply[0] != 200:
        return reply
    protected, payload, signature = reply[2].decode("ascii").split(".")
    document = {"protected": protected, "payload": payload, "signature": signature}
    return json_reply(200, document, "application/jose+json")
