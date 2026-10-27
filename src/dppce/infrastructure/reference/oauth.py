"""OAuth family: a token endpoint for the OAuth 2.0 client credentials grant.

Synthetic behavior, after RFC 6749, sections 2.3.1, 4.4, and 5. ``POST /oauth/token`` with
HTTP Basic client authentication and the form body ``grant_type=client_credentials`` issues the
TEST-ONLY bearer token of the role ``legitimate_interest`` from ``fixtures/reference/roles.json``.
The core accepts that token for that role. This is the one ``POST`` route of the reference
system. It changes no state: each request gets the same answer.

The client id and the client secret are TEST-ONLY values. The files
``fixtures/reference/secrets/TEST-ONLY-oauth-client-id`` and ``TEST-ONLY-oauth-client-secret``
hold them for a run. The flags:

- ``oauth_token_wrong_role`` (F-83): the endpoint issues the token of the role ``authority``.
- ``oauth_token_refused`` (B-21): the endpoint answers 401 with ``invalid_client``.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qs, unquote

from dppce.infrastructure.reference.base import Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset({"oauth_token_wrong_role", "oauth_token_refused"})
PATH: Final = "/oauth/token"
CLIENT_ID: Final = "TEST-ONLY-oauth-client-1"
CLIENT_SECRET: Final = "TEST-ONLY-oauth-secret-Qm7wZr4tLx9c"  # noqa: S105 - a TEST-ONLY fixture value
ROLE: Final = "legitimate_interest"
WRONG_ROLE: Final = "authority"
# The tokens of fixtures/reference/roles.json for ROLE and WRONG_ROLE. A test pins the equality.
ROLE_TOKEN: Final = "TEST-ONLY-UkcCFpq7E6jJFGj3QMhcqf25"  # noqa: S105 - a TEST-ONLY fixture value
WRONG_ROLE_TOKEN: Final = "TEST-ONLY-KLZ9STnwJZ4GqzEvoyb7z4BE"  # noqa: S105 - a TEST-ONLY fixture value
_NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error(status: int, code: str) -> Reply:
    reply = json_reply(status, {"error": code})
    headers = {**_NO_STORE, **({"WWW-Authenticate": 'Basic realm="reference"'} if status == 401 else {})}
    return reply[0], reply[1], reply[2], headers


def _client_ok(authorization: str | None) -> bool:
    scheme, _, value = (authorization or "").partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        pair = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    client_id, separator, secret = pair.partition(":")
    expected = f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    given = f"{unquote(client_id)}:{unquote(secret)}".encode()
    return bool(separator) and hmac.compare_digest(given, expected)


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    """The answer to a token request, or None for any other request."""
    if request.method != "POST" or request.path != PATH:
        return None
    if "oauth_token_refused" in system.faults or not _client_ok(request.header("authorization")):
        return _error(401, "invalid_client")
    media_type = (request.header("content-type") or "").split(";")[0].strip().lower()
    form = parse_qs(request.body.decode("ascii", "replace"))
    if media_type != "application/x-www-form-urlencoded" or form.get("grant_type") != ["client_credentials"]:
        return _error(400, "unsupported_grant_type")
    token = WRONG_ROLE_TOKEN if "oauth_token_wrong_role" in system.faults else ROLE_TOKEN
    reply = json_reply(200, {"access_token": token, "token_type": "Bearer", "expires_in": 300})
    return reply[0], reply[1], reply[2], dict(_NO_STORE)
