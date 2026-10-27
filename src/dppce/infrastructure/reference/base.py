"""Values that the reference system core and its family modules share."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

PUBLIC_ORIGIN: Final = "https://id.example.test"
RESOLVER_PATH: Final = re.compile(r"^/01/(?P<gtin>[0-9]{14})/21/(?P<serial>[A-Za-z0-9]+)$")

# (status, media type, body, extra headers). A 204 answer has no media type and no body.
Reply = tuple[int, str, bytes, dict[str, str]]


def json_reply(status: int, document: Any, media_type: str = "application/json") -> Reply:
    return status, media_type, json.dumps(document, sort_keys=True).encode("utf-8"), {}


@dataclass(frozen=True)
class Request:
    """One request to the reference system. Header names are in lower case."""

    method: str
    target: str
    headers: Mapping[str, str] = field(default_factory=dict)
    # Only the token request of the oauth family has a body (P2-28).
    body: bytes = b""

    @property
    def path(self) -> str:
        return urlsplit(self.target).path

    @property
    def query(self) -> str:
        return urlsplit(self.target).query

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Family(Protocol):
    """A family module. See ``dppce.infrastructure.reference`` for the contract."""

    @property
    def FLAGS(self) -> frozenset[str]: ...  # noqa: N802 - the module constant that a family exports

    def respond(self, system: ReferenceSystem, request: Request) -> Reply | None: ...
