"""Resolver family: the GS1 Digital Link resolver surface of the reference system.

Synthetic behavior, after RFC 9110 (negotiation), RFC 9264 (linkset), and the GS1 Conformant
Resolver standard. The core answers a default resolver request with a 303 to the passport.
This module adds:

- a linkset for ``?linkType=linkset`` or ``?linkType=all``, or for an ``Accept`` header that
  prefers ``application/linkset+json``, with ``Vary: Accept``;
- the description file ``/.well-known/gs1resolver``.

Every other request passes to the core, so the core answer stays the same byte for byte. The
engine transport sends ``Accept: */*``, which selects the linkset only under the flag
``resolver_linkset_as_passport``. The passport is the
only link, so every other ``linkType`` gets the core redirect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qs, urljoin

from dppce.infrastructure.reference.base import PUBLIC_ORIGIN, RESOLVER_PATH, Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

# B-10: the default request gets the linkset, as if the linkset were the passport.
FLAGS: Final = frozenset({"resolver_linkset_as_passport"})
LINKSET: Final = "application/linkset+json"
# A synthetic relation type in the reserved example domain. It is not a GS1 link type.
PASSPORT_RELATION: Final = "https://dppce.example.test/rel/passport"
WELL_KNOWN: Final = "/.well-known/gs1resolver"
# Field names as in the description file of the GS1 Resolver Community Edition (Apache-2.0,
# github.com/gs1/GS1_DigitalLink_Resolver_CE at bf885fd). The values are synthetic.
DESCRIPTION: Final = {
    "name": "dppce synthetic reference resolver",
    "resolverRoot": PUBLIC_ORIGIN,
    "supportedPrimaryKeys": ["01"],
    "supportedLinkType": [{"namespace": "https://dppce.example.test/rel/", "prefix": "dppce:"}],
}


def _quality(parameters: list[str]) -> float:
    for parameter in parameters:
        name, _, value = parameter.strip().partition("=")
        if name.strip().lower() == "q":
            try:
                return float(value)
            except ValueError:
                return 0.0
    return 1.0


def prefers_linkset(accept: str | None) -> bool:
    """True if ``accept`` lists the linkset type with a weight no lower than any other range."""
    weights: dict[str, float] = {}
    for item in (accept or "").split(","):
        media_range, *parameters = item.split(";")
        if media_range.strip():
            weights[media_range.strip().lower()] = _quality(parameters)
    linkset = weights.pop(LINKSET, 0.0)
    return linkset > 0 and linkset >= max(weights.values(), default=0.0)


def linkset(anchor: str, passport: str) -> bytes:
    """An RFC 9264 linkset with one link from the identifier to the passport."""
    document = {
        "linkset": [{"anchor": anchor, PASSPORT_RELATION: [{"href": passport, "type": "application/json"}]}]
    }
    return json_reply(200, document)[2]


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if request.path == WELL_KNOWN:
        return json_reply(200, DESCRIPTION)
    link_type = (parse_qs(request.query).get("linkType") or [""])[0]
    wanted = (
        link_type in ("linkset", "all")
        or prefers_linkset(request.header("accept"))
        or "resolver_linkset_as_passport" in system.faults
    )
    if RESOLVER_PATH.match(request.path) is None or not wanted:
        return None
    reply = system.handle(request.path, request.header("authorization"))
    status, _, _, headers = reply
    if status != 303:
        # A seeded resolver fault applies to the linkset request too.
        return reply
    anchor = PUBLIC_ORIGIN + request.path
    return 200, LINKSET, linkset(anchor, urljoin(anchor, headers["Location"])), {"Vary": "Accept"}
