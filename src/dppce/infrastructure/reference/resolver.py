"""Resolver family: the GS1 Digital Link resolver surface of the reference system.

Synthetic behavior, after RFC 9110 (negotiation), RFC 9264 (linkset), and the GS1 Conformant
Resolver standard. The core answers a default resolver request with a 303 to the passport.
This module adds:

- a linkset for ``?linkType=linkset`` or ``?linkType=all``, or for an ``Accept`` header that
  prefers ``application/linkset+json``, with ``Vary: Accept``;
- the description file ``/.well-known/gs1resolver``;
- under the flags ``negotiation_no_vary`` and ``negotiation_wrong_type``, an HTML page for the
  resolver path, chosen by the ``Accept`` header (F-72, F-73).

Every other request passes to the core, so the core answer stays the same byte for byte. The
engine transport sends ``Accept: */*``, which selects the linkset only under the flag
``resolver_linkset_as_passport``. The passport is the
only link, so every other ``linkType`` gets the core redirect.

The other flags of this module change the linkset, the description file, or the answer for an
unknown identifier. The flag ``resolver_rate_limited`` answers each default request with 429
(B-20). The flag ``resolver_linkset_link_broken`` adds a Link header to each linkset answer that
advertises a linkset of another identifier (F-76). Each answer without one of these flags stays
the same.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qs, urljoin

from dppce.infrastructure.reference.base import PUBLIC_ORIGIN, RESOLVER_PATH, Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset(
    {
        # B-10: the default request gets the linkset, as if the linkset were the passport.
        "resolver_linkset_as_passport",
        # F-48 to F-50: the linkset has a wrong shape, a wrong relation, or a wrong anchor.
        "resolver_linkset_invalid",
        "resolver_linkset_no_dpp",
        "resolver_linkset_anchor_mismatch",
        # F-51 and B-14: the description file names another root, or its path redirects.
        "wellknown_wrong_root",
        "wellknown_redirect",
        # F-52: an identifier that the resolver does not know, a wrong check digit included, gets 200.
        "resolver_200_for_invalid",
        # F-72: an HTML page for an Accept that prefers text/html, and no Vary header.
        "negotiation_no_vary",
        # F-73: the HTML page, with Vary, also for an Accept that prefers application/json.
        "negotiation_wrong_type",
        # B-20: the default request gets 429 with Retry-After 1, every time.
        "resolver_rate_limited",
        # F-76: a Link header of each linkset answer advertises a linkset of another identifier.
        "resolver_linkset_link_broken",
    }
)
# The query of the linkset that the flag resolver_linkset_link_broken advertises.
ADVERTISED_QUERY: Final = "linkType=linkset&view=advertised"
LINKSET: Final = "application/linkset+json"
# A synthetic relation type in the reserved example domain. It is not a GS1 link type.
PASSPORT_RELATION: Final = "https://dppce.example.test/rel/passport"
OTHER_RELATION: Final = "https://dppce.example.test/rel/other"
WELL_KNOWN: Final = "/.well-known/gs1resolver"
# Where the flag wellknown_redirect moves the description file.
MOVED_DESCRIPTION: Final = "/resolver-description.json"
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


def _weights(accept: str | None) -> dict[str, float]:
    weights: dict[str, float] = {}
    for item in (accept or "").split(","):
        media_range, *parameters = item.split(";")
        if media_range.strip():
            weights[media_range.strip().lower()] = _quality(parameters)
    return weights


HTML_PAGE: Final = (
    b"<!doctype html><html><head><title>Passport</title></head><body><p>Passport</p></body></html>\n"
)


def _negotiated(system: ReferenceSystem, request: Request) -> Reply | None:
    """The HTML page of the negotiation faults, or None where the core answers."""
    faults = system.faults & {"negotiation_no_vary", "negotiation_wrong_type"}
    if not faults or RESOLVER_PATH.match(request.path) is None:
        return None
    weights = _weights(request.header("accept"))
    html, json = weights.get("text/html", 0.0), weights.get("application/json", 0.0)
    # F-73 answers text/html where application/json is wanted. F-72 answers it only where HTML wins.
    if not (html > json or ("negotiation_wrong_type" in faults and json > 0)):
        return None
    vary = {} if "negotiation_no_vary" in faults else {"Vary": "Accept"}
    return 200, "text/html; charset=utf-8", HTML_PAGE, vary


def linkset(anchor: str, passport: str, faults: frozenset[str] = frozenset()) -> bytes:
    """An RFC 9264 linkset with one link from the identifier to the passport."""
    if "resolver_linkset_anchor_mismatch" in faults:
        # Another serial: the linkset describes a different item.
        anchor = anchor.rpartition("/")[0] + "/OTHER0001"
    relation = OTHER_RELATION if "resolver_linkset_no_dpp" in faults else PASSPORT_RELATION
    context = {"anchor": anchor, relation: [{"href": passport, "type": "application/json"}]}
    # The flag resolver_linkset_invalid gives the context object itself, not a list of them.
    document = {"linkset": context if "resolver_linkset_invalid" in faults else [context]}
    return json_reply(200, document)[2]


def _description(system: ReferenceSystem, request: Request) -> Reply | None:
    faults = system.faults
    if request.path == WELL_KNOWN and "wellknown_redirect" in faults:
        return 301, "text/plain", b"", {"Location": MOVED_DESCRIPTION}
    if request.path == WELL_KNOWN or (request.path == MOVED_DESCRIPTION and "wellknown_redirect" in faults):
        if "wellknown_wrong_root" in faults:
            return json_reply(200, {**DESCRIPTION, "resolverRoot": "https://other.example.test"})
        return json_reply(200, DESCRIPTION)
    return None


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if (description := _description(system, request)) is not None:
        return description
    if "resolver_200_for_invalid" in system.faults and RESOLVER_PATH.match(request.path) is not None:
        reply = system.handle(request.path, request.header("authorization"))
        if reply[0] == 404:
            return json_reply(200, {"status": "ok"})
    if (page := _negotiated(system, request)) is not None:
        return page
    link_type = (parse_qs(request.query).get("linkType") or [""])[0]
    default = not link_type and not prefers_linkset(request.header("accept"))
    if "resolver_rate_limited" in system.faults and default and RESOLVER_PATH.match(request.path):
        # B-20: every default request is rate limited, also the one retry after Retry-After.
        return 429, "text/plain", b"", {"Retry-After": "1"}
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
    faults = system.faults
    extra: dict[str, str] = {}
    if "resolver_linkset_link_broken" in faults:
        extra = {"Link": f'<{request.path}?{ADVERTISED_QUERY}>; rel="linkset"'}
        if request.query == ADVERTISED_QUERY:
            faults = faults | {"resolver_linkset_anchor_mismatch"}
    body = linkset(anchor, urljoin(anchor, headers["Location"]), faults)
    return 200, LINKSET, body, {"Vary": "Accept", **extra}
