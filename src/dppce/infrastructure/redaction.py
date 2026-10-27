"""Keep secrets and private network details out of records.

Records are retained, hashed into commitments, and can be opened to reviewers. A secret that
reaches a record is disclosed. The rules here are default-deny: a value is recorded only when
it is known to be safe.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final, NamedTuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REMOVED: Final = "<removed>"

# Request header values that are safe to keep. Every other value is removed from the record.
SAFE_REQUEST_HEADERS: Final = frozenset(
    {"accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "user-agent"}
)
# Response header values that are safe to keep. Every other value is removed from the record.
SAFE_RESPONSE_HEADERS: Final = frozenset(
    {
        "accept-ranges", "allow", "cache-control", "content-encoding", "content-language",
        "content-length", "content-type", "date", "etag", "expires", "last-modified",
        "retry-after", "transfer-encoding", "vary",
        # CORS (OD-06). The allowed origin is a URL, so it is redacted below, not kept as sent.
        "access-control-allow-credentials", "access-control-allow-headers",
        "access-control-allow-methods", "access-control-expose-headers", "access-control-max-age",
    }
)  # fmt: skip
# These hold URLs. They are kept, with each URL redacted.
_URL_RESPONSE_HEADERS: Final = frozenset({"location", "content-location", "access-control-allow-origin"})
# A link-value of RFC 8288, section 3: a target, then parameters that are a name, name=token, or
# name=quoted-string. A token cannot hold ":" or "/", so only a quoted rel can hold an extension
# relation (an IRI, section 3.3). A quoted string can hold "," and ";". The marker REMOVED that
# redaction leaves reads as a parameter too. Only "rel", at most once, and a fixed "type" are kept.
_TARGET: Final = re.compile(r"\s*<([^<>\s]*)>\s*")
_TCHARS: Final = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PARAMETER: Final = re.compile(
    rf';\s*(?:({_TCHARS})(?:\s*=\s*({_TCHARS}|"(?:[^"\\]|\\.)*"))?|{re.escape(REMOVED)})\s*'
)
_NEXT_LINK: Final = re.compile(r",\s*")
_QUOTED_PAIR: Final = re.compile(r"\\(.)")
# Fixed media types cannot carry a secret, so a type parameter with one of them is kept.
_KEPT_TYPES: Final = frozenset({"application/linkset+json", "application/ld+json", "application/json"})
# The link types of the GS1 Web Vocabulary: each sub-property of gs1:linkType in v1.16/gs1Voc.jsonld
# of github.com/gs1/WebVoc at commit f8f407bf717233c871dca2f62f4e45b0940e8cad (Apache-2.0, read on
# 2026-10-27, SHA-256 5b417c158cca7e55766dc5e35a1fa480273f036720b6c7382d61ea6939a7ee66). The file marks
# productSustainabilityInfo as deprecated. The names are fixed, so they cannot carry a secret.
# The file is vendored in tests/vectors/gs1-webvoc/, and tests/test_external_vectors.py checks this list.
_GS1_LINK_TYPES: Final = (
    "activityIdeas", "allergenInfo", "appDownload", "backgroundInfo", "brandHomepageClinical",
    "brandHomepagePatient", "careersInfo", "certificationInfo", "consumerHandlingStorageInfo",
    "defaultLink", "defaultLinkMulti", "dpp", "eifu", "epcis", "epil", "eventsInfo", "faqs", "handledBy",
    "hasRetailers", "homepage", "ingredientsInfo", "instructions", "jws", "leaveReview", "locationInfo",
    "logisticsInfo", "loyaltyProgram", "masterData", "menuInfo", "nutritionalInfo", "openingHoursInfo",
    "paymentLink", "pip", "productSustainabilityInfo", "promotion", "purchaseSuppliesOrAccessories",
    "quickStartGuide", "recallStatus", "recipeInfo", "registerProduct", "registryEntry", "relatedImage",
    "relatedVideo", "reportFound", "review", "safetyInfo", "scheduleTime", "serviceInfo", "smartLabel",
    "smpc", "socialMedia", "statisticInfo", "subscribe", "support", "sustainabilityInfo", "traceability",
    "tutorial", "userAgreement", "verificationService", "whatsInTheBox",
)  # fmt: skip
# The two spellings of a GS1 link type: the compact gs1: form and the IRI of the vocabulary context.
_GS1_FORMS: Final = ("gs1:", "https://ref.gs1.org/voc/")
JSONLD_CONTEXT: Final = "http://www.w3.org/ns/json-ld#context"
# Registered relation names that an API uses for paging and description, linkset (RFC 9264), the
# JSON-LD context relation, and the GS1 link types. A word outside this list can be a secret, so it
# is dropped and its link gets the marker. An extension relation is compared as exact text.
_RELATIONS: Final = frozenset(
    {
        "alternate", "canonical", "collection", "describedby", "first", "help", "item", "last",
        "license", "linkset", "next", "prev", "previous", "profile", "related", "self", "service-desc",
        "service-doc", "service-meta", "type", "up", JSONLD_CONTEXT,
    }
    | {form + name for form in _GS1_FORMS for name in _GS1_LINK_TYPES}
)  # fmt: skip
_EXTENSION: Final = re.compile(r"[:/#]")

_SENSITIVE_PARAMETER: Final = re.compile(
    r"token|secret|passw|pwd|sig|key|auth|credential|session|code|jwt|bearer", re.IGNORECASE
)
# IPv6 prefixes that carry an IPv4 address. The embedded address decides where a packet goes.
_NAT64: Final = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def redact_url(url: str) -> str:
    """Return ``url`` without userinfo, without a fragment, and without the values of
    credential-like query parameters.

    A fragment is never sent to a server, and an OAuth-style redirect can carry a token in it.
    A URL with nothing to remove is returned unchanged, byte for byte.
    """
    try:
        parts = urlsplit(url)
        has_userinfo = parts.username is not None or parts.password is not None
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return REMOVED
    sensitive = any(_SENSITIVE_PARAMETER.search(name) for name, _ in pairs)
    if not has_userinfo and not sensitive and not parts.fragment and not url.endswith("#"):
        return url
    netloc = parts.netloc.rpartition("@")[2] if has_userinfo else parts.netloc
    query = (
        urlencode([(n, REMOVED if _SENSITIVE_PARAMETER.search(n) else v) for n, v in pairs])
        if sensitive
        else parts.query
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


class Link(NamedTuple):
    """One link of a ``Link`` value.

    ``media_type`` is a kept type parameter in lower case. ``other`` is true if the link has another
    parameter, such as a title, a type with another value, or the marker that redaction leaves.
    """

    target: str
    relations: tuple[str, ...]
    media_type: str | None
    other: bool


def redact_link(value: str) -> str:
    """Keep the redacted targets, the relations of the closed list, and a fixed type parameter.

    Each other parameter, and each relation outside the list, is replaced with one marker per link:
    a title or an anchor is free text that a system can fill with anything. Only a value that is not
    well-formed is removed as a whole. The output parses to the same links and redacts to itself.
    """
    links = parse_link(value)
    if links is None:
        return REMOVED
    out: list[str] = []
    for link in links:
        kept = tuple(r for r in link.relations if r in _RELATIONS)
        out.append(
            f"<{redact_url(link.target)}>"
            + (f'; rel="{" ".join(kept)}"' if kept else "")
            + (f'; type="{link.media_type}"' if link.media_type else "")
            + (f"; {REMOVED}" if link.other or len(kept) < len(link.relations) else "")
        )
    return ", ".join(out)


def parse_link(value: str) -> list[Link] | None:
    """Read a ``Link`` value as RFC 8288 link-values, or None for a value that is not well-formed.

    A value is not well-formed if a link has no target, a target that is not a URI reference, a
    parameter of another form, or a second rel. A registered relation name is case-insensitive,
    so it is given in lower case. An extension relation keeps its case.
    """
    links: list[Link] = []
    at = 0
    while True:
        found = _TARGET.match(value, at)
        if found is None or redact_url(found.group(1)) == REMOVED:
            return None
        at = found.end()
        rels: list[str] = []
        media: str | None = None
        other = False
        while (parameter := _PARAMETER.match(value, at)) is not None:
            at = parameter.end()
            name, raw = (parameter.group(1) or "").lower(), parameter.group(2) or ""
            text = _QUOTED_PAIR.sub(r"\1", raw[1:-1]) if raw.startswith('"') else raw
            if name == "rel":
                rels.append(text)
            elif name == "type" and media is None and text.lower() in _KEPT_TYPES:
                media = text.lower()
            else:
                other = True
        if len(rels) > 1:
            return None
        words = rels[0].split() if rels else []
        relations = tuple(w if _EXTENSION.search(w) else w.lower() for w in words)
        links.append(Link(found.group(1), relations, media, other))
        if at == len(value):
            return links
        separator = _NEXT_LINK.match(value, at)
        if separator is None:
            return None
        at = separator.end()


def redact_request_headers(headers: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple((k, v if k.lower() in SAFE_REQUEST_HEADERS else REMOVED) for k, v in sorted(headers.items()))


def redact_response_headers(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Keep the names. Keep a value only if its name is known to be safe."""
    out: list[tuple[str, str]] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in SAFE_RESPONSE_HEADERS:
            out.append((name, value))
        elif lowered in _URL_RESPONSE_HEADERS:
            out.append((name, redact_url(value)))
        elif lowered == "link":
            out.append((name, redact_link(value)))
        else:
            out.append((name, REMOVED))
    return tuple(out)


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address that a translation or tunnel prefix carries, if any."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if any(ip in network for network in _NAT64):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _routable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # ``is_global`` alone is not enough: it is true for multicast addresses such as 224.0.0.1.
    return ip.is_global and not (
        ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    )


def is_public_address(address: str) -> bool:
    """True only if the address, and any IPv4 address embedded in it, is a public unicast address.

    A NAT64, 6to4, Teredo, or IPv4-mapped address can look global while it leads to a private
    IPv4 address. Both layers must be public. In practice a NAT64, 6to4, or Teredo address is
    always refused, because the prefix itself is not public unicast space. A system that is
    reachable only through such a prefix needs an entry in ``allow_private_hosts``.
    """
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            # An IPv4-mapped address is the IPv4 address. The other prefixes must be public too.
            return _routable(embedded) and (ip.ipv4_mapped is not None or _routable(ip))
    return _routable(ip)
