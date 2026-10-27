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
# Link values are read as RFC 8288, appendix B, reads them: a target in "<" and ">", then parameters
# after ";". A value is a quoted string (a "," or ";" in it does not split) or the text up to the
# next ";" or ",". Reading stops where a link-value does not start with a target; the links before
# that point count. The marker REMOVED that redaction leaves reads as a parameter name.
_OWS: Final = re.compile(r"[ \t]*")
_SEPARATORS: Final = re.compile(r"[ \t,]*")
_PARAMETER: Final = re.compile(
    r";[ \t]*(?P<name>[^ \t=;,]*)[ \t]*"
    r'(?:=[ \t]*(?:"(?P<quoted>(?:[^"\\]|\\.)*)"?|(?P<token>[^;,]*)))?'
)
_QUOTED_PAIR: Final = re.compile(r"\\(.)")
# A target that is not a URI reference is recorded as this marker, so its free text never reaches a record.
_TARGET_REMOVED: Final = "%3Cremoved%3E"
# RFC 3986, section 2: unreserved and reserved characters, and "%" only before two hex digits.
_URI_REFERENCE: Final = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
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
# is dropped and its link gets the marker. RFC 8288, section 2.1.2: every relation, an extension
# relation too, is compared without case, so a word is read in the spelling of the list.
_RELATIONS: Final = frozenset(
    {
        "alternate", "canonical", "collection", "describedby", "first", "help", "item", "last",
        "license", "linkset", "next", "prev", "previous", "profile", "related", "self", "service-desc",
        "service-doc", "service-meta", "type", "up", JSONLD_CONTEXT,
    }
    | {form + name for form in _GS1_FORMS for name in _GS1_LINK_TYPES}
)  # fmt: skip
_SPELLING: Final = {r.lower(): r for r in _RELATIONS}

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

    ``relations`` holds each word of the first rel in lower case, or in the spelling of the closed
    list. ``media_type`` is a kept type parameter in lower case. ``other`` is true if the link has
    another parameter, such as a title, a later rel, a type with another value, or the marker.
    """

    target: str
    relations: tuple[str, ...]
    media_type: str | None
    other: bool


class LinkValue(NamedTuple):
    """The links of a ``Link`` value, and whether reading reached the end of the value."""

    links: tuple[Link, ...]
    complete: bool


def redact_link(value: str) -> str:
    """Keep the redacted targets, the relations of the closed list, and a fixed type parameter.

    Each other parameter, and each relation outside the list, is replaced with one marker per link:
    a title or an anchor is free text that a system can fill with anything. A target that is not a
    URI reference becomes a marker. Where reading stopped, one marker stands for the rest of the
    value. The output parses to the same links and redacts to itself.
    """
    parsed = parse_link(value)
    out: list[str] = []
    for link in parsed.links:
        kept = tuple(r for r in link.relations if r in _RELATIONS)
        out.append(
            f"<{_link_target(link.target)}>"
            + (f'; rel="{" ".join(kept)}"' if kept else "")
            + (f'; type="{link.media_type}"' if link.media_type else "")
            + (f"; {REMOVED}" if link.other or len(kept) < len(link.relations) else "")
        )
    if not parsed.complete or not out:
        out.append(REMOVED)
    return ", ".join(out)


def _link_target(target: str) -> str:
    """The recorded form of a Link target.

    A target that is not a URI reference, or that has userinfo or a fragment, becomes the marker.
    Redaction would remove userinfo or a fragment without a trace, and URL parsers disagree on the
    host of a target with "\\" before "@". A credential-like query value is redacted in place,
    because its marker shows in the recorded target.
    """
    if _URI_REFERENCE.fullmatch(target) is None or "#" in target:
        return _TARGET_REMOVED
    try:
        userinfo = "@" in urlsplit(target).netloc
    except ValueError:
        return _TARGET_REMOVED
    redacted = redact_url(target)
    return _TARGET_REMOVED if userinfo or redacted == REMOVED else redacted


def parse_link(value: str) -> LinkValue:
    """Read a ``Link`` value as RFC 8288, appendix B, reads it.

    Reading stops where a link-value does not start with a target in "<" and ">", or where a link
    is followed by something other than "," or the end. The links before that point are kept. A
    value that ends with the marker REMOVED as its own link-value stopped in redaction, so it is
    not complete. Section 3.3: only the first rel counts, and a later one is another parameter.
    """
    links: list[Link] = []
    at = _skip(_SEPARATORS, value, 0)
    while at < len(value):
        if value[at:] == REMOVED or value[at] != "<" or (close := value.find(">", at)) < 0:
            return LinkValue(tuple(links), complete=False)
        target, at = value[at + 1 : close], close + 1
        rel: str | None = None
        media: str | None = None
        other = False
        while (parameter := _PARAMETER.match(value, _skip(_OWS, value, at))) is not None:
            at = parameter.end()
            name = parameter["name"].lower()
            quoted, token = parameter["quoted"], parameter["token"]
            text = _QUOTED_PAIR.sub(r"\1", quoted) if quoted is not None else (token or "").strip(" \t")
            if name == "rel" and rel is None:
                rel = text
            elif name == "type" and media is None and text.lower() in _KEPT_TYPES:
                media = text.lower()
            else:
                other = True
        words = (rel or "").split()
        links.append(Link(target, tuple(_SPELLING.get(w.lower(), w.lower()) for w in words), media, other))
        at = _skip(_OWS, value, at)
        if at < len(value) and value[at] != ",":
            return LinkValue(tuple(links), complete=False)
        at = _skip(_SEPARATORS, value, at)
    return LinkValue(tuple(links), complete=True)


def _skip(pattern: re.Pattern[str], value: str, at: int) -> int:
    found = pattern.match(value, at)
    return found.end() if found else at


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
