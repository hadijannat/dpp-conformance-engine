"""Keep secrets and private network details out of records.

Records are retained, hashed into commitments, and can be opened to reviewers. A secret that
reaches a record is disclosed. The rules here are default-deny: a value is recorded only when
it is known to be safe.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final
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
# One link: a target and at most one "rel" parameter. Any other parameter can hold any text.
# Only the quoted form can hold ":", "/", or "#": an extension relation is an IRI (RFC 8288, 3.3).
_LINK: Final = re.compile(
    r'\s*<([^<>\s]*)>(?:\s*;\s*rel=(?:"([A-Za-z][A-Za-z0-9 .:/#-]*)"|"?([A-Za-z][A-Za-z0-9 .-]*)"?))?\s*'
)
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
# JSON-LD context relation, and the GS1 link types. A word outside this list can be a secret, so a
# value with one is removed. An extension relation is compared as exact text.
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


def redact_link(value: str) -> str:
    """Keep the redacted targets and the relation names of a ``Link`` header.

    A value with any other parameter, or one that this simple reading cannot split, is removed
    as a whole: a title or an anchor is free text that a system can fill with anything.
    """
    links = parse_link(value)
    if links is None or not all(set(relations) <= _RELATIONS for _, relations in links):
        return REMOVED
    return ", ".join(
        f"<{redact_url(target)}>" + (f'; rel="{" ".join(relations)}"' if relations else "")
        for target, relations in links
    )


def parse_link(value: str) -> list[tuple[str, tuple[str, ...]]] | None:
    """Split a ``Link`` value into its targets and their relations, or None for any other form.

    A registered relation name is case-insensitive, so it is given in lower case. An extension
    relation keeps its case.
    """
    links: list[tuple[str, tuple[str, ...]]] = []
    for part in value.split(","):
        match = _LINK.fullmatch(part)
        if match is None:
            return None
        words = (match.group(2) or match.group(3) or "").split()
        links.append((match.group(1), tuple(w if _EXTENSION.search(w) else w.lower() for w in words)))
    return links


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
