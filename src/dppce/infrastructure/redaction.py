"""Keep secrets and private network details out of records.

Records are retained, hashed into commitments, and can be opened to reviewers. A secret that
reaches a record is disclosed. The rules here are default-deny: a value is recorded only when
it is known to be safe.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from functools import lru_cache
from itertools import accumulate
from typing import Final, NamedTuple
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlsplit

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
# The processor model is the Link parser of jsonld.js 8.3.3 (lib/util.js, parseLinkHeader). It splits
# a Link value at each "," outside "<...>" and outside a quoted string that ends at the next '"'. Of
# each part it reads the first target and its parameters, without unescaping. A later parameter
# replaces one of the same name. It uses three regular expressions with "\s". A scanner in linear
# time gives the same results: tests/test_link_processor.py compares the two. pyld 3.0.0
# (parse_link_header) uses the same expressions with Python "\s", which adds "\x85". It reads with
# re.findall, so an unquoted value reads as "", and a link without parameters raises an error. The
# model reads an unquoted target as "" for pyld. It keeps the jsonld.js reading of an unquoted rel,
# so it reads each context link that pyld reads, and more. "\s" is white space after the gate below.
_JS_SPACE: Final = " \t\xa0"
_PY_SPACE: Final = " \t\xa0\x85"
# A control character other than HTAB, or a character above "\xff", is not valid in an HTTP field
# value (RFC 9110, section 5.5). A header value arrives as latin-1 text, so "\x80" to "\xff" are bytes
# of UTF-8 text. The Python header parser can leave the line break of an obs-fold in a value.
_NOT_IN_FIELD: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f\u0100-\U0010ffff]")
_PART_STOP: Final = re.compile(r'[<",]')
# A scheme, if any, and then "//": the start of an authority.
_AUTHORITY_START: Final = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")
# The schemes whose URLs always have an authority, so "//" must follow the scheme.
_SPECIAL_SCHEMES: Final = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
# A target that is not a URI reference is recorded as this marker, so its free text never reaches a record.
_TARGET_REMOVED: Final = "%3Cremoved%3E"
# The recorded form of a Link value that reading stopped in before its first link.
LINK_STOPPED: Final = f"<{_TARGET_REMOVED}>, {REMOVED}"
# The suffix of a recorded redirect target after a Location that the URL readers read apart: the record
# does not hold the base path that a consumer reads. redact_url removes every other fragment.
BASE_UNKNOWN: Final = f"#{REMOVED}"
# The suffix after a Location with an empty ";" parameter that urljoin drops: the record does
# not hold the query and the last segment that a consumer reads.
QUERY_UNKNOWN: Final = f"#?{REMOVED}"
# RFC 3986, section 2: unreserved and reserved characters, and "%" only before two hex digits.
_URI_REFERENCE: Final = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
# Fixed media types cannot carry a secret, so a type parameter with one of them is kept.
_KEPT_TYPES: Final = frozenset({"application/linkset+json", "application/ld+json", "application/json"})
_JSONLD_TYPE: Final = "application/ld+json"
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
# The networks that the ipaddress module of CPython 3.12.3, 3.12.12, 3.12.13, 3.13.12, or 3.14.4 calls
# not global, multicast, reserved, loopback, link-local, or unspecified, without nested ones. The
# versions read the IANA IPv4 and IPv6 Special-Purpose Address Registries differently, so the union
# is the rule: an address is public only if each of these versions calls it public. Inside
# 192.0.0.0/24, each one calls 192.0.0.9 and 192.0.0.10 global.
_NOT_PUBLIC: Final = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "::/8", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/8", "200::/7", "400::/6", "800::/5",
        "1000::/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "4000::/3", "6000::/3",
        "8000::/3", "a000::/3", "c000::/3", "e000::/4", "f000::/5", "f800::/6", "fc00::/7",
        "fe00::/9", "fe80::/10", "ff00::/8",
    )
)  # fmt: skip
_PUBLIC_IN_NOT_PUBLIC: Final = (ipaddress.ip_network("192.0.0.9/32"), ipaddress.ip_network("192.0.0.10/32"))
# The schemes of uses_netloc and uses_relative in urllib.parse of CPython 3.12 to 3.14.
_USES_NETLOC: Final = frozenset(
    {
        "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp",
        "snews", "prospero", "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git",
        "git+ssh", "ws", "wss", "itms-services",
    }
)  # fmt: skip
_USES_RELATIVE: Final = frozenset(
    {
        "", "ftp", "http", "gopher", "nntp", "imap", "wais", "file", "https", "shttp", "mms",
        "prospero", "rtsp", "rtsps", "rtspu", "sftp", "svn", "svn+ssh", "ws", "wss",
    }
)  # fmt: skip


def url_unsplit(parts: tuple[str, str, str, str, str]) -> str:
    """urlunsplit as CPython 3.12.12 and 3.13 write it, on every Python.

    CPython 3.12.3 writes an empty authority for ("http", "", "b") and drops one for
    ("mailto", "", "//;"), so a record would depend on the Python that wrote it.
    """
    scheme, netloc, path, query, fragment = parts
    if netloc:
        path = f"//{netloc}{path if not path or path.startswith('/') else '/' + path}"
    elif path.startswith("//") or (scheme and scheme in _USES_NETLOC and (not path or path.startswith("/"))):
        path = "//" + path
    url = f"{scheme}:{path}" if scheme else path
    return url + (f"?{query}" if query else "") + (f"#{fragment}" if fragment else "")


def url_unparse(parts: tuple[str, str, str, str, str, str]) -> str:
    """urlunparse as CPython 3.12.12 and 3.13 write it: the parameter joins the path first."""
    scheme, netloc, path, params, query, fragment = parts
    return url_unsplit((scheme, netloc, f"{path};{params}" if params else path, query, fragment))


def url_join(base: str, url: str) -> str:
    """urljoin as CPython 3.12.12 and 3.13 resolve, on every Python.

    The readers of redirect_mark and reads_apart are written against it: it drops an empty ";"
    parameter, "?" query, and "#" fragment, and reads "..;x" as "..". CPython 3.14 keeps them, and
    3.12.3 writes an empty authority. urlparse gives the same parts on each version, except that
    3.12.3 accepts more bracketed hosts.
    """
    if not base or not url:
        return url or base
    bscheme, bnetloc, bpath, bparams, bquery, _ = urlparse(base)
    scheme, netloc, path, params, query, fragment = urlparse(url, bscheme)
    if scheme != bscheme or scheme not in _USES_RELATIVE:
        return url
    if scheme in _USES_NETLOC:
        if netloc:
            return url_unparse((scheme, netloc, path, params, query, fragment))
        netloc = bnetloc
    if not path and not params:
        return url_unparse((scheme, netloc, bpath, bparams, query or bquery, fragment))
    directory = bpath.split("/")
    # The last segment of the base is a directory only if it is empty.
    directory = directory[:-1] if directory[-1] else directory
    if path.startswith("/"):
        segments = path.split("/")
    else:
        segments = directory + path.split("/")
        segments[1:-1] = [s for s in segments[1:-1] if s]
    resolved: list[str] = []
    for segment in segments:
        if segment == "..":
            if resolved:
                resolved.pop()
        elif segment != ".":
            resolved.append(segment)
    if segments[-1] in (".", ".."):
        resolved.append("")
    return url_unparse((scheme, netloc, "/".join(resolved) or "/", params, query, fragment))


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
    return url_unsplit((parts.scheme, netloc, parts.path, query, ""))


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
    value. The output parses to the same links and redacts to itself, except the bare marker of a
    value without a link: it reads as a malformed value.
    """
    return _recorded(_live(value))


def _live(value: str) -> LinkValue:
    """Read a ``Link`` value as the system sent it.

    A value with a character that a field value cannot hold is not complete. The gate is here, not in
    ``parse_link``: before P2-26, a recorded target could hold such a character, and an old recording
    must keep its reading.
    """
    parsed = parse_link(value)
    readable = _NOT_IN_FIELD.search(value) is None and _types_agree(parsed.links, value)
    return parsed if readable else LinkValue(parsed.links, complete=False)


def _recorded(parsed: LinkValue) -> str:
    out: list[str] = []
    for link in parsed.links:
        kept = tuple(r for r in link.relations if r in _RELATIONS)
        out.append(
            f"<{_link_target(link.target)}>"
            + (f'; rel="{" ".join(kept)}"' if kept else "")
            + (f'; type="{link.media_type}"' if link.media_type else "")
            + (f"; {REMOVED}" if link.other or len(kept) < len(link.relations) else "")
        )
    # The bare marker is the form of an old recording and of a value without a link. So a malformed
    # value without a link gets one link with the target marker before the stop marker.
    if not parsed.complete and not out:
        out.append(f"<{_TARGET_REMOVED}>")
    if not parsed.complete or not out:
        out.append(REMOVED)
    return ", ".join(out)


def _link_target(target: str) -> str:
    """The recorded form of a Link target.

    A target that is not a URI reference, or that has userinfo, a fragment, or an empty authority,
    becomes the marker. So does a target with a scheme such as https that "//" does not follow, and a
    target that Python urljoin can resolve to another URL than WHATWG URL or pyld does.
    Redaction would remove userinfo or a fragment without a trace. URL parsers disagree on the host
    of a target with "\\" before "@", with an empty authority, or with such a scheme. A credential-like
    query value is redacted in place, because its marker shows in the recorded target.
    """
    if _URI_REFERENCE.fullmatch(target) is None or "#" in target:
        return _TARGET_REMOVED
    try:
        parts = urlsplit(target)
    except ValueError:
        return _TARGET_REMOVED
    netloc = parts.netloc
    # Python joins "https:/ctx" or "https:ctx" to the base host. pyld keeps a value with ":" as it is.
    if parts.scheme in _SPECIAL_SCHEMES and not target[len(parts.scheme) + 1 :].startswith("//"):
        return _TARGET_REMOVED
    if _changed_by_urljoin(target, parts.scheme, netloc):
        return _TARGET_REMOVED
    # Python joins the path of an empty authority to the base host. WHATWG reads its first segment as host.
    empty_authority = not netloc and _AUTHORITY_START.match(target) is not None
    redacted = redact_url(target)
    return _TARGET_REMOVED if "@" in netloc or empty_authority or redacted == REMOVED else redacted


def _changed_by_urljoin(target: str, scheme: str, netloc: str) -> bool:
    """True if Python urljoin can resolve ``target`` to a URL that WHATWG URL or pyld 3.0.0 does not.

    urljoin drops an empty ";" parameter and an empty "?" query, and reads "..;x" at the end as "..".
    It does not read "%2e" as ".". It removes empty segments of a relative path that does not start
    with "/". The readers also differ on a dot segment after another segment, on a dot segment in a
    URL with a scheme, and on a dot segment at the end before a query. pyld drops the first "." of a
    relative path that starts with ".", not "..", not "./", and has more than two characters. So only
    a leading run of "." and ".." segments is kept, in a relative target. A scheme in upper case is
    not a change: every reader writes it in lower case.
    """
    if url_unparse(urlparse(target)) != scheme + target[len(scheme) :]:
        return True
    segments = urlsplit(target).path.split("/")
    dots = [s.split(";")[0].lower().replace("%2e", ".") in (".", "..") for s in segments]
    if any(dot and s not in (".", "..") for dot, s in zip(dots, segments, strict=True)):
        return True
    leading = next((i for i, dot in enumerate(dots) if not dot), len(dots))
    if any(dots[leading:]) or (any(dots) and (scheme or netloc)) or (dots[-1] and "?" in target):
        return True
    if scheme or netloc or target.startswith("/"):
        return False
    pyld_strip = target.startswith(".") and not target.startswith(("..", "./")) and len(target) > 2
    return "" in segments[1:-1] or pyld_strip


def resolutions(base: str, target: str) -> tuple[str, ...]:
    """The URLs that the WHATWG URL parser and pyld 3.0.0 resolve the kept ``target`` to, each once.

    For a target that redaction keeps, both agree with Python urljoin unless the target is a relative
    path and the base path has an empty or dot segment or a "\\". urljoin removes empty segments of
    the base path, and it does not read "%2e" as ".". There the RFC 3986 merge, which keeps empty
    segments, gives each reading: pyld reads the base as it is, and WHATWG first reads each "\\" as
    "/", removes the dot segments, and reads "%2e" as ".". A reading keeps a character that WHATWG
    percent-encodes, as urljoin does. Raises ValueError as urljoin does.
    """
    relative = urlsplit(target)
    readings = None
    if not (relative.scheme or relative.netloc or target.startswith("/")):
        readings = _odd_base(base)
    if readings is None:
        return (url_join(base, target),)
    scheme, netloc, base_query, directories = readings
    out: list[str] = []
    for dotted, directory in zip((False, True), directories, strict=True):
        path, query = directory.path, relative.query
        if relative.path:
            path = directory.merge(relative.path, dotted=dotted)
        elif not query:
            query = base_query
        out.append(url_unsplit((scheme, netloc, path, query, relative.fragment)))
    return tuple(dict.fromkeys(out))


class _Directory:
    """A base path and its directory without dot segments, merged with a relative path in time that
    does not grow with the base path. A system under test can send a long base path and many links.
    """

    def __init__(self, path: str, *, dotted: bool) -> None:
        self.path = path
        kept: list[str] = []
        # Each segment of the directory comes before the segments of a relative path, so none is final.
        for segment in path[: path.rfind("/") + 1].split("/")[1:-1]:
            dot = _dot(segment, dotted=dotted)
            if dot == ".." and kept:
                kept.pop()
            if dot is None:
                kept.append(segment)
        self._joined = "/" + "/".join(kept)
        # The length of "/" and the first k kept segments, joined with "/", for k from 1.
        self._ends = [0, *accumulate(len(s) + 1 for s in kept)]

    def merge(self, relative: str, *, dotted: bool) -> str:
        """``_without_dots`` of the directory followed by ``relative``, which is not empty."""
        kept, extra = len(self._ends) - 1, list[str]()
        segments = relative.split("/")
        for index, segment in enumerate(segments):
            dot = _dot(segment, dotted=dotted)
            if dot == "..":
                if extra:
                    extra.pop()
                elif kept:
                    kept -= 1
            if dot is None:
                extra.append(segment)
            elif index == len(segments) - 1:
                extra.append("")  # a final dot segment leaves a directory
        tail = "/".join(extra)
        if not kept:
            return "/" + tail
        head = self._joined[: self._ends[kept]]
        return f"{head}/{tail}" if extra else head


@lru_cache(maxsize=8)
def _odd_base(base: str) -> tuple[str, str, str, tuple[_Directory, _Directory]] | None:
    """The parts of ``base`` and the pyld and WHATWG readings of its path, or None for a plain base.

    The readers of one record call this for each link, so the result is computed once per base.
    """
    parts = urlsplit(base)
    if not _odd_path(parts.path):
        return None
    whatwg = _without_dots((parts.path or "/").replace("\\", "/"), dotted=True)
    directories = (_Directory(parts.path or "/", dotted=False), _Directory(whatwg, dotted=True))
    return parts.scheme, parts.netloc, parts.query, directories


def hides_base_path(base: str, target: str) -> bool:
    """True if ``target`` reads the path of ``base`` and the record does not hold the path that a
    consumer reads.

    The transport replaces an echoed engine credential in a recorded redirect target with the marker.
    A credential can hold "/", so a relative path target on a path with the marker reads an unknown
    path. Redaction of a query parameter does not change the path. On a base that ends with
    BASE_UNKNOWN, a relative path, a query, and an empty target read an unknown path. On a base that
    ends with QUERY_UNKNOWN, a query and an empty target do. Raises ValueError as urlsplit does.
    """
    if mark := _mark(base):
        return _reads_unknown(mark, target)
    relative = urlsplit(target)
    local = not (relative.scheme or relative.netloc or target.startswith("/"))
    return local and bool(relative.path) and REMOVED in _unquoted_path(base)


@lru_cache(maxsize=8)
def _unquoted_path(url: str) -> str:
    return unquote(url.partition("?")[0])


def moves_host(location: str) -> bool:
    """True if WHATWG URL can read the redirect ``location`` with another host than Python urljoin.

    In an http or https URL, WHATWG URL reads "\\" as "/". It reads the first segment after an empty
    authority as the host, and urljoin keeps the host of the base. RFC 9110, section 4.2.1, says that
    a recipient rejects an http URL with an empty host. Both remove a tab and a line break. Raises
    ValueError as urlsplit does.
    """
    netloc = urlsplit(location).netloc
    whatwg = location.replace("\\", "/")
    return urlsplit(whatwg).netloc != netloc or (not netloc and _AUTHORITY_START.match(whatwg) is not None)


def reads_apart(base: str, location: str) -> bool:
    """True if Python urljoin can resolve the redirect ``location`` against ``base`` to another path
    than WHATWG URL or requests does.

    WHATWG URL reads "\\" as "/" and keeps the empty segments of a relative path. WHATWG URL and
    requests read "%2e" as ".". urljoin does neither, it removes the empty segments of the base path
    for a relative path, and it reads "..;x" as "..". It also drops an empty ";" parameter, "?" query,
    or "#" fragment, but that changes no path: see redirect_mark. Raises ValueError as urlsplit does.
    """
    trimmed = _without_empty_ends(location)[0]
    parsed = urlparse(trimmed)
    if url_unparse(parsed) != parsed.scheme + trimmed[len(parsed.scheme) :]:
        return True
    path = urlsplit(location).path
    segments = path.split("/")
    if "\\" in location or any(_dot(s.split(";")[0], dotted=True) and s not in (".", "..") for s in segments):
        return True
    relative = bool(path) and not path.startswith("/") and not urlsplit(location).netloc
    return relative and ("" in segments[:-1] or _odd_path(urlsplit(base).path))


def redirect_mark(previous: str, base: str, location: str) -> str:
    """The suffix of the recorded redirect target after ``location``, which urljoin joined to ``base``.

    The suffix is BASE_UNKNOWN after a Location that the readers read apart. It is QUERY_UNKNOWN after
    one with an empty ";" parameter, which urljoin drops and WHATWG URL keeps. A
    Location keeps the suffix of the previous recorded target ``previous`` if it reads the part of
    that base that the record does not hold. Raises ValueError as urlsplit does.
    """
    own = BASE_UNKNOWN if reads_apart(base, location) else ""
    if not own and _without_empty_ends(location)[1]:
        own = QUERY_UNKNOWN
    before = _mark(previous)
    # urljoin and WHATWG URL read a Location with the scheme of the base and no "//" after it, such as
    # "http:w", as the relative reference after the scheme.
    scheme, _, rest = location.partition(":")
    same = urlsplit(location).scheme == scheme.lower() == urlsplit(base).scheme
    reference = rest if same and not rest.startswith("//") else location
    kept = before if before and _reads_unknown(before, reference) else ""
    return BASE_UNKNOWN if BASE_UNKNOWN in (own, kept) else own or kept


def unmarked(url: str) -> str:
    """``url`` without the suffix BASE_UNKNOWN or QUERY_UNKNOWN: the URL that the transport fetched."""
    return url.removesuffix(BASE_UNKNOWN).removesuffix(QUERY_UNKNOWN)


def _mark(url: str) -> str:
    """The suffix of ``url`` that the transport added, or ""."""
    return next((m for m in (BASE_UNKNOWN, QUERY_UNKNOWN) if url.endswith(m)), "")


def _reads_unknown(mark: str, target: str) -> bool:
    """True if ``target`` reads the part of a base with the suffix ``mark`` that the record does not hold."""
    relative = urlsplit(target)
    if relative.scheme or relative.netloc or target.startswith("/"):
        return False
    return mark == BASE_UNKNOWN or not relative.path


def _without_empty_ends(location: str) -> tuple[str, bool]:
    """``location`` without an empty "#" fragment, "?" query, and ";" parameter, which urljoin drops,
    and whether it had the parameter.

    A target resolves to no fragment of its base. Node.js 22 new URL() resolves each target against a
    base with an empty query as urljoin does without it. So only the parameter changes a resolution.
    urlparse reads a parameter after the first ";" of the last path segment.
    """
    head, _, fragment = location.partition("#")
    head, _, query = head.partition("?")
    path = urlsplit(head).path
    params = path.endswith(";") and path.find(";", path.rfind("/") + 1) == len(path) - 1
    trimmed = (
        (head[:-1] if params else head)
        + (f"?{query}" if query else "")
        + (f"#{fragment}" if fragment else "")
    )
    return trimmed, params


def _odd_path(path: str) -> bool:
    """True if ``path`` has an empty segment before its last, a dot segment, or a "\\"."""
    segments = path.split("/")[1:]
    return "" in segments[:-1] or any(_dot(s, dotted=True) for s in segments) or "\\" in path


def _dot(segment: str, *, dotted: bool) -> str | None:
    """ "." or ".." if ``segment`` is a dot segment, with "%2e" read as "." if ``dotted``."""
    name = segment.lower().replace("%2e", ".") if dotted else segment
    return name if name in (".", "..") else None


def _without_dots(path: str, *, dotted: bool) -> str:
    """RFC 3986, section 5.2.4: ``path`` without its dot segments. Empty segments stay."""
    out: list[str] = []
    segments = path.split("/")[1:]
    for index, segment in enumerate(segments):
        dot = _dot(segment, dotted=dotted)
        if dot == ".." and out:
            out.pop()
        if dot is None:
            out.append(segment)
        elif index == len(segments) - 1:
            out.append("")  # a final dot segment leaves a directory
    return "/" + "/".join(out)


def parse_link(value: str) -> LinkValue:
    """Read a ``Link`` value as RFC 8288, appendix B, reads it.

    Reading stops where a link-value does not start with a target in "<" and ">", or where a link
    is followed by something other than "," or the end. The links before that point are kept. A
    value that ends with the marker REMOVED as its own link-value, also before spaces or tabs,
    stopped in redaction, so it is not complete. Section 3.3: only the first rel counts, and a
    later one is another parameter. A value is not complete either if a processor that splits on
    commas, as jsonld.js does, reads other targets or other context links.
    """
    links: list[Link] = []
    at = _skip(_SEPARATORS, value, 0)
    while at < len(value):
        stopped = value.startswith(REMOVED, at) and _skip(_OWS, value, at + len(REMOVED)) == len(value)
        if stopped or value[at] != "<" or (close := value.find(">", at)) < 0:
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
    return LinkValue(tuple(links), complete=_agrees(links, value))


def _agrees(links: list[Link] | tuple[Link, ...], value: str) -> bool:
    """True if both processor models read the targets of ``links`` in order, with the same context links."""
    read = [(x.target, JSONLD_CONTEXT in x.relations) for x in links]
    return read == _processor_links(value, _JS_SPACE) == _processor_links(value, _PY_SPACE, pyld=True)


def _types_agree(links: list[Link] | tuple[Link, ...], value: str) -> bool:
    """True unless the processor model reads the type application/ld+json for a link of ``links``
    that the engine reads with another type.

    pyld 3.0.0 loads the target of an alternate link with that type, and the model reads the last
    parameter named exactly "type", as pyld does. The engine keeps the first kept type. Only redaction
    reads this rule, on a value whose targets agree with the model.
    """
    for space, pyld in ((_JS_SPACE, False), (_PY_SPACE, True)):
        for link, (_, parameters) in zip(links, _processor_read(value, space), strict=False):
            read = ""
            for name, text, quoted in parameters:
                if name == "type":
                    read = text if quoted or not pyld else ""
            if read == _JSONLD_TYPE and link.media_type != _JSONLD_TYPE:
                return False
    return True


def _processor_links(value: str, space: str, *, pyld: bool = False) -> list[tuple[str, bool]]:
    """Each target that the processor model reads in ``value``, and whether its rel names the context.

    With ``pyld``, an unquoted target parameter reads as "": pyld reads parameters with re.findall,
    which gives "" for the quoted group of an unquoted value. A rel keeps the jsonld.js reading. pyld
    reads an unquoted rel as "" and finds no context there, so the model reads more contexts than pyld.
    """
    out: list[tuple[str, bool]] = []
    for first, parameters in _processor_read(value, space):
        named = {"target": first, "rel": ""}
        # Each parameter is assigned to the link, so the last one named exactly "target" replaces it.
        for name, text, quoted in parameters:
            named[name] = "" if pyld and name == "target" and not quoted else text
        out.append((named["target"], JSONLD_CONTEXT in named["rel"].lower().split()))
    return out


def _processor_read(value: str, space: str) -> list[tuple[str, list[tuple[str, str, bool]]]]:
    """Each target and its parameters, as the regular expressions of jsonld.js and pyld read them.

    ``space`` is the set of characters that "\\s" matches. The results equal findall of the part
    expression, search of the link expression on each part, and finditer of the parameter expression.
    A parameter is its name, its value, and whether the value is quoted.
    """
    out: list[tuple[str, list[tuple[str, str, bool]]]] = []
    for part in _processor_parts(value):
        # "\s*<([^>]*)>": the first "<" of the part, if a ">" follows it.
        opening = part.find("<")
        closing = part.find(">", opening + 1) if opening >= 0 else -1
        if closing < 0:
            continue
        # "\s*(?:;\s*(.*))?": the parameters start after ";" and white space.
        after = _skip_space(part, closing + 1, space)
        parameters = part[_skip_space(part, after + 1, space) :] if part.startswith(";", after) else ""
        out.append((part[opening + 1 : closing], _processor_parameters(parameters, space)))
    return out


def _processor_parts(value: str) -> list[str]:
    """The matches of '(?:<[^>]*>|"[^"]*"|[^,])+': runs without a "," outside "<...>" and "\\"...\\""."""
    parts: list[str] = []
    after = {">": _finder(value, ">"), '"': _finder(value, '"')}
    start = at = 0
    while (found := _PART_STOP.search(value, at)) is not None:
        at = found.start()
        if value[at] == ",":
            if start < at:
                parts.append(value[start:at])
            start = at = at + 1
            continue
        closing = after[">" if value[at] == "<" else '"'](at + 1)
        # Without a closing character, "<" or '"' is one character of the part.
        at = closing + 1 if closing < len(value) else at + 1
    if start < len(value):
        parts.append(value[start:])
    return parts


def _processor_parameters(text: str, space: str) -> list[tuple[str, str, bool]]:
    """The name and value of each match of '(.*?)=(?:"([^"]*)"|([^"]*?))\\s*(?:;\\s*|\\Z)' in ``text``.

    A match at a position does not depend on where its name starts. So if no "=" after the start of
    a name gives a match, no later start does, and the matches end.
    """
    out: list[tuple[str, str, bool]] = []
    quote, semicolon = _finder(text, '"'), _finder(text, ";")
    start, equals = 0, text.find("=")
    while equals >= 0:
        found = _processor_value(text, equals, space, quote, semicolon)
        if found is None:
            equals = text.find("=", equals + 1)
            continue
        value, end, quoted = found
        out.append((text[start:equals], value, quoted))
        start, equals = end, text.find("=", end)
    return out


def _processor_value(
    text: str, equals: int, space: str, quote: Callable[[int], int], semicolon: Callable[[int], int]
) -> tuple[str, int, bool] | None:
    """The value after the "=" at ``equals``, the end of the match, and whether the value is quoted.

    None if no match ends there.
    """
    size = len(text)
    if text.startswith('"', equals + 1):
        # '"([^"]*)"': the quoted value must be followed by white space, and then ";" or the end.
        closing = quote(equals + 2)
        after = _skip_space(text, closing + 1, space) if closing < size else size + 1
        if after == size:
            return text[equals + 2 : closing], size, True
        if text.startswith(";", after):
            return text[equals + 2 : closing], _skip_space(text, after + 1, space), True
        return None  # the unquoted form cannot start with '"'
    # '([^"]*?)': the shortest value without '"' that white space and then ";" or the end follow.
    stop = semicolon(equals + 1)
    if quote(equals + 1) < stop:
        return None
    value_end = stop
    while value_end > equals + 1 and text[value_end - 1] in space:
        value_end -= 1
    return text[equals + 1 : value_end], (_skip_space(text, stop + 1, space) if stop < size else size), False


def _finder(text: str, char: str) -> Callable[[int], int]:
    """A function that gives the index of the next ``char`` at or after a position, or ``len(text)``.

    The positions of the calls must not decrease. So each scan of ``text`` starts after the last
    result, and all calls together read ``text`` once.
    """
    found = -1

    def at_or_after(position: int) -> int:
        nonlocal found
        if found < position:
            found = text.find(char, position)
            found = len(text) if found < 0 else found
        return found

    return at_or_after


def _skip_space(text: str, at: int, space: str) -> int:
    while at < len(text) and text[at] in space:
        at += 1
    return at


def _skip(pattern: re.Pattern[str], value: str, at: int) -> int:
    found = pattern.match(value, at)
    return found.end() if found else at


def redact_request_headers(headers: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple((k, v if k.lower() in SAFE_REQUEST_HEADERS else REMOVED) for k, v in sorted(headers.items()))


def redact_response_headers(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Keep the names. Keep a value only if its name is known to be safe.

    An HTTP client hands the application one ``Link`` value: the lines in wire order, joined with
    ", ". If the processor model reads that value differently than the engine reads the lines, the
    record of the last line gets the stop marker. A recorded value is never joined: its markers read
    as targets to the model.
    """
    out: list[tuple[str, str]] = []
    lines: list[tuple[int, str, LinkValue]] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in SAFE_RESPONSE_HEADERS:
            out.append((name, value))
        elif lowered in _URL_RESPONSE_HEADERS:
            out.append((name, redact_url(value)))
        elif lowered == "link":
            parsed = _live(value)
            lines.append((len(out), value, parsed))
            out.append((name, _recorded(parsed)))
        else:
            out.append((name, REMOVED))
    # A line whose reading stopped is already not complete, so its record shows the stop.
    if len(lines) > 1 and all(parsed.complete for _, _, parsed in lines):
        links = [link for _, _, parsed in lines for link in parsed.links]
        joined = ", ".join(value for _, value, _ in lines)
        if not (_agrees(links, joined) and _types_agree(links, joined)):
            index = lines[-1][0]
            name, kept = out[index]
            out[index] = (name, LINK_STOPPED if kept == REMOVED else f"{kept}, {REMOVED}")
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
    # Not the is_global of the running Python: its sets differ between CPython patch releases.
    return any(ip in network for network in _PUBLIC_IN_NOT_PUBLIC) or not any(
        ip in network for network in _NOT_PUBLIC
    )


def is_public_address(address: str) -> bool:
    """True only if the address, and any IPv4 address embedded in it, is a public unicast address.

    A NAT64, 6to4, Teredo, or IPv4-mapped address can look global while it leads to a private
    IPv4 address. Both layers must be public. A NAT64, 6to4, or Teredo address is always refused,
    because each prefix is in _NOT_PUBLIC. The rule is the same on every Python. A system that is
    reachable only through such a prefix needs an entry in ``allow_private_hosts``.
    """
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            # An IPv4-mapped address is the IPv4 address. The other prefixes must be public too.
            return _routable(embedded) and (ip.ipv4_mapped is not None or _routable(ip))
    return _routable(ip)
