"""One answer on every CPython that pyproject allows.

The stdlib changed between CPython patch releases. urlunsplit, urlunparse, and urljoin of 3.12.3
write an empty authority where 3.12.12 and 3.13 do not, and urljoin of 3.14 keeps an empty ";",
"?", and "#". The is_global sets of ipaddress differ between 3.12.3 and 3.12.12. The engine
judges with its own rules, so each answer here is the same on 3.12.3, 3.12.12, 3.13, and 3.14.

The URL answers are those of CPython 3.12.12 and 3.13, which the developer Python and the CI job
on 3.13 use. A public address is one that the stdlib of each of these versions calls global.

Every server is a loopback server that the test starts. No test contacts another host.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from dppce.adapters.common import effective_url
from dppce.adapters.resolver import _invalid_variant, _with_link_type
from dppce.cli import _token_url
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.redaction import (
    BASE_UNKNOWN,
    QUERY_UNKNOWN,
    hides_base_path,
    is_public_address,
    reads_apart,
    redact_link,
    redact_url,
    redirect_mark,
    resolutions,
)
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.models import NetworkPolicy
from tests.test_credential_schemes import NOW, TokenSystem, _authorization, _Resolver
from tests.test_data_document_source import ALLOWED, passed, verdict
from tests.test_link_processor import CTX, Redirected, _follow
from tests.test_review_adapters import OVERRIDE, _override
from tests.test_rulepack_v2 import BODY, contexts

REMOVED_QUERY = "%3Cremoved%3E"
REMOVED_TARGET = "%3Cremoved%3E"

# -- URLs: an empty authority ------------------------------------------------------------------------


def test_a_location_with_the_base_scheme_and_no_slashes_is_a_relative_reference() -> None:
    # urljoin and WHATWG URL read "http:b" on an http base as "b". CPython 3.12.3 urlunparse wrote
    # "http:///b" for it, so reads_apart was true there and the record got the unknown-base mark.
    assert reads_apart("http://h/x", "http:b") is False
    assert redirect_mark("", "http://h/x", "http:b") == ""
    assert reads_apart("http://h/x", "git:b") is False
    assert redirect_mark("", "http://h/x", "http:b;") == QUERY_UNKNOWN


def test_an_empty_authority_with_a_parameter_keeps_only_the_query_mark() -> None:
    assert reads_apart("http://h/x", "mailto:////;") is False
    assert redirect_mark("", "http://h/x", "mailto:////;") == QUERY_UNKNOWN
    # A Location with an empty authority after the scheme of the base is read apart on every Python.
    assert redirect_mark("", "http://h/x", "http:/b") == BASE_UNKNOWN


def test_a_302_to_the_base_scheme_without_slashes_is_recorded_without_a_mark(
    tmp_path: Path, loopback: Any
) -> None:
    server, record = _follow(loopback, ["http:b"], f"<ctx>; {CTX}")
    assert record.status == 200
    assert record.redirects == (f"{server.origin}/dpp/b",)
    # The record holds the path that a consumer reads, so a relative context target is judged.
    assert hides_base_path(record.redirects[-1], "ctx") is False
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    allowed = [ALLOWED[0], f"{server.origin}/dpp/ctx"]
    outcome = contexts(tmp_path, Redirected(BODY, links, record.redirects[-1]), allowed_contexts=allowed)
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize(
    ("locations", "recorded", "paths"),
    [
        # urljoin of 3.12 and 3.13 drops an empty query, fragment, and ";" parameter, and reads "..;x"
        # as "..". urljoin of 3.14 keeps them. The marks of redirect_mark follow the first reading.
        (["/a?q=1", "?"], ["/a?q=1", "/a?q=1"], ["/dpp/1", "/a?q=1", "/a?q=1"]),
        (["/a?q=1", "?#"], ["/a?q=1", "/a?q=1"], ["/dpp/1", "/a?q=1", "/a?q=1"]),
        (["/a/b//c/", ";"], ["/a/b//c/", f"/a/b//c/{BASE_UNKNOWN}"], ["/dpp/1", "/a/b//c/", "/a/b//c/"]),
        (["/a/b/", "..;x"], ["/a/b/", f"/a/;x{BASE_UNKNOWN}"], ["/dpp/1", "/a/b/", "/a/;x"]),
    ],
)
def test_the_transport_joins_a_location_with_one_rule(
    loopback: Any, locations: list[str], recorded: list[str], paths: list[str]
) -> None:
    server, record = _follow(loopback, locations, f"<ctx>; {CTX}")
    assert record.status == 200
    assert record.redirects == tuple(server.origin + hop for hop in recorded)
    assert [seen["path"] for seen in server.seen] == paths


@pytest.mark.parametrize(
    ("url", "recorded"),
    [
        ("mailto:////x?token=1", f"mailto:////x?token={REMOVED_QUERY}"),
        ("mailto:////;?token=1", f"mailto:////;?token={REMOVED_QUERY}"),
        ("http:b?token=1", f"http:b?token={REMOVED_QUERY}"),
        ("git:b?token=1", f"git:b?token={REMOVED_QUERY}"),
        ("http:////x?token=1", f"http:////x?token={REMOVED_QUERY}"),
        ("////x?token=1", f"////x?token={REMOVED_QUERY}"),
        ("//x?token=1", f"//x?token={REMOVED_QUERY}"),
        ("http:?token=1", f"http://?token={REMOVED_QUERY}"),
        ("http:b#f", "http:b"),
    ],
)
def test_redaction_keeps_the_authority_form_of_a_url(url: str, recorded: str) -> None:
    assert redact_url(url) == recorded


@pytest.mark.parametrize(
    ("value", "recorded"),
    [
        # A scheme with an authority in urllib, no "//", and not special: no reader reads it apart.
        ('<git:b?token=1>; rel="next"', f'<git:b?token={REMOVED_QUERY}>; rel="next"'),
        ('<git:b>; rel="next"', '<git:b>; rel="next"'),
        ('<telnet:b?x=1>; rel="next"', '<telnet:b?x=1>; rel="next"'),
        ('<nfs:x>; rel="next"', '<nfs:x>; rel="next"'),
        ('<x:b?token=1>; rel="next"', f'<x:b?token={REMOVED_QUERY}>; rel="next"'),
        # An empty authority, and a special scheme without "//", become the marker.
        ('<mailto:////x?token=1>; rel="next"', f'<{REMOVED_TARGET}>; rel="next"'),
        ('<http:b?token=1>; rel="next"', f'<{REMOVED_TARGET}>; rel="next"'),
    ],
)
def test_a_link_target_without_an_authority_is_recorded_alike(value: str, recorded: str) -> None:
    assert redact_link(value) == recorded


@pytest.mark.parametrize(
    ("base", "target", "urls"),
    [
        ("http:b", "c", ("http:c",)),
        ("http:b", "?q", ("http:b?q",)),
        ("http:/a//b/", "c", ("http:///a//b/c",)),
        ("http://h/a//b/", "c", ("http://h/a//b/c",)),
        ("http://h/x", "c", ("http://h/c",)),
    ],
)
def test_resolutions_of_a_base_without_a_host(base: str, target: str, urls: tuple[str, ...]) -> None:
    assert resolutions(base, target) == urls


def test_the_resolver_helpers_keep_a_url_without_a_host() -> None:
    # The checks pass only URLs with a host. The helpers still give one answer for each shape.
    assert _with_link_type("http:b") == "http:b?linkType=linkset"
    assert _with_link_type("http:b?q=1") == "http:b?q=1&linkType=linkset"
    assert _with_link_type("http:////x") == "http:////x?linkType=linkset"
    assert _invalid_variant("http:/01/09506000134352/21/x") == "http:///01/09506000134353/21/x"


def test_the_origin_override_keeps_a_path_that_starts_with_two_slashes(tmp_path: Path) -> None:
    # The override replaces the origin only. CPython 3.12.12 urlunsplit writes "////t" for the path
    # "//t" without an authority, which would request another path than the public URL names.
    ctx = _override(tmp_path)
    assert effective_url(ctx, "https://id.example//t?a=1#f") == (f"{OVERRIDE}//t?a=1#f", ("origin_override",))
    endpoints = dict(ctx.ixit.endpoints) | {"token": "https://id.example//t?a=1#f"}
    ixit = ctx.ixit.model_copy(update={"endpoints": endpoints})
    assert _token_url(ixit, "auditor", "token") == f"{OVERRIDE}//t?a=1"


# -- addresses -------------------------------------------------------------------------------------

# Every network that the ipaddress module of CPython 3.12.3, 3.12.12, 3.12.13, 3.13.12, or 3.14.4
# calls not global, multicast, reserved, loopback, link-local, or unspecified. Read from
# _IPv4Constants and _IPv6Constants of each version. 192.0.0.9 and 192.0.0.10 are global in all.
# ::ffff:0:0/96 is not here: an IPv4-mapped address is judged as its IPv4 address.
_STDLIB_NOT_PUBLIC = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/29", "192.0.0.8/32", "192.0.0.11/32", "192.0.0.12/30", "192.0.0.16/28", "192.0.0.32/27",
    "192.0.0.64/26", "192.0.0.128/25", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
    "::1/128", "::/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
    "2001:db8::/32", "2001:10::/28", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10",
    "::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "4000::/3", "6000::/3",
    "8000::/3", "a000::/3", "c000::/3", "e000::/4", "f000::/5", "f800::/6", "fe00::/9", "ff00::/8",
)  # fmt: skip


@pytest.mark.parametrize("network", _STDLIB_NOT_PUBLIC)
def test_an_address_that_one_python_calls_not_public_is_not_public(network: str) -> None:
    net = ipaddress.ip_network(network)
    for address in {net[0], net[-1], net[net.num_addresses // 2]}:
        assert not is_public_address(str(address)), address


@pytest.mark.parametrize(
    "address",
    [
        # 6to4, Teredo, and NAT64 addresses with a public IPv4 address in them.
        "2002:5db8:d822::1",
        "2002:808:808::1",
        "2001:0:4136:e378:8000:63bf:a2f7:f7f7",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
        # Global for 3.12.12 and later, not global for 3.12.3: refused.
        "2001:1::1",
        "2001:1::2",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
        # Global for 3.12.3 only: refused.
        "3fff::1",
        "192.0.0.8",
        "192.0.0.255",
        "::ffff:192.0.0.8",
    ],
)
def test_a_translated_or_disputed_address_is_never_public(address: str) -> None:
    assert is_public_address(address) is False


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "93.184.216.34", "192.0.0.9", "192.0.0.10", "::ffff:8.8.8.8", "2606:4700:4700::1111"],
)
def test_a_public_unicast_address_is_public(address: str) -> None:
    assert is_public_address(address) is True


def test_a_token_request_to_an_ipv4_mapped_loopback_address_goes_over_http() -> None:
    # CPython 3.12.3 calls ::ffff:127.0.0.1 not loopback; 3.12.12 reads it as its IPv4 address.
    system = TokenSystem()
    origin = f"http://token.example.test:{system.server.port}"
    policy = {
        "allowed_hosts": ("127.0.0.1", "token.example.test"),
        "allow_private_hosts": ("127.0.0.1", "token.example.test"),
    }
    settings = TransportConfig(
        policy=NetworkPolicy(**policy),
        engine_version="1.2.3",
        oauth_clients=system.client(f"{origin}/token"),
        authorization=_authorization(system.origin, endpoints=(system.origin, origin)),
    )
    resolver = _Resolver({"127.0.0.1": ["127.0.0.1"], "token.example.test": ["::ffff:127.0.0.1"]})
    engine = PolicyTransport(settings, FrozenClock(NOW), resolver=resolver, sleep=lambda _: None)
    send = PolicyTransport._send
    targets: list[str] = []

    def to_ipv4(self: PolicyTransport, target: Any, *args: Any) -> Any:
        # The test connects to the IPv4 address that the mapped address names.
        targets.append(target.address)
        return send(self, dataclasses.replace(target, address="127.0.0.1"), *args)

    try:
        with mock.patch.object(PolicyTransport, "_send", to_ipv4):
            record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    finally:
        system.server.close()
    assert record.error is None
    assert targets[0] == "::ffff:127.0.0.1"
    assert len(system.posts) == 1
