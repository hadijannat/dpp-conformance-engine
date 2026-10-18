"""Tests for the transport, redaction, and authorization survivors of the mutation run of 2026-10-18.

The run is ``uv run just mutation`` (mutmut 3.8.0) at commit 6602f8c. These three modules are the
same at dbc88e0. Each test names, in its docstring, the surviving mutants that it kills. The
record is ``validation/records/mutation-2026-10-18.md``, section "Round 3".

Every server is a loopback server that the test starts. A table resolver answers every name that
a test resolves. The exception is the system resolver test, which resolves the numeric loopback
address 127.0.0.2. A name that is not a loopback name ends in ``.test``. The exception is the host
``xxxx`` in the hostless-URL test, which the test never resolves.
"""

from __future__ import annotations

import contextlib
import gc
import http.server
import json
import os
import pathlib
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.jws import LocalSigner, sign_compact
from dppce.infrastructure.authorization import (
    AUTHORIZATION_TYP,
    AuthorizationError,
    issue_authorization,
    validate_authorization,
)
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.redaction import _RELATIONS, is_public_address, redact_link, redact_url
from dppce.infrastructure.transport import (
    MIN_SECRET_LENGTH,
    PolicyTransport,
    SystemResolver,
    TransportConfig,
    _close_all,
    _pin,
    origin_of,
)
from dppce.models import NetworkPolicy, TrustBundle
from tests.support import reply
from tests.test_transport import LOCAL, NOW, Start, authorization, transport

TOKEN = "TEST-ONLY-Q7xZ9kLm"
SHORT = "TEST-ONLY-ZULU-1"
LONG = "TEST-ONLY-ALPHA-TEST-ONLY-ZULU-1"
NOW_STAMP = "2026-10-13T12:00:00Z"  # NOW as a stamp
_UNSET = object()


def engine(
    policy: dict[str, Any] | None = None,
    *,
    resolver: Any = None,
    sleep: Callable[[float], None] = lambda _: None,
    monotonic: Callable[[], float] = time.monotonic,
    **config: Any,
) -> PolicyTransport:
    """A transport whose policy is LOCAL with ``policy`` merged in."""
    settings = TransportConfig(
        policy=NetworkPolicy(**(LOCAL | (policy or {}))), engine_version="1.2.3", **config
    )
    return PolicyTransport(settings, FrozenClock(NOW), resolver, sleep=sleep, monotonic=monotonic)


class MappedResolver:
    """Answers from a table and records each question. A name outside the table does not resolve."""

    def __init__(self, answers: dict[str, list[str]]) -> None:
        self._answers = answers
        self.asked: list[tuple[object, object]] = []

    def resolve(self, host: str, port: int) -> list[str]:
        self.asked.append((host, port))
        if host not in self._answers:
            raise OSError("no such host")
        return self._answers[host]


def ticks(*values: float) -> Callable[[], float]:
    """A monotonic clock that returns ``values`` in turn, then repeats the last one."""
    left = list(values)

    def now() -> float:
        return left.pop(0) if len(left) > 1 else left[0]

    return now


class RawServer:
    """A loopback TCP server that sends fixed bytes, so that a test controls the exact reply."""

    def __init__(self, payload: bytes, *, hold: bool = False) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.release = threading.Event()
        self._payload = payload
        self._hold = hold
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        with contextlib.suppress(OSError):
            while True:
                peer, _ = self.listener.accept()
                with peer, contextlib.suppress(OSError):
                    peer.settimeout(5)
                    peer.recv(65536)  # the request or the ClientHello
                    peer.sendall(self._payload)
                    if self._hold:
                        self.release.wait(5)
                    while peer.recv(65536):
                        pass

    def close(self) -> None:
        self.release.set()
        self.listener.close()


@pytest.fixture
def raw() -> Iterator[Callable[..., RawServer]]:
    servers: list[RawServer] = []

    def start(payload: bytes, *, hold: bool = False) -> RawServer:
        server = RawServer(payload, hold=hold)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, object]]:
    """Each (address, timeout) that the transport passes to socket.create_connection."""
    seen: list[tuple[object, object]] = []
    real = socket.create_connection

    def spy(address: Any, timeout: Any = _UNSET, *args: Any, **kwargs: Any) -> socket.socket:
        seen.append((address, timeout))
        if timeout is _UNSET:
            return real(address, *args, **kwargs)
        return real(address, timeout, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", spy)
    return seen


class _Unplugged:
    def shutdown(self, how: int) -> None:
        return


class ExpireAtStart:
    """Stands in for threading.Timer. The deadline is marked as passed, and the socket stays usable."""

    def __init__(self, interval: float, function: Callable[..., None], args: tuple[Any, ...] = ()) -> None:
        self.function = function
        self.daemon = False

    def start(self) -> None:
        self.function(_Unplugged())

    def cancel(self) -> None:
        return


class ShutdownAtStart:
    """Stands in for threading.Timer. The deadline passes at once and shuts down the real socket."""

    def __init__(self, interval: float, function: Callable[..., None], args: tuple[Any, ...] = ()) -> None:
        self.function = function
        self.args = args
        self.daemon = False

    def start(self) -> None:
        self.function(*self.args)

    def cancel(self) -> None:
        return


def echo(request: http.server.BaseHTTPRequestHandler) -> None:
    length = int(request.headers.get("Content-Length", "0"))
    reply(request, body=request.rfile.read(length))


def redirect_to(target: str) -> Callable[[http.server.BaseHTTPRequestHandler], None]:
    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        if request.path.startswith("/hop"):
            reply(request, 302, b"", {"Location": target})
        else:
            reply(request)

    return handler


# -- name resolution, origins, and pinning ------------------------------------------------------


def test_system_resolver_resolves_the_named_host() -> None:
    """The system resolver resolves the host that it gets. 127.0.0.2 is numeric: no DNS query.

    Kills:
    dppce.infrastructure.transport.xǁSystemResolverǁresolve__mutmut_2
    """
    assert SystemResolver().resolve("127.0.0.2", 80) == ["127.0.0.2"]


def test_origin_of_a_url_without_a_host_names_no_host() -> None:
    """A URL without a host has an origin without a host.

    Kills:
    dppce.infrastructure.transport.x_origin_of__mutmut_6
    """
    assert origin_of("http:///x") == "http://"


def test_an_endpoint_that_cannot_be_parsed_names_no_origin(loopback: Start) -> None:
    """An authorization endpoint that cannot be parsed names no origin. The other endpoints still apply.

    Kills:
    dppce.infrastructure.transport.x__origins__mutmut_2
    """
    server = loopback(reply)
    auth = authorization(endpoints=("http://[::1", server.origin))
    assert transport(authorization=auth).fetch(Request("GET", f"{server.origin}/ok")).status == 200


def test_pin_refuses_a_link_a_directory_and_a_fifo(tmp_path: Path) -> None:
    """The pin opens a regular file only. It does not follow a link, and a FIFO does not block it.

    Kills:
    dppce.infrastructure.transport.x__pin__mutmut_2
    dppce.infrastructure.transport.x__pin__mutmut_3
    dppce.infrastructure.transport.x__pin__mutmut_4
    dppce.infrastructure.transport.x__pin__mutmut_10
    dppce.infrastructure.transport.x__pin__mutmut_11
    dppce.infrastructure.transport.x__pin__mutmut_13
    dppce.infrastructure.transport.x__pin__mutmut_19
    dppce.infrastructure.transport.x__pin__mutmut_20
    dppce.infrastructure.transport.x__pin__mutmut_31
    """
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"image-bytes")
    link = tmp_path / "link.png"
    os.symlink(sample, link)
    assert _pin(link) == (None, None)
    assert _pin(tmp_path) == (None, None)

    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    results: list[object] = []
    thread = threading.Thread(target=lambda: results.append(_pin(pipe)), daemon=True)
    thread.start()
    thread.join(5)
    blocked = thread.is_alive()
    if blocked:
        # Release the blocked open, so that no thread outlives the test.
        os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        thread.join(5)
    assert not blocked, "the open of a FIFO blocked"
    assert results == [(None, None)]


def test_closing_the_pins_goes_on_after_a_failed_close(tmp_path: Path) -> None:
    """A descriptor that does not close does not stop the close of the others.

    Kills:
    dppce.infrastructure.transport.x__close_all__mutmut_1
    """
    (tmp_path / "a").write_bytes(b"a")
    (tmp_path / "b").write_bytes(b"b")
    first = os.open(tmp_path / "a", os.O_RDONLY)
    second = os.open(tmp_path / "b", os.O_RDONLY)
    os.close(first)
    _close_all((first, second))
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(second)


# -- connections, timeouts, and TLS -------------------------------------------------------------


def test_the_connection_goes_to_the_checked_address_with_the_request_timeout(
    loopback: Start, connections: list[tuple[object, object]]
) -> None:
    """A plain HTTP connection goes to the checked address with the timeout of one request.

    Kills:
    dppce.infrastructure.transport.xǁ_PinnedHTTPConnectionǁ__init____mutmut_3
    dppce.infrastructure.transport.xǁ_PinnedHTTPConnectionǁ__init____mutmut_6
    dppce.infrastructure.transport.xǁ_PinnedHTTPConnectionǁ__init____mutmut_7
    dppce.infrastructure.transport.xǁ_PinnedHTTPConnectionǁconnect__mutmut_3
    dppce.infrastructure.transport.xǁ_PinnedHTTPConnectionǁconnect__mutmut_5
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_124
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_16
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_21
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_26
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_27
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_44
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_45
    """
    server = loopback(reply)
    resolver = MappedResolver({"sut.test": ["127.0.0.1"]})
    policy = {"allowed_hosts": ("sut.test",), "allow_private_hosts": ("sut.test",), "timeout_ms": 900}
    record = engine(policy, resolver=resolver).fetch(Request("GET", f"http://sut.test:{server.port}/ok"))
    assert record.status == 200
    assert connections == [(("127.0.0.1", server.port), 0.9)]
    assert server.seen[0]["Host"] == f"sut.test:{server.port}"


def test_an_https_url_uses_tls_on_the_checked_address(
    raw: Callable[..., RawServer], connections: list[tuple[object, object]]
) -> None:
    """An https URL uses TLS on the checked address. A plain HTTP reply is then a TLS error.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_28
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_29
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_119
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_29
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_31
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_32
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_33
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_34
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_35
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_36
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_37
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_38
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_40
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_41
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_86
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_89
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_90
    dppce.infrastructure.transport.xǁ_PinnedHTTPSConnectionǁ__init____mutmut_2
    dppce.infrastructure.transport.xǁ_PinnedHTTPSConnectionǁ__init____mutmut_3
    dppce.infrastructure.transport.xǁ_PinnedHTTPSConnectionǁ__init____mutmut_6
    dppce.infrastructure.transport.xǁ_PinnedHTTPSConnectionǁ__init____mutmut_7
    dppce.infrastructure.transport.xǁ_PinnedHTTPSConnectionǁ__init____mutmut_9
    """
    server = raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    resolver = MappedResolver({"sut.test": ["127.0.0.1"]})
    policy = {"allowed_hosts": ("sut.test",), "allow_private_hosts": ("sut.test",), "timeout_ms": 900}
    record = engine(policy, resolver=resolver).fetch(Request("GET", f"https://sut.test:{server.port}/ok"))
    assert (record.error, record.status, record.attempts) == ("tls", None, 1)
    assert connections == [(("127.0.0.1", server.port), 0.9)]


def test_a_url_without_a_port_uses_the_default_port_of_its_scheme() -> None:
    """A URL without a port resolves the named host with port 80 for http and 443 for https.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_10
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_11
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_12
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_13
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_14
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_15
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_16
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_40
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_41
    """
    resolver = MappedResolver({"sut.test": ["93.184.216.34"]})
    subject = engine({"allowed_hosts": ("sut.test",)}, resolver=resolver)
    # The host is public and there is no authorization, so no connection is made.
    assert subject.fetch(Request("GET", "http://sut.test/")).error == "authorization_denied"
    assert subject.fetch(Request("GET", "https://sut.test/")).error == "authorization_denied"
    assert resolver.asked == [("sut.test", 80), ("sut.test", 443)]


def test_a_url_without_a_host_is_denied_for_every_host_list() -> None:
    """A URL without a host is denied before name resolution, whatever hosts the policy lists.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_7
    """
    resolver = MappedResolver({})
    subject = engine({"allowed_hosts": ("xxxx",), "allow_private_hosts": ("xxxx",)}, resolver=resolver)
    assert subject.fetch(Request("GET", "http:///x")).error == "policy_denied"
    assert resolver.asked == []


@pytest.mark.parametrize("userinfo", ["user@", ":pw@"])
def test_a_url_with_a_user_name_or_a_password_alone_is_denied(userinfo: str, loopback: Start) -> None:
    """A URL with a user name and no password, or a password and no user name, is denied.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_22
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_23
    """
    server = loopback(reply)
    record = transport().fetch(Request("GET", f"http://{userinfo}127.0.0.1:{server.port}/ok"))
    assert record.error == "policy_denied"
    assert server.seen == []


@pytest.mark.parametrize("answer", [[], ["not-an-address"]])
def test_an_empty_or_unreadable_dns_answer_is_a_dns_error(answer: list[str]) -> None:
    """An empty name answer, or an answer that is not an address, is a DNS error.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_48
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_49
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_50
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_56
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_57
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_58
    """
    subject = engine({"allowed_hosts": ("sut.test",)}, resolver=MappedResolver({"sut.test": answer}))
    assert subject.fetch(Request("GET", "http://sut.test/")).error == "dns"


@pytest.mark.parametrize("field", ["not_before", "not_after"])
def test_an_authorization_is_valid_at_both_ends_of_its_period(field: str, loopback: Start) -> None:
    """The transport accepts an authorization at the first and at the last instant of its period.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_95
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_96
    """
    server = loopback(reply)
    auth = authorization(endpoints=(server.origin,), **{field: NOW_STAMP})
    assert transport(authorization=auth).fetch(Request("GET", f"{server.origin}/ok")).status == 200


def test_the_request_line_keeps_the_path_and_the_query(loopback: Start) -> None:
    """The request line holds "/" for an empty path, and the query as the URL gives it.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_108
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_112
    dppce.infrastructure.transport.xǁPolicyTransportǁ_target__mutmut_116
    """
    server = loopback(reply)
    subject = transport()
    subject.fetch(Request("GET", server.origin))
    subject.fetch(Request("GET", f"{server.origin}/q?lang=en&x=a?b"))
    assert [seen["path"] for seen in server.seen] == ["/", "/q?lang=en&x=a?b"]


def test_the_wait_between_requests_counts_the_time_since_the_last_one(loopback: Start) -> None:
    """The wait before a request is the minimum interval less the time since the last request.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_5
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_8
    """
    server = loopback(reply)
    now = [100.0]
    waits: list[float] = []
    subject = engine({"min_interval_ms": 500}, sleep=waits.append, monotonic=lambda: now[0])
    subject.fetch(Request("GET", f"{server.origin}/ok"))
    now[0] = 100.25
    subject.fetch(Request("GET", f"{server.origin}/ok"))
    assert waits == [0.25]


# -- bodies, protocol errors, and the deadline timer --------------------------------------------


def test_a_write_sends_its_body(loopback: Start) -> None:
    """An authorized write sends its body to the system.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_65
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_69
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_125
    """
    server = loopback(echo)
    subject = transport(authorization=authorization(endpoints=(server.origin,)))
    assert subject.fetch(Request("POST", f"{server.origin}/x", body=b"payload")).body == b"payload"


def test_the_body_limit_bounds_the_read_of_a_longer_body(raw: Callable[..., RawServer]) -> None:
    """The transport reads one byte past the body limit and no more. It does not wait for the rest.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_74
    """
    server = raw(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n" + b"x" * 2048, hold=True)
    try:
        record = engine({"max_body_bytes": 1024, "timeout_ms": 900}).fetch(
            Request("GET", f"http://127.0.0.1:{server.port}/big")
        )
    finally:
        server.release.set()
    assert (record.status, record.error, len(record.body), record.truncated) == (200, None, 1024, True)


def test_a_body_of_exactly_the_limit_is_not_truncated(loopback: Start) -> None:
    """A body of exactly the body limit is kept whole and is not marked as truncated.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_82
    """
    server = loopback(lambda r: reply(r, body=b"x" * 1024))
    record = engine({"max_body_bytes": 1024}).fetch(Request("GET", f"{server.origin}/ok"))
    assert (len(record.body), record.truncated) == (1024, False)


def test_a_reply_that_is_not_http_is_a_protocol_error_and_is_not_retried(
    raw: Callable[..., RawServer],
) -> None:
    """A reply that is not HTTP is a protocol error. A protocol error is not retried.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_92
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_95
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_96
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_132
    """
    server = raw(b"garbage\r\n\r\n")
    record = engine({"retries": 2}).fetch(Request("GET", f"http://127.0.0.1:{server.port}/ok"))
    assert (record.error, record.status, record.attempts) == ("protocol", None, 1)


def test_a_header_value_that_http_cannot_carry_is_a_protocol_error(loopback: Start) -> None:
    """A request header value that HTTP cannot encode is a protocol error. Nothing is sent.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_103
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_104
    """
    server = loopback(reply)
    record = transport().fetch(Request("GET", f"{server.origin}/ok", headers={"X-Test": "☃"}))
    assert record.error == "protocol"
    assert server.seen == []


def test_a_reply_cut_by_the_deadline_is_a_timeout(
    raw: Callable[..., RawServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A protocol error after the deadline passed is a timeout.

    The test replaces threading.Timer to simulate the expiry of the deadline.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_91
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_93
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_94
    """
    monkeypatch.setattr(threading, "Timer", ExpireAtStart)
    server = raw(b"garbage\r\n\r\n")
    assert transport().fetch(Request("GET", f"http://127.0.0.1:{server.port}/ok")).error == "timeout"


def test_a_send_cut_by_the_deadline_is_a_timeout(loopback: Start, monkeypatch: pytest.MonkeyPatch) -> None:
    """A socket error after the deadline passed is a timeout.

    The test replaces threading.Timer to simulate the expiry of the deadline. The stand-in shuts
    down the socket at once, as the real timer does when the deadline passes.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_97
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_99
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_100
    """
    monkeypatch.setattr(threading, "Timer", ShutdownAtStart)
    server = loopback(reply)
    assert transport().fetch(Request("GET", f"{server.origin}/ok")).error == "timeout"


# -- request headers and credentials ------------------------------------------------------------


def test_the_request_headers_without_a_contact(loopback: Start) -> None:
    """Without a contact, the User-Agent names the engine only. The transport asks for no encoding.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_3
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_4
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_13
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_14
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_15
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_16
    dppce.infrastructure.transport.xǁPolicyTransportǁ_headers__mutmut_17
    """
    server = loopback(reply)
    record = transport().fetch(Request("GET", f"{server.origin}/ok"))
    assert server.seen[0]["User-Agent"] == "dppce/1.2.3"
    assert server.seen[0]["Accept-Encoding"] == "identity"
    assert record.request_headers == (
        ("Accept", "*/*"),
        ("Accept-Encoding", "<removed>"),
        ("User-Agent", "dppce/1.2.3"),
    )


@pytest.mark.parametrize(
    ("echoed", "kept"),
    [
        (b"echo:" + TOKEN[:17].encode(), b"echo:<removed>"),
        (b"echo:" + TOKEN[:8].encode(), b"echo:<removed>"),
        (b"echo:" + TOKEN[:7].encode(), b"echo:" + TOKEN[:7].encode()),
    ],
)
def test_a_credential_cut_by_the_body_end_is_removed_from_its_eighth_character(
    echoed: bytes, kept: bytes, loopback: Start
) -> None:
    """A head of a credential at the end of the body is removed if it has 8 characters or more.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_scrub__mutmut_45
    dppce.infrastructure.transport.xǁPolicyTransportǁ_scrub__mutmut_46
    dppce.infrastructure.transport.xǁPolicyTransportǁ_scrub__mutmut_47
    dppce.infrastructure.transport.xǁPolicyTransportǁ_scrub__mutmut_53
    """
    server = loopback(lambda r: reply(r, body=echoed))
    subject = transport(credentials={"auditor": (server.origin, TOKEN)})
    assert subject.fetch(Request("GET", f"{server.origin}/ok")).body == kept


def test_a_credential_inside_a_longer_one_is_removed_as_a_whole(loopback: Start) -> None:
    """A credential that holds a shorter credential is removed as a whole.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ__init____mutmut_29
    dppce.infrastructure.transport.xǁPolicyTransportǁ__init____mutmut_32
    """
    server = loopback(lambda r: reply(r, body=b"echo:" + LONG.encode()))
    subject = transport(credentials={"a": (server.origin, SHORT), "b": (server.origin, LONG)})
    assert subject.fetch(Request("GET", f"{server.origin}/ok")).body == b"echo:<removed>"


def test_a_credential_of_exactly_the_minimum_length_is_accepted() -> None:
    """A credential of exactly the minimum length is accepted. One character less is refused.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ__init____mutmut_24
    """
    assert len("TEST-ONLY-12") == MIN_SECRET_LENGTH
    transport(credentials={"r": ("http://127.0.0.1", "TEST-ONLY-12")})
    with pytest.raises(ValueError, match="12 characters"):
        transport(credentials={"r": ("http://127.0.0.1", "TEST-ONLY-1")})


def test_the_pinned_sample_is_closed_with_the_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transport keeps the sample open while it lives, and closes it when it ends.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ__init____mutmut_13
    dppce.infrastructure.transport.xǁPolicyTransportǁ__init____mutmut_18
    """
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"image-bytes")
    opened: list[int] = []
    real_open = os.open
    with monkeypatch.context() as patch:

        def spy(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            handle = real_open(path, flags, *args, **kwargs)
            opened.append(handle)
            return handle

        patch.setattr(os, "open", spy)
        subject = transport(samples={"qr_image": sample})
    assert len(opened) == 1
    os.fstat(opened[0])
    del subject
    gc.collect()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(opened[0])


# -- deadline, retries, and redirects -----------------------------------------------------------


def test_the_total_deadline_is_the_total_timeout(
    loopback: Start, connections: list[tuple[object, object]]
) -> None:
    """The deadline of a fetch is the total timeout. It bounds the socket timeout of a request.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_10
    """
    server = loopback(reply)
    subject = engine({"timeout_ms": 5000, "total_timeout_ms": 2000}, monotonic=lambda: 100.0)
    subject.fetch(Request("GET", f"{server.origin}/ok"))
    assert connections[0][1] == 2.0


def test_a_refused_request_is_not_marked_truncated() -> None:
    """A request that the policy refuses has no body, and its record is not marked as truncated.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_12
    """
    record = transport({}).fetch(Request("GET", "http://127.0.0.1/"))
    assert (record.error, record.truncated) == ("policy_denied", False)


def test_a_write_is_sent_once_however_many_retries() -> None:
    """A write is sent once. The retries of the policy apply only to safe methods.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_104
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_106
    """
    subject = transport(
        LOCAL | {"retries": 2, "timeout_ms": 500},
        authorization=authorization(endpoints=("http://127.0.0.1:1",)),
    )
    record = subject.fetch(Request("POST", "http://127.0.0.1:1/", body=b"1"))
    assert (record.error, record.attempts) == ("connect", 1)


def test_the_deadline_has_passed_when_no_time_is_left(loopback: Start) -> None:
    """With no time left, the fetch is a timeout and sends nothing.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_113
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_115
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_116
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_117
    """
    server = loopback(reply)
    record = engine({"total_timeout_ms": 1000}, monotonic=ticks(100.0, 101.0)).fetch(
        Request("GET", f"{server.origin}/ok")
    )
    assert (record.error, record.attempts) == ("timeout", 0)
    assert server.seen == []


def test_one_second_left_is_enough_to_send(loopback: Start) -> None:
    """With exactly one second left, the fetch sends its request.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_114
    """
    server = loopback(reply)
    # The deadline is 102.0, so exactly 1.0 second is left at 101.0.
    record = engine({"total_timeout_ms": 2000}, monotonic=ticks(100.0, 101.0)).fetch(
        Request("GET", f"{server.origin}/ok")
    )
    assert (record.status, record.attempts) == (200, 1)


def test_a_write_does_not_follow_a_redirect(loopback: Start) -> None:
    """A write keeps the redirect response and does not follow it.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_146
    """
    server = loopback(redirect_to("/landed"))
    subject = transport(authorization=authorization(endpoints=(server.origin,)))
    record = subject.fetch(Request("POST", f"{server.origin}/hop", body=b"1"))
    assert (record.status, record.redirects) == (302, ())
    assert [seen["path"] for seen in server.seen] == ["/hop"]


def test_a_location_without_a_redirect_status_is_not_followed(loopback: Start) -> None:
    """A Location header in a response that is not a redirect is not followed.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_147
    """
    server = loopback(lambda r: reply(r, 200, b"{}", {"Location": "/landed"}))
    record = transport().fetch(Request("GET", f"{server.origin}/ok"))
    assert (record.status, record.redirects) == (200, ())
    assert len(server.seen) == 1


def test_a_redirect_stopped_at_the_limit_keeps_its_response(loopback: Start) -> None:
    """A redirect past the limit is recorded with its status and its headers.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_162
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_166
    """
    server = loopback(lambda r: reply(r, 302, b"", {"Location": "/again"}))
    record = transport(LOCAL | {"max_redirects": 1}).fetch(Request("GET", f"{server.origin}/again"))
    assert (record.error, record.status) == ("too_many_redirects", 302)
    assert record.header("location") == "/again"


def test_a_location_that_is_not_a_url_keeps_the_response(loopback: Start) -> None:
    """A Location that is not a URL ends the fetch. The record keeps the status and the headers.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_179
    """
    server = loopback(redirect_to("http://[::1"))
    record = transport().fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.error, record.status) == ("redirect_out_of_scope", 302)
    assert record.header("location") == "<removed>"
    assert record.header("content-type") == "application/json"
    assert record.redirects == ()


def test_an_out_of_scope_hop_keeps_the_redirect_response(loopback: Start) -> None:
    """A hop outside the policy ends the fetch. The record keeps the status and the headers.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_198
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_201
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_202
    """
    server = loopback(redirect_to("http://out-of-scope.example.test/"))
    record = transport().fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.error, record.status) == ("redirect_out_of_scope", 302)
    assert record.header("location") == "http://out-of-scope.example.test/"


def test_a_hop_to_a_public_host_without_an_authorization_is_out_of_scope(loopback: Start) -> None:
    """A hop that needs an authorization that is not there is out of scope.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_195
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_196
    """
    server = loopback(redirect_to("http://pub.test/x"))
    resolver = MappedResolver({"127.0.0.1": ["127.0.0.1"], "pub.test": ["93.184.216.34"]})
    policy = {"allowed_hosts": ("127.0.0.1", "pub.test"), "allow_private_hosts": ("127.0.0.1",)}
    record = engine(policy, resolver=resolver).fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.error, record.status) == ("redirect_out_of_scope", 302)


def test_a_hop_whose_name_does_not_resolve_keeps_the_dns_error(loopback: Start) -> None:
    """A hop to a name that does not resolve is a DNS error, not an out-of-scope hop.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_204
    """
    server = loopback(redirect_to("http://gone.test/x"))
    resolver = MappedResolver({"127.0.0.1": ["127.0.0.1"]})
    subject = engine({"allowed_hosts": ("127.0.0.1", "gone.test")}, resolver=resolver)
    record = subject.fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.error, record.status) == ("dns", 302)


def test_a_hop_off_the_credential_origin_keeps_the_redirect_response(loopback: Start) -> None:
    """A role request stops at a hop to a different origin. The record keeps the status and headers.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_213
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_217
    """
    other = loopback(reply)
    landing = f"http://localhost:{other.port}/landed"
    first = loopback(redirect_to(landing))
    resolver = MappedResolver({"127.0.0.1": ["127.0.0.1"], "localhost": ["127.0.0.1"]})
    subject = engine(resolver=resolver, credentials={"auditor": (first.origin, TOKEN)})
    record = subject.fetch(Request("GET", f"{first.origin}/hop", role="auditor"))
    assert (record.error, record.status) == ("redirect_out_of_scope", 302)
    assert record.header("location") == landing
    assert other.seen == []


def test_an_authorized_redirect_hop_is_checked_with_the_method_and_the_role(loopback: Start) -> None:
    """An authorization that permits the method and the role of the request also permits the hop.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_186
    dppce.infrastructure.transport.xǁPolicyTransportǁfetch__mutmut_187
    """
    server = loopback(redirect_to("/landed"))
    auth = authorization(endpoints=(server.origin,), methods=("GET",), roles=("anonymous",), scopes=("read",))
    record = transport(authorization=auth).fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.status, record.redirects) == (200, (f"{server.origin}/landed",))


# -- artifacts ----------------------------------------------------------------------------------


def test_an_artifact_record_names_the_read_and_the_local_role(tmp_path: Path) -> None:
    """An artifact record has the method READ, the role local, one attempt, and no HTTP fields.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_71
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_73
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_77
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_80
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_102
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_103
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_104
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_105
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_106
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_107
    """
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"image-bytes")
    record = transport(samples={"qr_image": sample}).artifact("qr_image")
    assert (
        record.method,
        record.role,
        record.truncated,
        record.attempts,
        record.status,
        record.request_headers,
    ) == ("READ", "local", False, 1, None, ())


def test_a_sample_of_exactly_the_size_limit_is_read(tmp_path: Path) -> None:
    """A sample of exactly the size limit is read.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_58
    """
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"x" * 64)
    record = transport(samples={"qr_image": sample}, max_artifact_bytes=64).artifact("qr_image")
    assert (record.error, len(record.body)) == (None, 64)


def test_a_sample_that_grew_after_the_size_check_is_read_only_to_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sample that grew after the size check is read only to the size limit.

    The test replaces os.fstat to simulate the race: the size check sees 10 bytes.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_63
    """
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"x" * 100)
    subject = transport(samples={"qr_image": sample}, max_artifact_bytes=64)
    real_fstat = os.fstat

    def shrunk(handle: int) -> os.stat_result:
        fields = list(real_fstat(handle)[:10])
        fields[6] = 10  # st_size
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", shrunk)
    record = subject.artifact("qr_image")
    assert (record.error, len(record.body)) == (None, 64)


def test_a_link_swapped_in_after_the_path_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A link that replaces the sample after the path check is not followed.

    The test replaces Path.resolve to simulate a swap after the check: the check sees no link.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_19
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_20
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_26
    dppce.infrastructure.transport.xǁPolicyTransportǁartifact__mutmut_27
    """
    sample = tmp_path / "a.png"
    sample.write_bytes(b"image-bytes")
    subject = transport(samples={"qr_image": sample})
    moved = tmp_path / "b.png"
    os.rename(sample, moved)
    os.symlink(moved, sample)
    monkeypatch.setattr(pathlib.Path, "resolve", lambda self, strict=False: self)
    assert subject.artifact("qr_image").error == "artifact_unavailable"


# -- redaction ----------------------------------------------------------------------------------


def test_redact_url_returns_a_url_with_nothing_to_remove_unchanged() -> None:
    """A URL with nothing to remove comes back unchanged, also with an empty query.

    Kills:
    dppce.infrastructure.redaction.x_redact_url__mutmut_6
    """
    assert redact_url("https://sut.example/a?") == "https://sut.example/a?"


def test_redact_url_removes_a_password_that_holds_an_at_sign() -> None:
    """The whole userinfo is removed, also if the password holds an at sign.

    Kills:
    dppce.infrastructure.redaction.x_redact_url__mutmut_29
    """
    assert redact_url("https://user:p@ss@sut.example/x") == "https://sut.example/x"


def test_redact_url_keeps_a_plain_query_when_it_removes_other_parts() -> None:
    """A query without a credential-like name is kept as it is when other parts are removed.

    Kills:
    dppce.infrastructure.redaction.x_redact_url__mutmut_34
    """
    assert redact_url("https://sut.example/x?q=a%20b#top") == "https://sut.example/x?q=a%20b"
    assert redact_url("https://user@sut.example/x?q=a%20b") == "https://sut.example/x?q=a%20b"


def test_redact_link_keeps_targets_and_relation_names() -> None:
    """A Link header keeps its redacted targets and its registered relation names in lower case.

    Kills:
    dppce.infrastructure.redaction.x_redact_link__mutmut_12
    dppce.infrastructure.redaction.x_redact_link__mutmut_15
    dppce.infrastructure.redaction.x_redact_link__mutmut_16
    dppce.infrastructure.redaction.x_redact_link__mutmut_17
    dppce.infrastructure.redaction.x_redact_link__mutmut_18
    dppce.infrastructure.redaction.x_redact_link__mutmut_20
    dppce.infrastructure.redaction.x_redact_link__mutmut_21
    dppce.infrastructure.redaction.x_redact_link__mutmut_27
    """
    assert redact_link("<https://sut.example/a>") == "<https://sut.example/a>"
    assert redact_link('<https://sut.example/a>; rel="Next Last", <https://sut.example/b?token=S1>') == (
        '<https://sut.example/a>; rel="next last", <https://sut.example/b?token=%3Cremoved%3E>'
    )
    every = f'<https://sut.example/a>; rel="{" ".join(sorted(_RELATIONS))}"'
    assert redact_link(every) == every


def test_is_public_address_reads_no_ipv4_address_outside_a_translation_prefix() -> None:
    """A global IPv6 address outside every translation prefix carries no IPv4 address.

    Kills:
    dppce.infrastructure.redaction.x__embedded_ipv4__mutmut_6
    """
    assert is_public_address("2606:2800:220:1::a00:1") is True


def test_is_public_address_refuses_a_local_use_nat64_address_with_any_middle_bits() -> None:
    """A local-use NAT64 address is read by its low 32 bits, whatever its middle bits are.

    Kills:
    dppce.infrastructure.redaction.x__embedded_ipv4__mutmut_10
    """
    assert is_public_address("64:ff9b:1::1:a00:1") is False


# -- authorization ------------------------------------------------------------------------------


def test_validate_authorization_needs_the_named_key_with_the_authorization_purpose(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """The named key must have the authorization purpose. A key without it is not trusted.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_18
    """
    token = issue_authorization(authorization(), signer)
    report_only = trust.model_copy(
        update={"keys": (trust.keys[0].model_copy(update={"purposes": ("report",)}),)}
    )
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(token, report_only, NOW, "urn:example:sut")
    assert caught.value.code == "AUTHZ.ISSUER.UNTRUSTED"


@pytest.mark.parametrize("field", ["not_before", "not_after"])
def test_validate_authorization_key_validity_includes_both_ends(
    field: str, signer: LocalSigner, trust: TrustBundle
) -> None:
    """The key is valid at the first and at the last instant of its validity.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_37
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_38
    """
    token = issue_authorization(authorization(), signer)
    edge = trust.model_copy(update={"keys": (trust.keys[0].model_copy(update={field: NOW_STAMP}),)})
    assert validate_authorization(token, edge, NOW, "urn:example:sut") == authorization()


@pytest.mark.parametrize("field", ["not_before", "not_after"])
def test_validate_authorization_period_includes_both_ends(
    field: str, signer: LocalSigner, trust: TrustBundle
) -> None:
    """The authorization is valid at the first and at the last instant of its period.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_104
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_105
    """
    edge = authorization(**{field: NOW_STAMP})
    token = issue_authorization(edge, signer)
    assert validate_authorization(token, trust, NOW, "urn:example:sut") == edge


def test_validate_authorization_refuses_a_signed_payload_that_is_not_canonical(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """A signed payload that is valid but not canonical is malformed.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_58
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_60
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_61
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_62
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_63
    """
    indented = json.dumps(json.loads(canonical_bytes(authorization())), indent=1).encode()
    token = sign_compact(indented, signer, typ=AUTHORIZATION_TYP)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(token, trust, NOW, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"
    assert str(caught.value) == "The signed payload is not a canonical authorization."


def test_validate_authorization_reports_a_one_line_parse_error(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """A payload that does not parse is malformed. The message is the one line of the parse error.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_81
    """
    token = sign_compact(b'{"a":1,"a":2}', signer, typ=AUTHORIZATION_TYP)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(token, trust, NOW, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"
    assert str(caught.value) == "duplicate object key: a"
