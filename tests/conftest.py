"""Shared fixtures. Every key here is generated for the test run and is not a real key."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import EvidenceEnvelope, TrustBundle, TrustedKey
from tests.support import ISSUER, KID, Handler, LoopbackServer, make_envelope


@pytest.fixture(scope="session")
def signer() -> LocalSigner:
    return LocalSigner.generate(KID)


@pytest.fixture(scope="session")
def trust(signer: LocalSigner) -> TrustBundle:
    key = TrustedKey(
        kid=KID,
        issuer=ISSUER,
        purposes=("report", "authorization"),
        public_jwk=signer.public_jwk(),
        not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z",
    )
    return TrustBundle(schema_version="dppce.trust/2", policy_version="test-1", keys=(key,))


@pytest.fixture
def signed(signer: LocalSigner) -> EvidenceEnvelope:
    return sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")


@pytest.fixture
def loopback() -> Iterator[Callable[[Handler], LoopbackServer]]:
    servers: list[LoopbackServer] = []

    def start(handler: Handler) -> LoopbackServer:
        server = LoopbackServer(handler)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


_real_connect = socket.socket.connect
_real_getaddrinfo = socket.getaddrinfo


def _is_loopback_name(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if host is None or host == "" or str(host).lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


def _is_loopback(address: object) -> bool:
    if not isinstance(address, tuple) or not address:
        return True  # a Unix domain socket path: local by definition
    try:
        return ipaddress.ip_address(str(address[0]).split("%")[0]).is_loopback
    except ValueError:
        return str(address[0]) == "localhost"


@pytest.fixture(autouse=True, scope="session")
def _no_external_network() -> Iterator[None]:
    """Fail any test that opens a connection to, or looks up the name of, a host other than loopback.

    The suite must never contact a real DPP system, registry, or third-party service. CI also
    removes network access at the operating-system level; this guard works on every machine.
    A name lookup is guarded too: SystemResolver calls getaddrinfo, so a mutant of transport.py
    could otherwise send a real DNS query.
    """

    def guarded(self: socket.socket, address: object) -> None:
        if not _is_loopback(address):
            raise AssertionError(f"a test tried to connect to {address!r}; tests use loopback only")
        _real_connect(self, address)  # type: ignore[arg-type]

    def guarded_getaddrinfo(host: object, *args: Any, **kwargs: Any) -> Any:
        if not _is_loopback_name(host):
            raise AssertionError(f"a test tried to resolve {host!r}; tests use loopback only")
        return _real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]

    socket.socket.connect = guarded  # type: ignore[method-assign, assignment]
    socket.getaddrinfo = guarded_getaddrinfo
    try:
        yield
    finally:
        socket.socket.connect = _real_connect  # type: ignore[method-assign]
        socket.getaddrinfo = _real_getaddrinfo
